//! The sans-IO state machine behind [`Relay`](crate::relay::Relay): one
//! request table, pending publishes, and NIP-42 state. No I/O, clock, or
//! channels — the driver owns those; this owns the protocol decisions.
//! Protocol-driven writes and waiter resolutions are queued as [`Out`]s
//! and drained through [`Session::poll_out`].

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};

use nk_core::{ClientMessage, CountResult, Event, EventId, Filter, RelayMessage, SubscriptionId};

use super::neg::{NegSession, Reconciliation, Round};
use super::{Error, Result};

/// What the session wants the driver to do.
#[derive(Debug)]
pub(crate) enum Out {
    /// Write this client message.
    Send(ClientMessage<'static>),
    /// Sign a kind-22242 `AUTH` event for this challenge (off-loop work).
    Sign(String),
    /// Deliver `event` to request `id` (a subscription or fetch).
    Event {
        /// The receiving request.
        id: SubscriptionId,
        /// The verified, matching event.
        event: Event,
    },
    /// `EOSE` for `id` — first one only for subscriptions, terminal for
    /// fetches (a `Send(CLOSE)` precedes it in the queue).
    Eose(SubscriptionId),
    /// `id` ended; `reason` is the relay's `CLOSED`/`NEG-ERR` message.
    Closed {
        /// The ended request.
        id: SubscriptionId,
        /// The relay's machine-readable reason.
        reason: String,
    },
    /// A NIP-45 `COUNT` reply.
    Counted {
        /// The count's id.
        id: SubscriptionId,
        /// The relay's result.
        result: CountResult,
    },
    /// A finished NIP-77 sync.
    Reconciled {
        /// The NEG id.
        id: SubscriptionId,
        /// The final have/need sets.
        result: Reconciliation,
    },
    /// A request failed locally (negentropy build/codec error).
    Failed {
        /// The failed request.
        id: SubscriptionId,
        /// The error to surface.
        error: Error,
    },
    /// `EVENT` was accepted (`true`) or refused (`false`) with `message`.
    Published {
        /// The published event id.
        id: EventId,
        /// The relay's `saved` flag.
        accepted: bool,
        /// The machine-readable relay message.
        message: String,
    },
    /// An inbound `EVENT` failed acceptance on a live request.
    Rejected {
        /// The request the event targeted.
        id: SubscriptionId,
        /// Why it was dropped.
        reason: RejectReason,
    },
    /// A `NOTICE` for tracing.
    Notice(String),
}

/// Why an inbound `EVENT` was dropped (NIP-01 acceptance).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// `Event::verify` failed — bad id or signature.
    InvalidSignature,
    /// The event matched none of the request's filters.
    FilterMismatch,
}

/// A request's position in the NIP-42 flow.
#[derive(Clone, Debug, Default)]
enum AuthMark {
    /// Never refused — the normal state.
    #[default]
    Fresh,
    /// Refused with `auth-required:`; the value is the original reason,
    /// surfaced when AUTH fails or can't run.
    Waiting(String),
    /// The good AUTH already resent this request once; a second refusal
    /// is terminal.
    Retried,
}

/// The kind of an open request, keyed by subscription id.
#[derive(Debug)]
enum Kind {
    /// A `REQ` stream — the only kind replayed after reconnect.
    Sub {
        /// The `REQ`'s filters — inbound events must match at least one.
        filters: Vec<Filter>,
        /// `EOSE` has been delivered once.
        eose: bool,
    },
    /// A bounded `REQ` closed by its `EOSE`.
    Fetch {
        /// The `REQ`'s filters.
        filters: Vec<Filter>,
    },
    /// A `COUNT`.
    Count {
        /// The `COUNT`'s filters (kept for the AUTH retry).
        filters: Vec<Filter>,
    },
    /// A NIP-77 sync — the negentropy state machine lives here so the
    /// table stays protocol-routing only.
    Neg(Box<NegState>),
}

/// The `NEG` variant's payload.
#[derive(Debug)]
struct NegState {
    /// The `NEG-OPEN` filter (kept for the AUTH retry).
    filter: Filter,
    /// The caller's item set — rebuilds `neg` on a retry.
    items: Vec<(nk_core::Timestamp, EventId)>,
    /// The live sync.
    neg: NegSession,
}

impl NegState {
    /// Rebuilds the sync from `items` for an AUTH retry; returns the
    /// `NEG-OPEN` wire message.
    fn restart(&mut self, id: &SubscriptionId) -> Result<ClientMessage<'static>> {
        let (neg, message) = NegSession::start(&self.items)?;
        self.neg = neg;
        Ok(neg_open(id, &self.filter, message))
    }
}

/// The `NEG-OPEN` wire message for `id`.
fn neg_open(id: &SubscriptionId, filter: &Filter, message: String) -> ClientMessage<'static> {
    ClientMessage::NegOpen {
        subscription_id: Cow::Owned(id.clone()),
        filter: Cow::Owned(filter.clone()),
        message: Cow::Owned(message),
    }
}

/// One open request.
#[derive(Debug)]
struct Request {
    kind: Kind,
    auth: AuthMark,
}

/// A pending publish — concurrent publishes of the same id join it.
#[derive(Debug)]
struct Publish {
    /// The payload — resent after a good AUTH.
    event: Event,
    /// Its NIP-42 position.
    auth: AuthMark,
}

/// NIP-42 state for the current connection only — [`Session::disconnected`]
/// clears it so a stale challenge is never signed for a new socket.
#[derive(Debug, Default)]
struct Auth {
    /// The latest challenge.
    challenge: Option<String>,
    /// A signing task is running off the driver loop.
    signing: bool,
    /// The AUTH event awaiting its `OK`.
    inflight: Option<EventId>,
}

/// What [`Session::disconnected`] reports — every one-shot in flight.
#[derive(Debug, Default)]
pub(crate) struct Lost {
    /// Publish ids to fail with `Disconnected`.
    pub(crate) publishes: Vec<EventId>,
    /// Non-subscription request ids to fail with `Disconnected`.
    pub(crate) requests: Vec<SubscriptionId>,
}

/// The relay session: requests, pending publishes, acceptance rules, AUTH.
#[derive(Debug)]
pub(crate) struct Session {
    requests: HashMap<SubscriptionId, Request>,
    publishes: HashMap<EventId, Publish>,
    auth: Auth,
    /// `options.signer.is_some()` — without a signer, `auth-required:`
    /// refusals are terminal.
    can_auth: bool,
    /// Driver-bound outputs, in order — drained by `poll_out`.
    outs: VecDeque<Out>,
}

impl Session {
    /// A fresh session; `can_auth` mirrors `options.signer.is_some()`.
    pub(crate) fn new(can_auth: bool) -> Self {
        Self {
            requests: HashMap::new(),
            publishes: HashMap::new(),
            auth: Auth::default(),
            can_auth,
            outs: VecDeque::new(),
        }
    }

    /// The next driver-bound output, in order.
    pub(crate) fn poll_out(&mut self) -> Option<Out> {
        self.outs.pop_front()
    }

    /// The wire message that (re)opens `id` — `REQ` for Sub/Fetch,
    /// `COUNT` for Count, `None` for NEG (it opens through `open_neg`).
    fn wire_msg(id: &SubscriptionId, kind: &Kind) -> Option<ClientMessage<'static>> {
        match kind {
            Kind::Sub { filters, .. } | Kind::Fetch { filters } => Some(ClientMessage::Req {
                subscription_id: Cow::Owned(id.clone()),
                filters: Cow::Owned(filters.clone()),
            }),
            Kind::Count { filters } => Some(ClientMessage::Count {
                subscription_id: Cow::Owned(id.clone()),
                filters: Cow::Owned(filters.clone()),
            }),
            Kind::Neg(_) => None,
        }
    }

    /// Registers `kind` under `id` and queues its open message.
    fn open(&mut self, id: &SubscriptionId, kind: Kind) {
        if let Some(msg) = Self::wire_msg(id, &kind) {
            self.outs.push_back(Out::Send(msg));
        }
        self.requests.insert(
            id.clone(),
            Request {
                kind,
                auth: AuthMark::Fresh,
            },
        );
    }

    /// Registers a `REQ` subscription and queues the `REQ`.
    pub(crate) fn open_sub(&mut self, id: &SubscriptionId, filters: Vec<Filter>) {
        self.open(
            id,
            Kind::Sub {
                filters,
                eose: false,
            },
        );
    }

    /// Registers a bounded `REQ` and queues it.
    pub(crate) fn open_fetch(&mut self, id: &SubscriptionId, filters: Vec<Filter>) {
        self.open(id, Kind::Fetch { filters });
    }

    /// Registers a NIP-45 `COUNT` and queues it.
    pub(crate) fn open_count(&mut self, id: &SubscriptionId, filters: Vec<Filter>) {
        self.open(id, Kind::Count { filters });
    }

    /// Registers a NIP-77 sync and queues the `NEG-OPEN`.
    ///
    /// # Errors
    ///
    /// [`Error::Negentropy`] when the item set cannot be sealed — nothing
    /// is registered or queued.
    pub(crate) fn open_neg(
        &mut self,
        id: SubscriptionId,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
    ) -> Result<()> {
        let (neg, message) = NegSession::start(&items)?;
        let msg = neg_open(&id, &filter, message);
        self.requests.insert(
            id,
            Request {
                kind: Kind::Neg(Box::new(NegState { filter, items, neg })),
                auth: AuthMark::Fresh,
            },
        );
        self.outs.push_back(Out::Send(msg));
        Ok(())
    }

    /// Registers `event` for its `OK` and queues the `EVENT`; `false`
    /// joins the in-flight publish instead.
    pub(crate) fn publish(&mut self, event: Event) -> bool {
        if self.publishes.contains_key(&event.id()) {
            return false;
        }
        self.publishes.insert(
            event.id(),
            Publish {
                event: event.clone(),
                auth: AuthMark::Fresh,
            },
        );
        self.outs
            .push_back(Out::Send(ClientMessage::Event(Cow::Owned(event))));
        true
    }

    /// Removes request `id` and queues its local-close wire message —
    /// `CLOSE` for subs and fetches, `NEG-CLOSE` for syncs, nothing for
    /// counts and unknown ids.
    pub(crate) fn close(&mut self, id: &SubscriptionId) {
        let Some(req) = self.requests.remove(id) else {
            return;
        };
        match req.kind {
            Kind::Sub { .. } | Kind::Fetch { .. } => {
                self.outs
                    .push_back(Out::Send(ClientMessage::Close(Cow::Owned(id.clone()))));
            }
            Kind::Neg { .. } => {
                self.outs
                    .push_back(Out::Send(ClientMessage::NegClose(Cow::Owned(id.clone()))));
            }
            Kind::Count { .. } => {}
        }
    }

    /// Drops a pending publish without resolving it (deadline expiry).
    pub(crate) fn forget_publish(&mut self, id: &EventId) {
        self.publishes.remove(id);
    }

    /// `REQ`s for every live subscription — the reconnect replay set.
    pub(crate) fn replay(&self) -> Vec<ClientMessage<'static>> {
        self.requests
            .iter()
            .filter(|(_, req)| matches!(req.kind, Kind::Sub { .. }))
            .filter_map(|(id, req)| Self::wire_msg(id, &req.kind))
            .collect()
    }

    /// The socket dropped: every one-shot is lost, subscriptions survive
    /// with their auth marks reset, and the whole AUTH state clears — a
    /// new connection gets a new challenge.
    pub(crate) fn disconnected(&mut self) -> Lost {
        let mut lost = Lost {
            publishes: self.publishes.keys().copied().collect(),
            requests: Vec::new(),
        };
        self.publishes.clear();
        self.requests.retain(|id, req| {
            if matches!(req.kind, Kind::Sub { .. }) {
                req.auth = AuthMark::Fresh;
                true
            } else {
                lost.requests.push(id.clone());
                false
            }
        });
        self.auth = Auth::default();
        lost
    }

    /// A fresh challenge queues a `Sign`; a sign request already
    /// outstanding or an AUTH event awaiting its `OK` queues nothing.
    fn want_sign(&mut self) {
        let Some(challenge) = self.auth.challenge.clone() else {
            return;
        };
        if self.auth.signing || self.auth.inflight.is_some() {
            return;
        }
        self.auth.signing = true;
        self.outs.push_back(Out::Sign(challenge));
    }

    /// An `auth-required:` refusal may retry once when a signer is
    /// present, a challenge is known, and the entry is still `Fresh`.
    const fn may_retry(&self, mark: &AuthMark) -> bool {
        self.can_auth && self.auth.challenge.is_some() && matches!(mark, AuthMark::Fresh)
    }

    /// A terminal refusal (`CLOSED`, `NEG-ERR`) on `id`. `kind_ok`
    /// restricts which request kinds the message applies to — a mismatch
    /// is ignored. `auth-required:` takes the NIP-42 path; anything else
    /// removes the entry and queues `Out::Closed`.
    fn refused_or_closed(
        &mut self,
        id: SubscriptionId,
        reason: String,
        kind_ok: impl Fn(&Kind) -> bool,
    ) {
        let Some(req) = self.requests.get(&id) else {
            return;
        };
        if !kind_ok(&req.kind) {
            return;
        }
        if reason.starts_with("auth-required:") && self.may_retry(&req.auth) {
            if let Some(entry) = self.requests.get_mut(&id) {
                entry.auth = AuthMark::Waiting(reason);
            }
            self.want_sign();
            return;
        }
        self.requests.remove(&id);
        self.outs.push_back(Out::Closed { id, reason });
    }

    /// Every `Waiting` entry on both tables — `(request ids, publish ids)`.
    fn waiting(&self) -> (Vec<SubscriptionId>, Vec<EventId>) {
        let requests = self
            .requests
            .iter()
            .filter(|(_, r)| matches!(r.auth, AuthMark::Waiting(_)))
            .map(|(id, _)| id.clone())
            .collect();
        let publishes = self
            .publishes
            .iter()
            .filter(|(_, p)| matches!(p.auth, AuthMark::Waiting(_)))
            .map(|(id, _)| *id)
            .collect();
        (requests, publishes)
    }

    /// An `OK` on the in-flight AUTH event: retry every `Waiting` entry
    /// (once) or surface its stored reason when refused.
    fn on_auth_ok(&mut self, accepted: bool) {
        self.auth.inflight = None;
        if accepted {
            let (requests, publishes) = self.waiting();
            for id in requests {
                self.retry_request(&id);
            }
            for id in publishes {
                self.retry_publish(&id);
            }
        } else {
            self.fallbacks();
        }
    }

    /// Resends one `Waiting` publish; `Retried` marks it terminal next.
    fn retry_publish(&mut self, id: &EventId) {
        let Some(p) = self.publishes.get_mut(id) else {
            return;
        };
        p.auth = AuthMark::Retried;
        let event = p.event.clone();
        self.outs
            .push_back(Out::Send(ClientMessage::Event(Cow::Owned(event))));
    }

    /// Resends one `Waiting` request; `Retried` marks it so a second
    /// `auth-required:` is terminal.
    fn retry_request(&mut self, id: &SubscriptionId) {
        /// What the retry produced — applied once the request borrow ends.
        enum Retry {
            /// Queue the (re)open message.
            Send(ClientMessage<'static>),
            /// The NEG session failed to rebuild — terminal.
            Fail(Error),
        }
        let retry = match self.requests.get_mut(id) {
            Some(req) => {
                req.auth = AuthMark::Retried;
                match &mut req.kind {
                    Kind::Sub { .. } | Kind::Fetch { .. } | Kind::Count { .. } => {
                        Self::wire_msg(id, &req.kind).map(Retry::Send)
                    }
                    Kind::Neg(state) => match state.restart(id) {
                        Ok(msg) => Some(Retry::Send(msg)),
                        Err(error) => Some(Retry::Fail(error)),
                    },
                }
            }
            None => None,
        };
        match retry {
            Some(Retry::Send(msg)) => self.outs.push_back(Out::Send(msg)),
            Some(Retry::Fail(error)) => {
                self.requests.remove(id);
                self.outs.push_back(Out::Failed {
                    id: id.clone(),
                    error,
                });
            }
            None => {}
        }
    }

    /// Every `Waiting` entry's normal terminal output — the stored reason.
    fn fallbacks(&mut self) {
        let (requests, publishes) = self.waiting();
        for id in requests {
            if let Some(req) = self.requests.remove(&id)
                && let AuthMark::Waiting(reason) = req.auth
            {
                self.outs.push_back(Out::Closed { id, reason });
            }
        }
        for id in publishes {
            if let Some(p) = self.publishes.remove(&id)
                && let AuthMark::Waiting(reason) = p.auth
            {
                self.outs.push_back(Out::Published {
                    id,
                    accepted: false,
                    message: reason,
                });
            }
        }
    }

    /// The off-loop signer produced `event` for `challenge`.
    ///
    /// A stale signature (a newer challenge arrived meanwhile) re-signs;
    /// with nothing `Waiting` the event is dropped unused.
    pub(crate) fn signed(&mut self, challenge: &str, event: Event) {
        self.auth.signing = false;
        let (requests, publishes) = self.waiting();
        if requests.is_empty() && publishes.is_empty() {
            return;
        }
        if self.auth.challenge.as_deref() != Some(challenge) {
            // The signed event answers a superseded challenge — sign the
            // current one instead, or fail the waiters when there is none.
            match self.auth.challenge.clone() {
                Some(current) => {
                    self.auth.signing = true;
                    self.outs.push_back(Out::Sign(current));
                }
                None => self.fallbacks(),
            }
            return;
        }
        self.auth.inflight = Some(event.id());
        self.outs
            .push_back(Out::Send(ClientMessage::Auth(Cow::Owned(event))));
    }

    /// Signing failed or was impossible — every `Waiting` entry falls
    /// back to its stored reason.
    pub(crate) fn sign_failed(&mut self) {
        self.auth.signing = false;
        self.fallbacks();
    }

    /// An inbound `EVENT` for a subscription or fetch.
    fn on_event(&mut self, id: SubscriptionId, event: Cow<'_, Event>) {
        let Some(req) = self.requests.get(&id) else {
            return;
        };
        let (Kind::Sub { filters, .. } | Kind::Fetch { filters }) = &req.kind else {
            return;
        };
        // NIP-01: only verified events matching a filter are delivered.
        if event.verify().is_err() {
            self.outs.push_back(Out::Rejected {
                id,
                reason: RejectReason::InvalidSignature,
            });
            return;
        }
        if !filters.iter().any(|f| f.matches(&event)) {
            self.outs.push_back(Out::Rejected {
                id,
                reason: RejectReason::FilterMismatch,
            });
            return;
        }
        self.outs.push_back(Out::Event {
            id,
            event: event.into_owned(),
        });
    }

    /// One `NEG-MSG` round on a `Kind::Neg` entry — other kinds ignore
    /// it; the entry is removed only on the terminal round.
    fn on_neg_msg(&mut self, id: SubscriptionId, message: &str) {
        let round = match self.requests.get_mut(&id) {
            Some(req) => match &mut req.kind {
                Kind::Neg(state) => Some(state.neg.on_msg(message)),
                _ => None,
            },
            None => None,
        };
        let Some(round) = round else {
            return;
        };
        match round {
            Ok(Round::Next(next)) => {
                self.outs.push_back(Out::Send(ClientMessage::NegMsg {
                    subscription_id: Cow::Owned(id),
                    message: Cow::Owned(next),
                }));
            }
            Ok(Round::Done(result)) => {
                // Sync finished — `NEG-CLOSE`, then resolve the waiter.
                self.requests.remove(&id);
                self.outs
                    .push_back(Out::Send(ClientMessage::NegClose(Cow::Owned(id.clone()))));
                self.outs.push_back(Out::Reconciled { id, result });
            }
            Err(error) => {
                // Codec error — terminal, entry comes out.
                self.requests.remove(&id);
                self.outs
                    .push_back(Out::Send(ClientMessage::NegClose(Cow::Owned(id.clone()))));
                self.outs.push_back(Out::Failed { id, error });
            }
        }
    }

    /// A `NEG-ERR` applies only to `Kind::Neg`.
    fn on_neg_err(&mut self, id: SubscriptionId, reason: String) {
        self.refused_or_closed(id, reason, |k| matches!(k, Kind::Neg(_)));
    }

    /// An `OK` for a pending publish or the in-flight AUTH.
    fn on_ok(&mut self, id: EventId, accepted: bool, message: String) {
        if self.auth.inflight == Some(id) {
            self.on_auth_ok(accepted);
            return;
        }
        let Some(pending) = self.publishes.get(&id) else {
            return;
        };
        if !accepted && message.starts_with("auth-required:") && self.may_retry(&pending.auth) {
            let Some(p) = self.publishes.get_mut(&id) else {
                return;
            };
            p.auth = AuthMark::Waiting(message);
            self.want_sign();
            return;
        }
        // Terminal — accepted, refused, or a second auth-required.
        if let Some(done) = self.publishes.remove(&id) {
            let message = match done.auth {
                AuthMark::Waiting(reason) => reason,
                _ => message,
            };
            self.outs.push_back(Out::Published {
                id,
                accepted,
                message,
            });
        }
    }

    /// `EOSE` on a sub fires once; on a fetch it also queues `CLOSE`.
    fn on_eose(&mut self, id: SubscriptionId) {
        if matches!(
            self.requests.get(&id).map(|r| &r.kind),
            Some(Kind::Fetch { .. })
        ) {
            self.requests.remove(&id);
            self.outs
                .push_back(Out::Send(ClientMessage::Close(Cow::Owned(id.clone()))));
            self.outs.push_back(Out::Eose(id));
            return;
        }
        let Some(req) = self.requests.get_mut(&id) else {
            return;
        };
        if let Kind::Sub { eose, .. } = &mut req.kind
            && !*eose
        {
            *eose = true;
            self.outs.push_back(Out::Eose(id));
        }
    }

    /// The single entry point for inbound relay traffic; every output
    /// lands in the `poll_out` queue.
    pub(crate) fn handle(&mut self, message: RelayMessage<'_>) {
        match message {
            RelayMessage::Event {
                subscription_id,
                event,
            } => self.on_event(subscription_id.into_owned(), event),
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => self.on_ok(event_id, accepted, message.into_owned()),
            RelayMessage::Eose(id) => self.on_eose(id.into_owned()),
            RelayMessage::Closed {
                subscription_id,
                message,
            } => {
                self.refused_or_closed(subscription_id.into_owned(), message.into_owned(), |_| {
                    true
                });
            }
            RelayMessage::Auth { challenge } => {
                self.auth.challenge = Some(challenge.into_owned());
            }
            RelayMessage::Count {
                subscription_id,
                result,
            } => {
                let id = subscription_id.into_owned();
                // S1: a COUNT reply only resolves a `Kind::Count` entry —
                // a misbehaving relay cannot kill a live subscription.
                if matches!(
                    self.requests.get(&id).map(|r| &r.kind),
                    Some(Kind::Count { .. })
                ) {
                    self.requests.remove(&id);
                    self.outs.push_back(Out::Counted { id, result });
                }
            }
            RelayMessage::NegMsg {
                subscription_id,
                message,
            } => self.on_neg_msg(subscription_id.into_owned(), &message),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } => self.on_neg_err(subscription_id.into_owned(), message.into_owned()),
            RelayMessage::Notice(message) => {
                self.outs.push_back(Out::Notice(message.into_owned()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use super::*;
    use nk_core::{EventBuilder, Keys, Kind, SecretKey, Timestamp};

    fn keys() -> Keys {
        Keys::new(SecretKey::from_bytes([7; 32]).unwrap())
    }

    fn event(content: &str, kind: u16) -> Event {
        keys()
            .sign_event(
                EventBuilder::new(Kind::new(kind), content)
                    .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000)),
                &mut nk_core::rand_core::UnwrapErr(nk_core::SysRng),
            )
            .unwrap()
    }

    fn auth_event(challenge: &str) -> Event {
        keys()
            .sign_event(
                EventBuilder::auth(
                    &nk_core::RelayUrl::parse("wss://relay.test").unwrap(),
                    challenge,
                )
                .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000)),
                &mut nk_core::rand_core::UnwrapErr(nk_core::SysRng),
            )
            .unwrap()
    }

    fn sub_id() -> SubscriptionId {
        SubscriptionId::generate().unwrap()
    }

    fn msg(json: &str) -> RelayMessage<'static> {
        RelayMessage::from_json(json).unwrap().into_owned()
    }

    /// Every output queued so far.
    fn drain(s: &mut Session) -> Vec<Out> {
        let mut outs = Vec::new();
        while let Some(out) = s.poll_out() {
            outs.push(out);
        }
        outs
    }

    /// A `REQ` sub whose open message is consumed at once.
    fn open(s: &mut Session, id: &SubscriptionId) {
        s.open_sub(id, vec![Filter::new()]);
        drop(drain(s));
    }

    #[test]
    fn eose_delivered_once() {
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let eose = format!(r#"["EOSE","{}"]"#, id.as_str());
        s.handle(msg(&eose));
        assert!(matches!(drain(&mut s).as_slice(), [Out::Eose(_)]));
        s.handle(msg(&eose));
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn fetch_eose_sends_close_and_removes() {
        let mut s = Session::new(false);
        let id = sub_id();
        s.open_fetch(&id, vec![Filter::new()]);
        drop(drain(&mut s));
        s.handle(msg(&format!(r#"["EOSE","{}"]"#, id.as_str())));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Send(ClientMessage::Close(_)), Out::Eose(_)]
        ));
        // Gone — a second EOSE is unknown.
        s.handle(msg(&format!(r#"["EOSE","{}"]"#, id.as_str())));
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn closed_removes_sub_and_forwards_reason() {
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: nope"]"#,
            id.as_str()
        )));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Closed { reason, .. }] if reason == "auth-required: nope"
        ));
        let ev = event("hi", 1);
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn ok_routes_to_pending() {
        let mut s = Session::new(false);
        let ev = event("x", 1);
        assert!(s.publish(ev.clone()));
        drop(drain(&mut s));
        s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Published { accepted: true, .. }]
        ));
        s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())));
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn joining_publish_reuses_pending_entry() {
        let mut s = Session::new(false);
        let ev = event("x", 1);
        assert!(s.publish(ev.clone()));
        assert!(!s.publish(ev));
    }

    #[test]
    fn invalid_signature_dropped() {
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let ev = event("x", 1);
        let bad = Event::new(
            ev.id(),
            ev.pubkey(),
            ev.created_at(),
            ev.kind(),
            ev.tags().clone(),
            "forged".to_owned(),
            ev.sig(),
        );
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            bad.to_json()
        )));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Rejected {
                reason: RejectReason::InvalidSignature,
                ..
            }]
        ));
    }

    #[test]
    fn non_matching_event_dropped() {
        let mut s = Session::new(false);
        let id = sub_id();
        s.open_sub(
            &id,
            vec![Filter::new().kinds([Kind::new(7)]).expect("filter")],
        );
        drop(drain(&mut s));
        let ev = event("x", 1);
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Rejected {
                reason: RejectReason::FilterMismatch,
                ..
            }]
        ));
    }

    #[test]
    fn unknown_subscription_event_ignored() {
        let mut s = Session::new(false);
        let id = sub_id();
        let ev = event("x", 1);
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn replay_lists_open_reqs_only() {
        let mut s = Session::new(false);
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        s.open_fetch(&b, vec![Filter::new()]);
        drop(drain(&mut s));
        let replay = s.replay();
        assert_eq!(replay.len(), 1);
        assert!(matches!(replay.first(), Some(ClientMessage::Req { .. })));
    }

    #[test]
    fn disconnected_drains_oneshots_keeps_subs() {
        let mut s = Session::new(true);
        let sub = sub_id();
        open(&mut s, &sub);
        s.open_fetch(&sub_id(), vec![Filter::new()]);
        s.open_count(&sub_id(), vec![Filter::new()]);
        s.open_neg(sub_id(), Filter::new(), Vec::new()).unwrap();
        let ev = event("x", 1);
        assert!(s.publish(ev.clone()));
        drop(drain(&mut s));
        // Arm a challenge so we can check it clears.
        s.handle(msg(r#"["AUTH","chal-1"]"#));
        let lost = s.disconnected();
        assert_eq!(lost.publishes, vec![ev.id()]);
        let mut lost_ids = lost.requests;
        lost_ids.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        assert_eq!(lost_ids.len(), 3);
        // Subs replay; AUTH state cleared — a later auth-required is terminal.
        assert_eq!(s.replay().len(), 1);
        let c = sub_id();
        open(&mut s, &c);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: stale"]"#,
            c.as_str()
        )));
        let out = drain(&mut s);
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }

    #[test]
    fn disconnect_clears_inflight_auth() {
        let mut s = Session::new(true);
        s.handle(msg(r#"["AUTH","chal-1"]"#));
        let a = sub_id();
        open(&mut s, &a);
        let refuse = |id: &SubscriptionId| {
            msg(&format!(
                r#"["CLOSED","{}","auth-required: x"]"#,
                id.as_str()
            ))
        };
        s.handle(refuse(&a));
        assert!(matches!(drain(&mut s).as_slice(), [Out::Sign(_)]));
        // The AUTH goes out; the socket drops before its OK.
        s.signed("chal-1", event("auth", 22242));
        let sent = drain(&mut s);
        assert!(matches!(sent.as_slice(), [Out::Send(_)]));
        drop(s.disconnected());
        // The new connection's challenge must be signable at once.
        s.handle(msg(r#"["AUTH","chal-2"]"#));
        s.handle(refuse(&a));
        let out = drain(&mut s);
        assert!(matches!(out.as_slice(), [Out::Sign(c)] if c == "chal-2"));
    }

    #[test]
    fn auth_required_shares_one_sign() {
        let mut s = Session::new(true);
        s.handle(msg(r#"["AUTH","chal"]"#));
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        s.open_count(&b, vec![Filter::new()]);
        drop(drain(&mut s));
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        let o1 = drain(&mut s);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            b.as_str()
        )));
        let o2 = drain(&mut s);
        assert!(matches!(o1.as_slice(), [Out::Sign(c)] if c == "chal"));
        // Second refusal joins the in-flight sign — no second Sign.
        assert!(o2.is_empty());
    }

    #[test]
    fn signed_then_ok_retries_once() {
        let mut s = Session::new(true);
        s.handle(msg(r#"["AUTH","chal"]"#));
        let a = sub_id();
        open(&mut s, &a);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        drop(drain(&mut s));
        let signed_ev = auth_event("chal");
        s.signed("chal", signed_ev);
        let sent = drain(&mut s);
        assert!(matches!(
            sent.as_slice(),
            [Out::Send(ClientMessage::Auth(_))]
        ));
        // OK accepted → the REQ is resent once.
        s.handle(msg(&format!(
            r#"["OK","{}",true,""]"#,
            auth_event("chal").id().to_hex()
        )));
        let ok_out = drain(&mut s);
        assert!(
            matches!(ok_out.as_slice(), [Out::Send(ClientMessage::Req { .. })]),
            "{ok_out:?}"
        );
        // A second auth-required is terminal now.
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: again"]"#,
            a.as_str()
        )));
        let out = drain(&mut s);
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }

    #[test]
    fn signed_ok_refused_surfaces_original_reason() {
        let mut s = Session::new(true);
        s.handle(msg(r#"["AUTH","chal"]"#));
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        s.open_count(&b, vec![Filter::new()]);
        drop(drain(&mut s));
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: first"]"#,
            a.as_str()
        )));
        drop(drain(&mut s));
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: second"]"#,
            b.as_str()
        )));
        drop(drain(&mut s));
        s.signed("chal", auth_event("chal"));
        let out = drain(&mut s);
        assert!(matches!(
            out.as_slice(),
            [Out::Send(ClientMessage::Auth(_))]
        ));
        s.handle(msg(&format!(
            r#"["OK","{}",false,"invalid: no"]"#,
            auth_event("chal").id().to_hex()
        )));
        let ok = drain(&mut s);
        // Both fall back with their ORIGINAL reasons.
        let mut reasons: Vec<&str> = ok
            .iter()
            .filter_map(|o| match o {
                Out::Closed { reason, .. } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        // HashMap order — the set is what matters, not the sequence.
        reasons.sort_unstable();
        assert_eq!(reasons, ["auth-required: first", "auth-required: second"]);
    }

    #[test]
    fn stale_challenge_resigns_current() {
        let mut s = Session::new(true);
        s.handle(msg(r#"["AUTH","old"]"#));
        let a = sub_id();
        open(&mut s, &a);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        drop(drain(&mut s));
        // A new challenge arrives before signing finished.
        s.handle(msg(r#"["AUTH","new"]"#));
        s.signed("old", auth_event("old"));
        let out = drain(&mut s);
        assert!(matches!(out.as_slice(), [Out::Sign(c)] if c == "new"));
    }

    #[test]
    fn count_on_live_sub_id_is_ignored() {
        // S1: a COUNT reply for a non-Count id must not kill the request.
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        s.handle(msg(&format!(
            r#"["COUNT","{}",{{"count":7}}]"#,
            id.as_str()
        )));
        assert!(drain(&mut s).is_empty());
        // The sub is still open — an EVENT for it is delivered.
        let ev = event("hi", 1);
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        let delivered = drain(&mut s);
        assert!(matches!(delivered.as_slice(), [Out::Event { .. }]));
    }

    #[test]
    fn neg_frames_on_sub_id_are_ignored() {
        // S2: NEG-ERR/NEG-MSG apply only to Kind::Neg.
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        s.handle(msg(&format!(
            r#"["NEG-ERR","{}","error: whatever"]"#,
            id.as_str()
        )));
        assert!(drain(&mut s).is_empty());
        s.handle(msg(&format!(r#"["NEG-MSG","{}","deadbeef"]"#, id.as_str())));
        assert!(drain(&mut s).is_empty());
        let ev = event("hi", 1);
        s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        let delivered = drain(&mut s);
        assert!(matches!(delivered.as_slice(), [Out::Event { .. }]));
    }

    #[test]
    fn no_signer_auth_required_is_terminal() {
        let mut s = Session::new(false);
        s.handle(msg(r#"["AUTH","chal"]"#));
        let a = sub_id();
        open(&mut s, &a);
        s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        let out = drain(&mut s);
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }
}
