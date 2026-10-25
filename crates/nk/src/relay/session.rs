//! The sans-IO state machine behind [`Relay`](crate::relay::Relay): one
//! request table, pending publishes, and NIP-42 state. No I/O, clock, or
//! channels — the driver owns those; this owns the protocol decisions.
//! Protocol-driven writes come out as [`Out::Send`].

use std::borrow::Cow;
use std::collections::HashMap;

use nk_core::{ClientMessage, CountResult, Event, EventId, Filter, RelayMessage, SubscriptionId};

use super::neg::{NegSession, Reconciliation};
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
    /// fetches (a `Send(CLOSE)` precedes it in the batch).
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
    /// The accumulated have/need across rounds.
    out: Reconciliation,
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
}

impl Session {
    /// A fresh session; `can_auth` mirrors `options.signer.is_some()`.
    pub(crate) fn new(can_auth: bool) -> Self {
        Self {
            requests: HashMap::new(),
            publishes: HashMap::new(),
            auth: Auth::default(),
            can_auth,
        }
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

    /// Registers `kind` under `id` and returns its open message.
    fn open(&mut self, id: &SubscriptionId, kind: Kind) -> ClientMessage<'static> {
        let msg = Self::wire_msg(id, &kind);
        self.requests.insert(
            id.clone(),
            Request {
                kind,
                auth: AuthMark::Fresh,
            },
        );
        // Only `open_neg` registers a kind without a `wire_msg`.
        msg.unwrap_or_else(|| ClientMessage::Close(Cow::Owned(id.clone())))
    }

    /// Registers a `REQ` subscription; returns the wire message.
    pub(crate) fn open_sub(
        &mut self,
        id: &SubscriptionId,
        filters: Vec<Filter>,
    ) -> ClientMessage<'static> {
        self.open(
            id,
            Kind::Sub {
                filters,
                eose: false,
            },
        )
    }

    /// Registers a bounded `REQ`; returns the wire message.
    pub(crate) fn open_fetch(
        &mut self,
        id: &SubscriptionId,
        filters: Vec<Filter>,
    ) -> ClientMessage<'static> {
        self.open(id, Kind::Fetch { filters })
    }

    /// Registers a NIP-45 `COUNT`; returns the wire message.
    pub(crate) fn open_count(
        &mut self,
        id: &SubscriptionId,
        filters: Vec<Filter>,
    ) -> ClientMessage<'static> {
        self.open(id, Kind::Count { filters })
    }

    /// Registers a NIP-77 sync; returns the `NEG-OPEN` wire message.
    ///
    /// # Errors
    ///
    /// [`Error::Negentropy`] when the item set cannot be sealed.
    pub(crate) fn open_neg(
        &mut self,
        id: SubscriptionId,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
    ) -> Result<ClientMessage<'static>> {
        let mut neg = NegSession::new(&items)?;
        let message = neg.initiate()?;
        self.requests.insert(
            id.clone(),
            Request {
                kind: Kind::Neg(Box::new(NegState {
                    filter: filter.clone(),
                    items,
                    neg,
                    out: Reconciliation::default(),
                })),
                auth: AuthMark::Fresh,
            },
        );
        Ok(ClientMessage::NegOpen {
            subscription_id: Cow::Owned(id),
            filter: Cow::Owned(filter),
            message: Cow::Owned(message),
        })
    }

    /// Registers `event` for its `OK`; `None` joins the in-flight publish.
    pub(crate) fn publish(&mut self, event: Event) -> Option<ClientMessage<'static>> {
        if self.publishes.contains_key(&event.id()) {
            return None;
        }
        self.publishes.insert(
            event.id(),
            Publish {
                event: event.clone(),
                auth: AuthMark::Fresh,
            },
        );
        Some(ClientMessage::Event(Cow::Owned(event)))
    }

    /// Removes request `id`; returns the local-close wire message —
    /// `CLOSE` for subs and fetches, `NEG-CLOSE` for syncs, `None` for
    /// counts and unknown ids.
    pub(crate) fn close(&mut self, id: &SubscriptionId) -> Option<ClientMessage<'static>> {
        let req = self.requests.remove(id)?;
        match req.kind {
            Kind::Sub { .. } | Kind::Fetch { .. } => {
                Some(ClientMessage::Close(Cow::Owned(id.clone())))
            }
            Kind::Neg { .. } => Some(ClientMessage::NegClose(Cow::Owned(id.clone()))),
            Kind::Count { .. } => None,
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

    /// A fresh challenge arms `signed`; `false` when a sign request is
    /// already outstanding or an AUTH event is awaiting its `OK`.
    fn want_sign(&mut self) -> Option<Out> {
        let challenge = self.auth.challenge.clone()?;
        if self.auth.signing || self.auth.inflight.is_some() {
            return None;
        }
        self.auth.signing = true;
        Some(Out::Sign(challenge))
    }

    /// An `auth-required:` refusal may retry once when a signer is
    /// present, a challenge is known, and the entry is still `Fresh`.
    const fn may_retry(&self, mark: &AuthMark) -> bool {
        self.can_auth && self.auth.challenge.is_some() && matches!(mark, AuthMark::Fresh)
    }

    /// A terminal refusal (`CLOSED`, `NEG-ERR`) on `id`. `kind_ok`
    /// restricts which request kinds the message applies to — a mismatch
    /// is ignored. `auth-required:` takes the NIP-42 path; anything else
    /// removes the entry and surfaces `Out::Closed`.
    fn refused_or_closed(
        &mut self,
        id: SubscriptionId,
        reason: String,
        kind_ok: impl Fn(&Kind) -> bool,
    ) -> Vec<Out> {
        let Some(req) = self.requests.get(&id) else {
            return Vec::new();
        };
        if !kind_ok(&req.kind) {
            return Vec::new();
        }
        if reason.starts_with("auth-required:") && self.may_retry(&req.auth) {
            if let Some(entry) = self.requests.get_mut(&id) {
                entry.auth = AuthMark::Waiting(reason);
            }
            return self.want_sign().into_iter().collect();
        }
        self.requests.remove(&id);
        vec![Out::Closed { id, reason }]
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
    fn on_auth_ok(&mut self, accepted: bool) -> Vec<Out> {
        self.auth.inflight = None;
        let mut outs = Vec::new();
        if accepted {
            let (requests, publishes) = self.waiting();
            for id in requests {
                outs.extend(self.retry_request(&id));
            }
            for id in publishes {
                outs.extend(self.retry_publish(&id));
            }
        } else {
            outs.extend(self.fallbacks());
        }
        outs
    }

    /// Resends one `Waiting` publish; `Retried` marks it terminal next.
    fn retry_publish(&mut self, id: &EventId) -> Vec<Out> {
        let Some(p) = self.publishes.get_mut(id) else {
            return Vec::new();
        };
        p.auth = AuthMark::Retried;
        vec![Out::Send(ClientMessage::Event(Cow::Owned(p.event.clone())))]
    }

    /// Resends one `Waiting` request; `Retried` marks it so a second
    /// `auth-required:` is terminal.
    fn retry_request(&mut self, id: &SubscriptionId) -> Vec<Out> {
        let Some(req) = self.requests.get_mut(id) else {
            return Vec::new();
        };
        req.auth = AuthMark::Retried;
        match &mut req.kind {
            Kind::Sub { .. } | Kind::Fetch { .. } | Kind::Count { .. } => {
                Self::wire_msg(id, &req.kind).map_or_else(Vec::new, |m| vec![Out::Send(m)])
            }
            Kind::Neg(state) => {
                let NegState {
                    filter,
                    items,
                    neg,
                    out,
                } = &mut **state;
                match NegSession::new(items).and_then(|mut n| n.initiate().map(|m| (n, m))) {
                    Ok((n, message)) => {
                        *neg = n;
                        *out = Reconciliation::default();
                        vec![Out::Send(ClientMessage::NegOpen {
                            subscription_id: Cow::Owned(id.clone()),
                            filter: Cow::Owned(filter.clone()),
                            message: Cow::Owned(message),
                        })]
                    }
                    Err(error) => {
                        self.requests.remove(id);
                        vec![Out::Failed {
                            id: id.clone(),
                            error,
                        }]
                    }
                }
            }
        }
    }

    /// Every `Waiting` entry's normal terminal output — the stored reason.
    fn fallbacks(&mut self) -> Vec<Out> {
        let mut outs = Vec::new();
        let (requests, publishes) = self.waiting();
        for id in requests {
            if let Some(req) = self.requests.remove(&id)
                && let AuthMark::Waiting(reason) = req.auth
            {
                outs.push(Out::Closed { id, reason });
            }
        }
        for id in publishes {
            if let Some(p) = self.publishes.remove(&id)
                && let AuthMark::Waiting(reason) = p.auth
            {
                outs.push(Out::Published {
                    id,
                    accepted: false,
                    message: reason,
                });
            }
        }
        outs
    }

    /// The off-loop signer produced `event` for `challenge`.
    ///
    /// A stale signature (a newer challenge arrived meanwhile) re-signs;
    /// with nothing `Waiting` the event is dropped unused.
    pub(crate) fn signed(&mut self, challenge: &str, event: Event) -> Vec<Out> {
        self.auth.signing = false;
        let (requests, publishes) = self.waiting();
        if requests.is_empty() && publishes.is_empty() {
            return Vec::new();
        }
        if self.auth.challenge.as_deref() != Some(challenge) {
            // The signed event answers a superseded challenge — sign the
            // current one instead, or fail the waiters when there is none.
            return match &self.auth.challenge {
                Some(current) => {
                    self.auth.signing = true;
                    vec![Out::Sign(current.clone())]
                }
                None => self.fallbacks(),
            };
        }
        self.auth.inflight = Some(event.id());
        vec![Out::Send(ClientMessage::Auth(Cow::Owned(event)))]
    }

    /// Signing failed or was impossible — every `Waiting` entry falls
    /// back to its stored reason.
    pub(crate) fn sign_failed(&mut self) -> Vec<Out> {
        self.auth.signing = false;
        self.fallbacks()
    }

    /// An inbound `EVENT` for a subscription or fetch.
    fn on_event(&self, id: SubscriptionId, event: Cow<'_, Event>) -> Vec<Out> {
        let Some(req) = self.requests.get(&id) else {
            return Vec::new();
        };
        let (Kind::Sub { filters, .. } | Kind::Fetch { filters }) = &req.kind else {
            return Vec::new();
        };
        // NIP-01: only verified events matching a filter are delivered.
        if event.verify().is_err() {
            return vec![Out::Rejected {
                id,
                reason: RejectReason::InvalidSignature,
            }];
        }
        if !filters.iter().any(|f| f.matches(&event)) {
            return vec![Out::Rejected {
                id,
                reason: RejectReason::FilterMismatch,
            }];
        }
        vec![Out::Event {
            id,
            event: event.into_owned(),
        }]
    }

    /// One `NEG-MSG` round on a `Kind::Neg` entry — other kinds ignore
    /// it; the entry is removed only on the terminal round.
    fn on_neg_msg(&mut self, id: SubscriptionId, message: &str) -> Vec<Out> {
        let Some(req) = self.requests.get_mut(&id) else {
            return Vec::new();
        };
        let Kind::Neg(state) = &mut req.kind else {
            return Vec::new();
        };
        let round = state.neg.on_msg(message, &mut state.out);
        let Ok(next) = &round else {
            // Codec error — terminal, entry comes out below.
            let close = Out::Send(ClientMessage::NegClose(Cow::Owned(id.clone())));
            self.requests.remove(&id);
            return match round {
                Err(error) => vec![close, Out::Failed { id, error }],
                Ok(_) => Vec::new(),
            };
        };
        let Some(next) = next else {
            // Sync finished — terminal round.
            let close = Out::Send(ClientMessage::NegClose(Cow::Owned(id.clone())));
            let Some(taken) = self.requests.remove(&id) else {
                return Vec::new();
            };
            let Kind::Neg(done) = taken.kind else {
                return Vec::new();
            };
            return vec![
                close,
                Out::Reconciled {
                    id,
                    result: done.out,
                },
            ];
        };
        vec![Out::Send(ClientMessage::NegMsg {
            subscription_id: Cow::Owned(id),
            message: Cow::Owned(next.clone()),
        })]
    }

    /// A `NEG-ERR` applies only to `Kind::Neg`.
    fn on_neg_err(&mut self, id: SubscriptionId, reason: String) -> Vec<Out> {
        self.refused_or_closed(id, reason, |k| matches!(k, Kind::Neg(_)))
    }

    /// An `OK` for a pending publish or the in-flight AUTH.
    fn on_ok(&mut self, id: EventId, accepted: bool, message: String) -> Vec<Out> {
        if self.auth.inflight == Some(id) {
            return self.on_auth_ok(accepted);
        }
        let Some(pending) = self.publishes.get(&id) else {
            return Vec::new();
        };
        if !accepted && message.starts_with("auth-required:") && self.may_retry(&pending.auth) {
            let Some(p) = self.publishes.get_mut(&id) else {
                return Vec::new();
            };
            p.auth = AuthMark::Waiting(message);
            return self.want_sign().into_iter().collect();
        }
        // Terminal — accepted, refused, or a second auth-required.
        if let Some(done) = self.publishes.remove(&id) {
            let message = match done.auth {
                AuthMark::Waiting(reason) => reason,
                _ => message,
            };
            vec![Out::Published {
                id,
                accepted,
                message,
            }]
        } else {
            Vec::new()
        }
    }

    /// `EOSE` on a sub fires once; on a fetch it also sends `CLOSE`.
    fn on_eose(&mut self, id: SubscriptionId) -> Vec<Out> {
        let Some(req) = self.requests.get_mut(&id) else {
            return Vec::new();
        };
        match &mut req.kind {
            Kind::Sub { eose: true, .. } => Vec::new(),
            Kind::Sub { eose, .. } => {
                *eose = true;
                vec![Out::Eose(id)]
            }
            Kind::Fetch { .. } => {
                self.requests.remove(&id);
                vec![
                    Out::Send(ClientMessage::Close(Cow::Owned(id.clone()))),
                    Out::Eose(id),
                ]
            }
            _ => Vec::new(),
        }
    }

    /// The single entry point for inbound relay traffic.
    pub(crate) fn handle(&mut self, message: RelayMessage<'_>) -> Vec<Out> {
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
                self.refused_or_closed(subscription_id.into_owned(), message.into_owned(), |_| true)
            }
            RelayMessage::Auth { challenge } => {
                self.auth.challenge = Some(challenge.into_owned());
                Vec::new()
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
                    vec![Out::Counted { id, result }]
                } else {
                    Vec::new()
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
            RelayMessage::Notice(message) => vec![Out::Notice(message.into_owned())],
            _ => Vec::new(),
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

    fn open(s: &mut Session, id: &SubscriptionId) {
        drop(s.open_sub(id, vec![Filter::new()]));
    }

    #[test]
    fn eose_delivered_once() {
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let eose = format!(r#"["EOSE","{}"]"#, id.as_str());
        assert!(matches!(s.handle(msg(&eose)).as_slice(), [Out::Eose(_)]));
        assert!(s.handle(msg(&eose)).is_empty());
    }

    #[test]
    fn fetch_eose_sends_close_and_removes() {
        let mut s = Session::new(false);
        let id = sub_id();
        drop(s.open_fetch(&id, vec![Filter::new()]));
        let out = s.handle(msg(&format!(r#"["EOSE","{}"]"#, id.as_str())));
        assert!(matches!(
            out.as_slice(),
            [Out::Send(ClientMessage::Close(_)), Out::Eose(_)]
        ));
        // Gone — a second EOSE is unknown.
        assert!(
            s.handle(msg(&format!(r#"["EOSE","{}"]"#, id.as_str())))
                .is_empty()
        );
    }

    #[test]
    fn closed_removes_sub_and_forwards_reason() {
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let out = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: nope"]"#,
            id.as_str()
        )));
        assert!(matches!(
            out.as_slice(),
            [Out::Closed { reason, .. }] if reason == "auth-required: nope"
        ));
        let ev = event("hi", 1);
        let out2 = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(out2.is_empty());
    }

    #[test]
    fn ok_routes_to_pending() {
        let mut s = Session::new(false);
        let ev = event("x", 1);
        assert!(s.publish(ev.clone()).is_some());
        let out = s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())));
        assert!(matches!(
            out.as_slice(),
            [Out::Published { accepted: true, .. }]
        ));
        assert!(
            s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())))
                .is_empty()
        );
    }

    #[test]
    fn joining_publish_reuses_pending_entry() {
        let mut s = Session::new(false);
        let ev = event("x", 1);
        assert!(s.publish(ev.clone()).is_some());
        assert!(s.publish(ev).is_none());
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
        let out = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            bad.to_json()
        )));
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
        drop(s.open_sub(&id, vec![Filter::new().kinds([Kind::new(7)])]));
        let ev = event("x", 1);
        let out = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
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
        let out = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(out.is_empty());
    }

    #[test]
    fn replay_lists_open_reqs_only() {
        let mut s = Session::new(false);
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        drop(s.open_fetch(&b, vec![Filter::new()]));
        let replay = s.replay();
        assert_eq!(replay.len(), 1);
        assert!(matches!(replay.first(), Some(ClientMessage::Req { .. })));
    }

    #[test]
    fn disconnected_drains_oneshots_keeps_subs() {
        let mut s = Session::new(true);
        let sub = sub_id();
        open(&mut s, &sub);
        drop(s.open_fetch(&sub_id(), vec![Filter::new()]));
        drop(s.open_count(&sub_id(), vec![Filter::new()]));
        drop(s.open_neg(sub_id(), Filter::new(), Vec::new()).unwrap());
        let ev = event("x", 1);
        drop(s.publish(ev.clone()));
        // Arm a challenge so we can check it clears.
        drop(s.handle(msg(r#"["AUTH","chal-1"]"#)));
        let lost = s.disconnected();
        assert_eq!(lost.publishes, vec![ev.id()]);
        let mut lost_ids = lost.requests;
        lost_ids.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        assert_eq!(lost_ids.len(), 3);
        // Subs replay; AUTH state cleared — a later auth-required is terminal.
        assert_eq!(s.replay().len(), 1);
        let c = sub_id();
        open(&mut s, &c);
        let out = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: stale"]"#,
            c.as_str()
        )));
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }

    #[test]
    fn disconnect_clears_inflight_auth() {
        let mut s = Session::new(true);
        drop(s.handle(msg(r#"["AUTH","chal-1"]"#)));
        let a = sub_id();
        open(&mut s, &a);
        let refuse = |id: &SubscriptionId| {
            msg(&format!(
                r#"["CLOSED","{}","auth-required: x"]"#,
                id.as_str()
            ))
        };
        assert!(matches!(s.handle(refuse(&a)).as_slice(), [Out::Sign(_)]));
        // The AUTH goes out; the socket drops before its OK.
        let sent = s.signed("chal-1", event("auth", 22242));
        assert!(matches!(sent.as_slice(), [Out::Send(_)]));
        drop(s.disconnected());
        // The new connection's challenge must be signable at once.
        drop(s.handle(msg(r#"["AUTH","chal-2"]"#)));
        let out = s.handle(refuse(&a));
        assert!(matches!(out.as_slice(), [Out::Sign(c)] if c == "chal-2"));
    }

    #[test]
    fn auth_required_shares_one_sign() {
        let mut s = Session::new(true);
        drop(s.handle(msg(r#"["AUTH","chal"]"#)));
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        drop(s.open_count(&b, vec![Filter::new()]));
        let o1 = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        let o2 = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            b.as_str()
        )));
        assert!(matches!(o1.as_slice(), [Out::Sign(c)] if c == "chal"));
        // Second refusal joins the in-flight sign — no second Sign.
        assert!(o2.is_empty());
    }

    #[test]
    fn signed_then_ok_retries_once() {
        let mut s = Session::new(true);
        drop(s.handle(msg(r#"["AUTH","chal"]"#)));
        let a = sub_id();
        open(&mut s, &a);
        drop(s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        ))));
        let signed_ev = auth_event("chal");
        let sent = s.signed("chal", signed_ev);
        assert!(matches!(
            sent.as_slice(),
            [Out::Send(ClientMessage::Auth(_))]
        ));
        // OK accepted → the REQ is resent once.
        let ok_out = s.handle(msg(&format!(
            r#"["OK","{}",true,""]"#,
            auth_event("chal").id().to_hex()
        )));
        assert!(
            matches!(ok_out.as_slice(), [Out::Send(ClientMessage::Req { .. })]),
            "{ok_out:?}"
        );
        // A second auth-required is terminal now.
        let out = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: again"]"#,
            a.as_str()
        )));
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }

    #[test]
    fn signed_ok_refused_surfaces_original_reason() {
        let mut s = Session::new(true);
        drop(s.handle(msg(r#"["AUTH","chal"]"#)));
        let a = sub_id();
        let b = sub_id();
        open(&mut s, &a);
        drop(s.open_count(&b, vec![Filter::new()]));
        drop(s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: first"]"#,
            a.as_str()
        ))));
        drop(s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: second"]"#,
            b.as_str()
        ))));
        let out = s.signed("chal", auth_event("chal"));
        assert!(matches!(
            out.as_slice(),
            [Out::Send(ClientMessage::Auth(_))]
        ));
        let ok = s.handle(msg(&format!(
            r#"["OK","{}",false,"invalid: no"]"#,
            auth_event("chal").id().to_hex()
        )));
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
        drop(s.handle(msg(r#"["AUTH","old"]"#)));
        let a = sub_id();
        open(&mut s, &a);
        drop(s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        ))));
        // A new challenge arrives before signing finished.
        drop(s.handle(msg(r#"["AUTH","new"]"#)));
        let out = s.signed("old", auth_event("old"));
        assert!(matches!(out.as_slice(), [Out::Sign(c)] if c == "new"));
    }

    #[test]
    fn count_on_live_sub_id_is_ignored() {
        // S1: a COUNT reply for a non-Count id must not kill the request.
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let out = s.handle(msg(&format!(
            r#"["COUNT","{}",{{"count":7}}]"#,
            id.as_str()
        )));
        assert!(out.is_empty());
        // The sub is still open — an EVENT for it is delivered.
        let ev = event("hi", 1);
        let delivered = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(matches!(delivered.as_slice(), [Out::Event { .. }]));
    }

    #[test]
    fn neg_frames_on_sub_id_are_ignored() {
        // S2: NEG-ERR/NEG-MSG apply only to Kind::Neg.
        let mut s = Session::new(false);
        let id = sub_id();
        open(&mut s, &id);
        let err_out = s.handle(msg(&format!(
            r#"["NEG-ERR","{}","error: whatever"]"#,
            id.as_str()
        )));
        assert!(err_out.is_empty());
        let msg_out = s.handle(msg(&format!(r#"["NEG-MSG","{}","deadbeef"]"#, id.as_str())));
        assert!(msg_out.is_empty());
        let ev = event("hi", 1);
        let delivered = s.handle(msg(&format!(
            r#"["EVENT","{}",{}]"#,
            id.as_str(),
            ev.to_json()
        )));
        assert!(matches!(delivered.as_slice(), [Out::Event { .. }]));
    }

    #[test]
    fn no_signer_auth_required_is_terminal() {
        let mut s = Session::new(false);
        drop(s.handle(msg(r#"["AUTH","chal"]"#)));
        let a = sub_id();
        open(&mut s, &a);
        let out = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required: x"]"#,
            a.as_str()
        )));
        assert!(matches!(out.as_slice(), [Out::Closed { .. }]));
    }
}
