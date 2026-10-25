//! The sans-IO state machine behind [`Relay`]: a subscription table, pending
//! publishes, and inbound-message routing. No I/O, clock, or channels — the
//! driver owns those; this owns the protocol decisions.

use std::collections::{HashMap, HashSet};

use nk_core::{Event, EventId, Filter, RelayMessage, SubscriptionId};

/// What the session wants the driver to do after `handle`.
#[derive(Debug)]
pub(crate) enum Out {
    /// Deliver `event` to subscription `id`.
    Deliver {
        /// The receiving subscription.
        id: SubscriptionId,
        /// The event to deliver.
        event: Event,
    },
    /// Send `EOSE` to subscription `id` (first time only).
    Eose(SubscriptionId),
    /// The relay closed `id`; forward `reason` to its stream.
    Closed {
        /// The closed subscription.
        id: SubscriptionId,
        /// The relay's `CLOSED` message.
        reason: String,
    },
    /// `EVENT` was accepted (`true`) or refused (`false`) with `message`.
    PublishDone {
        /// The published event id.
        id: EventId,
        /// The relay's `saved` flag.
        accepted: bool,
        /// The machine-readable relay message.
        message: String,
    },
    /// A `NOTICE` for tracing.
    Notice(String),
    /// Send `CLOSE` for `id` (the subscription is being ended locally).
    SendClose(SubscriptionId),
    /// An inbound `EVENT` failed acceptance on a live subscription.
    Rejected {
        /// The subscription the event targeted.
        id: SubscriptionId,
        /// Why it was dropped.
        reason: RejectReason,
    },
}

/// Why a live subscription dropped an inbound `EVENT` (NIP-01 acceptance).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// `Event::verify` failed — bad id or signature.
    InvalidSignature,
    /// The event matched none of the subscription's filters.
    FilterMismatch,
}

/// Per-subscription state.
#[derive(Debug)]
struct SubState {
    /// The `REQ`'s filters — inbound events must match at least one.
    filters: Vec<Filter>,
    /// `EOSE` has been delivered once.
    eose: bool,
}

/// The relay session: subscriptions, pending publishes, acceptance rules.
#[derive(Debug, Default)]
pub(crate) struct Session {
    subs: HashMap<SubscriptionId, SubState>,
    /// Events waiting on `OK`; joining concurrent publishes share the entry.
    pending: HashSet<EventId>,
}

impl Session {
    /// Registers a subscription; returns its filters for the `REQ` write.
    pub(crate) fn add_sub(&mut self, id: SubscriptionId, filters: Vec<Filter>) {
        self.subs.insert(
            id,
            SubState {
                filters,
                eose: false,
            },
        );
    }

    /// Marks `id` locally closed (lagged stream); the driver sends `CLOSE`.
    pub(crate) fn close_sub(&mut self, id: &SubscriptionId) -> Option<Out> {
        self.subs.remove(id).map(|_| Out::SendClose(id.clone()))
    }

    /// Registers `id` for an `OK`; `false` joins the in-flight publish.
    pub(crate) fn add_pending(&mut self, id: EventId) -> bool {
        self.pending.insert(id)
    }

    /// Open `REQ`s to replay after a reconnect.
    pub(crate) fn replay_reqs(&self) -> Vec<(SubscriptionId, Vec<Filter>)> {
        self.subs
            .iter()
            .map(|(id, s)| (id.clone(), s.filters.clone()))
            .collect()
    }

    /// Pending publish ids to fail on disconnect.
    pub(crate) fn take_pending(&mut self) -> Vec<EventId> {
        self.pending.drain().collect()
    }

    /// The single entry point for inbound relay traffic.
    pub(crate) fn handle(&mut self, message: RelayMessage<'_>) -> Vec<Out> {
        match message {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                let Some(sub) = self.subs.get(subscription_id.as_ref()) else {
                    return Vec::new();
                };
                // NIP-01: only verified events matching a filter are
                // delivered; the rest are reported as rejected.
                if event.verify().is_err() {
                    return vec![Out::Rejected {
                        id: subscription_id.into_owned(),
                        reason: RejectReason::InvalidSignature,
                    }];
                }
                if !sub.filters.iter().any(|f| f.matches(&event)) {
                    return vec![Out::Rejected {
                        id: subscription_id.into_owned(),
                        reason: RejectReason::FilterMismatch,
                    }];
                }
                vec![Out::Deliver {
                    id: subscription_id.into_owned(),
                    event: event.into_owned(),
                }]
            }
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                // One `OK` releases every joining publish.
                if !self.pending.remove(&event_id) {
                    return Vec::new();
                }
                vec![Out::PublishDone {
                    id: event_id,
                    accepted,
                    message: message.into_owned(),
                }]
            }
            RelayMessage::Eose(id) => {
                let Some(sub) = self.subs.get_mut(id.as_ref()) else {
                    return Vec::new();
                };
                if sub.eose {
                    return Vec::new();
                }
                sub.eose = true;
                vec![Out::Eose(id.into_owned())]
            }
            RelayMessage::Closed {
                subscription_id,
                message,
            } => {
                if self.subs.remove(subscription_id.as_ref()).is_none() {
                    return Vec::new();
                }
                vec![Out::Closed {
                    id: subscription_id.into_owned(),
                    reason: message.into_owned(),
                }]
            }
            RelayMessage::Notice(message) => vec![Out::Notice(message.into_owned())],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
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

    fn sub_id() -> SubscriptionId {
        SubscriptionId::generate().unwrap()
    }

    fn msg(json: &str) -> RelayMessage<'static> {
        RelayMessage::from_json(json).unwrap().into_owned()
    }

    #[test]
    fn eose_delivered_once() {
        let mut s = Session::default();
        let id = sub_id();
        s.add_sub(id.clone(), vec![Filter::new()]);
        let eose = format!(r#"["EOSE","{}"]"#, id.as_str());
        let out = s.handle(msg(&eose));
        assert!(matches!(out.as_slice(), [Out::Eose(_)]));
        assert!(s.handle(msg(&eose)).is_empty());
    }

    #[test]
    fn closed_removes_sub_and_forwards_reason() {
        let mut s = Session::default();
        let id = sub_id();
        s.add_sub(id.clone(), vec![Filter::new()]);
        let out = s.handle(msg(&format!(
            r#"["CLOSED","{}","auth-required"]"#,
            id.as_str()
        )));
        assert!(matches!(
            out.as_slice(),
            [Out::Closed { reason, .. }] if reason == "auth-required"
        ));
        // Later events for the closed sub are dropped.
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
        let mut s = Session::default();
        let ev = event("x", 1);
        assert!(s.add_pending(ev.id()));
        let out = s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())));
        assert!(matches!(
            out.as_slice(),
            [Out::PublishDone { accepted: true, .. }]
        ));
        // Stale OK is ignored.
        let out2 = s.handle(msg(&format!(r#"["OK","{}",true,""]"#, ev.id().to_hex())));
        assert!(out2.is_empty());
    }

    #[test]
    fn joining_publish_reuses_pending_entry() {
        let mut s = Session::default();
        let ev = event("x", 1);
        assert!(s.add_pending(ev.id()));
        assert!(!s.add_pending(ev.id()));
    }

    #[test]
    fn invalid_signature_dropped() {
        let mut s = Session::default();
        let id = sub_id();
        s.add_sub(id.clone(), vec![Filter::new()]);
        // Forge a bad signature by mutating content after signing.
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
        let mut s = Session::default();
        let id = sub_id();
        s.add_sub(id.clone(), vec![Filter::new().kinds([Kind::new(7)])]);
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
        let mut s = Session::default();
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
        let mut s = Session::default();
        let a = sub_id();
        let b = sub_id();
        s.add_sub(a.clone(), vec![Filter::new().kinds([Kind::new(1)])]);
        s.add_sub(b.clone(), vec![Filter::new().kinds([Kind::new(7)])]);
        s.handle(msg(&format!(r#"["CLOSED","{}","x"]"#, b.as_str())));
        let replay = s.replay_reqs();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay.first().map(|(i, _)| i), Some(&a));
    }
}
