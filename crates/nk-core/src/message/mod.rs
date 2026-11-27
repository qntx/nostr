//! Client and relay wire messages —
//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
//! [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md),
//! [NIP-45](https://github.com/nostr-protocol/nips/blob/master/45.md),
//! [NIP-77](https://github.com/nostr-protocol/nips/blob/master/77.md).
//!
//! `to_json` writes the byte-exact wire form (filters and events go through
//! the canonical writer); `from_json` validates subscription ids in both
//! directions (1..=64 Unicode scalar values) and requires the `OK` event id
//! to be 64 lowercase hex.

mod client;
mod count;
mod relay;
mod subscription;

pub use client::ClientMessage;
pub use count::{CountResult, Hll};
pub use relay::RelayMessage;
pub use subscription::SubscriptionId;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use serde::de::{DeserializeOwned, Error as DeError, SeqAccess};

use crate::json::JsonError;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Why a wire message could not be parsed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The wire text is not valid JSON.
    #[error("invalid JSON")]
    InvalidJson {
        /// The serde parse failure.
        #[source]
        source: JsonError,
    },
    /// The wire value is not a non-empty JSON array whose first element is
    /// the message type string.
    #[error("message must be a non-empty JSON array")]
    NotAMessageArray,
    /// The message type string is not a known NIP-01/42/45/77 type.
    #[error("unknown message type {ty}")]
    UnknownType {
        /// The unrecognized type string.
        ty: String,
    },
    /// A known message type has the wrong arity or field types.
    #[error("invalid {ty} message")]
    InvalidMessage {
        /// The message type (`EVENT`, `REQ`, `OK`, …).
        ty: &'static str,
    },
    /// An embedded event or filter failed wire validation.
    #[error("invalid {ty} payload")]
    InvalidPayload {
        /// The containing message type.
        ty: &'static str,
        /// The error describing the offending field.
        #[source]
        source: JsonError,
    },
    /// The subscription id length is outside `1..=64` scalar values.
    #[error("subscription id length {len} is outside 1..=64")]
    InvalidSubscriptionId {
        /// The length in Unicode scalar values.
        len: usize,
    },
    /// A NIP-45 sketch is not a 512-character hex string.
    #[error("invalid NIP-45 HLL sketch: expected 512-char hex")]
    InvalidHll,
    /// A NIP-77 negentropy message is not non-empty even-length hex.
    #[error("invalid negentropy message: expected non-empty even-length hex")]
    InvalidNegMessage,
    /// The caller-provided random source failed.
    #[error("random source failed")]
    Rng,
}

/// Reads the `["<TYPE>", ...]` head of a message seq; the first element
/// must be a string naming a type in `known`.
pub(crate) fn read_type<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    known: &'static [&'static str],
) -> Result<&'static str, A::Error> {
    let label = seq
        .next_element::<String>()?
        .ok_or_else(|| DeError::custom(Error::NotAMessageArray))?;
    known
        .iter()
        .copied()
        .find(|known| *known == label)
        .ok_or_else(|| DeError::custom(Error::UnknownType { ty: label.clone() }))
}

/// A non-empty, even-length lowercase hex string.
pub(crate) fn parse_neg_hex(raw: &str) -> Result<String, Error> {
    if raw.is_empty()
        || !raw.len().is_multiple_of(2)
        || !raw
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::InvalidNegMessage);
    }
    Ok(String::from(raw))
}

/// Reads a subscription id element; the element must be a string.
pub(crate) fn sub_id<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    ty: &'static str,
) -> Result<SubscriptionId, A::Error> {
    seq.next_element::<SubscriptionId>()?
        .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))
}

/// Reads a string element; the element must be a string.
pub(crate) fn string_item<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    ty: &'static str,
) -> Result<String, A::Error> {
    seq.next_element::<String>()?
        .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))
}

/// Reads an event element.
pub(crate) fn event_item<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    ty: &'static str,
) -> Result<crate::event::Event, A::Error> {
    seq.next_element::<crate::event::Event>()?
        .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))
}

/// Reads a filter element.
pub(crate) fn filter_item<'de, A: SeqAccess<'de>>(
    seq: &mut A,
    ty: &'static str,
) -> Result<crate::filter::Filter, A::Error> {
    seq.next_element::<crate::filter::Filter>()?
        .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))
}

/// Drains the remaining seq elements: trailing elements beyond a message's
/// defined arity are ignored (`serde_json` errors if a seq visitor leaves
/// elements unread).
pub(crate) fn drain<'de, A: SeqAccess<'de>>(seq: &mut A) -> Result<(), A::Error> {
    while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Reads an optional element leniently: captures it as raw JSON, then parses
/// the captured text as `T`. Any element that fails the `T` parse — mistyped,
/// out of range, or a lone-surrogate escape — reads as `None` rather than
/// failing the frame, the same lenience COUNT applies to a bad
/// `approximate`/`hll`.
fn optional_value<'de, A: SeqAccess<'de>, T: DeserializeOwned>(
    seq: &mut A,
) -> Result<Option<T>, A::Error> {
    Ok(seq
        .next_element::<Box<serde_json::value::RawValue>>()?
        .and_then(|raw| serde_json::from_str::<T>(raw.get()).ok()))
}

/// Reads an optional `<params>` element (NIP-01 OK/CLOSED): `Some` when the
/// element is a string, `None` when absent or any other JSON type.
pub(crate) fn optional_string<'de, A: SeqAccess<'de>>(
    seq: &mut A,
) -> Result<Option<String>, A::Error> {
    optional_value::<A, String>(seq)
}

/// Reads optional NIP-67 EOSE completeness hints: `Some` when the element is
/// an all-string array (empty included), `None` when absent or mistyped.
pub(crate) fn optional_hints<'de, A: SeqAccess<'de>>(
    seq: &mut A,
) -> Result<Option<Vec<String>>, A::Error> {
    optional_value::<A, Vec<String>>(seq)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::borrow::Cow;
    use alloc::string::ToString;
    use core::str::FromStr;

    use super::*;
    use crate::event::{Event, Kind};
    use crate::filter::Filter;

    fn signed_event() -> Event {
        let keys =
            crate::key::Keys::new(crate::key::SecretKey::from_bytes([3; 32]).expect("scalar"));
        let unsigned = crate::event::UnsignedEvent::new(
            keys.public_key(),
            crate::time::Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            crate::event::Tags::new(),
            "gm",
        );
        crate::testutil::sign_with_aux(&keys, unsigned, [1; 32])
    }

    #[test]
    fn subscription_id_bounds_count_scalar_values() {
        assert!(SubscriptionId::new("").is_err());
        assert!(SubscriptionId::new("a").is_ok());
        assert_eq!(
            SubscriptionId::new("a".repeat(64))
                .expect("64 chars")
                .as_str()
                .chars()
                .count(),
            64
        );
        assert!(SubscriptionId::new("a".repeat(65)).is_err());
        // Astral characters count once each, not per UTF-16 unit.
        assert!(SubscriptionId::new("\u{1F600}".repeat(64)).is_ok());
        assert!(SubscriptionId::new("\u{1F600}".repeat(65)).is_err());
        assert!(matches!(
            SubscriptionId::new("x".repeat(65)).unwrap_err(),
            Error::InvalidSubscriptionId { len: 65 }
        ));
    }

    #[test]
    fn subscription_id_traits_and_serde() {
        let id = SubscriptionId::new("sub").expect("valid");
        assert_eq!(id.to_string(), "sub");
        assert_eq!(id.as_ref(), "sub");
        assert_eq!(serde_json::to_string(&id).expect("ser"), "\"sub\"");
        let back: SubscriptionId = serde_json::from_str("\"sub\"").expect("de");
        assert_eq!(back, id);
        assert!(serde_json::from_str::<SubscriptionId>("\"\"").is_err());
        assert!(serde_json::from_str::<SubscriptionId>("123").is_err());
    }

    #[test]
    fn subscription_id_from_rng_is_16_lower_hex() {
        struct Zero;
        impl rand_core::TryRng for Zero {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                dest.fill(0);
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Zero {}
        let id = SubscriptionId::from_rng(&mut Zero).expect("rng");
        assert_eq!(id.as_str(), "0000000000000000");
    }

    #[test]
    fn count_hll_zero_merge_and_hex() {
        let mut a = Hll::zero();
        assert_eq!(a.to_string(), "00".repeat(256));
        let b = Hll::from_str(&"ab".repeat(256)).expect("lowercase parses");
        a.merge(&b);
        assert_eq!(a.to_string(), "ab".repeat(256));
        // `from_str` is caller input — uppercase normalizes to lowercase.
        assert_eq!(
            Hll::from_str(&"AB".repeat(256)).unwrap().to_string(),
            "ab".repeat(256)
        );
        assert!(Hll::from_str("ab").is_err());
        assert!(Hll::from_str(&"zz".repeat(256)).is_err());
        assert!(matches!(
            Hll::from_str("ab").unwrap_err(),
            Error::InvalidHll
        ));
    }

    #[test]
    fn client_encode_matches_ts() {
        let id = SubscriptionId::new("sub").expect("id");
        let filter = Filter::new().kinds([Kind::TEXT_NOTE]).expect("filter");
        assert_eq!(
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            }
            .to_json(),
            "[\"REQ\",\"sub\",{\"kinds\":[1]}]"
        );
        // An empty filter slice encodes as `["REQ","sub"]` per the design table.
        assert_eq!(
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(&[][..]),
            }
            .to_json(),
            "[\"REQ\",\"sub\"]"
        );
        assert_eq!(
            ClientMessage::Close(Cow::Borrowed(&id)).to_json(),
            "[\"CLOSE\",\"sub\"]"
        );
        assert_eq!(
            ClientMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("deadbeef"),
            }
            .to_json(),
            "[\"NEG-MSG\",\"sub\",\"deadbeef\"]"
        );
        assert_eq!(
            ClientMessage::NegClose(Cow::Borrowed(&id)).to_json(),
            "[\"NEG-CLOSE\",\"sub\"]"
        );
        let event = signed_event();
        let wire = ClientMessage::Event(Cow::Borrowed(&event)).to_json();
        assert!(wire.starts_with("[\"EVENT\",{\"id\":\""));
        // Round-trip: parse(encode(x)) reproduces an equivalent message.
        assert_eq!(
            ClientMessage::from_json(&wire).expect("parse"),
            ClientMessage::Event(Cow::Owned(event))
        );
    }

    #[test]
    fn client_parse_rules() {
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        assert!(matches!(
            ClientMessage::from_json(&alloc::format!("[\"EVENT\",{event_json}]")).expect("event"),
            ClientMessage::Event(_)
        ));
        for bad in [
            "not json",
            "{}",
            "[]",
            "[42]",
            "[\"REQ\"]",
            "[\"REQ\",\"sub\"]",
            "[\"REQ\",1,{\"kinds\":[1]}]",
            "[\"REQ\",\"sub\",42]",
            "[\"REQ\",\"s\",{\"kinds\":[65536]}]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]}]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},32,\"aabb\"]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"abc\"]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"zz\"]",
            "[\"NEG-MSG\",\"s\",\"\"]",
            "[\"NEG-MSG\",\"s\",\"a\"]",
            "[\"UNKNOWN\",\"s\"]",
            "[\"CLOSE\",\"\"]",
            "[\"CLOSE\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
        ] {
            assert!(ClientMessage::from_json(bad).is_err(), "{bad}");
        }
        // Uppercase NEG hex is invalid protocol text.
        assert!(ClientMessage::from_json("[\"NEG-MSG\",\"s\",\"FF00\"]").is_err());
        let ClientMessage::NegMsg { message, .. } =
            ClientMessage::from_json("[\"NEG-MSG\",\"s\",\"ff00\"]").expect("neg-msg")
        else {
            panic!("expected NegMsg");
        };
        assert_eq!(message.as_ref(), "ff00");
    }

    #[test]
    fn relay_parse_rules() {
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        let ok = RelayMessage::from_json(&alloc::format!(
            "[\"OK\",\"{}\",true,\"saved\"]",
            event.id().to_hex()
        ))
        .expect("ok");
        assert!(matches!(ok, RelayMessage::Ok { accepted: true, .. }));
        // Ruling 5: uppercase or short ids are rejected.
        for bad in [
            "not json",
            "[\"OK\",\"id\",true,\"\"]",
            "[\"OK\",\"AAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",true,\"\"]",
            "[\"OK\",\"aaaa\",true,\"\"]",
            "[\"EOSE\",\"\"]",
            "[\"EVENT\",\"s\",{}]",
            "[\"COUNT\",\"s\",{\"count\":-1}]",
            "[\"COUNT\",\"s\",{\"count\":1.5}]",
            "[\"COUNT\",\"s\",\"x\"]",
            "[\"NEG-ERR\",\"s\"]",
        ] {
            assert!(RelayMessage::from_json(bad).is_err(), "{bad}");
        }
        let relay_event =
            RelayMessage::from_json(&alloc::format!("[\"EVENT\",\"s\",{event_json}]"))
                .expect("event");
        assert!(matches!(relay_event, RelayMessage::Event { .. }));
    }

    #[test]
    fn relay_optional_and_trailing_elements() {
        let ok_hex = "a".repeat(64);
        let ok_parts = |raw: &str| -> (bool, Option<String>) {
            let RelayMessage::Ok {
                accepted, params, ..
            } = RelayMessage::from_json(raw).unwrap_or_else(|e| panic!("{raw}: {e}"))
            else {
                panic!("expected Ok: {raw}");
            };
            (accepted, params.map(Cow::into_owned))
        };
        let closed_params = |raw: &str| -> Option<String> {
            let RelayMessage::Closed { params, .. } =
                RelayMessage::from_json(raw).unwrap_or_else(|e| panic!("{raw}: {e}"))
            else {
                panic!("expected Closed: {raw}");
            };
            params.map(Cow::into_owned)
        };
        let eose_hints = |raw: &str| -> Option<Vec<String>> {
            let RelayMessage::Eose { hints, .. } =
                RelayMessage::from_json(raw).unwrap_or_else(|e| panic!("{raw}: {e}"))
            else {
                panic!("expected Eose: {raw}");
            };
            hints
        };
        // NIP-01 `<params>`: a string element surfaces; mistyped or
        // missing is treated as absent, extra elements are ignored.
        assert_eq!(
            ok_parts(&alloc::format!(
                "[\"OK\",\"{ok_hex}\",false,\"rate-limited: slow down\",\"1000\"]"
            )),
            (false, Some(String::from("1000")))
        );
        assert_eq!(
            ok_parts(&alloc::format!("[\"OK\",\"{ok_hex}\",true,\"\",1000]")),
            (true, None)
        );
        // A mistyped `<params>` reads as absent even when the element is a
        // number serde_json cannot represent (`1e400` overflows f64); a
        // trailing `1e400` after valid params is ignored entirely.
        assert_eq!(
            ok_parts(&alloc::format!("[\"OK\",\"{ok_hex}\",true,\"\",1e400]")),
            (true, None)
        );
        assert_eq!(
            ok_parts(&alloc::format!(
                "[\"OK\",\"{ok_hex}\",true,\"\",\"p\",1e400]"
            )),
            (true, Some(String::from("p")))
        );
        assert_eq!(
            ok_parts(&alloc::format!(
                "[\"OK\",\"{ok_hex}\",true,\"\",\"p\",\"x\"]"
            )),
            (true, Some(String::from("p")))
        );
        // A lone-surrogate escape can't deserialize as a `String`, so like a
        // mistyped element it reads as absent (required strings reject the
        // whole frame instead — serde_json's string path validates escapes).
        assert_eq!(
            ok_parts(&alloc::format!(
                "[\"OK\",\"{ok_hex}\",true,\"\",\"\\ud800\"]"
            )),
            (true, None)
        );
        // NIP-67 EOSE hints: an all-string array is kept (empty
        // included); anything else drops.
        assert_eq!(
            eose_hints("[\"EOSE\",\"s\",[\"auth\",\"finish\"]]"),
            Some(alloc::vec![String::from("auth"), String::from("finish")])
        );
        assert_eq!(eose_hints("[\"EOSE\",\"s\",[]]"), Some(Vec::new()));
        for raw in [
            "[\"EOSE\",\"s\",\"x\"]",
            "[\"EOSE\",\"s\",[\"more\",1]]",
            "[\"EOSE\",\"s\",1e400]",
            "[\"EOSE\",\"s\",[\"more\",1e400]]",
            "[\"EOSE\",\"s\",[\"finish\",\"\\ud800\"]]",
        ] {
            assert_eq!(eose_hints(raw), None, "{raw}");
        }
        // NIP-01 CLOSED `<params>`: same rule as OK.
        assert_eq!(
            closed_params("[\"CLOSED\",\"s\",\"bye\",\"2500\"]"),
            Some(String::from("2500"))
        );
        assert_eq!(closed_params("[\"CLOSED\",\"s\",\"bye\",5]"), None);
        // Every relay type tolerates trailing elements; the optional
        // NEG-ERR 4th element is dropped, not surfaced.
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        for (raw, encoded) in [
            (
                alloc::format!("[\"EVENT\",\"s\",{event_json},\"x\"]"),
                alloc::format!("[\"EVENT\",\"s\",{event_json}]"),
            ),
            (
                String::from("[\"NOTICE\",\"a\",\"b\"]"),
                String::from("[\"NOTICE\",\"a\"]"),
            ),
            (
                String::from("[\"AUTH\",\"c\",true]"),
                String::from("[\"AUTH\",\"c\"]"),
            ),
            (
                String::from("[\"COUNT\",\"s\",{\"count\":3},\"x\"]"),
                String::from("[\"COUNT\",\"s\",{\"count\":3}]"),
            ),
            (
                String::from("[\"NEG-MSG\",\"s\",\"aabb\",7]"),
                String::from("[\"NEG-MSG\",\"s\",\"aabb\"]"),
            ),
            (
                String::from("[\"NEG-ERR\",\"s\",\"blocked: too big\",100000]"),
                String::from("[\"NEG-ERR\",\"s\",\"blocked: too big\"]"),
            ),
        ] {
            let msg = RelayMessage::from_json(&raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(msg.to_json(), encoded, "{raw}");
        }
    }

    #[test]
    fn relay_malformed_required_elements_reject() {
        let ok_hex = "a".repeat(64);
        for bad in [
            alloc::format!("[\"OK\",\"{ok_hex}\",\"true\",\"\"]"),
            alloc::format!("[\"OK\",\"{ok_hex}\",true]"),
            alloc::format!("[\"OK\",\"{ok_hex}\",\"true\",\"\",\"1000\"]"),
            String::from("[\"EOSE\",42,[\"finish\"]]"),
            String::from("[\"CLOSED\",\"s\",5,\"1000\"]"),
            String::from("[\"EVENT\",\"s\"]"),
            String::from("[\"UNKNOWN\",\"s\"]"),
        ] {
            assert!(RelayMessage::from_json(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_trailing_elements() {
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        for (raw, encoded) in [
            (
                alloc::format!("[\"EVENT\",{event_json},{{}}]"),
                alloc::format!("[\"EVENT\",{event_json}]"),
            ),
            (
                alloc::format!("[\"AUTH\",{event_json},\"x\"]"),
                alloc::format!("[\"AUTH\",{event_json}]"),
            ),
            (
                String::from("[\"CLOSE\",\"a\",\"b\"]"),
                String::from("[\"CLOSE\",\"a\"]"),
            ),
            (
                String::from("[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"aabb\",\"extra\"]"),
                String::from("[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"aabb\"]"),
            ),
            (
                String::from("[\"NEG-MSG\",\"s\",\"aabb\",7]"),
                String::from("[\"NEG-MSG\",\"s\",\"aabb\"]"),
            ),
            (
                String::from("[\"NEG-CLOSE\",\"s\",\"x\"]"),
                String::from("[\"NEG-CLOSE\",\"s\"]"),
            ),
        ] {
            let msg = ClientMessage::from_json(&raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(msg.to_json(), encoded, "{raw}");
        }
        // The legacy 5-element NEG-OPEN stays rejected: element 3 is
        // not the hex message.
        assert!(
            ClientMessage::from_json("[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},32,\"61\"]").is_err()
        );
    }

    #[test]
    fn relay_count_result_parsing() {
        // approximate/hll wrong types are ignored, not errors; an
        // uppercase hll is invalid protocol text — the field drops.
        let RelayMessage::Count { result, .. } = RelayMessage::from_json(
            "[\"COUNT\",\"s\",{\"count\":7,\"approximate\":\"yes\",\"hll\":\"zz\"}]",
        )
        .expect("count") else {
            panic!("expected Count");
        };
        assert_eq!(
            result,
            CountResult {
                count: 7,
                approximate: None,
                hll: None,
            }
        );
        let RelayMessage::Count {
            result: max_result, ..
        } = RelayMessage::from_json(&alloc::format!(
            "[\"COUNT\",\"s\",{{\"count\":{},\"approximate\":true,\"hll\":\"{}\"}}]",
            9_007_199_254_740_991u64,
            "ab".repeat(256)
        ))
        .expect("max safe")
        else {
            panic!("expected Count");
        };
        assert_eq!(max_result.count, 9_007_199_254_740_991);
        assert_eq!(max_result.approximate, Some(true));
        assert_eq!(max_result.hll.expect("hll").to_string(), "ab".repeat(256));
        // 2^53 is rejected.
        assert!(RelayMessage::from_json("[\"COUNT\",\"s\",{\"count\":9007199254740992}]").is_err());
    }

    #[test]
    fn relay_encode_matches_ts() {
        let id = SubscriptionId::new("sub").expect("id");
        let event = signed_event();
        assert_eq!(
            RelayMessage::Ok {
                event_id: event.id(),
                accepted: true,
                message: Cow::Borrowed(""),
                params: None,
            }
            .to_json(),
            alloc::format!("[\"OK\",\"{}\",true,\"\"]", event.id().to_hex())
        );
        // NIP-01 `<params>` and NIP-67 EOSE hints serialize when `Some`.
        assert_eq!(
            RelayMessage::Ok {
                event_id: event.id(),
                accepted: true,
                message: Cow::Borrowed(""),
                params: Some(Cow::Borrowed("1000")),
            }
            .to_json(),
            alloc::format!("[\"OK\",\"{}\",true,\"\",\"1000\"]", event.id().to_hex())
        );
        assert_eq!(
            RelayMessage::Eose {
                subscription_id: Cow::Borrowed(&id),
                hints: None,
            }
            .to_json(),
            "[\"EOSE\",\"sub\"]"
        );
        assert_eq!(
            RelayMessage::Eose {
                subscription_id: Cow::Borrowed(&id),
                hints: Some(alloc::vec![String::from("finish")]),
            }
            .to_json(),
            "[\"EOSE\",\"sub\",[\"finish\"]]"
        );
        assert_eq!(
            RelayMessage::Closed {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("m"),
                params: Some(Cow::Borrowed("2500")),
            }
            .to_json(),
            "[\"CLOSED\",\"sub\",\"m\",\"2500\"]"
        );
        assert_eq!(
            RelayMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                result: CountResult {
                    count: 7,
                    approximate: Some(true),
                    hll: Some(Hll::from_str(&"ab".repeat(256)).expect("hll")),
                },
            }
            .to_json(),
            alloc::format!(
                "[\"COUNT\",\"sub\",{{\"count\":7,\"approximate\":true,\"hll\":\"{}\"}}]",
                "ab".repeat(256)
            )
        );
    }

    #[test]
    fn into_owned_gives_static() {
        let id = SubscriptionId::new("sub").expect("id");
        let msg = ClientMessage::Close(Cow::Borrowed(&id));
        let owned_msg: ClientMessage<'static> = msg.into_owned();
        assert_eq!(owned_msg, ClientMessage::Close(Cow::Owned(id.clone())));
        let relay = RelayMessage::Eose {
            subscription_id: Cow::Owned(id),
            hints: Some(alloc::vec![String::from("finish")]),
        };
        let owned_relay: RelayMessage<'static> = relay.into_owned();
        assert!(matches!(owned_relay, RelayMessage::Eose { .. }));
    }

    #[test]
    #[cfg(feature = "os-rng")]
    fn subscription_id_generate_is_16_lower_hex() {
        let id = SubscriptionId::generate().expect("os rng");
        assert_eq!(id.as_str().len(), 16);
        assert!(
            id.as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn count_hll_serde_round_trip() {
        let hll = Hll::from_str(&"ab".repeat(256)).expect("hll");
        let json = serde_json::to_string(&hll).expect("ser");
        assert_eq!(json, alloc::format!("\"{}\"", "ab".repeat(256)));
        let back: Hll = serde_json::from_str(&json).expect("de");
        assert_eq!(back, hll);
        // Lowercase only; wrong lengths, case, non-hex, non-strings fail.
        assert!(serde_json::from_str::<Hll>(&alloc::format!("\"{}\"", "AB".repeat(256))).is_err());
        assert!(serde_json::from_str::<Hll>("\"ab\"").is_err());
        assert!(serde_json::from_str::<Hll>(&alloc::format!("\"{}\"", "zz".repeat(256))).is_err());
        assert!(serde_json::from_str::<Hll>("5").is_err());
    }

    #[test]
    fn into_owned_covers_every_variant() {
        let id = SubscriptionId::new("sub").expect("id");
        let filter = Filter::new().kinds([Kind::TEXT_NOTE]).expect("filter");
        let event = signed_event();
        let event_id = event.id();
        let clients: [ClientMessage<'_>; 8] = [
            ClientMessage::Event(Cow::Borrowed(&event)),
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            },
            ClientMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            },
            ClientMessage::Close(Cow::Borrowed(&id)),
            ClientMessage::Auth(Cow::Borrowed(&event)),
            ClientMessage::NegOpen {
                subscription_id: Cow::Borrowed(&id),
                filter: Cow::Borrowed(&filter),
                message: Cow::Borrowed("aabb"),
            },
            ClientMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
            ClientMessage::NegClose(Cow::Borrowed(&id)),
        ];
        for message in clients {
            let encoded = message.to_json();
            let owned: ClientMessage<'static> = message.into_owned();
            assert_eq!(owned.to_json(), encoded);
        }
        let relays: [RelayMessage<'_>; 9] = [
            RelayMessage::Event {
                subscription_id: Cow::Borrowed(&id),
                event: Cow::Borrowed(&event),
            },
            RelayMessage::Ok {
                event_id,
                accepted: true,
                message: Cow::Borrowed("m"),
                params: Some(Cow::Borrowed("1000")),
            },
            RelayMessage::Eose {
                subscription_id: Cow::Borrowed(&id),
                hints: Some(alloc::vec![String::from("finish")]),
            },
            RelayMessage::Closed {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("m"),
                params: None,
            },
            RelayMessage::Notice(Cow::Borrowed("n")),
            RelayMessage::Auth {
                challenge: Cow::Borrowed("c"),
            },
            RelayMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                result: CountResult {
                    count: 1,
                    approximate: Some(true),
                    hll: Some(Hll::zero()),
                },
            },
            RelayMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
            RelayMessage::NegErr {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
        ];
        for message in relays {
            let encoded = message.to_json();
            let owned: RelayMessage<'static> = message.into_owned();
            assert_eq!(owned.to_json(), encoded);
        }
    }

    #[test]
    fn types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SubscriptionId>();
        assert_send_sync::<Hll>();
        assert_send_sync::<CountResult>();
        assert_send_sync::<ClientMessage<'static>>();
        assert_send_sync::<RelayMessage<'static>>();
    }
}
