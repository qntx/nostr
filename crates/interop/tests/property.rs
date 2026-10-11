//! Property-based checks against rust-nostr's public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    reason = "a malformed fixture or impossible strategy value must fail loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

use nostr::event::SignEvent;
use nostr::prelude::{
    Event, Keys, Kind, PublicKey, SecretKey, Tag, Tags, Timestamp, UnsignedEvent,
};
use proptest::prelude::*;
use proptest::test_runner::Config;

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn any_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::any(), 0..=64)
        .prop_map(|chars| chars.into_iter().collect())
}

fn secret_key() -> impl Strategy<Value = SecretKey> {
    proptest::array::uniform32(proptest::num::u8::ANY)
        .prop_filter_map("secret key must be a valid scalar", |bytes| {
            SecretKey::from_slice(&bytes).ok()
        })
}

fn public_key() -> impl Strategy<Value = PublicKey> {
    proptest::array::uniform32(proptest::num::u8::ANY).prop_map(|bytes| {
        PublicKey::from_slice(&bytes).expect("any 32 bytes is a valid x-only key")
    })
}

fn tag() -> impl Strategy<Value = Tag> {
    proptest::collection::vec(any_string(), 1..=4)
        .prop_map(|items| Tag::parse(items).expect("non-empty string tag parses"))
}

fn tags() -> impl Strategy<Value = Tags> {
    proptest::collection::vec(tag(), 0..=6).prop_map(|tags| tags.into_iter().collect::<Tags>())
}

fn unsigned_parts() -> impl Strategy<Value = (u64, u16, Tags, String)> {
    (
        0..=MAX_SAFE_INTEGER,
        proptest::num::u16::ANY,
        tags(),
        any_string(),
    )
}

fn unsigned_event() -> impl Strategy<Value = UnsignedEvent> {
    (public_key(), unsigned_parts()).prop_map(|(pubkey, (secs, kind, tags, content))| {
        UnsignedEvent::new(
            pubkey,
            Timestamp::from_secs(secs),
            Kind::from(kind),
            tags,
            content,
        )
    })
}

fn signed_event() -> impl Strategy<Value = Event> {
    (secret_key(), unsigned_parts()).prop_map(|(secret, (secs, kind, tags, content))| {
        let keys = Keys::new(secret);
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(secs),
            Kind::from(kind),
            tags,
            content,
        );
        keys.sign_event(unsigned)
            .expect("generated unsigned signs with its own keypair")
    })
}

proptest! {
    #![proptest_config(Config::with_cases(256))]

    /// The id is a deterministic function of the unsigned event fields.
    #[test]
    fn compute_id_is_deterministic(unsigned in unsigned_event()) {
        prop_assert_eq!(unsigned.compute_id(), unsigned.compute_id());
    }

    /// A freshly signed event passes id and signature verification.
    #[test]
    fn signed_event_verifies(event in signed_event()) {
        prop_assert!(event.verify().is_ok());
    }

    #[test]
    fn event_serde_round_trip(event in signed_event()) {
        let wire = serde_json::to_string(&event).expect("event serializes");
        let back: Event = serde_json::from_str(&wire).expect("event re-parses");
        prop_assert_eq!(event, back);
    }
}
