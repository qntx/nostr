//! Property-based checks against the nk-core public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a malformed fixture or impossible strategy value must fail loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

use nk_core::{
    Event, EventId, Filter, Keys, Kind, PublicKey, SecretKey, SingleLetterTag, SubscriptionId, Tag,
    Tags, Timestamp, UnsignedEvent,
};
use proptest::prelude::*;
use proptest::test_runner::Config;

/// The wire-integer bound shared by every numeric field (NK-ADR-012 ruling 9).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Any Unicode scalar value, including control characters, U+2028/U+2029 and
/// astral planes. Rust `String`s can never hold lone surrogates, matching the
/// wire-side acceptance rule.
fn any_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::any(), 0..=64)
        .prop_map(|chars| chars.into_iter().collect())
}

fn secret_key() -> impl Strategy<Value = SecretKey> {
    proptest::array::uniform32(proptest::num::u8::ANY)
        .prop_filter_map("secret key must be a valid scalar", |bytes| {
            SecretKey::from_bytes(bytes).ok()
        })
}

fn public_key() -> impl Strategy<Value = PublicKey> {
    proptest::array::uniform32(proptest::num::u8::ANY).prop_map(PublicKey::from_bytes)
}

fn tag() -> impl Strategy<Value = Tag> {
    proptest::collection::vec(any_string(), 1..=4)
        .prop_map(|items| Tag::new(items).expect("generated tag is non-empty"))
}

fn tags() -> impl Strategy<Value = Tags> {
    proptest::collection::vec(tag(), 0..=6).prop_map(|tags| tags.into_iter().collect::<Tags>())
}

/// The parts of an unsigned event minus the pubkey (set to the signing
/// keypair's key where a signed event is wanted).
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
            Kind::new(kind),
            tags,
            content,
        )
    })
}

fn signed_event() -> impl Strategy<Value = Event> {
    (
        secret_key(),
        proptest::array::uniform32(proptest::num::u8::ANY),
        unsigned_parts(),
    )
        .prop_map(|(secret, aux, (secs, kind, tags, content))| {
            let keys = Keys::new(secret);
            keys.sign_event_with_aux(
                UnsignedEvent::new(
                    keys.public_key(),
                    Timestamp::from_secs(secs),
                    Kind::new(kind),
                    tags,
                    content,
                ),
                &aux,
            )
            .expect("generated unsigned signs with its own keypair")
        })
}

fn filter() -> impl Strategy<Value = Filter> {
    (
        proptest::option::of(proptest::collection::vec(
            proptest::array::uniform32(proptest::num::u8::ANY).prop_map(EventId::from_bytes),
            0..=4,
        )),
        proptest::option::of(proptest::collection::vec(public_key(), 0..=4)),
        proptest::option::of(proptest::collection::vec(proptest::num::u16::ANY, 0..=6)),
        proptest::collection::vec(
            (
                prop::char::range('a', 'z'),
                proptest::collection::vec(any_string(), 0..=4),
            ),
            0..=4,
        ),
        proptest::option::of(0..=MAX_SAFE_INTEGER),
        proptest::option::of(0..=MAX_SAFE_INTEGER),
        proptest::option::of(0..=MAX_SAFE_INTEGER),
        proptest::option::of(any_string()),
    )
        .prop_map(|(ids, authors, kinds, tags, since, until, limit, search)| {
            let mut filter = Filter::new();
            if let Some(ids) = ids {
                filter = filter.ids(ids);
            }
            if let Some(authors) = authors {
                filter = filter.authors(authors);
            }
            if let Some(kinds) = kinds {
                filter = filter.kinds(kinds.into_iter().map(Kind::new));
            }
            for (letter, values) in tags {
                let letter =
                    SingleLetterTag::new(letter).expect("'a'..='z' is always a single-letter tag");
                filter = filter.tag(letter, values);
            }
            if let Some(secs) = since {
                filter = filter.since(Timestamp::from_secs(secs));
            }
            if let Some(secs) = until {
                filter = filter.until(Timestamp::from_secs(secs));
            }
            if let Some(limit) = limit {
                filter = filter.limit(usize::try_from(limit).expect("u64 bound fits usize"));
            }
            if let Some(search) = search {
                filter = filter.search(search);
            }
            filter
        })
}

fn subscription_id() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::any(), 0..=70)
        .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(Config::with_cases(256))]

    /// The hand-written canonical writer must agree byte-for-byte with
    /// serde_json's compact escaping (the same output `JSON.stringify`
    /// produces for valid Unicode).
    #[test]
    fn canonical_json_matches_serde_json(unsigned in unsigned_event()) {
        let reference = serde_json::to_string(&(
            0,
            unsigned.pubkey().to_hex(),
            unsigned.created_at().as_secs(),
            unsigned.kind().as_u16(),
            unsigned.tags(),
            unsigned.content(),
        ))
        .expect("reference tuple serializes");
        prop_assert_eq!(unsigned.canonical_json(), reference);
    }

    #[test]
    fn event_serde_round_trip(event in signed_event()) {
        let wire = serde_json::to_string(&event).expect("event serializes");
        let back: Event = serde_json::from_str(&wire).expect("event re-parses");
        prop_assert_eq!(event, back);
    }

    /// Canonical filter output is a fixed point of parse-then-serialize.
    #[test]
    fn filter_canonical_is_fixed_point(filter in filter()) {
        let canonical = filter.canonical_json();
        prop_assert_eq!(
            serde_json::to_string(&filter).expect("filter serializes"),
            canonical.as_str()
        );
        let parsed: Filter = serde_json::from_str(&canonical).expect("canonical filter re-parses");
        prop_assert_eq!(parsed.canonical_json(), canonical);
    }

    #[test]
    fn subscription_id_accepts_1_to_64_scalars(id in subscription_id()) {
        let len = id.chars().count();
        let result = SubscriptionId::new(&id);
        if (1..=64).contains(&len) {
            prop_assert!(result.is_ok(), "len {len} must be accepted");
        } else {
            prop_assert!(result.is_err(), "len {len} must be rejected");
        }
    }
}

/// The exact length boundaries, pinned so shrinking can never hide them.
#[test]
fn subscription_id_boundaries() {
    assert!(SubscriptionId::new("").is_err());
    assert!(SubscriptionId::new("a".repeat(64)).is_ok());
    assert!(SubscriptionId::new("\u{1F600}".repeat(64)).is_ok());
    assert!(SubscriptionId::new("a".repeat(65)).is_err());
    assert!(SubscriptionId::new("\u{1F600}".repeat(65)).is_err());
}
