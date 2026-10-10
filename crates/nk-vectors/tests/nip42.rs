//! `vectors/nip42/codec.json` — NIP-42 `auth_event` templates and
//! `is_auth_required` prefix recognition.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip42.test.ts`; regenerate with
//! `bun packages/nostr/scripts/parity/gen/all.ts`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use nk::nips::nip42;
use nk::{Kind, PublicKey, RelayUrl, Tag, Timestamp};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip42/codec.json"
));

const PUBKEY: &str = "79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6";

/// `relay` is the raw vector input; `tags`/`content` are the expected event
/// fields. `rust: false` marks relay strings the typed `RelayUrl` API cannot
/// express or that differ from their normalized form.
#[derive(Debug, Deserialize)]
struct AuthCase {
    relay: String,
    challenge: String,
    tags: Vec<Vec<String>>,
    content: String,
    rust: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AuthRequiredCase {
    reason: String,
    result: bool,
}

#[derive(Debug, Deserialize)]
struct Vector {
    auth: Vec<AuthCase>,
    auth_required: Vec<AuthRequiredCase>,
}

#[test]
fn auth_event_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let pubkey = PublicKey::from_hex(PUBKEY).expect("vector pubkey");
    let mut ran = 0;
    let mut skipped = 0;
    for (i, case) in vector.auth.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let relay = RelayUrl::parse(&case.relay)
            .unwrap_or_else(|e| panic!("case {i}: relay {:?} must parse: {e}", case.relay));
        let event = nip42::auth_event(&relay, &case.challenge)
            .build_at(pubkey, Timestamp::from_secs(1_700_000_000));
        assert_eq!(event.kind(), Kind::CLIENT_AUTH, "case {i}: kind");
        let tags: Vec<&[String]> = event.tags().iter().map(Tag::as_slice).collect();
        assert_eq!(tags.len(), case.tags.len(), "case {i}: tag count");
        for (want, got) in case.tags.iter().zip(tags) {
            assert_eq!(want.as_slice(), got, "case {i}: tag");
        }
        assert_eq!(event.content(), case.content, "case {i}: content");
        ran += 1;
    }
    assert_eq!(ran + skipped, vector.auth.len());
    assert!(skipped > 0, "expected some TS-only relay-string cases");
}

#[test]
fn auth_required_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.auth_required.iter().enumerate() {
        assert_eq!(
            nip42::is_auth_required(&case.reason),
            case.result,
            "case {i}: is_auth_required"
        );
    }
}
