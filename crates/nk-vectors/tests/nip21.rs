//! `vectors/nip21/uri.json` — NIP-21 `nostr:` URI vectors.
//!
//! The same file is replayed by `packages/nostr/tests/vectors/nip21.test.ts`;
//! regenerate with `bun packages/nostr/scripts/parity/gen/all.ts`.

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

use nk::nips::nip21::{self, NostrUri};
use serde::Deserialize;

use common::entity_json;

const URI: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip21/uri.json"
));

/// One vector case: `{input, is_uri, value, uri, decoded}` on success or
/// `{input, is_uri, error}` on failure.
#[derive(Debug, Deserialize)]
struct Case {
    input: String,
    is_uri: bool,
    value: Option<String>,
    uri: Option<String>,
    decoded: Option<common::EntityJson>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

#[test]
fn uri_vectors() {
    let vector: Vector = serde_json::from_str(URI).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let parsed = NostrUri::parse(&case.input);
        // `is_uri` tracks the URI shape: a well-shaped entity that fails
        // NIP-19 decode still counts; a missing scheme or `nsec` does not.
        assert_eq!(
            case.is_uri,
            !matches!(
                parsed,
                Err(nip21::Error::MissingScheme | nip21::Error::SecretKey)
            ),
            "case {i}: is_uri"
        );
        if let Some(error) = &case.error {
            assert_eq!(error, "Nip21Error", "case {i}: unexpected error class");
            assert!(parsed.is_err(), "case {i}: parse must fail");
            continue;
        }
        let parsed = parsed.unwrap_or_else(|e| panic!("case {i}: parse failed: {e}"));
        assert_eq!(parsed.as_str(), case.value.as_deref().unwrap(), "case {i}");
        assert_eq!(parsed.to_string(), case.uri.as_deref().unwrap(), "case {i}");
        let decoded: common::EntityJson =
            serde_json::from_value(serde_json::to_value(entity_json(parsed.entity())).unwrap())
                .unwrap();
        assert_eq!(&decoded, case.decoded.as_ref().unwrap(), "case {i}");
    }
}
