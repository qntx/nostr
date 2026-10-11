//! Executes `vectors/nip21/uri.json` against rust-nostr's public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use common::{DivergenceCheck, entity_json};
use nostr::nips::nip19::{Nip19, ToBech32};
use nostr::nips::nip21::Nip21;
use serde::Deserialize;

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
    let mut check = DivergenceCheck::new("nip21.uri");
    for (i, case) in vector.cases.iter().enumerate() {
        let parsed = Nip21::parse(&case.input);
        // `is_uri` tracks the URI shape: a well-formed `nostr:` entity that
        // fails bech32 decode still counts; a missing/foreign scheme or a
        // secret-key variant does not. rust-nostr reports the same split via
        // `Nip21::parse` (scheme check + `TryFrom<Nip19>` rejection of nsec).
        let outcome = parsed.map(|nip21| {
            let nip19 = Nip19::from(nip21.clone());
            (
                nip19.to_bech32().ok(),
                nip21.to_nostr_uri().ok(),
                entity_json(&nip19),
            )
        });
        let agrees = match (&case.error, &outcome) {
            (Some(_), Err(_)) => true,
            (None, Ok((value, uri, decoded))) => {
                value.as_deref() == case.value.as_deref()
                    && uri.as_deref() == case.uri.as_deref()
                    && decoded.as_ref() == case.decoded.as_ref()
            }
            _ => false,
        };
        let got = match &outcome {
            Ok((_, uri, _)) => format!("parsed to {}", uri.as_deref().unwrap_or("?")),
            Err(_) => "rejected".to_owned(),
        };
        check.check(
            &format!("{i}"),
            agrees && outcome_ok_shape(case, &outcome),
            &got,
        );
    }
    check.finish();
}

/// The `is_uri` flag: nostr accepts a `nostr:`-prefixed decodable entity the
/// same way the flag predicts.
type Outcome =
    Result<(Option<String>, Option<String>, Option<common::EntityJson>), nostr::error::Error>;

const fn outcome_ok_shape(case: &Case, outcome: &Outcome) -> bool {
    // Cases whose `is_uri` is false carry a missing/foreign scheme or an
    // `nsec`/`ncryptsec` variant; nostr rejects those at the same boundary,
    // so `is_uri == false` must coincide with `Err`.
    case.is_uri || outcome.is_err()
}
