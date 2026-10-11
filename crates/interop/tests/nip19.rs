//! Executes `vectors/nip19/codec.json` and `vectors/nip19/official.json`
//! against rust-nostr's `Nip19` bech32 API.

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

use common::{DivergenceCheck, EntityJson, entity_from_json, entity_json};
use nostr::nips::nip19::{FromBech32, Nip19, ToBech32};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip19/codec.json"
));

const OFFICIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip19/official.json"
));

/// One vector case: `{input, decoded, encoded}`, `{input, error}`,
/// `{encode, decoded, encoded}`, or `{encode, error}`.
#[derive(Debug, Deserialize)]
struct Case {
    input: Option<String>,
    encode: Option<EntityJson>,
    decoded: Option<EntityJson>,
    encoded: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

fn decode_outcome(input: &str) -> (Option<(Option<EntityJson>, String)>, String) {
    Nip19::from_bech32(input).map_or_else(
        |_| (None, "rejected".to_owned()),
        |entity| {
            let reencode = entity.to_bech32().ok();
            (
                Some((entity_json(&entity), reencode.unwrap_or_default())),
                "decoded".to_owned(),
            )
        },
    )
}

fn run_case(label: &str, case: &Case, check: &mut DivergenceCheck) {
    if let Some(input) = &case.input {
        let (outcome, got) = decode_outcome(input);
        let agrees = match (&case.error, outcome) {
            (Some(_), None) => true,
            (None, Some((decoded, reencode))) => {
                decoded.as_ref() == case.decoded.as_ref()
                    && case
                        .encoded
                        .as_ref()
                        .is_none_or(|encoded| reencode == *encoded)
            }
            _ => false,
        };
        check.check(label, agrees, &got);
    } else if let Some(encode) = &case.encode {
        let outcome = entity_from_json(encode)
            .ok()
            .and_then(|entity| entity.to_bech32().ok());
        let agrees = match (&case.error, &outcome) {
            (Some(_), None) => true,
            (None, Some(code)) => case.encoded.as_ref() == Some(code),
            _ => false,
        };
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(label, agrees, &got);
    } else {
        panic!("{label}: malformed case, needs input or encode");
    }
}

fn codec_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("codec.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case(&format!("codec/{index}"), case, check);
    }
}

fn official_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(OFFICIAL).expect("official.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case(&format!("official/{index}"), case, check);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip19.codec");
    codec_vectors(&mut check);
    official_vectors(&mut check);
    check.finish();
}
