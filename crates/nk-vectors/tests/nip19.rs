//! Executes `vectors/nip19/codec.json` and `vectors/nip19/official.json`
//! against the nk-nips `nip19` API.

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

use nk_nips::ErrorKind;
use nk_nips::nip19;
use serde::Deserialize;

use common::{EntityJson, encode_entity, entity_json};

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

fn run_decode_case(label: &str, input: &str, case: &Case) {
    match nip19::decode(input) {
        Ok(entity) => {
            let expected = case
                .decoded
                .as_ref()
                .unwrap_or_else(|| panic!("{label}: unexpected decode success"));
            assert_eq!(&entity_json(&entity), expected, "{label}: decode mismatch");
            if let Some(encoded) = &case.encoded {
                let reencoded = entity
                    .to_bech32()
                    .unwrap_or_else(|e| panic!("{label}: re-encode failed: {e}"));
                assert_eq!(reencoded, *encoded, "{label}: re-encode mismatch");
            }
        }
        Err(error) => {
            assert_eq!(
                case.error.as_deref(),
                Some("Nip19Error"),
                "{label}: unexpected decode error {error}"
            );
            assert_eq!(error.kind(), ErrorKind::Nip19, "{label}");
        }
    }
}

fn run_encode_case(label: &str, encode: &EntityJson, case: &Case) {
    match encode_entity(encode) {
        Ok(code) => {
            assert_eq!(
                case.encoded.as_deref(),
                Some(code.as_str()),
                "{label}: encode mismatch"
            );
            if let Some(expected) = &case.decoded {
                let entity = nip19::decode(&code)
                    .unwrap_or_else(|e| panic!("{label}: encoded string failed to decode: {e}"));
                assert_eq!(&entity_json(&entity), expected, "{label}");
            }
        }
        Err(name) => {
            assert_eq!(
                case.error.as_deref(),
                Some(name),
                "{label}: unexpected encode error"
            );
        }
    }
}

fn run_case(file: &str, index: usize, case: &Case) {
    let label = format!("{file} case {index}");
    if let Some(input) = &case.input {
        run_decode_case(&label, input, case);
    } else if let Some(encode) = &case.encode {
        run_encode_case(&label, encode, case);
    } else {
        panic!("{label}: malformed case, needs input or encode");
    }
}

#[test]
fn codec_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("codec.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case("codec.json", index, case);
    }
}

#[test]
fn official_vectors() {
    let vector: Vector = serde_json::from_str(OFFICIAL).expect("official.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case("official.json", index, case);
    }
}
