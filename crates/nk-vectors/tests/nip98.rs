//! `vectors/nip98/codec.json` — NIP-98 `auth_event`/`token`/`unpack_token`/
//! `validate_auth_event` cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip98.test.ts`; regenerate with
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

use nk::nips::nip98;
use nk::{Event, Keys, SecretKey, Timestamp};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip98/codec.json"
));

/// `payload_hex` is the raw request body; `null` means no payload argument.
/// `payload_json` marks TS-only object payloads (`JSON.stringify` hashing).
#[derive(Debug, Deserialize)]
struct AuthCase {
    url: String,
    method: String,
    payload_hex: Option<String>,
    content: String,
    created_at: u64,
    event: Event,
    token: String,
    header: String,
    rust: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UnpackCase {
    token: String,
    event: Option<Event>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidateCase {
    event: Event,
    url: String,
    method: String,
    payload_hex: Option<String>,
    now: u64,
    max_skew_secs: u64,
    result: bool,
    rust: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    secret_key: String,
    aux: String,
    auth: Vec<AuthCase>,
    unpack: Vec<UnpackCase>,
    validate: Vec<ValidateCase>,
}

fn keys(vector: &Vector) -> Keys {
    Keys::new(SecretKey::from_hex(&vector.secret_key).expect("vector secret key"))
}

fn aux(vector: &Vector) -> [u8; 32] {
    let bytes = common::unhex(&vector.aux).expect("vector aux hex");
    bytes.try_into().expect("aux is 32 bytes")
}

fn payload_bytes(hex: &str) -> Vec<u8> {
    common::unhex(hex).expect("payload_hex must be hex")
}

#[test]
fn auth_event_token_header() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let keys = keys(&vector);
    let aux = aux(&vector);
    let mut skipped = 0;
    for (i, case) in vector.auth.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let payload = case.payload_hex.as_deref().map(payload_bytes);
        let unsigned =
            nip98::auth_event(&case.url, &case.method, payload.as_deref(), &case.content)
                .build_at(keys.public_key(), Timestamp::from_secs(case.created_at));
        let event = keys
            .sign_event_with_aux(unsigned, &aux)
            .expect("signing a built event cannot fail");
        assert_eq!(event, case.event, "case {i}: signed event");
        assert_eq!(nip98::token(&event), case.token, "case {i}: token");
        assert_eq!(
            nip98::authorization_header(&event),
            case.header,
            "case {i}: header"
        );
    }
    assert!(skipped > 0, "expected some TS-only object-payload cases");
}

#[test]
fn unpack_token_cases() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.unpack.iter().enumerate() {
        match (&case.event, &case.error) {
            (Some(event), None) => {
                assert_eq!(
                    nip98::unpack_token(&case.token).expect("case must unpack"),
                    *event,
                    "case {i}"
                );
            }
            (None, Some(error)) => {
                let err = nip98::unpack_token(&case.token).unwrap_err();
                assert_eq!(err.to_string(), format!("nip98: {error}"), "case {i}");
            }
            _ => panic!("case {i}: exactly one of event/error must be set"),
        }
    }
}

#[test]
fn validate_auth_event_cases() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let mut skipped = 0;
    for (i, case) in vector.validate.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let payload = case.payload_hex.as_deref().map(payload_bytes);
        assert_eq!(
            nip98::validate_auth_event(
                &case.event,
                &case.url,
                &case.method,
                payload.as_deref(),
                Timestamp::from_secs(case.now),
                case.max_skew_secs,
            ),
            case.result,
            "case {i}"
        );
    }
    assert!(skipped > 0, "expected some TS-only validate cases");
}
