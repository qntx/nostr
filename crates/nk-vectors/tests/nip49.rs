//! `vectors/nip49/{official,codec,max-logn}.json` — NIP-49 `ncryptsec` vectors.
//!
//! The same files are replayed by `packages/nostr/tests/vectors/nip49.test.ts`;
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

use nk::SecretKey;
use nk::nips::ErrorKind;
use nk::nips::nip49::{self, EncryptOptions, KeySecurity};
use serde::Deserialize;

const OFFICIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/official.json"
));
const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/codec.json"
));
const MAX_LOGN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/max-logn.json"
));

/// Valid `encrypt_with`/`decrypt` case from `codec.json`.
#[derive(Debug, Deserialize)]
struct Case {
    secret: String,
    password: String,
    log_n: u8,
    key_security: u8,
    salt: String,
    nonce: String,
    ncryptsec: String,
}

/// Failure case from `codec.json`.
#[derive(Debug, Deserialize)]
struct InvalidCase {
    ncryptsec: String,
    password: String,
    max_log_n: u8,
    error: String,
}

#[derive(Debug, Deserialize)]
struct CodecVector {
    cases: Vec<Case>,
    invalid: Vec<InvalidCase>,
}

/// Spec-example decrypt case from `official.json`.
#[derive(Debug, Deserialize)]
struct OfficialCase {
    ncryptsec: String,
    password: String,
    max_log_n: u8,
    secret: String,
    key_security: u8,
}

#[derive(Debug, Deserialize)]
struct OfficialVector {
    cases: Vec<OfficialCase>,
}

/// Ceiling case from `max-logn.json`. `maxLogN` may be a non-integer
/// fixture (the TS API validates its range separately).
#[derive(Debug, Deserialize)]
struct MaxLognCase {
    input: String,
    password: String,
    #[serde(rename = "maxLogN")]
    max_log_n: serde_json::Value,
    secret: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MaxLognVector {
    cases: Vec<MaxLognCase>,
}

fn key_security(byte: u8) -> KeySecurity {
    match byte {
        0x00 => KeySecurity::Insecure,
        0x01 => KeySecurity::Secure,
        0x02 => KeySecurity::Unknown,
        other => panic!("bad key_security fixture {other}"),
    }
}

fn assert_decrypted(input: &str, password: &str, max_log_n: u8, secret: &str, ksb: u8, i: usize) {
    let out = nip49::decrypt(input, password, max_log_n)
        .unwrap_or_else(|e| panic!("case {i}: decrypt: {e}"));
    out.secret_key.with_secret_bytes(|bytes| {
        let want = common::unhex(secret).expect("secret hex");
        assert_eq!(&want[..], bytes, "case {i}: secret");
    });
    assert_eq!(out.key_security, key_security(ksb), "case {i}: ksb");
}

#[test]
fn nip49_official() {
    let vector: OfficialVector = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        assert_decrypted(
            &case.ncryptsec,
            &case.password,
            case.max_log_n,
            &case.secret,
            case.key_security,
            i,
        );
    }
}

#[test]
fn nip49_codec() {
    let vector: CodecVector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let secret = SecretKey::from_hex(&case.secret).expect("secret hex");
        let salt = common::unhex(&case.salt).expect("salt hex");
        let nonce = common::unhex(&case.nonce).expect("nonce hex");
        let options = EncryptOptions::new()
            .log_n(case.log_n)
            .expect("log_n in range")
            .key_security(key_security(case.key_security));
        assert_eq!(
            nip49::encrypt_with(
                &secret,
                &case.password,
                options,
                <&[u8; 16]>::try_from(salt.as_slice()).expect("16-byte salt"),
                <&[u8; 24]>::try_from(nonce.as_slice()).expect("24-byte nonce"),
            )
            .expect("encrypt_with"),
            case.ncryptsec,
            "case {i}: encrypt_with"
        );
        assert_decrypted(
            &case.ncryptsec,
            &case.password,
            22,
            &case.secret,
            case.key_security,
            i,
        );
    }
    // The decomposed/composed NFKC pair lands as two identical `ncryptsec`
    // payloads; their `encrypt_with` byte-equality above is the parity proof.
    let pairs = vector
        .cases
        .iter()
        .enumerate()
        .flat_map(|(i, a)| vector.cases.iter().skip(i + 1).map(move |b| (a, b)))
        .filter(|(a, b)| a.ncryptsec == b.ncryptsec && a.password != b.password)
        .count();
    assert_eq!(pairs, 1, "exactly one NFKC pair shares a payload");
    for (i, case) in vector.invalid.iter().enumerate() {
        assert_eq!(case.error, "Nip49Error", "invalid {i}: class");
        let err = nip49::decrypt(&case.ncryptsec, &case.password, case.max_log_n)
            .expect_err("case must fail");
        assert_eq!(err.kind(), ErrorKind::Nip49, "invalid {i}");
    }
}

#[test]
fn nip49_max_logn() {
    let vector: MaxLognVector = serde_json::from_str(MAX_LOGN).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        // A non-integer ceiling cannot be expressed by the Rust API (`u8`);
        // the TS runner pins the integer check for those fixtures.
        let Some(raw) = case.max_log_n.as_u64() else {
            assert!(case.error.is_some(), "case {i}: non-integer must fail");
            continue;
        };
        let max_log_n = u8::try_from(raw).unwrap_or(u8::MAX);
        match (&case.secret, &case.error) {
            (Some(secret), None) => {
                let out = nip49::decrypt(&case.input, &case.password, max_log_n)
                    .unwrap_or_else(|e| panic!("case {i}: decrypt: {e}"));
                out.secret_key.with_secret_bytes(|bytes| {
                    let want = common::unhex(secret).expect("secret hex");
                    assert_eq!(&want[..], bytes, "case {i}: secret");
                });
            }
            (None, Some(error)) => {
                assert_eq!(error, "Nip49Error", "case {i}: class");
                let err = nip49::decrypt(&case.input, &case.password, max_log_n)
                    .expect_err("case must fail");
                assert_eq!(err.kind(), ErrorKind::Nip49, "case {i}");
            }
            other => panic!("case {i}: malformed fixture {other:?}"),
        }
    }
}
