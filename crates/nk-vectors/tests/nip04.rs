//! `vectors/nip04/codec.json` — NIP-04 AES-256-CBC payload vectors.
//!
//! The same file is replayed by `packages/nostr/tests/vectors/nip04.test.ts`;
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

use nk::nips::ErrorKind;
use nk::nips::nip04::{self, SharedSecret};
use nk::{PublicKey, SecretKey};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip04/codec.json"
));

/// Valid case: `encrypt_with_iv` under both `derive` and `from_bytes` must
/// reproduce `payload` byte-for-byte, and `decrypt` must return `plaintext`.
#[derive(Debug, Deserialize)]
struct Case {
    sec1: String,
    pub2: String,
    shared_secret: String,
    iv: String,
    plaintext: String,
    payload: String,
}

/// Failure case: `op` is "decrypt" (decrypt `payload` under the recorded
/// shared secret) or "derive" (deriving from `sec1`/`pub2` must fail).
#[derive(Debug, Deserialize)]
struct InvalidCase {
    op: String,
    sec1: String,
    pub2: String,
    shared_secret: String,
    payload: String,
    error: String,
}

#[derive(Debug, Deserialize)]
struct Vector {
    cases: Vec<Case>,
    invalid: Vec<InvalidCase>,
}

fn arr32(hex: &str) -> [u8; 32] {
    common::unhex(hex)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .expect("32-byte hex field")
}

fn arr16(hex: &str) -> [u8; 16] {
    common::unhex(hex)
        .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        .expect("16-byte hex field")
}

#[test]
fn nip04_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let secret = SecretKey::from_hex(&case.sec1).expect("secret hex");
        let peer = PublicKey::from_hex(&case.pub2).expect("pubkey hex");
        let derived = SharedSecret::derive(&secret, &peer).expect("derive");
        let from_bytes = SharedSecret::from_bytes(arr32(&case.shared_secret));
        let iv = arr16(&case.iv);
        for (name, key) in [("derive", &derived), ("from_bytes", &from_bytes)] {
            assert_eq!(
                nip04::encrypt_with_iv(key, &case.plaintext, &iv),
                case.payload,
                "case {i}: encrypt_with_iv {name}"
            );
            assert_eq!(
                nip04::decrypt(key, &case.payload).unwrap(),
                case.plaintext,
                "case {i}: decrypt {name}"
            );
        }
    }
    for (i, case) in vector.invalid.iter().enumerate() {
        assert_eq!(case.error, "CryptoError", "invalid {i}: class");
        let err = match case.op.as_str() {
            "decrypt" => {
                let key = SharedSecret::from_bytes(arr32(&case.shared_secret));
                nip04::decrypt(&key, &case.payload).expect_err("case must fail")
            }
            "derive" => {
                let secret = SecretKey::from_hex(&case.sec1).expect("secret hex");
                let peer = PublicKey::from_hex(&case.pub2).expect("pubkey hex");
                SharedSecret::derive(&secret, &peer).expect_err("derive must fail")
            }
            op => panic!("invalid {i}: unknown op {op}"),
        };
        assert_eq!(err.kind(), ErrorKind::Crypto, "invalid {i}");
    }
}
