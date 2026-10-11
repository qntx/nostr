//! Executes `vectors/nip04/codec.json` against rust-nostr's public API.

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

use common::{DivergenceCheck, unhex_arr};
use nostr::nips::nip04;
use nostr::prelude::{PublicKey, SecretKey};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip04/codec.json"
));

#[derive(Debug, Deserialize)]
struct Case {
    sec1: String,
    pub2: String,
    #[allow(dead_code, reason = "the shared secret is implied by sec1+pub2")]
    shared_secret: String,
    iv: String,
    plaintext: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct InvalidCase {
    op: String,
    sec1: String,
    pub2: String,
    #[allow(dead_code, reason = "the shared secret is implied by sec1+pub2")]
    shared_secret: String,
    payload: String,
    error: String,
}

#[derive(Debug, Deserialize)]
struct Vector {
    cases: Vec<Case>,
    invalid: Vec<InvalidCase>,
}

#[test]
fn nip04_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let mut check = DivergenceCheck::new("nip04.codec");
    for (i, case) in vector.cases.iter().enumerate() {
        let outcome = (|| -> Option<(String, String)> {
            let secret = SecretKey::from_hex(&case.sec1).ok()?;
            let peer = PublicKey::from_hex(&case.pub2).ok()?;
            let iv: [u8; 16] = unhex_arr(&case.iv)?;
            let payload = nip04::encrypt_with_iv(&secret, &peer, &case.plaintext, iv).ok()?;
            let plaintext = nip04::decrypt(&secret, &peer, &payload).ok()?;
            Some((payload, plaintext))
        })();
        let got = match &outcome {
            Some((payload, _)) => format!("encrypts to {payload}"),
            None => "rejected".to_owned(),
        };
        let agrees = outcome.is_some_and(|(payload, plaintext)| {
            payload == case.payload && plaintext == case.plaintext
        });
        check.check(&i.to_string(), agrees, &got);
    }
    for (i, case) in vector.invalid.iter().enumerate() {
        let rejected = match case.op.as_str() {
            "decrypt" => {
                let key_ok = unhex_arr::<32>(&case.shared_secret).is_some();
                let secret = SecretKey::from_hex(&case.sec1).ok();
                let peer = PublicKey::from_hex(&case.pub2).ok();
                match (secret, peer) {
                    // The vector carries a pre-derived shared secret; nostr's
                    // public API always derives from the keypair, so feed the
                    // recorded keys — a tampered ciphertext still rejects.
                    (Some(secret), Some(peer)) if key_ok => {
                        nip04::decrypt(&secret, &peer, &case.payload).is_err()
                    }
                    _ => true,
                }
            }
            "derive" => {
                match (
                    SecretKey::from_hex(&case.sec1),
                    PublicKey::from_hex(&case.pub2),
                ) {
                    (Ok(secret), Ok(peer)) => nip04::encrypt(&secret, &peer, "x").is_err(),
                    _ => true,
                }
            }
            _ => false,
        };
        check.check(
            &format!("invalid/{i}"),
            rejected == case.error.as_str().eq("CryptoError"),
            if rejected { "rejected" } else { "accepted" },
        );
    }
    check.finish();
}
