//! vectors/ecdh.json — `ecdh`. The same file drives
//! packages/nostr/tests/vectors/ecdh.test.ts.

#![cfg(any(feature = "nip04", feature = "nip44"))]

use nk_core::nips::ecdh;
use nk_core::{PublicKey, SecretKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    sec: String,
    #[serde(rename = "pub")]
    pub_key: String,
    #[serde(rename = "sharedX")]
    shared_x: Option<String>,
}

#[test]
fn shared_x_matches_vectors() {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/ecdh.json"
    ));
    let doc: serde_json::Value = serde_json::from_str(text).expect("ecdh.json must parse");
    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).expect("cases must decode");

    for case in &cases {
        let sec_bytes = crate::common::unhex_arr::<32>(&case.sec);
        let pub_bytes = crate::common::unhex_arr::<32>(&case.pub_key);
        match (&case.shared_x, sec_bytes, pub_bytes) {
            (Some(expected), Some(sec), Some(pkb)) => {
                let secret = SecretKey::from_bytes(sec).expect("valid secret");
                let peer = PublicKey::from_slice(&pkb).expect("valid x-only key");
                let x = ecdh::shared_x(&secret, &peer).expect("shared_x");
                assert_eq!(
                    crate::common::hex_str(&*x),
                    *expected,
                    "sec {}… pub {}…",
                    &case.sec[..8],
                    &case.pub_key[..8],
                );
            }
            (None, sec, pub_bytes) => {
                // Invalid input: zero secret / secret ≥ n fails SecretKey
                // construction; a non-lifting x fails PublicKey or shared_x.
                let secret = sec.and_then(|s| SecretKey::from_bytes(s).ok());
                let peer = pub_bytes.and_then(|p| PublicKey::from_slice(&p).ok());
                if let (Some(secret), Some(peer)) = (secret, peer) {
                    assert!(
                        ecdh::shared_x(&secret, &peer).is_err(),
                        "expected shared_x to reject sec {}… pub {}…",
                        &case.sec[..8],
                        &case.pub_key[..8],
                    );
                }
            }
            (Some(_), _, _) => panic!("valid case with undecodable hex"),
        }
    }
}
