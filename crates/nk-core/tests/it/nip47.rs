//! vectors/nip47.json — `nip47`. The same file drives
//! packages/nostr/tests/nip47.test.ts.

#![cfg(feature = "nip44")]

use nk_core::nips::nip44::ConversationKey;
use nk_core::nips::nip47::{self, NwcOutcome};
use nk_core::{PublicKey, SecretKey};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Doc {
    keys: Keys,
    cases: Vec<Value>,
}

#[derive(Deserialize)]
struct Keys {
    #[serde(rename = "clientSecret")]
    client_secret: String,
    #[serde(rename = "walletPubkey")]
    wallet_pubkey: String,
}

fn tags_of(v: &Value) -> Vec<(String, String)> {
    v["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|t| {
            (
                t[0].as_str().unwrap().to_string(),
                t[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn nip47_matches_vectors() {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip47.json"
    ));
    let doc: Doc = serde_json::from_str(text).expect("nip47.json must parse");
    let client_sk =
        SecretKey::from_bytes(crate::common::unhex_arr::<32>(&doc.keys.client_secret).unwrap())
            .unwrap();
    let wallet_pk =
        PublicKey::from_slice(&crate::common::unhex_arr::<32>(&doc.keys.wallet_pubkey).unwrap())
            .unwrap();
    let conv = ConversationKey::derive(&client_sk, &wallet_pk).expect("conversation key");

    for case in &doc.cases {
        let id = case["id"].as_str().unwrap();
        let ok = case["ok"].as_bool().unwrap();
        match case["kind"].as_str().unwrap() {
            "uri" => {
                assert_eq!(
                    nip47::parse_connection_uri(case["input"].as_str().unwrap()).is_ok(),
                    ok,
                    "{id}"
                );
            }
            "info" => {
                let info = nip47::parse_info_event(
                    case["input"]["kind"].as_u64().unwrap() as u16,
                    case["input"]["content"].as_str().unwrap(),
                    &tags_of(&case["input"]),
                )
                .expect("info parses");
                let methods: Vec<&str> = case["expect"]["methods"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap())
                    .collect();
                assert_eq!(info.methods, methods, "{id}");
                assert_eq!(
                    info.nip44,
                    case["expect"]["nip44"].as_bool().unwrap(),
                    "{id}"
                );
            }
            "response" => {
                let plaintext = conv
                    .decrypt(case["input"]["content"].as_str().unwrap())
                    .expect("response decrypts");
                let outcome =
                    nip47::decode_response_payload(case["method"].as_str().unwrap(), &plaintext);
                assert_eq!(outcome.is_ok(), ok, "{id}");
                if ok && let Some(code) = case["expect"].get("code") {
                    assert_eq!(
                        outcome.unwrap(),
                        NwcOutcome::Err(code.as_str().unwrap().to_string()),
                        "{id}"
                    );
                }
            }
            other => panic!("unknown case kind {other}"),
        }
    }
}
