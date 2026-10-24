//! vectors/nip57/codec.json — `nip57.zap`.

use core::str::FromStr;

use nk_core::nips::nip57::{Bolt11, ZapTarget, validate_zap_receipt};
use nk_core::{Event, EventBuilder, PublicKey, RelayUrl, Timestamp};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct ZapCase {
    name: String,
    input: Value,
    amount: Option<Value>,
    relays: Vec<String>,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    lnurl: Option<String>,
    #[serde(default)]
    out: Option<Value>,
    #[serde(default)]
    err: Option<String>,
    #[serde(default)]
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct BoltCase {
    name: String,
    invoice: String,
    #[serde(default)]
    out: Option<Value>,
}

#[derive(Deserialize)]
struct ReceiptCase {
    name: String,
    receipt: Value,
    #[serde(rename = "nostrPubkey")]
    nostr_pubkey: String,
    #[serde(default)]
    lnurl: Option<String>,
    result: Value,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip57/codec.json"
));

#[test]
fn nip57_zap_request() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ZapCase> = serde_json::from_value(doc["zap_request"].clone()).unwrap();
    for case in &cases {
        // `"rust": false` — raw-string relays/pubkeys or non-integer amounts
        // the typed API cannot express; asserted as marked.
        if case.rust == Some(false) {
            continue;
        }
        let event: Option<Event> = if case.input.get("pubkey").is_none() {
            Some(serde_json::from_value(case.input["event"].clone()).unwrap())
        } else {
            None
        };
        let target = match &event {
            Some(e) => ZapTarget::Event(e),
            None => ZapTarget::Profile(
                PublicKey::from_hex(case.input["pubkey"].as_str().unwrap()).unwrap(),
            ),
        };
        let relays: Vec<RelayUrl> = case
            .relays
            .iter()
            .map(|r| RelayUrl::parse(r).unwrap())
            .collect();
        let result = EventBuilder::zap_request(
            target,
            case.amount.as_ref().and_then(Value::as_u64).unwrap_or(0),
            &relays,
            &case.comment,
            case.lnurl.as_deref(),
        );
        if case.err.is_some() {
            assert!(result.is_err(), "{}: expected error", case.name);
            continue;
        }
        let out = case
            .out
            .as_ref()
            .unwrap_or_else(|| panic!("{}: out", case.name));
        let unsigned = result.unwrap().build_at(
            PublicKey::from_hex(&"11".repeat(32)).unwrap(),
            Timestamp::from_secs(out["created_at"].as_u64().unwrap()),
        );
        let got = json!({
            "kind": unsigned.kind().as_u16(),
            "created_at": unsigned.created_at().as_secs(),
            "content": unsigned.content(),
            "tags": unsigned.tags().iter().map(|t| t.as_slice()).collect::<Vec<_>>(),
        });
        assert_eq!(&got, out, "{}", case.name);
    }
}

#[test]
fn nip57_bolt11() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<BoltCase> = serde_json::from_value(doc["bolt11"].clone()).unwrap();
    for case in &cases {
        let parsed = Bolt11::from_str(&case.invoice);
        match &case.out {
            Some(want) => {
                let b = parsed.unwrap_or_else(|e| panic!("{}: {e}", case.name));
                let mut got = json!({
                    "paymentHash": crate::common::hex_str(&b.payment_hash),
                    "timestamp": b.timestamp,
                });
                if let Some(m) = b.amount_msats {
                    got["amountMsats"] = json!(m);
                }
                if let Some(d) = &b.description {
                    got["description"] = json!(d);
                }
                if let Some(h) = &b.description_hash {
                    got["descriptionHash"] = json!(crate::common::hex_str(h));
                }
                got["expiry"] = json!(b.expiry);
                assert_eq!(&got, want, "{}", case.name);
            }
            None => assert!(parsed.is_err(), "{}", case.name),
        }
    }
}

#[test]
fn nip57_receipt() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ReceiptCase> = serde_json::from_value(doc["receipt"].clone()).unwrap();
    for case in &cases {
        let receipt: Event = serde_json::from_value(case.receipt.clone()).unwrap();
        let pubkey = PublicKey::from_hex(&case.nostr_pubkey).unwrap();
        let got = validate_zap_receipt(&receipt, &pubkey, case.lnurl.as_deref());
        match (&got, &case.result) {
            (Ok(valid), r) if r["valid"] == true => {
                assert_eq!(
                    serde_json::to_value(&valid.request).unwrap(),
                    r["request"],
                    "{} request",
                    case.name
                );
                if let Some(w) = r.get("amountMsats") {
                    assert_eq!(
                        valid.amount_msats.map_or(json!(null), |m| json!(m)),
                        *w,
                        "{} amount",
                        case.name
                    );
                }
            }
            (Err(e), r) if r["valid"] == false => {
                assert_eq!(e.to_string(), r["reason"], "{}", case.name);
            }
            _ => panic!("{}: got {:?}, want {}", case.name, got.is_ok(), case.result),
        }
    }
}
