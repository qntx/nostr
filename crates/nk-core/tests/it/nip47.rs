//! vectors/nip47/codec.json — `nip47.codec`. Structural codec cases always
//! run; encrypted payload decryption cases run under their crypto features.

use core::str::FromStr;

use nk_core::nips::nip47::{
    self, ErrorCode, ListTransactionsParams, LookupInvoiceParams, MakeInvoiceParams, Method,
    Notification, NwcResult, NwcUri, PayInvoiceParams, Request, Transaction, TransactionType,
};
use nk_core::{Event, Kind};
use serde_json::{Value, json};

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip47/codec.json"
));

fn doc() -> Value {
    serde_json::from_str(JSON).unwrap()
}

fn event(value: &Value) -> Event {
    serde_json::from_value(value.clone()).unwrap()
}

fn opt_string(obj: &Value, key: &str) -> Option<String> {
    obj.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn opt_u64(obj: &Value, key: &str) -> Option<u64> {
    obj.get(key).and_then(Value::as_u64)
}

fn request(value: &Value) -> Request {
    let method = value["method"].as_str().unwrap();
    let params = &value["params"];
    let metadata = params
        .get("metadata")
        .map(|value| serde_json::to_string(value).unwrap());
    match method {
        "pay_invoice" => Request::PayInvoice(PayInvoiceParams {
            invoice: params["invoice"].as_str().unwrap().to_owned(),
            amount: opt_u64(params, "amount"),
            metadata,
        }),
        "make_invoice" => Request::MakeInvoice(MakeInvoiceParams {
            amount: params["amount"].as_u64().unwrap(),
            description: opt_string(params, "description"),
            description_hash: opt_string(params, "description_hash"),
            expiry: opt_u64(params, "expiry"),
            metadata,
        }),
        "lookup_invoice" => Request::LookupInvoice(LookupInvoiceParams {
            payment_hash: opt_string(params, "payment_hash"),
            invoice: opt_string(params, "invoice"),
        }),
        "get_balance" => Request::GetBalance,
        "get_info" => Request::GetInfo,
        "list_transactions" => Request::ListTransactions(ListTransactionsParams {
            from: opt_u64(params, "from"),
            until: opt_u64(params, "until"),
            limit: opt_u64(params, "limit"),
            offset: opt_u64(params, "offset"),
            unpaid: params.get("unpaid").and_then(Value::as_bool),
            transaction_type: params
                .get("type")
                .and_then(Value::as_str)
                .map(|kind| match kind {
                    "incoming" => TransactionType::Incoming,
                    "outgoing" => TransactionType::Outgoing,
                    other => panic!("unknown transaction type {other}"),
                }),
        }),
        "get_budget" => Request::GetBudget,
        other => panic!("unknown method {other}"),
    }
}

fn insert_opt(map: &mut serde_json::Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), value);
    }
}

fn tx_json(tx: &Transaction) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("type".into(), json!(tx.transaction_type.as_str()));
    insert_opt(
        &mut map,
        "state",
        tx.state.map(|state| json!(state.as_str())),
    );
    insert_opt(&mut map, "invoice", tx.invoice.clone().map(Value::from));
    insert_opt(
        &mut map,
        "description",
        tx.description.clone().map(Value::from),
    );
    insert_opt(
        &mut map,
        "description_hash",
        tx.description_hash.clone().map(Value::from),
    );
    insert_opt(&mut map, "preimage", tx.preimage.clone().map(Value::from));
    map.insert("payment_hash".into(), json!(tx.payment_hash));
    map.insert("amount".into(), json!(tx.amount));
    insert_opt(&mut map, "fees_paid", tx.fees_paid.map(Value::from));
    map.insert("created_at".into(), json!(tx.created_at));
    insert_opt(&mut map, "expires_at", tx.expires_at.map(Value::from));
    insert_opt(&mut map, "settled_at", tx.settled_at.map(Value::from));
    insert_opt(
        &mut map,
        "metadata",
        tx.metadata
            .as_deref()
            .map(|metadata| serde_json::from_str(metadata).unwrap()),
    );
    Value::Object(map)
}

fn result_json(result: &NwcResult) -> Value {
    match result {
        NwcResult::PayInvoice(pay) => {
            let mut map = serde_json::Map::new();
            map.insert("method".into(), json!("pay_invoice"));
            map.insert("preimage".into(), json!(pay.preimage));
            insert_opt(&mut map, "fees_paid", pay.fees_paid.map(Value::from));
            Value::Object(map)
        }
        NwcResult::MakeInvoice(tx) => json!({"method":"make_invoice","transaction":tx_json(tx)}),
        NwcResult::LookupInvoice(tx) => {
            json!({"method":"lookup_invoice","transaction":tx_json(tx)})
        }
        NwcResult::GetBalance(balance) => json!({"method":"get_balance","balance":balance}),
        NwcResult::GetInfo(info) => {
            let mut map = serde_json::Map::new();
            map.insert("method".into(), json!("get_info"));
            insert_opt(&mut map, "alias", info.alias.clone().map(Value::from));
            insert_opt(&mut map, "color", info.color.clone().map(Value::from));
            insert_opt(&mut map, "pubkey", info.pubkey.clone().map(Value::from));
            insert_opt(&mut map, "network", info.network.clone().map(Value::from));
            insert_opt(&mut map, "block_height", info.block_height.map(Value::from));
            insert_opt(
                &mut map,
                "block_hash",
                info.block_hash.clone().map(Value::from),
            );
            map.insert("methods".into(), json!(info.methods));
            insert_opt(
                &mut map,
                "extensions",
                info.extensions.clone().map(Value::from),
            );
            insert_opt(
                &mut map,
                "notifications",
                info.notifications.clone().map(Value::from),
            );
            Value::Object(map)
        }
        NwcResult::ListTransactions(list) => json!({
            "method":"list_transactions",
            "transactions":list.transactions.iter().map(tx_json).collect::<Vec<_>>(),
            "total_count":list.total_count,
        }),
        NwcResult::GetBudget(budget) => {
            let budget_json = budget.map(|budget| {
                let mut map = serde_json::Map::new();
                map.insert("used_budget".into(), json!(budget.used_budget));
                map.insert("total_budget".into(), json!(budget.total_budget));
                insert_opt(&mut map, "renews_at", budget.renews_at.map(Value::from));
                map.insert(
                    "renewal_period".into(),
                    json!(budget.renewal_period.as_str()),
                );
                Value::Object(map)
            });
            json!({"method":"get_budget","budget":budget_json})
        }
    }
}

#[test]
fn nip47_uri_vectors() {
    for case in doc()["uri"].as_array().unwrap() {
        let parsed = NwcUri::from_str(case["input"].as_str().unwrap());
        if case["ok"].as_bool().unwrap() {
            let parsed = parsed.unwrap();
            if let Some(expect) = case.get("expect") {
                if let Some(pubkey) = expect.get("walletPubkey").and_then(Value::as_str) {
                    assert_eq!(parsed.wallet_pubkey.to_hex(), pubkey, "{}", case["name"]);
                }
                if let Some(relays) = expect.get("relays") {
                    assert_eq!(
                        parsed.relays,
                        relays
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|relay| relay.as_str().unwrap().to_owned())
                            .collect::<Vec<_>>(),
                        "{}",
                        case["name"]
                    );
                }
                if let Some(lud16) = expect.get("lud16").and_then(Value::as_str) {
                    assert_eq!(parsed.lud16.as_deref(), Some(lud16), "{}", case["name"]);
                }
            }
        } else {
            assert!(parsed.is_err(), "{}", case["name"]);
        }
    }
}

#[test]
fn nip47_info_vectors() {
    for case in doc()["info"].as_array().unwrap() {
        let parsed = nip47::Info::from_event(&event(&case["event"]));
        if case.get("error").and_then(Value::as_bool) == Some(true) {
            assert!(parsed.is_err(), "{}", case["name"]);
            continue;
        }
        let info = parsed.unwrap();
        let expect = &case["expect"];
        if let Some(methods) = expect.get("methods") {
            assert_eq!(
                info.methods,
                methods
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|method| method.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>(),
                "{}",
                case["name"]
            );
        }
        if let Some(encryptions) = expect.get("encryptions") {
            let want = if encryptions.is_null() {
                None
            } else {
                Some(
                    encryptions
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|encryption| encryption.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>(),
                )
            };
            assert_eq!(info.encryptions, want, "{}", case["name"]);
        }
        if let Some(encryption) = expect.get("encryption") {
            if encryption.is_null() {
                assert!(info.negotiate().is_err(), "{}", case["name"]);
            } else {
                assert_eq!(
                    info.negotiate().unwrap().as_str(),
                    encryption.as_str().unwrap(),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn nip47_request_vectors() {
    for case in doc()["request"].as_array().unwrap() {
        assert_eq!(
            request(&case["request"]).to_json(),
            case["json"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn nip47_response_vectors() {
    for case in doc()["response"].as_array().unwrap() {
        let method = Method::from_wire(case["method"].as_str().unwrap()).unwrap();
        let parsed = nip47::parse_response_payload(method, case["json"].as_str().unwrap());
        if case.get("nonCanonicalJson").and_then(Value::as_bool) == Some(true) {
            assert!(
                parsed.is_err(),
                "non-canonical JSON must be rejected: {}",
                case["name"]
            );
            continue;
        }
        if case.get("error").and_then(Value::as_bool) == Some(true) {
            assert!(parsed.is_err(), "{}", case["name"]);
            continue;
        }
        let outcome = parsed.unwrap();
        let expect = &case["expect"];
        match outcome {
            Ok(result) => assert_eq!(result_json(&result), *expect, "{}", case["name"]),
            Err(error) => {
                assert_eq!(
                    json!({
                        "code":error.code.as_str(),
                        "walletCode":error.wallet_code,
                        "message":error.message,
                    }),
                    *expect,
                    "{}",
                    case["name"]
                );
                if error.wallet_code == "BAD_REQUEST" {
                    assert_eq!(error.code, ErrorCode::Other, "{}", case["name"]);
                }
            }
        }
    }
}

#[test]
fn nip47_notification_vectors() {
    for case in doc()["notification"].as_array().unwrap() {
        let parsed = nip47::parse_notification_payload(case["json"].as_str().unwrap());
        if case.get("error").and_then(Value::as_bool) == Some(true) {
            assert!(parsed.is_err(), "{}", case["name"]);
            continue;
        }
        let got = parsed.unwrap();
        match (got, &case["expect"]) {
            (None, value) if value.is_null() => {}
            (Some(Notification::PaymentReceived(tx)), expect) => {
                assert_eq!(
                    json!({"type":"payment_received","transaction":tx_json(&tx)}),
                    *expect,
                );
            }
            (Some(Notification::PaymentSent(tx)), expect) => {
                assert_eq!(
                    json!({"type":"payment_sent","transaction":tx_json(&tx)}),
                    *expect,
                );
            }
            (None, expect) => panic!("{}: expected {}", case["name"], expect),
        }
    }
}

#[test]
fn nip47_envelope_vectors() {
    for case in doc()["envelope"].as_array().unwrap() {
        let request = event(&case["request"]);
        let response = event(&case["response"]);
        assert_eq!(
            response.verify().is_ok() && nip47::is_response_to(&response, &request),
            case["matches"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[cfg(any(feature = "nip44", feature = "nip04"))]
fn decrypt_and_check(case: &Value, plaintext: &str) {
    assert_eq!(
        plaintext,
        case["plaintext"].as_str().unwrap(),
        "{}",
        case["name"]
    );
    let method = Method::from_wire(case["method"].as_str().unwrap()).unwrap();
    let parsed = nip47::parse_response_payload(method, plaintext)
        .unwrap()
        .unwrap();
    assert_eq!(result_json(&parsed), case["expect"], "{}", case["name"]);
}

#[cfg(feature = "nip44")]
#[test]
fn nip47_nip44_encrypted_vectors() {
    use nk_core::nips::nip44::ConversationKey;

    let keys = &doc()["keys"];
    let secret = nk_core::SecretKey::from_bytes(
        crate::common::unhex_arr::<32>(keys["clientSecret"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let wallet = nk_core::PublicKey::from_hex(keys["walletPubkey"].as_str().unwrap()).unwrap();
    let conversation = ConversationKey::derive(&secret, &wallet).unwrap();
    for case in doc()["encrypted"].as_array().unwrap() {
        if case["scheme"].as_str().unwrap() == "nip44_v2" {
            let plaintext = conversation
                .decrypt(case["response"]["content"].as_str().unwrap())
                .unwrap();
            decrypt_and_check(case, &plaintext);
        }
    }
}

#[cfg(feature = "nip04")]
#[test]
fn nip47_nip04_encrypted_vectors() {
    use nk_core::nips::nip04::SharedSecret;

    let keys = &doc()["keys"];
    let secret = nk_core::SecretKey::from_bytes(
        crate::common::unhex_arr::<32>(keys["clientSecret"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let wallet = nk_core::PublicKey::from_hex(keys["walletPubkey"].as_str().unwrap()).unwrap();
    let shared = SharedSecret::derive(&secret, &wallet).unwrap();
    for case in doc()["encrypted"].as_array().unwrap() {
        if case["scheme"].as_str().unwrap() == "nip04" {
            let plaintext = shared
                .decrypt(case["response"]["content"].as_str().unwrap())
                .unwrap();
            decrypt_and_check(case, &plaintext);
        }
    }
}

#[test]
fn nip47_payload_limit_counts_utf16_units() {
    let pad = "\u{1f600}".repeat(524_300);
    let payload = format!(
        r#"{{"result_type":"get_balance","result":{{"balance":1}},"error":null,"pad":"{pad}"}}"#
    );
    assert!(nip47::parse_response_payload(Method::GetBalance, &payload).is_err());
    assert!(nip47::parse_notification_payload(&payload).is_err());
}

#[test]
fn nip47_kind_constants() {
    assert_eq!(Kind::new(nip47::INFO_KIND).as_u16(), 13_194);
}
