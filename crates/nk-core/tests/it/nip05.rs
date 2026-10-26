//! vectors/nip05/codec.json — `nip05.codec`.

use nk_core::PublicKey;
use nk_core::nips::nip05::{Nip05Address, Nip05Document};

use serde_json::Value;

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip05/codec.json"
));

fn pk(s: &str) -> PublicKey {
    PublicKey::from_hex(s).unwrap()
}

#[test]
fn nip05_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["parse"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        match &case["out"] {
            Value::Null => {
                let err = input.parse::<Nip05Address>().unwrap_err();
                let trimmed = input.trim();
                assert!(
                    trimmed.is_empty() || !err.to_string().contains(trimmed),
                    "{}",
                    case["name"]
                );
            }
            out => {
                let address = input.parse::<Nip05Address>().unwrap();
                assert_eq!(
                    address.local(),
                    out["local"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    address.domain(),
                    out["domain"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn nip05_well_known() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["well_known"].as_array().unwrap() {
        let input = format!(
            "{}@{}",
            case["local"].as_str().unwrap(),
            case["domain"].as_str().unwrap()
        );
        let address = input.parse::<Nip05Address>().unwrap();
        assert_eq!(
            address.well_known_url(),
            case["out"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn nip05_document() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["document"].as_array().unwrap() {
        let json = case["json"].as_str().unwrap();
        let out = &case["out"];
        if out.get("err") == Some(&Value::Bool(true)) {
            assert!(Nip05Document::from_json(json).is_err(), "{}", case["name"]);
            continue;
        }
        let parsed = Nip05Document::from_json(json).unwrap();
        // names: map local -> hex
        let names = out["names"].as_object().unwrap();
        assert_eq!(parsed.names().len(), names.len(), "{}", case["name"]);
        for (local, hex) in names {
            assert_eq!(
                parsed.names().get(local.as_str()).unwrap(),
                &pk(hex.as_str().unwrap()),
                "{}",
                case["name"]
            );
        }
        // relays: optional map hex -> urls
        match out.get("relays") {
            None | Some(Value::Null) => assert!(parsed.relays().is_none(), "{}", case["name"]),
            Some(relays) => {
                let relays = relays.as_object().unwrap();
                let parsed_relays = parsed.relays().unwrap();
                assert_eq!(parsed_relays.len(), relays.len(), "{}", case["name"]);
                for (hex, urls) in relays {
                    let want: Vec<String> = urls
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|u| u.as_str().unwrap().to_owned())
                        .collect();
                    assert_eq!(
                        parsed_relays.get(&pk(hex)).unwrap(),
                        &want,
                        "{}",
                        case["name"]
                    );
                }
            }
        }
        // nip46: optional {relays?, nostrconnectUrl?}
        match out.get("nip46") {
            None | Some(Value::Null) => assert!(parsed.nip46().is_none(), "{}", case["name"]),
            Some(nip46) => {
                let found = parsed.nip46().unwrap();
                let want_relays: Option<Vec<String>> = nip46
                    .get("relays")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|u| u.as_str().unwrap().to_owned()).collect());
                assert_eq!(found.relays, want_relays, "{}", case["name"]);
                let want_url = nip46.get("nostrconnectUrl").and_then(Value::as_str);
                assert_eq!(
                    found.nostrconnect_url.as_deref(),
                    want_url,
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn nip05_lookup() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["lookup"].as_array().unwrap() {
        let parsed = Nip05Document::from_json(case["json"].as_str().unwrap()).unwrap();
        let address = case["identifier"]
            .as_str()
            .unwrap()
            .parse::<Nip05Address>()
            .unwrap();
        match &case["out"] {
            Value::Null => assert!(parsed.profile(&address).is_none(), "{}", case["name"]),
            out => {
                let profile = parsed.profile(&address).unwrap();
                assert_eq!(
                    profile.pubkey,
                    pk(out["pubkey"].as_str().unwrap()),
                    "{}",
                    case["name"]
                );
                let want: Vec<String> = out
                    .get("relays")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|u| u.as_str().unwrap().to_owned()).collect())
                    .unwrap_or_default();
                assert_eq!(profile.relays, want, "{}", case["name"]);
            }
        }
    }
}
