//! vectors/nip21/uri.json — `nip21.uri`.

use nk_core::nips::nip19::Entity;
use nk_core::nips::nip21::NostrUri;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::hex_str;

#[derive(Deserialize)]
struct Case {
    input: String,
    is_uri: bool,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    decoded: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip21/uri.json"
));

fn entity_json(e: &Entity) -> Value {
    match e {
        Entity::Public(p) => json!({"type": "npub", "pubkey": p.to_hex()}),
        Entity::Note(id) => json!({"type": "note", "id": id.to_hex()}),
        Entity::Secret(s) => {
            json!({"type": "nsec", "secret": s.with_secret_bytes(|b| hex_str(b))})
        }
        Entity::Profile(p) => {
            json!({"type": "nprofile", "pubkey": p.pubkey.to_hex(), "relays": p.relays})
        }
        Entity::Event(p) => {
            let mut v = json!({"type": "nevent", "id": p.id.to_hex(), "relays": p.relays});
            if let Some(a) = p.author {
                v["author"] = json!(a.to_hex());
            }
            if let Some(k) = p.kind {
                v["kind"] = json!(k.as_u16());
            }
            v
        }
        Entity::Address(p) => json!({
            "type": "naddr", "identifier": p.identifier, "pubkey": p.pubkey.to_hex(),
            "kind": p.kind.as_u16(), "relays": p.relays,
        }),
        _ => unreachable!(),
    }
}

#[test]
fn nip21_uri() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        let parsed = NostrUri::parse(&case.input);
        if !case.is_uri || case.error.is_some() {
            assert!(parsed.is_err(), "case {i}: {}", case.input);
            continue;
        }
        let uri = parsed.unwrap_or_else(|e| panic!("case {i}: {e}"));
        if let Some(value) = &case.value {
            assert_eq!(uri.as_str(), value, "case {i} value");
        }
        if let Some(want) = &case.uri {
            assert_eq!(uri.to_string(), *want, "case {i} uri");
        }
        if let Some(want) = &case.decoded {
            assert_eq!(&entity_json(uri.entity()), want, "case {i} decoded");
        }
    }
}
