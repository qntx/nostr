//! vectors/nip19/{codec,official}.json — `nip19.codec`.

use core::str::FromStr;

use nk_core::nips::nip19::{AddressPointer, Entity, EventPointer, ProfilePointer};
use nk_core::{EventId, Kind, PublicKey, SecretKey};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    encode: Option<Value>,
    #[serde(default)]
    decoded: Option<Value>,
    #[serde(default)]
    encoded: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    rust: Option<bool>,
}

fn entity_json(e: &Entity) -> Value {
    match e {
        Entity::Public(p) => json!({"type": "npub", "pubkey": p.to_hex()}),
        Entity::Note(id) => json!({"type": "note", "id": id.to_hex()}),
        Entity::Secret(s) => {
            json!({"type": "nsec", "secret": s.with_secret_bytes(|b| crate::common::hex_str(b))})
        }
        Entity::Profile(ProfilePointer { pubkey, relays }) => {
            json!({"type": "nprofile", "pubkey": pubkey.to_hex(), "relays": relays})
        }
        Entity::Event(EventPointer {
            id,
            relays,
            author,
            kind,
        }) => {
            let mut v = json!({
                "type": "nevent",
                "id": id.to_hex(),
                "relays": relays,
            });
            if let Some(author) = author {
                v["author"] = json!(author.to_hex());
            }
            if let Some(kind) = kind {
                v["kind"] = json!(kind.as_u16());
            }
            v
        }
        Entity::Address(AddressPointer {
            identifier,
            pubkey,
            kind,
            relays,
        }) => json!({
            "type": "naddr",
            "identifier": identifier,
            "pubkey": pubkey.to_hex(),
            "kind": kind.as_u16(),
            "relays": relays,
        }),
        _ => unreachable!("Entity is non_exhaustive; handle new variants when added"),
    }
}

fn entity_from(v: &Value) -> Option<Entity> {
    Some(match v["type"].as_str()? {
        "npub" => Entity::Public(PublicKey::from_hex(v["pubkey"].as_str()?).ok()?),
        "note" => Entity::Note(EventId::from_hex(v["id"].as_str()?).ok()?),
        "nsec" => Entity::Secret(SecretKey::from_hex(v["secret"].as_str()?).ok()?),
        "nprofile" => Entity::Profile(ProfilePointer {
            pubkey: PublicKey::from_hex(v["pubkey"].as_str()?).ok()?,
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        "nevent" => Entity::Event(EventPointer {
            id: EventId::from_hex(v["id"].as_str()?).ok()?,
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            author: v["author"]
                .as_str()
                .and_then(|s| PublicKey::from_hex(s).ok()),
            kind: match v.get("kind") {
                Some(k) if !k.is_null() => Some(Kind::new(u16::try_from(k.as_u64()?).ok()?)),
                _ => None,
            },
        }),
        "naddr" => Entity::Address(AddressPointer {
            identifier: v["identifier"].as_str()?.to_owned(),
            pubkey: PublicKey::from_hex(v["pubkey"].as_str()?).ok()?,
            kind: Kind::new(u16::try_from(v["kind"].as_u64()?).ok()?),
            relays: v["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        _ => return None,
    })
}

fn run_case(i: usize, case: &Case) {
    // `"rust": false` — API-shape cases (e.g. raw `Uint8Array` inputs or
    // non-canonical forms the strict decoder rejects before entity
    // semantics) that cannot be expressed here; asserted as marked.
    if case.rust == Some(false) {
        return;
    }
    if let Some(input) = &case.input {
        // decode direction
        match (&case.decoded, &case.error) {
            (Some(want), None) => {
                let entity =
                    Entity::from_str(input).unwrap_or_else(|e| panic!("case {i} decode: {e}"));
                assert_eq!(&entity_json(&entity), want, "case {i} decoded");
            }
            (None, Some(_)) => {
                assert!(Entity::from_str(input).is_err(), "case {i} error");
            }
            _ => panic!("case {i}: decoded xor error"),
        }
        if let Some(want) = &case.encoded {
            let entity = Entity::from_str(input).unwrap();
            assert_eq!(entity.to_bech32().unwrap(), *want, "case {i} re-encode");
        }
    }
    if let Some(enc) = &case.encode {
        match (&case.encoded, &case.error) {
            (Some(want), None) => {
                let entity = entity_from(enc).unwrap();
                assert_eq!(entity.to_bech32().unwrap(), *want, "case {i} encode");
            }
            (None, Some(_)) => {
                // Entity construction or encoding must fail.
                let result = entity_from(enc).and_then(|e| e.to_bech32().ok());
                assert!(result.is_none(), "case {i} error");
            }
            _ => panic!("case {i}: encoded xor error"),
        }
        if case.error.is_none()
            && let Some(want_decoded) = &case.decoded
        {
            assert_eq!(
                &entity_json(&entity_from(enc).unwrap()),
                want_decoded,
                "case {i} decoded"
            );
        }
    }
}

#[test]
fn nip19_codec() {
    const JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip19/codec.json"
    ));
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        run_case(i, case);
    }
}

#[test]
fn nip19_official() {
    const JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip19/official.json"
    ));
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        run_case(i, case);
    }
}
