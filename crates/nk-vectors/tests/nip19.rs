//! Executes `vectors/nip19/codec.json` and `vectors/nip19/official.json`
//! against the nk-nips `nip19` API.

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

use nk_core::{EventId, Kind, PublicKey, SecretKey};
use nk_nips::ErrorKind;
use nk_nips::nip19::{self, AddressPointer, Entity, EventPointer, ProfilePointer};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip19/codec.json"
));
const OFFICIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip19/official.json"
));

/// The vector's normalized entity shape (TS `DecodedResult` / pointer input).
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum EntityJson {
    Nprofile {
        pubkey: String,
        relays: Vec<String>,
    },
    Nevent {
        id: String,
        relays: Vec<String>,
        author: Option<String>,
        kind: Option<u64>,
    },
    Naddr {
        identifier: String,
        pubkey: String,
        kind: u64,
        relays: Vec<String>,
    },
    Nsec {
        secret: String,
    },
    Npub {
        pubkey: String,
    },
    Note {
        id: String,
    },
}

/// One vector case: `{input, decoded, encoded}`, `{input, error}`,
/// `{encode, decoded, encoded}`, or `{encode, error}`.
#[derive(Debug, Deserialize)]
struct Case {
    input: Option<String>,
    encode: Option<EntityJson>,
    decoded: Option<EntityJson>,
    encoded: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

/// Lowercase hex for a byte slice — nk-core exposes no public hex encoder.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String is infallible");
        out
    })
}

/// Converts a decoded `Entity` into the normalized vector shape.
fn entity_json(entity: &Entity) -> EntityJson {
    match entity {
        Entity::Profile(p) => EntityJson::Nprofile {
            pubkey: p.pubkey.to_hex(),
            relays: p.relays.clone(),
        },
        Entity::Event(p) => EntityJson::Nevent {
            id: p.id.to_hex(),
            relays: p.relays.clone(),
            author: p.author.map(PublicKey::to_hex),
            kind: p.kind.map(|k| u64::from(k.as_u16())),
        },
        Entity::Address(p) => EntityJson::Naddr {
            identifier: p.identifier.clone(),
            pubkey: p.pubkey.to_hex(),
            kind: u64::from(p.kind.as_u16()),
            relays: p.relays.clone(),
        },
        Entity::Secret(secret) => EntityJson::Nsec {
            secret: secret.with_secret_bytes(|b| hex(b)),
        },
        Entity::Public(pubkey) => EntityJson::Npub {
            pubkey: pubkey.to_hex(),
        },
        Entity::Note(id) => EntityJson::Note { id: id.to_hex() },
        _ => panic!("unexpected entity variant"),
    }
}

const fn hex_err_name() -> &'static str {
    "HexError"
}

/// Builds a typed pointer/entity from the vector shape. Hex failures surface
/// as `HexError` (nk-core's `ErrorKind::Hex`), kinds above 65535 as
/// `Nip19Error` — the classes the TS encoders throw for those inputs.
fn encode_entity(entity: &EntityJson) -> Result<String, &'static str> {
    fn pubkey(hex: &str) -> Result<PublicKey, &'static str> {
        PublicKey::from_hex(hex).map_err(|_| hex_err_name())
    }
    fn id(hex: &str) -> Result<EventId, &'static str> {
        EventId::from_hex(hex).map_err(|_| hex_err_name())
    }
    fn kind(raw: u64) -> Result<Kind, &'static str> {
        u16::try_from(raw).map(Kind::new).map_err(|_| "Nip19Error")
    }
    match entity {
        EntityJson::Nprofile { pubkey: pk, relays } => ProfilePointer {
            pubkey: pubkey(pk)?,
            relays: relays.clone(),
        }
        .to_bech32(),
        EntityJson::Nevent {
            id: event_id,
            relays,
            author,
            kind: k,
        } => EventPointer {
            id: id(event_id)?,
            relays: relays.clone(),
            author: author.as_deref().map(pubkey).transpose()?,
            kind: k.map(kind).transpose()?,
        }
        .to_bech32(),
        EntityJson::Naddr {
            identifier,
            pubkey: pk,
            kind: k,
            relays,
        } => AddressPointer {
            identifier: identifier.clone(),
            pubkey: pubkey(pk)?,
            kind: kind(*k)?,
            relays: relays.clone(),
        }
        .to_bech32(),
        EntityJson::Nsec { secret } => Ok(nip19::encode_nsec(
            &SecretKey::from_hex(secret).map_err(|_| hex_err_name())?,
        )),
        EntityJson::Npub { pubkey: pk } => Ok(nip19::encode_npub(&pubkey(pk)?)),
        EntityJson::Note { id: event_id } => Ok(nip19::encode_note(&id(event_id)?)),
    }
    .map_err(|_| "Nip19Error")
}

fn run_decode_case(label: &str, input: &str, case: &Case) {
    match nip19::decode(input) {
        Ok(entity) => {
            let expected = case
                .decoded
                .as_ref()
                .unwrap_or_else(|| panic!("{label}: unexpected decode success"));
            assert_eq!(&entity_json(&entity), expected, "{label}: decode mismatch");
            if let Some(encoded) = &case.encoded {
                let reencoded = entity
                    .to_bech32()
                    .unwrap_or_else(|e| panic!("{label}: re-encode failed: {e}"));
                assert_eq!(reencoded, *encoded, "{label}: re-encode mismatch");
            }
        }
        Err(error) => {
            assert_eq!(
                case.error.as_deref(),
                Some("Nip19Error"),
                "{label}: unexpected decode error {error}"
            );
            assert_eq!(error.kind(), ErrorKind::Nip19, "{label}");
        }
    }
}

fn run_encode_case(label: &str, encode: &EntityJson, case: &Case) {
    match encode_entity(encode) {
        Ok(code) => {
            assert_eq!(
                case.encoded.as_deref(),
                Some(code.as_str()),
                "{label}: encode mismatch"
            );
            if let Some(expected) = &case.decoded {
                let entity = nip19::decode(&code)
                    .unwrap_or_else(|e| panic!("{label}: encoded string failed to decode: {e}"));
                assert_eq!(&entity_json(&entity), expected, "{label}");
            }
        }
        Err(name) => {
            assert_eq!(
                case.error.as_deref(),
                Some(name),
                "{label}: unexpected encode error"
            );
        }
    }
}

fn run_case(file: &str, index: usize, case: &Case) {
    let label = format!("{file} case {index}");
    if let Some(input) = &case.input {
        run_decode_case(&label, input, case);
    } else if let Some(encode) = &case.encode {
        run_encode_case(&label, encode, case);
    } else {
        panic!("{label}: malformed case, needs input or encode");
    }
}

#[test]
fn codec_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("codec.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case("codec.json", index, case);
    }
}

#[test]
fn official_vectors() {
    let vector: Vector = serde_json::from_str(OFFICIAL).expect("official.json should parse");
    for (index, case) in vector.cases.iter().enumerate() {
        run_case("official.json", index, case);
    }
}
