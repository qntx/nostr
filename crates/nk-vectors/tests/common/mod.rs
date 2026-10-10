//! Helpers shared by the nk-vectors integration tests: the normalized entity
//! shape used by the `vectors/nip19`, `vectors/nip21`, and `nip19.codec` diff
//! cases on both sides.

#![allow(dead_code, reason = "each test binary uses a subset")]

use nk_core::{EventId, Kind, PublicKey, SecretKey};
use nk_nips::nip10::{Quote, ThreadReferences};
use nk_nips::nip19::{self, AddressPointer, Entity, EventPointer, ProfilePointer};
use serde::{Deserialize, Serialize};

/// The vector's normalized entity shape (TS `DecodedResult` / pointer input).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum EntityJson {
    Nprofile {
        pubkey: String,
        relays: Vec<String>,
    },
    Nevent {
        id: String,
        relays: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        author: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
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

/// Lowercase hex for a byte slice — nk-core exposes no public hex encoder.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String is infallible");
        out
    })
}

/// Decodes a hex string of either case; `None` on odd length or bad digits.
/// nk-core's typed `from_hex` constructors cover fixed-width keys — this is
/// for vector fields that need the raw byte length checked by the caller.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Converts a decoded `Entity` into the normalized vector shape.
pub(crate) fn entity_json(entity: &Entity) -> EntityJson {
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

/// The `nip10.thread` canonical event-pointer shape (TS `pointerJson`):
/// absent hints serialize as `null`, never omitted.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EventPointerJson {
    pub id: String,
    pub relays: Vec<String>,
    pub author: Option<String>,
    pub kind: Option<u64>,
}

/// The `nip10.thread` canonical quote shape — `{"type":"event"}` flattens the
/// pointer fields, `{"type":"address"}` carries the coordinate parts.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(crate) enum QuoteJson {
    Event(EventPointerJson),
    Address {
        identifier: String,
        pubkey: String,
        kind: u64,
        relays: Vec<String>,
    },
}

/// The `nip10.thread` canonical `ThreadReferences` output (TS `threadJson`).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadJson {
    pub root: Option<EventPointerJson>,
    pub reply: Option<EventPointerJson>,
    pub mentions: Vec<EventPointerJson>,
    pub quotes: Vec<QuoteJson>,
    pub profiles: Vec<ProfileJson>,
}

/// The canonical profile-pointer shape (`{"pubkey","relays"}`).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProfileJson {
    pub pubkey: String,
    pub relays: Vec<String>,
}

/// Converts a parsed `EventPointer` into the canonical vector shape.
pub(crate) fn event_pointer_json(p: &EventPointer) -> EventPointerJson {
    EventPointerJson {
        id: p.id.to_hex(),
        relays: p.relays.clone(),
        author: p.author.map(PublicKey::to_hex),
        kind: p.kind.map(|k| u64::from(k.as_u16())),
    }
}

/// Converts a parsed `Quote` into the canonical vector shape.
pub(crate) fn quote_json(q: &Quote) -> QuoteJson {
    match q {
        Quote::Event(p) => QuoteJson::Event(event_pointer_json(p)),
        Quote::Address(p) => QuoteJson::Address {
            identifier: p.identifier.clone(),
            pubkey: p.pubkey.to_hex(),
            kind: u64::from(p.kind.as_u16()),
            relays: p.relays.clone(),
        },
    }
}

/// Converts parsed `ThreadReferences` into the canonical vector shape.
pub(crate) fn thread_json(t: &ThreadReferences) -> ThreadJson {
    ThreadJson {
        root: t.root.as_ref().map(event_pointer_json),
        reply: t.reply.as_ref().map(event_pointer_json),
        mentions: t.mentions.iter().map(event_pointer_json).collect(),
        quotes: t.quotes.iter().map(quote_json).collect(),
        profiles: t
            .profiles
            .iter()
            .map(|p| ProfileJson {
                pubkey: p.pubkey.to_hex(),
                relays: p.relays.clone(),
            })
            .collect(),
    }
}

const fn hex_err_name() -> &'static str {
    "HexError"
}

/// Builds a typed pointer/entity from the vector shape. Hex failures surface
/// as `HexError` (nk-core's `ErrorKind::Hex`), kinds above 65535 as
/// `Nip19Error` — the classes the TS encoders throw for those inputs.
pub(crate) fn encode_entity(entity: &EntityJson) -> Result<String, &'static str> {
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
            // TS treats an empty author as absent (the TLV is omitted).
            author: author
                .as_deref()
                .filter(|a| !a.is_empty())
                .map(pubkey)
                .transpose()?,
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
