//! Helpers shared by the interop tests: hex codecs, the divergence registry
//! (`divergences.json`), and vector-path utilities.

#![allow(dead_code, reason = "each test binary uses a subset")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::Deserialize;

/// A registered divergence between the vector expectation and rust-nostr's
/// behavior. `side` is `"pending"` until V2 adjudicates it.
#[derive(Debug, Deserialize)]
pub(crate) struct Divergence {
    /// The `parity.json` capability id (e.g. `nip19.codec`).
    pub capability: String,
    /// The case name/index within the vector file.
    pub case: String,
    /// `"pending"` until adjudicated.
    pub side: String,
    /// One-line factual description of the difference.
    pub reason: String,
}

const DIVERGENCES_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/divergences.json"));

static DIVERGENCES: LazyLock<BTreeMap<String, BTreeMap<String, String>>> = LazyLock::new(|| {
    let entries: Vec<Divergence> =
        serde_json::from_str(DIVERGENCES_JSON).expect("divergences.json must parse");
    let mut map: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for entry in entries {
        assert!(
            entry.side == "pending",
            "divergences.json {}/{}: side must be \"pending\" in V1",
            entry.capability,
            entry.case
        );
        let cases = map.entry(entry.capability.clone()).or_default();
        assert!(
            cases.insert(entry.case.clone(), entry.reason).is_none(),
            "divergences.json: duplicate case {}/{}",
            entry.capability,
            entry.case
        );
    }
    map
});

/// Tracks per-case agreement between rust-nostr and the vectors for one
/// capability. An unregistered divergence fails; a registered case that now
/// agrees is stale and also fails; a registered case never exercised fails.
pub(crate) struct DivergenceCheck {
    capability: &'static str,
    diverged: BTreeSet<String>,
    seen: BTreeSet<String>,
    got: BTreeMap<String, String>,
}

impl DivergenceCheck {
    /// Starts tracking `capability` (the `parity.json` id).
    pub(crate) fn new(capability: &'static str) -> Self {
        LazyLock::force(&DIVERGENCES);
        Self {
            capability,
            diverged: BTreeSet::new(),
            seen: BTreeSet::new(),
            got: BTreeMap::new(),
        }
    }

    /// Records the outcome for `case`: `agrees` means rust-nostr matched the
    /// vector expectation exactly. `got` is a one-line factual description
    /// of what rust-nostr did (used to draft `divergences.json` reasons).
    pub(crate) fn check(&mut self, case: &str, agrees: bool, got: &str) {
        self.seen.insert(case.to_owned());
        if !agrees {
            self.diverged.insert(case.to_owned());
            self.got.insert(case.to_owned(), got.to_owned());
        }
    }

    /// Asserts the outcome matches the registry exactly.
    pub(crate) fn finish(&self) {
        if let Ok(path) = std::env::var("NK_INTEROP_RECORD_OUT") {
            use std::io::Write as _;
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = LOCK.lock();
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("record file opens");
            for case in &self.diverged {
                let got = self.got.get(case).map_or("", String::as_str);
                writeln!(file, "{}\t{case}\t{got}", self.capability).expect("record line writes");
            }
            return;
        }
        let registered: BTreeSet<&String> = DIVERGENCES
            .get(self.capability)
            .map_or_else(BTreeSet::new, |cases| cases.keys().collect());
        for case in &self.diverged {
            assert!(
                registered.contains(case),
                "{}: unregistered divergence in case {case:?} — rust-nostr does not match the vector; add it to crates/interop/divergences.json",
                self.capability
            );
        }
        for case in registered {
            assert!(
                self.diverged.contains(case),
                "{}: stale divergence entry {case:?} — rust-nostr now agrees with the vector; remove it from crates/interop/divergences.json",
                self.capability
            );
            assert!(
                self.seen.contains(case),
                "{}: registered case {case:?} was never exercised — remove it from crates/interop/divergences.json",
                self.capability
            );
        }
    }
}

/// Lowercase hex for a byte slice.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String is infallible");
        out
    })
}

/// Decodes a hex string of either case; `None` on odd length or bad digits.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Decodes fixed-width hex; `None` on any failure.
pub(crate) fn unhex_arr<const N: usize>(s: &str) -> Option<[u8; N]> {
    unhex(s).and_then(|v| <[u8; N]>::try_from(v.as_slice()).ok())
}

use nostr::nips::nip19::{Nip19, Nip19Coordinate, Nip19Event, Nip19Profile};
use nostr::prelude::{Coordinate, EventId, Kind, PublicKey, RelayUrl, SecretKey};
use serde::Serialize;

/// The vector's normalized NIP-19 entity shape (TS `DecodedResult` / pointer
/// input).
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

/// Renders rust-nostr relay URLs back into the vector's raw string shape.
pub(crate) fn relay_json(relays: &[RelayUrl]) -> Vec<String> {
    relays.iter().map(|url| url.as_str().to_owned()).collect()
}

/// Converts a decoded `Nip19` into the normalized vector shape; `None` for
/// variants the vector schema does not carry (`ncryptsec`).
pub(crate) fn entity_json(entity: &Nip19) -> Option<EntityJson> {
    match entity {
        Nip19::Pubkey(public_key) => Some(EntityJson::Npub {
            pubkey: public_key.to_hex(),
        }),
        Nip19::EventId(id) => Some(EntityJson::Note { id: id.to_hex() }),
        Nip19::Secret(secret) => Some(EntityJson::Nsec {
            secret: secret.to_secret_hex(),
        }),
        Nip19::Profile(profile) => Some(EntityJson::Nprofile {
            pubkey: profile.public_key.to_hex(),
            relays: relay_json(&profile.relays),
        }),
        Nip19::Event(event) => Some(EntityJson::Nevent {
            id: event.event_id.to_hex(),
            relays: relay_json(&event.relays),
            author: event.author.map(|public_key| public_key.to_hex()),
            kind: event.kind.map(|kind| u64::from(kind.as_u16())),
        }),
        Nip19::Coordinate(coordinate) => Some(EntityJson::Naddr {
            identifier: coordinate.coordinate.identifier.clone(),
            pubkey: coordinate.coordinate.public_key.to_hex(),
            kind: u64::from(coordinate.coordinate.kind.as_u16()),
            relays: relay_json(&coordinate.relays),
        }),
        Nip19::EncryptedSecret(_) => None,
    }
}

/// Builds a `Nip19` from the vector's entity shape; `Err(())` when a field
/// cannot be represented (bad hex, out-of-range kind, unparseable relay URL).
pub(crate) fn entity_from_json(entity: &EntityJson) -> Result<Nip19, ()> {
    let parse_relays = |strings: &[String]| -> Result<Vec<RelayUrl>, ()> {
        strings
            .iter()
            .map(|raw| RelayUrl::parse(raw).map_err(|_| ()))
            .collect()
    };
    let public_key = |hex: &str| PublicKey::from_hex(hex).map_err(|_| ());
    match entity {
        EntityJson::Npub { pubkey } => Ok(Nip19::Pubkey(public_key(pubkey)?)),
        EntityJson::Note { id } => Ok(Nip19::EventId(EventId::from_hex(id).map_err(|_| ())?)),
        EntityJson::Nsec { secret } => {
            Ok(Nip19::Secret(SecretKey::from_hex(secret).map_err(|_| ())?))
        }
        EntityJson::Nprofile { pubkey, relays } => Ok(Nip19::Profile(Nip19Profile::new(
            public_key(pubkey)?,
            parse_relays(relays)?,
        ))),
        EntityJson::Nevent {
            id,
            relays,
            author,
            kind,
        } => {
            let mut event = Nip19Event::new(EventId::from_hex(id).map_err(|_| ())?)
                .relays(parse_relays(relays)?);
            if let Some(author) = author {
                event = event.author(public_key(author)?);
            }
            if let Some(kind) = kind {
                let kind = u16::try_from(*kind).map_err(|_| ())?;
                event = event.kind(Kind::from_u16(kind));
            }
            Ok(Nip19::Event(event))
        }
        EntityJson::Naddr {
            identifier,
            pubkey,
            kind,
            relays,
        } => {
            let kind = u16::try_from(*kind).map_err(|_| ())?;
            let coordinate = Coordinate::new(Kind::from_u16(kind), public_key(pubkey)?)
                .identifier(identifier.clone());
            Ok(Nip19::Coordinate(Nip19Coordinate::new(
                coordinate,
                parse_relays(relays)?,
            )))
        }
    }
}
