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

use nostr::nips::nip21::Nip21;
use nostr::parser::{NostrParser, Token};
use serde::Deserialize;

/// A registered divergence between the vector expectation and rust-nostr's
/// behavior. `side` records which implementation diverges from spec text or
/// where the difference is inherent:
/// - `rust-nostr`: rust-nostr deviates from the NIP or a referenced RFC; the
///   vector is correct.
/// - `platform`: inherent JSON/number-model difference (`JSON.parse` vs
///   `serde_json`); both are acceptable.
/// - `unspecified`: the NIP does not define the behavior; both are
///   acceptable choices.
#[derive(Debug, Deserialize)]
pub(crate) struct Divergence {
    /// The `parity.json` capability id (e.g. `nip19.codec`).
    pub capability: String,
    /// The case name/index within the vector file.
    pub case: String,
    /// One of `rust-nostr`, `platform`, `unspecified`.
    pub side: String,
    /// One-line rationale naming the relevant spec clause.
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
            matches!(
                entry.side.as_str(),
                "rust-nostr" | "platform" | "unspecified"
            ),
            "divergences.json {}/{}: side {:?} must be rust-nostr, platform or unspecified",
            entry.capability,
            entry.case,
            entry.side
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
    skipped: BTreeSet<String>,
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
            skipped: BTreeSet::new(),
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

    /// Marks `case` as not exercised: rust-nostr exposes no public API for
    /// it, so there is no behavior to compare and it is neither an agreement
    /// nor a divergence.
    pub(crate) fn skip(&mut self, case: &str) {
        self.skipped.insert(case.to_owned());
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
            for case in &self.seen {
                writeln!(file, "{}\t__seen__\t{case}", self.capability)
                    .expect("record line writes");
            }
            for case in &self.skipped {
                writeln!(file, "{}\t__skipped__\t{case}", self.capability)
                    .expect("record line writes");
            }
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
use nostr::prelude::{Coordinate, EventId, Kind, PublicKey, RelayUrl, SecretKey, UnsignedEvent};
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

/// Maps a decoded `Nip21` entity to the vector's `pointer` shape.
fn nip21_pointer(entity: &Nip21) -> serde_json::Value {
    match entity {
        Nip21::Pubkey(public_key) => serde_json::json!({
            "type": "profile",
            "pubkey": public_key.to_hex(),
            "relays": [],
        }),
        Nip21::Profile(profile) => serde_json::json!({
            "type": "profile",
            "pubkey": profile.public_key.to_hex(),
            "relays": relay_json(&profile.relays),
        }),
        Nip21::EventId(id) => serde_json::json!({
            "type": "event",
            "id": id.to_hex(),
            "relays": [],
            "author": null,
            "kind": null,
        }),
        Nip21::Event(event) => serde_json::json!({
            "type": "event",
            "id": event.event_id.to_hex(),
            "relays": relay_json(&event.relays),
            "author": event.author.map(|public_key| public_key.to_hex()),
            "kind": event.kind.map(|kind| u64::from(kind.as_u16())),
        }),
        Nip21::Coordinate(coordinate) => serde_json::json!({
            "type": "address",
            "identifier": coordinate.coordinate.identifier,
            "pubkey": coordinate.coordinate.public_key.to_hex(),
            "kind": u64::from(coordinate.coordinate.kind.as_u16()),
            "relays": relay_json(&coordinate.relays),
        }),
    }
}

/// Parses a JSON document; `None` when the input is not JSON.
pub(crate) fn json_value(raw: &str) -> Option<serde_json::Value> {
    serde_json::from_str(raw).ok()
}

/// JSON object key order is not semantic: two encoded documents are equal
/// when they parse to the same `serde_json::Value`.
pub(crate) fn json_eq(a: &str, b: &str) -> bool {
    json_value(a) == json_value(b)
}

/// Order-insensitive tag comparison for builder outputs where tag order
/// carries no meaning: the multisets of tag arrays must be identical.
pub(crate) fn same_tag_multiset(expected: &[Vec<String>], got: &[Vec<String>]) -> bool {
    fn count<'a>(
        tags: impl IntoIterator<Item = &'a Vec<String>>,
    ) -> BTreeMap<&'a Vec<String>, usize> {
        tags.into_iter().fold(BTreeMap::new(), |mut acc, tag| {
            *acc.entry(tag).or_default() += 1;
            acc
        })
    }
    count(expected) == count(got)
}

/// Compares an unsigned-event JSON document against a built
/// `nostr::UnsignedEvent`: `pubkey`/`created_at`/`kind`/`content` must match
/// exactly and `tags` must match as an order-insensitive multiset (builder
/// tag order carries no meaning).
pub(crate) fn unsigned_event_eq(expected: &serde_json::Value, got: &UnsignedEvent) -> bool {
    let tags: Vec<Vec<String>> = got.tags.iter().map(|tag| tag.as_slice().to_vec()).collect();
    let expected_tags: Vec<Vec<String>> = expected
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| {
                    tag.as_array().map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_owned))
                            .collect()
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    expected.get("pubkey").and_then(serde_json::Value::as_str) == Some(got.pubkey.to_hex().as_str())
        && expected
            .get("created_at")
            .and_then(serde_json::Value::as_u64)
            == Some(got.created_at.as_secs())
        && expected.get("kind").and_then(serde_json::Value::as_u64)
            == Some(u64::from(got.kind.as_u16()))
        && expected.get("content").and_then(serde_json::Value::as_str) == Some(got.content.as_str())
        && same_tag_multiset(&expected_tags, &tags)
}

/// Runs `nostr::parser::NostrParser` over `text` and renders the token stream
/// in the shared block vocabulary `text`/`reference`/`url`/`hashtag`:
/// consecutive `Text`/`Whitespace`/`LineBreak` tokens merge into one `text`
/// block; `Nostr`/`Url`/`Hashtag` map to `reference`/`url`/`hashtag`.
/// `NostrParser` only produces references for `nostr:`-prefixed entities, so
/// its `reference` blocks always carry `bare: false`.
fn flush_text(acc: &mut String, out: &mut Vec<serde_json::Value>) {
    if !acc.is_empty() {
        out.push(serde_json::json!({"type": "text", "text": acc.as_str()}));
        acc.clear();
    }
}

pub(crate) fn content_blocks(text: &str) -> serde_json::Value {
    let mut blocks: Vec<serde_json::Value> = Vec::new();
    let mut text_acc = String::new();
    let flush = flush_text;
    for token in NostrParser::new().parse(text) {
        match token {
            Token::Text(piece) => text_acc.push_str(piece),
            Token::Whitespace => text_acc.push(' '),
            Token::LineBreak => text_acc.push('\n'),
            Token::Url(url) => {
                flush(&mut text_acc, &mut blocks);
                blocks.push(serde_json::json!({"type": "url", "url": url.as_str()}));
            }
            Token::Hashtag(tag) => {
                flush(&mut text_acc, &mut blocks);
                blocks.push(serde_json::json!({"type": "hashtag", "value": tag}));
            }
            Token::Nostr(entity) => {
                flush(&mut text_acc, &mut blocks);
                blocks.push(serde_json::json!({
                    "type": "reference",
                    "bare": false,
                    "pointer": nip21_pointer(&entity),
                }));
            }
        }
    }
    flush(&mut text_acc, &mut blocks);
    serde_json::Value::Array(blocks)
}

/// Projects a TS token list onto the shared vocabulary that rust-nostr's
/// `NostrParser` can express, so `content_blocks` output is comparable.
/// Blocks tile `content` contiguously, so each block's source text is the
/// next `block`-sized slice of the input:
/// - `text`/`url`/`hashtag` keep their payload;
/// - `image`/`video`/`audio`/`relay` become `url` blocks on the same source;
/// - `reference` stays a reference only for `nostr:`-prefixed entities
///   (`bare: false`); bare bech32 references become `text` carrying the raw
///   source span;
/// - `invoice`/`emoji` become `text` carrying the raw source span;
/// - adjacent `text` blocks merge.
///
/// A block whose source span cannot be derived is left untouched, which
/// surfaces as a normal divergence rather than a panic.
/// Splits off the next `len` bytes of `rest` (clamped to the next char
/// boundary so a mismeasured span degrades to a divergence, not a panic)
/// and returns them.
fn take<'a>(rest: &mut &'a str, len: usize) -> &'a str {
    let mut n = len.min(rest.len());
    while n < rest.len() && !rest.is_char_boundary(n) {
        n += 1;
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    head
}

/// `true` for the NIP-19 data characters the scanner accepts after the HRP:
/// `[02-9ac-hj-np-z]` in either ASCII case (the bech32 charset minus
/// `1`, `b`, `i`, `o`).
fn is_nip19_data(c: char) -> bool {
    let c = c.to_ascii_lowercase();
    c.is_ascii_digit() && c != '1'
        || c == 'a'
        || ('c'..='h').contains(&c)
        || ('j'..='n').contains(&c)
        || ('p'..='z').contains(&c)
}

/// Byte length of the `nostr:`-prefixed or bare bech32 token at the head of
/// `rest` — the reference block's true source span, which can differ from
/// the re-encoded entity's length when the source carried non-canonical TLVs.
/// The token shape is `<hrp>1<data>` with the same HRP set and data charset
/// the TS scanner accepts; a non-matching head yields 0.
fn bech32_span(rest: &str, bare: bool) -> usize {
    let prefix_len = if bare {
        0
    } else {
        rest.get(.."nostr:".len())
            .filter(|head| head.eq_ignore_ascii_case("nostr:"))
            .map_or(0, str::len)
    };
    let after = rest.get(prefix_len..).unwrap_or_default();
    // `nsec` is only reachable behind a `nostr:` prefix; bare scanning
    // accepts the public entity HRPs only.
    let hrps: &[&str] = if bare {
        &["nprofile", "nevent", "naddr", "npub", "note"]
    } else {
        &["nprofile", "nevent", "naddr", "npub", "note", "nsec"]
    };
    let Some(body) = hrps.iter().find_map(|hrp| {
        after
            .get(..hrp.len())
            .filter(|head| head.eq_ignore_ascii_case(hrp))
            .and_then(|_| after.get(hrp.len()..))
            .filter(|tail| tail.starts_with('1'))
    }) else {
        return 0;
    };
    let run_len = body
        .get(1..)
        .unwrap_or_default()
        .chars()
        .take_while(|c| is_nip19_data(*c))
        .map(char::len_utf8)
        .sum::<usize>();
    prefix_len + after.len() - body.len() + 1 + run_len
}

pub(crate) fn project_blocks(content: &str, out: &serde_json::Value) -> serde_json::Value {
    let Some(blocks) = out.as_array() else {
        return out.clone();
    };
    let mut projected: Vec<serde_json::Value> = Vec::new();
    let mut text_acc = String::new();
    let mut rest = content;
    for block in blocks {
        let Some(kind) = block.get("type").and_then(serde_json::Value::as_str) else {
            projected.push(block.clone());
            continue;
        };
        match kind {
            "text" => {
                let text = block
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                text_acc.push_str(take(&mut rest, text.len()));
            }
            "url" | "image" | "video" | "audio" | "relay" => {
                flush_text(&mut text_acc, &mut projected);
                let url = block
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let _ = take(&mut rest, url.len());
                projected.push(serde_json::json!({"type": "url", "url": url}));
            }
            "hashtag" => {
                flush_text(&mut text_acc, &mut projected);
                if let Some(value) = block.get("value").and_then(serde_json::Value::as_str) {
                    let _ = take(&mut rest, value.len() + 1);
                }
                projected.push(block.clone());
            }
            "reference" => {
                let bare = block
                    .get("bare")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let span = bech32_span(rest, bare);
                if span == 0 {
                    projected.push(block.clone());
                    continue;
                }
                if bare {
                    text_acc.push_str(take(&mut rest, span));
                } else {
                    flush_text(&mut text_acc, &mut projected);
                    let _ = take(&mut rest, span);
                    projected.push(block.clone());
                }
            }
            "invoice" => {
                let bolt11 = block
                    .get("bolt11")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let prefix_len = rest
                    .get(.."lightning:".len())
                    .filter(|head| head.eq_ignore_ascii_case("lightning:"))
                    .map_or(0, str::len);
                text_acc.push_str(take(&mut rest, prefix_len + bolt11.len()));
            }
            "emoji" => {
                let shortcode = block
                    .get("shortcode")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                text_acc.push_str(take(&mut rest, shortcode.len() + 2));
            }
            _ => projected.push(block.clone()),
        }
    }
    flush_text(&mut text_acc, &mut projected);
    serde_json::Value::Array(projected)
}
