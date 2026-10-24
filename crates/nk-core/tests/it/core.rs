//! The `core.*` capabilities from `parity.json` driven against `nk-core`
//! with zero divergence handling: every case passes as written, and cases
//! flagged `"nonCanonicalJson": true` must be rejected by the strict
//! parser (they are inputs `JSON.parse` erases — integral floats,
//! exponents, `-0`, duplicate keys).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::struct_excessive_bools,
    clippy::match_same_arms,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::uninlined_format_args,
    clippy::useless_conversion,
    clippy::semicolon_if_nothing_returned,
    clippy::ignored_unit_patterns,
    clippy::single_char_pattern,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::doc_markdown,
    reason = "a malformed fixture file must fail the test loudly"
)]

use nk_core::{
    ClientMessage, Coordinate, DeletionTarget, Event, EventBuilder, EventId, Filter, Hll, Keys,
    Kind, Metadata, PublicKey, RelayMessage, RelayUrl, SecretKey, Tag, Timestamp, UnsignedEvent,
    fingerprint,
};
use serde::Deserialize;

use crate::common::{AuxRng, json_eq, unhex_arr};

const V: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/core");

macro_rules! vector {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/core/",
            $name
        ))
    };
}

fn strict_event(v: &serde_json::Value) -> Result<Event, nk_core::JsonError> {
    Event::from_json(&v.to_string())
}

fn strict_unsigned(v: &serde_json::Value) -> Result<UnsignedEvent, nk_core::JsonError> {
    UnsignedEvent::from_json(&v.to_string())
}

fn strict_filter(v: &serde_json::Value) -> Result<Filter, nk_core::JsonError> {
    Filter::from_json(&v.to_string())
}

#[derive(Deserialize)]
struct HexCase {
    op: String,
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[test]
fn hex() {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<HexCase>,
    }
    let v: Vec_ = serde_json::from_str(vector!("hex.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        match c.op.as_str() {
            // Caller-facing decode accepts any case.
            "caller" => {
                let got = EventId::from_hex(&c.input).ok().map(|id| id.to_hex());
                match (&c.output, &c.error) {
                    (Some(out), None) => assert_eq!(got.as_deref(), Some(out.as_str()), "case {i}"),
                    (None, Some(_)) => assert!(got.is_none(), "case {i} must reject"),
                    _ => panic!("case {i}: shape"),
                }
            }
            // Wire decode accepts lowercase only.
            "wire" => {
                let raw = format!("\"{}\"", c.input);
                let got = serde_json::from_str::<EventId>(&raw)
                    .ok()
                    .map(|id| id.to_hex());
                match (&c.output, &c.error) {
                    (Some(out), None) => assert_eq!(got.as_deref(), Some(out.as_str()), "case {i}"),
                    (None, Some(_)) => assert!(got.is_none(), "case {i} must reject"),
                    _ => panic!("case {i}: shape"),
                }
            }
            op => panic!("case {i}: unknown op {op}"),
        }
    }
}

#[derive(Deserialize)]
struct UrlCase {
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[test]
fn url_normalize() {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<UrlCase>,
    }
    let v: Vec_ = serde_json::from_str(vector!("url-normalize.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let got = RelayUrl::parse(&c.input)
            .ok()
            .map(|u| u.as_str().to_owned());
        match (&c.output, &c.error) {
            (Some(out), None) => {
                assert_eq!(got.as_deref(), Some(out.as_str()), "case {i}: {}", c.input)
            }
            (None, Some(_)) => assert!(got.is_none(), "case {i}: {} must reject", c.input),
            _ => panic!("case {i}: shape"),
        }
    }
}

#[test]
fn kind_classify() {
    #[derive(Deserialize)]
    struct Case {
        kind: u16,
        regular: bool,
        replaceable: bool,
        ephemeral: bool,
        addressable: bool,
        class: String,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("kind-classify.json")).unwrap();
    for c in &v.cases {
        let k = Kind::new(c.kind);
        let class = match k.class() {
            nk_core::KindClass::Regular => "regular",
            nk_core::KindClass::Replaceable => "replaceable",
            nk_core::KindClass::Ephemeral => "ephemeral",
            nk_core::KindClass::Addressable => "addressable",
        };
        assert!(k.is_regular() == c.regular, "kind {}", c.kind);
        assert!(k.is_replaceable() == c.replaceable, "kind {}", c.kind);
        assert!(k.is_ephemeral() == c.ephemeral, "kind {}", c.kind);
        assert!(k.is_addressable() == c.addressable, "kind {}", c.kind);
        assert_eq!(class, c.class, "kind {}", c.kind);
    }
}

#[derive(Deserialize)]
struct TagBuildCase {
    op: String,
    id: Option<String>,
    pubkey: Option<String>,
    relay: Option<String>,
    marker: Option<String>,
    petname: Option<String>,
    address: Option<String>,
    identifier: Option<String>,
    hashtag: Option<String>,
    url: Option<String>,
    kind: Option<serde_json::Value>,
    tag: Option<Vec<String>>,
}

/// Positional tag values: absent slots before a present one emit `""`.
fn positional<const N: usize>(positions: [Option<String>; N]) -> Vec<String> {
    let end = positions
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i| i + 1);
    positions
        .into_iter()
        .take(end)
        .map(Option::unwrap_or_default)
        .collect()
}

fn build_tag(c: &TagBuildCase, _i: usize) -> Option<Tag> {
    let relay = c.relay.as_deref().and_then(|r| RelayUrl::parse(r).ok());
    let bad_relay = c.relay.is_some() && relay.is_none();
    Some(match c.op.as_str() {
        "e" => {
            let id = EventId::from_hex(c.id.as_deref()?).ok()?;
            let pubkey = c
                .pubkey
                .as_deref()
                .and_then(|h| PublicKey::from_hex(h).ok());
            if bad_relay {
                // Relay hints are opaque strings on the wire; `Tag::custom`
                // expresses a hint that is not a valid relay URL, with the
                // same empty-string positional padding.
                return Some(Tag::custom(
                    "e",
                    core::iter::once(id.to_hex()).chain(positional([
                        c.relay.clone(),
                        c.marker.clone(),
                        pubkey.map(|p| p.to_hex()),
                    ])),
                ));
            }
            Tag::event(id, relay.as_ref(), c.marker.as_deref(), pubkey)
        }
        "p" => {
            let pubkey = PublicKey::from_hex(c.pubkey.as_deref()?).ok()?;
            if bad_relay {
                return Some(Tag::custom(
                    "p",
                    core::iter::once(pubkey.to_hex())
                        .chain(positional([c.relay.clone(), c.petname.clone()])),
                ));
            }
            Tag::public_key(pubkey, relay.as_ref(), c.petname.as_deref())
        }
        "a" => {
            // The address is stored verbatim — the TS builder does not
            // normalize (case 16 keeps an uppercase pubkey).
            return Some(Tag::custom(
                "a",
                positional([c.address.clone(), c.relay.clone()]),
            ));
        }
        "d" => Tag::identifier(c.identifier.clone()?),
        "t" => Tag::hashtag(c.hashtag.clone()?),
        "r" => Tag::reference(c.url.clone()?, c.marker.as_deref()),
        "k" => match c.kind.as_ref()? {
            serde_json::Value::Number(n) => Tag::kind(Kind::new(u16::try_from(n.as_u64()?).ok()?)),
            serde_json::Value::String(s) => Tag::custom("k", [s.clone()]),
            _ => return None,
        },
        _ => return None,
    })
    .into()
}

#[test]
fn tag_build() {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<TagBuildCase>,
    }
    let v: Vec_ = serde_json::from_str(vector!("tag-build.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let tag = build_tag(c, i);
        match (&c.tag, &tag) {
            (Some(expected), Some(tag)) => assert_eq!(tag.as_slice(), expected, "case {i}"),
            (Some(expected), None) => panic!(
                "case {i}: op {} not expressible, expected {expected:?}",
                c.op
            ),
            (None, Some(tag)) => panic!("case {i}: expected rejection, got {tag:?}"),
            (None, None) => {}
        }
    }
}

#[derive(Debug, Deserialize)]
struct ParsedAddress {
    kind: u16,
    pubkey: String,
    identifier: String,
}

#[derive(Deserialize)]
#[serde(tag = "op")]
enum TagAddressCase {
    #[serde(rename = "parse")]
    Parse {
        input: String,
        parsed: Option<ParsedAddress>,
    },
    #[serde(rename = "format")]
    Format {
        kind: u16,
        pubkey: String,
        identifier: String,
        formatted: String,
    },
}

#[test]
fn tag_address() {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<TagAddressCase>,
    }
    let v: Vec_ = serde_json::from_str(vector!("tag-address.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        match c {
            TagAddressCase::Parse { input, parsed } => {
                let got = input.parse::<Coordinate>().ok();
                match (parsed, got) {
                    (Some(exp), Some(a)) => {
                        assert_eq!(a.kind().as_u16(), exp.kind, "case {i}");
                        assert_eq!(a.pubkey().to_hex(), exp.pubkey, "case {i}");
                        assert_eq!(a.identifier(), exp.identifier, "case {i}");
                    }
                    (None, None) => {}
                    (exp, got) => panic!("case {i}: expected {exp:?}, got {got:?}"),
                }
            }
            TagAddressCase::Format {
                kind,
                pubkey,
                identifier,
                formatted,
            } => {
                let pk = PublicKey::from_hex(pubkey).expect("case pubkey");
                let a = Coordinate::new(Kind::new(*kind), pk, identifier);
                assert_eq!(a.to_string(), *formatted, "case {i}");
            }
        }
    }
}

#[test]
fn event_validate() {
    #[derive(Deserialize)]
    struct Case {
        reason: String,
        raw: String,
        parsed: Option<String>,
        error: Option<String>,
        #[serde(rename = "nonCanonicalJson", default)]
        non_canonical: bool,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("event-validate.json")).unwrap();
    for c in &v.cases {
        let parsed = Event::from_json(&c.raw);
        match (&c.parsed, &c.error, c.non_canonical, &parsed) {
            (Some(expected), None, false, Ok(event)) => assert_eq!(
                event.to_json(),
                *expected,
                "{}: re-encode mismatch",
                c.reason
            ),
            (_, _, true, Err(_)) => {}
            (None, Some(_), false, Err(_)) => {}
            (_, _, _, Ok(e)) => panic!("{}: must reject, got {}", c.reason, e.to_json()),
            (_, _, _, Err(e)) => panic!("{}: must accept, got {e}", c.reason),
        }
    }
}

#[test]
fn event_serialize() {
    #[derive(Deserialize)]
    struct Case {
        unsigned: serde_json::Value,
        serialized: String,
        id: String,
        #[serde(rename = "nonCanonicalJson", default)]
        non_canonical: bool,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("event-serialize.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let parsed = strict_unsigned(&c.unsigned);
        if c.non_canonical {
            assert!(parsed.is_err(), "case {i}: nonCanonicalJson must reject");
            continue;
        }
        let unsigned = parsed.unwrap_or_else(|e| panic!("case {i}: {e}"));
        assert_eq!(unsigned.id_preimage(), c.serialized, "case {i}: canonical");
        assert_eq!(unsigned.id().to_hex(), c.id, "case {i}: id");
    }
}

#[test]
fn event_order() {
    #[derive(Deserialize)]
    #[serde(tag = "op")]
    enum Case {
        #[serde(rename = "sort")]
        Sort {
            events: Vec<serde_json::Value>,
            order: Vec<String>,
        },
        #[serde(rename = "item")]
        Item {
            events: Vec<serde_json::Value>,
            order: Vec<String>,
        },
        #[serde(rename = "winner")]
        Winner {
            candidate: serde_json::Value,
            incumbent: serde_json::Value,
            wins: bool,
        },
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("event-order.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        match c {
            Case::Sort { events, order } => {
                let mut sorted: Vec<Event> =
                    events.iter().map(|e| strict_event(e).unwrap()).collect();
                sorted.sort_by(Event::cmp_newest_first);
                assert_eq!(
                    sorted.iter().map(|e| e.id().to_hex()).collect::<Vec<_>>(),
                    *order,
                    "case {i}"
                );
            }
            Case::Item { events, order } => {
                let mut sorted: Vec<Event> =
                    events.iter().map(|e| strict_event(e).unwrap()).collect();
                sorted.sort_by(Event::cmp_oldest_first);
                assert_eq!(
                    sorted.iter().map(|e| e.id().to_hex()).collect::<Vec<_>>(),
                    *order,
                    "case {i}"
                );
            }
            Case::Winner {
                candidate,
                incumbent,
                wins,
            } => {
                let cand = strict_event(candidate).unwrap();
                let inc = strict_event(incumbent).unwrap();
                assert_eq!(cand.supersedes(&inc), *wins, "case {i}");
            }
        }
    }
}

#[test]
fn event_signed_matches() {
    #[derive(Deserialize)]
    struct Case {
        unsigned: serde_json::Value,
        event: serde_json::Value,
        matches: bool,
        #[serde(default)]
        rust: Option<bool>,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("event-signed-matches.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let parsed =
            strict_unsigned(&c.unsigned).and_then(|u| strict_event(&c.event).map(|e| (u, e)));
        match parsed {
            Ok((unsigned, event)) => {
                assert_eq!(event.matches_unsigned(&unsigned), c.matches, "case {i}");
            }
            // `rust: false` marks object-level cases the strict wire decode
            // cannot express (uppercase wire pubkey, empty pubkey) — TS
            // evaluates the comparator on raw objects, bypassing validation.
            Err(e) => assert_eq!(c.rust, Some(false), "case {i}: rejected: {e}"),
        }
    }
}

#[test]
fn event_sign() {
    #[derive(Deserialize)]
    struct Case {
        #[serde(rename = "secretKey")]
        secret_key: String,
        aux: String,
        unsigned: serde_json::Value,
        event: serde_json::Value,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("event-sign.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let keys = Keys::new(SecretKey::from_hex(&c.secret_key).unwrap());
        let aux = unhex_arr::<32>(&c.aux).expect("case aux");
        let unsigned = strict_unsigned(&c.unsigned).unwrap();
        let signed = keys.sign_event(unsigned, &mut AuxRng(aux)).unwrap();
        let expected = strict_event(&c.event).unwrap();
        assert_eq!(signed, expected, "case {i}");
        signed.verify().unwrap();
    }
}

#[test]
fn filter_match() {
    #[derive(Deserialize)]
    struct Case {
        filter: serde_json::Value,
        event: serde_json::Value,
        matches: bool,
        #[serde(rename = "nonCanonicalJson", default)]
        non_canonical: bool,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("filter-match.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let filter = strict_filter(&c.filter);
        let event = strict_event(&c.event);
        if c.non_canonical {
            assert!(
                filter.is_err() || event.is_err(),
                "case {i}: nonCanonicalJson must reject"
            );
            continue;
        }
        let filter = filter.unwrap_or_else(|e| panic!("case {i}: filter rejected: {e}"));
        let event = event.unwrap_or_else(|e| panic!("case {i}: event rejected: {e}"));
        assert_eq!(filter.matches(&event), c.matches, "case {i}");
    }
}

#[test]
fn filter_limit() {
    #[derive(Deserialize)]
    struct Case {
        filter: serde_json::Value,
        limit: Option<u64>,
        error: Option<String>,
        #[serde(rename = "nonCanonicalJson", default)]
        non_canonical: bool,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("filter-limit.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let filter = strict_filter(&c.filter);
        if c.non_canonical || c.error.is_some() {
            assert!(filter.is_err(), "case {i}: must reject");
            continue;
        }
        let filter = filter.unwrap_or_else(|e| panic!("case {i}: {e}"));
        assert_eq!(
            filter.limit_bound(),
            c.limit.map(|l| l as usize),
            "case {i}"
        );
    }
}

#[test]
fn filter_canonicalize() {
    #[derive(Deserialize)]
    struct Case {
        input: serde_json::Value,
        #[serde(rename = "canonicalJson")]
        canonical_json: Option<String>,
        error: Option<String>,
        #[serde(rename = "nonCanonicalJson", default)]
        non_canonical: bool,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("filter-canonicalize.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let filter = strict_filter(&c.input);
        if c.non_canonical || c.error.is_some() {
            assert!(filter.is_err(), "case {i}: must reject");
            continue;
        }
        let filter = filter.unwrap_or_else(|e| panic!("case {i}: {e}"));
        assert_eq!(
            filter.to_json(),
            c.canonical_json.as_deref().unwrap(),
            "case {i}"
        );
    }
}

#[test]
fn filter_fingerprint() {
    #[derive(Deserialize)]
    struct Case {
        filters: Vec<serde_json::Value>,
        fingerprint: String,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("filter-fingerprint.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let filters: Vec<Filter> = c
            .filters
            .iter()
            .map(|f| strict_filter(f).unwrap_or_else(|e| panic!("case {i}: {e}")))
            .collect();
        assert_eq!(fingerprint(&filters), c.fingerprint, "case {i}");
    }
}

#[derive(Deserialize)]
struct MessageCase {
    raw: String,
    encoded: Option<String>,
    error: Option<String>,
    #[serde(rename = "nonCanonicalJson", default)]
    non_canonical: bool,
}

fn check_messages(file: &str, client: bool) {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<MessageCase>,
    }
    let v: Vec_ =
        serde_json::from_str(&std::fs::read_to_string(format!("{V}/{file}")).unwrap()).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        let parsed: Result<String, String> = if client {
            ClientMessage::from_json(&c.raw)
                .map(|m| m.to_json())
                .map_err(|e| e.to_string())
        } else {
            RelayMessage::from_json(&c.raw)
                .map(|m| m.to_json())
                .map_err(|e| e.to_string())
        };
        match (&parsed, &c.error, c.non_canonical) {
            (Ok(encoded), None, false) => assert!(
                json_eq(encoded, c.encoded.as_deref().unwrap_or(&c.raw)),
                "case {i}: re-encode mismatch for {}",
                c.raw
            ),
            (Err(_), Some(_), _) | (Err(_), None, true) => {}
            (Ok(_), Some(e), _) => panic!("case {i}: expected error {e}, got {:?}", parsed),
            (Ok(_), None, true) => panic!("case {i}: nonCanonicalJson must reject: {}", c.raw),
            (Err(e), None, false) => panic!("case {i}: rejected {}: {e}", c.raw),
        }
    }
}

#[test]
fn message_client() {
    check_messages("message-client.json", true);
}

#[test]
fn message_relay() {
    check_messages("message-relay.json", false);
}

#[test]
fn count_hll() {
    #[derive(Deserialize)]
    struct Case {
        inputs: Vec<String>,
        output: Option<String>,
        error: Option<String>,
    }
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<Case>,
    }
    let v: Vec_ = serde_json::from_str(vector!("count-hll.json")).unwrap();
    for (i, c) in v.cases.iter().enumerate() {
        if c.error.is_some() {
            assert!(
                c.inputs.iter().any(|input| input.parse::<Hll>().is_err()),
                "case {i}: some input must be a bad sketch"
            );
            continue;
        }
        let mut merged = Hll::zero();
        for input in &c.inputs {
            let sketch = input
                .parse::<Hll>()
                .unwrap_or_else(|_| panic!("case {i}: hll"));
            merged.merge(&sketch);
        }
        assert_eq!(merged.to_string(), c.output.as_deref().unwrap(), "case {i}");
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DeletionTargetCase {
    Id(String),
    Object { id: String, kind: Option<u16> },
    Address { address: String },
}

#[derive(Deserialize)]
struct BuilderCase {
    op: String,
    content: Option<String>,
    kind: Option<u16>,
    tags: Option<Vec<Vec<String>>>,
    meta: Option<serde_json::Value>,
    pubkeys: Option<Vec<String>>,
    targets: Option<Vec<DeletionTargetCase>>,
    reason: Option<String>,
    target: Option<serde_json::Value>,
    relay: Option<String>,
    p_pubkey: Option<String>,
    #[serde(rename = "unsignedJson")]
    unsigned_json: Option<String>,
    error: Option<String>,
}

fn build_case(c: &BuilderCase, i: usize) -> Result<EventBuilder, nk_core::event::Error> {
    let builder = match c.op.as_str() {
        "text_note" => EventBuilder::text_note(c.content.clone().unwrap_or_default()),
        "new" => {
            let tags =
                c.tags.clone().unwrap_or_default().into_iter().map(|items| {
                    Tag::new(items).unwrap_or_else(|e| panic!("case {i}: bad tag: {e}"))
                });
            EventBuilder::new(
                Kind::new(c.kind.unwrap_or_default()),
                c.content.clone().unwrap_or_default(),
            )
            .tags(tags)
        }
        "metadata" => {
            let meta: Metadata = serde_json::from_value(c.meta.clone().unwrap_or_default())
                .unwrap_or_else(|e| panic!("case {i}: bad metadata: {e}"));
            EventBuilder::metadata(&meta)
        }
        "contacts" => EventBuilder::contacts(
            c.pubkeys
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|h| PublicKey::from_hex(h).unwrap_or_else(|_| panic!("case {i}: pubkey"))),
        ),
        "deletion" => EventBuilder::deletion(
            c.targets.iter().flatten().map(|t| match t {
                DeletionTargetCase::Id(id) => DeletionTarget::Event {
                    id: EventId::from_hex(id).unwrap_or_else(|_| panic!("case {i}: id")),
                    kind: None,
                },
                DeletionTargetCase::Object { id, kind } => DeletionTarget::Event {
                    id: EventId::from_hex(id).unwrap_or_else(|_| panic!("case {i}: id")),
                    kind: kind.map(Kind::new),
                },
                DeletionTargetCase::Address { address } => DeletionTarget::Address(
                    address
                        .parse::<Coordinate>()
                        .unwrap_or_else(|_| panic!("case {i}: addr")),
                ),
            }),
            c.reason.clone().unwrap_or_default(),
        ),
        "reaction" => {
            let target = strict_event(c.target.as_ref().unwrap())
                .unwrap_or_else(|e| panic!("case {i}: target: {e}"));
            let hint = c.relay.as_deref().and_then(|r| RelayUrl::parse(r).ok());
            return EventBuilder::reaction(
                &target,
                c.content.clone().unwrap_or_else(|| "+".into()),
                hint.as_ref(),
            );
        }
        "repost" => {
            let target = strict_event(c.target.as_ref().unwrap())
                .unwrap_or_else(|e| panic!("case {i}: target: {e}"));
            let hint = RelayUrl::parse(c.relay.as_deref().unwrap())
                .unwrap_or_else(|_| panic!("case {i}: relay"));
            return EventBuilder::repost(&target, &hint);
        }
        "generic_repost" => {
            let target = strict_event(c.target.as_ref().unwrap())
                .unwrap_or_else(|e| panic!("case {i}: target: {e}"));
            let hint = RelayUrl::parse(c.relay.as_deref().unwrap())
                .unwrap_or_else(|_| panic!("case {i}: relay"));
            let p = c
                .p_pubkey
                .as_deref()
                .and_then(|h| PublicKey::from_hex(h).ok());
            return EventBuilder::generic_repost(&target, &hint, p);
        }
        other => panic!("case {i}: unknown op {other}"),
    };
    Ok(builder)
}

#[test]
fn builder() {
    #[derive(Deserialize)]
    struct Vec_ {
        cases: Vec<BuilderCase>,
    }
    let v: Vec_ = serde_json::from_str(vector!("builder.json")).unwrap();
    let pubkey =
        PublicKey::from_hex("90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23")
            .unwrap();
    let created_at = Timestamp::from_secs(1_700_000_000);
    for (i, c) in v.cases.iter().enumerate() {
        let outcome = build_case(c, i).map(|b| b.build_at(pubkey, created_at));
        match (&c.error, &c.unsigned_json, &outcome) {
            (None, Some(expected), Ok(unsigned)) => {
                assert_eq!(unsigned.to_json(), *expected, "case {i}: unsigned mismatch")
            }
            (Some(_), _, Err(_)) => {}
            (Some(e), _, Ok(u)) => panic!("case {i}: expected error {e}, got {}", u.to_json()),
            (None, Some(_), Err(e)) => panic!("case {i}: expected unsigned, got error {e}"),
            (None, None, _) => {}
        }
    }
}
