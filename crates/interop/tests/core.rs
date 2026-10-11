//! Executes `vectors/core/*.json` against rust-nostr's public API.
//!
//! Capabilities with no rust-nostr counterpart (hex codec, URL normalization
//! beyond `url::Url`, filter canonicalization/fingerprint, COUNT HLL) are not
//! run here; `parity.json` records them as `rust: null`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use common::{DivergenceCheck, unhex_arr};
use nostr::prelude::{
    ClientMessage, Contact, ContactListBuilder, Coordinate, Event, EventBuilder,
    EventDeletionRequest, EventId, Filter, FinalizeUnsignedEvent, IntoEventBuilder, Keys, Kind,
    Marker, MatchEventOptions, Metadata, Nip02Tag, Nip10Tag, PublicKey, ReactionBuilder,
    ReactionTarget, RelayMessage, RelayUrl, RepostBuilder, SecretKey, Tag, Timestamp,
    UnsignedEvent,
};
use serde::Deserialize;

const KIND_CLASSIFY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/kind-classify.json"
));
const TAG_ADDRESS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/tag-address.json"
));
const EVENT_VALIDATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-validate.json"
));
const EVENT_SERIALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-serialize.json"
));
const EVENT_SIGN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-sign.json"
));
const FILTER_MATCH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/filter-match.json"
));
const FILTER_LIMIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/filter-limit.json"
));
const BUILDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/builder.json"
));
const MESSAGE_CLIENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/message-client.json"
));
const MESSAGE_RELAY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/message-relay.json"
));
const TAG_BUILD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/tag-build.json"
));
const EVENT_ORDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-order.json"
));
const URL_NORMALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/url-normalize.json"
));
const EVENT_SIGNED_MATCHES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-signed-matches.json"
));

#[derive(Debug, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the struct mirrors the vector file's shape"
)]
struct KindClassifyCase {
    kind: u16,
    regular: bool,
    replaceable: bool,
    ephemeral: bool,
    addressable: bool,
    class: String,
}

#[test]
fn kind_classify() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<KindClassifyCase>,
    }
    let vector: Vector =
        serde_json::from_str(KIND_CLASSIFY).expect("kind-classify.json must parse");
    let mut check = DivergenceCheck::new("core.kind.classify");
    for case in &vector.cases {
        let kind = Kind::from_u16(case.kind);
        let class = if kind.is_addressable() {
            "addressable"
        } else if kind.is_ephemeral() {
            "ephemeral"
        } else if kind.is_replaceable() {
            "replaceable"
        } else {
            "regular"
        };
        let agrees = kind.is_regular() == case.regular
            && kind.is_replaceable() == case.replaceable
            && kind.is_ephemeral() == case.ephemeral
            && kind.is_addressable() == case.addressable
            && class == case.class;
        let got = format!(
            "regular={} replaceable={} ephemeral={} addressable={} class={class}",
            kind.is_regular(),
            kind.is_replaceable(),
            kind.is_ephemeral(),
            kind.is_addressable(),
        );
        check.check(&case.kind.to_string(), agrees, &got);
    }
    check.finish();
}

/// Parsed coordinate in a `tag-address.json` `parse` case.
#[derive(Debug, Deserialize)]
struct ParsedAddress {
    kind: u16,
    pubkey: String,
    identifier: String,
}

#[derive(Debug, Deserialize)]
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
    struct Vector {
        cases: Vec<TagAddressCase>,
    }
    let vector: Vector = serde_json::from_str(TAG_ADDRESS).expect("tag-address.json must parse");
    let mut check = DivergenceCheck::new("core.tag.address");
    for (index, case) in vector.cases.iter().enumerate() {
        match case {
            TagAddressCase::Parse { input, parsed } => {
                let coordinate = Coordinate::parse(input).ok();
                let got;
                let agrees = match (parsed, coordinate) {
                    (Some(expected), Some(coordinate)) => {
                        got = format!(
                            "parsed kind={} pubkey={} identifier={:?}",
                            coordinate.kind.as_u16(),
                            coordinate.public_key.to_hex(),
                            coordinate.identifier
                        );
                        coordinate.kind.as_u16() == expected.kind
                            && coordinate.public_key.to_hex() == expected.pubkey
                            && coordinate.identifier == expected.identifier
                    }
                    (None, None) => {
                        got = "rejected".into();
                        true
                    }
                    (Some(_), None) => {
                        got = "rejected".into();
                        false
                    }
                    (None, Some(coordinate)) => {
                        got = format!(
                            "parsed kind={} pubkey={} identifier={:?}",
                            coordinate.kind.as_u16(),
                            coordinate.public_key.to_hex(),
                            coordinate.identifier
                        );
                        false
                    }
                };
                check.check(&format!("{index}:{input}"), agrees, &got);
            }
            TagAddressCase::Format {
                kind,
                pubkey,
                identifier,
                formatted,
            } => {
                let outcome = PublicKey::from_hex(pubkey).map(|public_key| {
                    Coordinate::new(Kind::from_u16(*kind), public_key)
                        .identifier(identifier.clone())
                        .to_string()
                });
                let agrees = outcome.as_ref().is_ok_and(|got| got == formatted);
                check.check(
                    &format!("{index}:{formatted}"),
                    agrees,
                    &outcome.unwrap_or_else(|_| "rejected".into()),
                );
            }
        }
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct EventValidateCase {
    reason: String,
    raw: String,
    parsed: Option<String>,
    error: Option<String>,
}

#[test]
fn event_validate() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<EventValidateCase>,
    }
    let vector: Vector =
        serde_json::from_str(EVENT_VALIDATE).expect("event-validate.json must parse");
    let mut check = DivergenceCheck::new("core.event.validate");
    for case in &vector.cases {
        let parsed = Event::from_json(&case.raw);
        let got = parsed.as_ref().map_or_else(
            |_| "rejected".to_owned(),
            |event| format!("accepted, re-encodes as {}", event.as_json()),
        );
        let agrees = match (&case.parsed, &case.error, parsed) {
            (Some(expected), None, Ok(event)) => event.as_json() == *expected,
            (None, Some(_), Err(_)) => true,
            _ => false,
        };
        check.check(&case.reason, agrees, &got);
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct EventSerializeCase {
    unsigned: UnsignedEvent,
    #[allow(
        dead_code,
        reason = "the preimage bytes are never exposed by rust-nostr; only compute_id is compared"
    )]
    serialized: String,
    id: String,
}

#[test]
fn event_serialize() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<EventSerializeCase>,
    }
    let vector: Vector =
        serde_json::from_str(EVENT_SERIALIZE).expect("event-serialize.json must parse");
    let mut check = DivergenceCheck::new("core.event.serialize");
    for (index, case) in vector.cases.iter().enumerate() {
        // The preimage bytes are never exposed: `compute_id` builds and
        // hashes them internally, so only the `id` half is comparable.
        let id = case.unsigned.compute_id().to_hex();
        check.check(&format!("{index}:id"), id == case.id, &format!("id {id}"));
        check.skip(&format!("{index}:preimage"));
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct EventSignCase {
    #[serde(rename = "secretKey")]
    secret_key: String,
    aux: String,
    unsigned: UnsignedEvent,
    event: Event,
}

#[test]
fn event_sign() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<EventSignCase>,
    }
    let vector: Vector = serde_json::from_str(EVENT_SIGN).expect("event-sign.json must parse");
    let mut check = DivergenceCheck::new("core.event.sign");
    let secp = secp256k1::Secp256k1::new();
    for (index, case) in vector.cases.iter().enumerate() {
        let signed = (|| -> Option<Event> {
            let keys = Keys::new(SecretKey::from_hex(&case.secret_key).ok()?);
            let aux = unhex_arr::<32>(&case.aux)?;
            let unsigned = case.unsigned.clone();
            let id = unsigned.compute_id();
            if keys.public_key() != unsigned.pubkey {
                return None;
            }
            let sig = keys.sign_schnorr_with_aux_rand(&secp, id.as_bytes(), &aux);
            unsigned.add_signature(sig).ok()
        })();
        let agrees = signed
            .as_ref()
            .is_some_and(|event| *event == case.event && event.verify().is_ok());
        let got = signed
            .as_ref()
            .map_or_else(|| "rejected".to_owned(), Event::as_json);
        check.check(&index.to_string(), agrees, &got);
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct FilterMatchCase {
    filter: serde_json::Value,
    event: serde_json::Value,
    matches: bool,
}

#[test]
fn filter_match() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<FilterMatchCase>,
    }
    let vector: Vector = serde_json::from_str(FILTER_MATCH).expect("filter-match.json must parse");
    let mut check = DivergenceCheck::new("core.filter.match");
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = (|| -> Option<bool> {
            let filter = Filter::from_json(case.filter.to_string()).ok()?;
            let event = Event::from_json(case.event.to_string()).ok()?;
            Some(filter.match_event(&event, MatchEventOptions::default()))
        })();
        let got = outcome.map_or_else(
            || "input rejected".to_owned(),
            |result| format!("matched={result}"),
        );
        check.check(&index.to_string(), outcome == Some(case.matches), &got);
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct FilterLimitCase {
    filter: serde_json::Value,
    limit: Option<usize>,
}

#[test]
fn filter_limit() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<FilterLimitCase>,
    }
    let vector: Vector = serde_json::from_str(FILTER_LIMIT).expect("filter-limit.json must parse");
    let mut check = DivergenceCheck::new("core.filter.limit");
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = Filter::from_json(case.filter.to_string())
            .ok()
            .map(|filter| filter.limit);
        let got = outcome.map_or_else(
            || "input rejected".to_owned(),
            |limit| format!("limit={limit:?}"),
        );
        check.check(
            &index.to_string(),
            outcome.is_some_and(|o| o == case.limit),
            &got,
        );
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DeletionTargetCase {
    Id(String),
    Object { id: String, kind: Option<u16> },
    Address { address: String },
}

#[derive(Debug, Deserialize)]
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
    #[serde(rename = "unsignedJson")]
    unsigned_json: Option<String>,
    error: Option<String>,
}

#[allow(
    clippy::panic_in_result_fn,
    reason = "fixture-shape violations are generator bugs, not case results"
)]
fn build_case(case: &BuilderCase, index: usize) -> Option<EventBuilder> {
    match case.op.as_str() {
        "text_note" => Some(EventBuilder::new(
            Kind::TextNote,
            case.content.clone().unwrap_or_default(),
        )),
        "new" => {
            let tags = case
                .tags
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|items| Tag::parse(items).unwrap_or_else(|_| panic!("case {index}: bad tag")));
            Some(
                EventBuilder::new(
                    Kind::from_u16(case.kind.unwrap_or_default()),
                    case.content.clone().unwrap_or_default(),
                )
                .tags(tags),
            )
        }
        "metadata" => {
            let metadata: Metadata = serde_json::from_value(case.meta.clone()?)
                .unwrap_or_else(|_| panic!("case {index}: bad metadata"));
            Some(metadata.into_event_builder())
        }
        "contacts" => Some(
            ContactListBuilder::new(case.pubkeys.clone().unwrap_or_default().iter().map(|hex| {
                Contact::new(
                    PublicKey::from_hex(hex)
                        .unwrap_or_else(|_| panic!("case {index}: pubkey must parse")),
                )
            }))
            .into_event_builder(),
        ),
        "deletion" => {
            let mut request = EventDeletionRequest::new();
            for target in case.targets.iter().flatten() {
                request = match target {
                    DeletionTargetCase::Id(id) => request.id(EventId::from_hex(id)
                        .unwrap_or_else(|_| panic!("case {index}: id must parse"))),
                    DeletionTargetCase::Object { id, kind: _kind } => request
                        .id(EventId::from_hex(id)
                            .unwrap_or_else(|_| panic!("case {index}: id must parse"))),
                    DeletionTargetCase::Address { address } => request.coordinate(
                        Coordinate::parse(address)
                            .unwrap_or_else(|_| panic!("case {index}: address must parse")),
                    ),
                };
            }
            if let Some(reason) = &case.reason {
                request = request.reason(reason.clone());
            }
            Some(request.into_event_builder())
        }
        "reaction" => {
            let target = Event::from_json(case.target.as_ref()?.to_string()).ok()?;
            let hint = case.relay.as_deref().map(|raw| RelayUrl::parse(raw).ok())?;
            Some(
                ReactionBuilder::new(
                    ReactionTarget::new(&target, hint),
                    case.content.clone().unwrap_or_else(|| "+".into()),
                )
                .into_event_builder(),
            )
        }
        "repost" | "generic_repost" => {
            let target = Event::from_json(case.target.as_ref()?.to_string()).ok()?;
            let hint = RelayUrl::parse(case.relay.as_deref()?).ok()?;
            Some(
                RepostBuilder::new(&target)
                    .relay_url(hint)
                    .into_event_builder(),
            )
        }
        _ => None,
    }
}

#[test]
fn builder() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<BuilderCase>,
    }
    let vector: Vector = serde_json::from_str(BUILDER).expect("builder.json must parse");
    let mut check = DivergenceCheck::new("core.builder");
    let pubkey =
        PublicKey::from_hex("90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23")
            .expect("builder pubkey must parse");
    let created_at = Timestamp::from_secs(1_700_000_000);
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = build_case(case, index).map(|builder| {
            builder
                .custom_created_at(created_at)
                .finalize_unsigned(pubkey)
                .as_json()
        });
        let agrees = match (&case.error, &case.unsigned_json, &outcome) {
            (None, Some(expected), Some(json)) => json == expected,
            (Some(_), _, None) => true,
            _ => false,
        };
        let got = outcome.unwrap_or_else(|| "input not expressible".to_owned());
        check.check(&index.to_string(), agrees, &got);
    }
    check.finish();
}

#[derive(Deserialize)]
struct MessageVector {
    cases: Vec<MessageCase>,
}

#[derive(Deserialize)]
struct MessageCase {
    raw: String,
    encoded: Option<String>,
    error: Option<String>,
}

fn check_message_cases(
    vector: &str,
    capability: &'static str,
    parse: fn(&str) -> Result<String, String>,
) {
    let vector: MessageVector = serde_json::from_str(vector).expect("message vector must parse");
    let mut check = DivergenceCheck::new(capability);
    for case in &vector.cases {
        let parsed = parse(&case.raw);
        let agrees = match (&parsed, &case.error) {
            (Ok(encoded), None) => encoded == case.encoded.as_deref().unwrap_or(&case.raw),
            (Err(_), Some(_)) => true,
            _ => false,
        };
        let got = parsed.unwrap_or_else(|error| format!("rejected: {error}"));
        check.check(&case.raw, agrees, &got);
    }
    check.finish();
}

#[test]
fn message_client() {
    check_message_cases(MESSAGE_CLIENT, "core.message.client", |raw| {
        ClientMessage::from_json(raw)
            .map(|message| message.as_json())
            .map_err(|error| error.to_string())
    });
}

#[test]
fn message_relay() {
    check_message_cases(MESSAGE_RELAY, "core.message.relay", |raw| {
        RelayMessage::from_json(raw)
            .map(|message| message.as_json())
            .map_err(|error| error.to_string())
    });
}

#[derive(Debug, Deserialize)]
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
    tag: Vec<String>,
}

fn build_tag(case: &TagBuildCase, _index: usize) -> Option<Tag> {
    let relay = case
        .relay
        .as_deref()
        .and_then(|raw| RelayUrl::parse(raw).ok());
    match case.op.as_str() {
        "e" => {
            let id = EventId::from_hex(case.id.as_deref()?).ok()?;
            let pubkey = case
                .pubkey
                .as_deref()
                .and_then(|hex| PublicKey::from_hex(hex).ok());
            let marker = case
                .marker
                .as_deref()
                .and_then(|raw| raw.parse::<Marker>().ok());
            Some(
                Nip10Tag::Event {
                    id,
                    relay_hint: relay,
                    marker,
                    public_key: pubkey,
                }
                .into(),
            )
        }
        "p" => {
            let pubkey = PublicKey::from_hex(case.pubkey.as_deref()?).ok()?;
            if relay.is_none() && case.petname.is_none() {
                return Some(Tag::public_key(pubkey));
            }
            Some(
                Nip02Tag::PublicKey {
                    public_key: pubkey,
                    relay_hint: relay,
                    alias: case.petname.clone(),
                }
                .into(),
            )
        }
        "a" => {
            let coordinate = Coordinate::parse(case.address.as_deref()?).ok()?;
            Some(Tag::coordinate(coordinate, relay))
        }
        "d" => Some(Tag::identifier(case.identifier.clone()?)),
        "t" => Some(Tag::hashtag(case.hashtag.clone()?)),
        "r" => Some(Tag::custom(
            "r",
            case.url.iter().cloned().chain(case.marker.iter().cloned()),
        )),
        "k" => {
            let kind = match case.kind.as_ref() {
                Some(serde_json::Value::Number(n)) => {
                    n.as_u64().and_then(|v| u16::try_from(v).ok())?
                }
                _ => return None,
            };
            Some(Tag::custom("k", [kind.to_string()]))
        }
        _ => None,
    }
}

#[test]
fn tag_build() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<TagBuildCase>,
    }
    let vector: Vector = serde_json::from_str(TAG_BUILD).expect("tag-build.json must parse");
    let mut check = DivergenceCheck::new("core.tag.build");
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = build_tag(case, index).map(|tag| tag.as_slice().to_owned());
        let got = outcome.as_ref().map_or_else(
            || "input not expressible".to_owned(),
            |tag| format!("{tag:?}"),
        );
        check.check(&index.to_string(), outcome == Some(case.tag.clone()), &got);
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum EventOrderCase {
    #[serde(rename = "sort")]
    Sort {
        events: Vec<Event>,
        order: Vec<String>,
    },
    #[serde(rename = "item")]
    Item {
        #[allow(
            dead_code,
            reason = "rust-nostr exposes no public ascending-order comparator"
        )]
        events: Vec<Event>,
        #[allow(
            dead_code,
            reason = "rust-nostr exposes no public ascending-order comparator"
        )]
        order: Vec<String>,
    },
    #[serde(rename = "winner")]
    Winner {
        #[allow(
            dead_code,
            reason = "rust-nostr exposes no public replaceable-winner rule"
        )]
        candidate: Box<Event>,
        #[allow(
            dead_code,
            reason = "rust-nostr exposes no public replaceable-winner rule"
        )]
        incumbent: Box<Event>,
        #[allow(
            dead_code,
            reason = "rust-nostr exposes no public replaceable-winner rule"
        )]
        wins: bool,
    },
}

#[test]
fn event_order() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<EventOrderCase>,
    }
    let vector: Vector = serde_json::from_str(EVENT_ORDER).expect("event-order.json must parse");
    let mut check = DivergenceCheck::new("core.event.order");
    for (index, case) in vector.cases.iter().enumerate() {
        match case {
            // `nostr::Event`'s `Ord` is newest-first (created_at desc, id asc).
            EventOrderCase::Sort { events, order } => {
                let mut sorted = events.clone();
                sorted.sort();
                let agrees = sorted
                    .iter()
                    .map(|event| event.id.to_hex())
                    .collect::<Vec<_>>()
                    == *order;
                check.check(
                    &index.to_string(),
                    agrees,
                    &format!(
                        "order={:?}",
                        sorted
                            .iter()
                            .map(|event| event.id.to_hex())
                            .collect::<Vec<_>>()
                    ),
                );
            }
            // rust-nostr exposes no public ascending-order comparator or
            // replaceable-event winner rule.
            EventOrderCase::Item { .. } | EventOrderCase::Winner { .. } => {
                check.skip(&index.to_string());
            }
        }
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct SignedMatchesCase {
    unsigned: serde_json::Value,
    event: serde_json::Value,
    matches: bool,
}

#[test]
fn event_signed_matches() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<SignedMatchesCase>,
    }
    let vector: Vector =
        serde_json::from_str(EVENT_SIGNED_MATCHES).expect("event-signed-matches.json must parse");
    let mut check = DivergenceCheck::new("core.event.signed-matches");
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = (|| -> Option<bool> {
            let unsigned = UnsignedEvent::from_json(case.unsigned.to_string()).ok()?;
            let event = Event::from_json(case.event.to_string()).ok()?;
            Some(
                event.kind == unsigned.kind
                    && event.content == unsigned.content
                    && event.created_at == unsigned.created_at
                    && event.tags == unsigned.tags
                    && event.pubkey == unsigned.pubkey,
            )
        })();
        let got = outcome.map_or_else(
            || "input rejected".to_owned(),
            |result| format!("matched={result}"),
        );
        check.check(&index.to_string(), outcome == Some(case.matches), &got);
    }
    check.finish();
}

#[derive(Debug, Deserialize)]
struct UrlNormalizeCase {
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[test]
fn url_normalize() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<UrlNormalizeCase>,
    }
    let vector: Vector =
        serde_json::from_str(URL_NORMALIZE).expect("url-normalize.json must parse");
    let mut check = DivergenceCheck::new("core.url.normalize");
    for (index, case) in vector.cases.iter().enumerate() {
        let outcome = RelayUrl::parse(&case.input)
            .ok()
            .map(|url| url.as_str().to_owned());
        let agrees = match (&case.output, &case.error, &outcome) {
            (Some(expected), _, Some(got)) => expected == got,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&index.to_string(), agrees, &got);
    }
    check.finish();
}
