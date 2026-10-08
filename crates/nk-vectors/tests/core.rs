//! Executes `vectors/core/*.json` against the nk-core public API.

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

use nk_core::{
    ClientMessage, CountHll, DeletionTarget, ErrorKind, Event, EventAddress, EventBuilder, EventId,
    Filter, Keys, Kind, KindClass, ProfileMetadata, PublicKey, RelayMessage, RelayUrl, SecretKey,
    Tag, Timestamp, UnsignedEvent, cmp_newest_first, cmp_oldest_first, fingerprint,
};
use serde::Deserialize;

const URL_NORMALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/url-normalize.json"
));
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
const HEX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/hex.json"
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
const FILTER_CANONICALIZE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/filter-canonicalize.json"
));
const FILTER_FINGERPRINT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/filter-fingerprint.json"
));

/// One vector case: either an expected output or the expected error kind
/// (named after the TS error class).
#[derive(Debug, Deserialize)]
struct UrlNormalizeCase {
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UrlNormalizeVector {
    cases: Vec<UrlNormalizeCase>,
}

#[test]
fn url_normalize() {
    let vector: UrlNormalizeVector =
        serde_json::from_str(URL_NORMALIZE).expect("url-normalize.json must parse");
    assert!(!vector.cases.is_empty(), "url-normalize.json has no cases");
    let mut checked = 0_u32;
    for case in &vector.cases {
        match (&case.output, &case.error) {
            (Some(expected), None) => {
                assert_eq!(
                    RelayUrl::parse(&case.input)
                        .as_ref()
                        .map(RelayUrl::as_str)
                        .ok(),
                    Some(expected.as_str()),
                    "input {:?}",
                    case.input
                );
            }
            (None, Some(kind)) => {
                assert_eq!(
                    kind.as_str(),
                    "UrlError",
                    "input {:?}: unexpected error kind in vector",
                    case.input
                );
                assert_eq!(
                    RelayUrl::parse(&case.input).err().map(|error| error.kind()),
                    Some(ErrorKind::Url),
                    "input {:?}: expected ErrorKind::Url",
                    case.input
                );
            }
            (output, error) => {
                panic!(
                    "input {:?}: malformed case (output {output:?}, error {error:?})",
                    case.input
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "no url-normalize cases ran");
}

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

#[derive(Debug, Deserialize)]
struct KindClassifyVector {
    cases: Vec<KindClassifyCase>,
}

const fn class_name(class: KindClass) -> &'static str {
    match class {
        KindClass::Regular => "regular",
        KindClass::Replaceable => "replaceable",
        KindClass::Ephemeral => "ephemeral",
        KindClass::Addressable => "addressable",
    }
}

#[test]
fn kind_classify() {
    let vector: KindClassifyVector =
        serde_json::from_str(KIND_CLASSIFY).expect("kind-classify.json must parse");
    assert!(!vector.cases.is_empty(), "kind-classify.json has no cases");
    for case in &vector.cases {
        let kind = Kind::new(case.kind);
        assert_eq!(kind.is_regular(), case.regular, "kind {}", case.kind);
        assert_eq!(
            kind.is_replaceable(),
            case.replaceable,
            "kind {}",
            case.kind
        );
        assert_eq!(kind.is_ephemeral(), case.ephemeral, "kind {}", case.kind);
        assert_eq!(
            kind.is_addressable(),
            case.addressable,
            "kind {}",
            case.kind
        );
        assert_eq!(
            class_name(kind.class()),
            case.class.as_str(),
            "kind {}",
            case.kind
        );
    }
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

#[derive(Debug, Deserialize)]
struct TagAddressVector {
    cases: Vec<TagAddressCase>,
}

#[test]
fn tag_address() {
    let vector: TagAddressVector =
        serde_json::from_str(TAG_ADDRESS).expect("tag-address.json must parse");
    assert!(!vector.cases.is_empty(), "tag-address.json has no cases");
    for case in &vector.cases {
        match case {
            TagAddressCase::Parse { input, parsed } => {
                let address = input.parse::<EventAddress>().ok();
                match (parsed, address) {
                    (Some(expected), Some(address)) => {
                        assert_eq!(address.kind().as_u16(), expected.kind, "input {input:?}");
                        assert_eq!(
                            address.pubkey().to_hex(),
                            expected.pubkey.as_str(),
                            "input {input:?}"
                        );
                        assert_eq!(
                            address.identifier(),
                            expected.identifier.as_str(),
                            "input {input:?}"
                        );
                    }
                    (None, None) => {}
                    (expected, address) => {
                        panic!("input {input:?}: expected {expected:?}, got {address:?}")
                    }
                }
            }
            TagAddressCase::Format {
                kind,
                pubkey,
                identifier,
                formatted,
            } => {
                let pubkey = PublicKey::from_hex(pubkey)
                    .unwrap_or_else(|_| panic!("case pubkey {pubkey:?} must parse"));
                let address = EventAddress::new(Kind::new(*kind), pubkey, identifier.as_str());
                assert_eq!(address.to_string(), formatted.as_str());
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct EventValidateCase {
    reason: String,
    raw: String,
    parsed: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EventValidateVector {
    cases: Vec<EventValidateCase>,
}

#[test]
fn event_validate() {
    let vector: EventValidateVector =
        serde_json::from_str(EVENT_VALIDATE).expect("event-validate.json must parse");
    assert!(!vector.cases.is_empty(), "event-validate.json has no cases");
    for case in &vector.cases {
        match (&case.parsed, &case.error) {
            (Some(parsed), None) => {
                let event: Event = serde_json::from_str(&case.raw)
                    .unwrap_or_else(|e| panic!("{}: must parse: {e}", case.reason));
                let wire = serde_json::to_string(&event).expect("event serializes");
                assert_eq!(&wire, parsed, "{}: canonical output mismatch", case.reason);
            }
            (None, Some(error)) => {
                assert_eq!(
                    error.as_str(),
                    "EventValidationError",
                    "{}: unexpected error kind in vector",
                    case.reason
                );
                assert!(
                    serde_json::from_str::<Event>(&case.raw).is_err(),
                    "{}: invalid wire event must fail deserialization",
                    case.reason
                );
            }
            _ => panic!("{}: case needs exactly one of parsed/error", case.reason),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EventSerializeCase {
    unsigned: UnsignedEvent,
    serialized: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct EventSerializeVector {
    cases: Vec<EventSerializeCase>,
}

#[test]
fn event_serialize() {
    let vector: EventSerializeVector =
        serde_json::from_str(EVENT_SERIALIZE).expect("event-serialize.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "event-serialize.json has no cases"
    );
    for case in &vector.cases {
        assert_eq!(
            case.unsigned.canonical_json(),
            case.serialized.as_str(),
            "serialized mismatch for {case:?}"
        );
        assert_eq!(
            case.unsigned.id().to_hex(),
            case.id.as_str(),
            "id mismatch for {case:?}"
        );
    }
}

#[derive(Debug, Deserialize)]
struct HexCase {
    op: String,
    input: String,
    output: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HexVector {
    cases: Vec<HexCase>,
}

#[test]
fn hex() {
    let vector: HexVector = serde_json::from_str(HEX).expect("hex.json must parse");
    assert!(!vector.cases.is_empty(), "hex.json has no cases");
    for case in &vector.cases {
        let decoded = match case.op.as_str() {
            // Caller input: `PublicKey::from_hex` accepts any case.
            "caller" => PublicKey::from_hex(&case.input).map(PublicKey::to_hex).ok(),
            // Wire input: serde uses strict lowercase decode; the error kind is
            // embedded in the serde message and not inspectable.
            "wire" => serde_json::from_str::<PublicKey>(&quoted(&case.input))
                .map(PublicKey::to_hex)
                .ok(),
            op => panic!("unknown op {op:?}"),
        };
        match (&case.output, &case.error) {
            (Some(output), None) => {
                assert_eq!(
                    decoded.as_deref(),
                    Some(output.as_str()),
                    "input {:?}",
                    case.input
                );
            }
            (None, Some(kind)) => {
                assert_eq!(
                    kind.as_str(),
                    "HexError",
                    "input {:?}: unexpected error kind in vector",
                    case.input
                );
                if case.op == "caller" {
                    assert_eq!(
                        PublicKey::from_hex(&case.input)
                            .err()
                            .map(|error| error.kind()),
                        Some(ErrorKind::Hex),
                        "input {:?}: expected ErrorKind::Hex",
                        case.input
                    );
                } else {
                    assert!(
                        decoded.is_none(),
                        "input {:?}: expected a wire-decode error",
                        case.input
                    );
                }
            }
            (output, error) => {
                panic!(
                    "input {:?}: malformed case (output {output:?}, error {error:?})",
                    case.input
                )
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct EventSignCase {
    #[serde(rename = "secretKey")]
    secret_key: String,
    aux: String,
    unsigned: UnsignedEvent,
    event: Event,
}

#[derive(Debug, Deserialize)]
struct EventSignVector {
    cases: Vec<EventSignCase>,
}

#[test]
fn event_sign() {
    let vector: EventSignVector =
        serde_json::from_str(EVENT_SIGN).expect("event-sign.json must parse");
    assert!(!vector.cases.is_empty(), "event-sign.json has no cases");
    for (index, case) in vector.cases.iter().enumerate() {
        let keys = Keys::new(
            SecretKey::from_hex(&case.secret_key)
                .unwrap_or_else(|_| panic!("case {index}: secret key must be a scalar")),
        );
        // The aux value is a 32-byte hex string; `EventId` is the public
        // fixed-width hex container.
        let aux = EventId::from_hex(&case.aux)
            .unwrap_or_else(|_| panic!("case {index}: aux must be 64 hex chars"));
        let signed = keys
            .sign_event_with_aux(case.unsigned.clone(), aux.as_bytes())
            .unwrap_or_else(|_| panic!("case {index}: pubkey must match"));
        assert_eq!(signed, case.event, "case {index}: signed event mismatch");
        assert_eq!(
            serde_json::to_string(&signed).expect("signed event serializes"),
            serde_json::to_string(&case.event).expect("vector event serializes"),
            "case {index}: wire serialization mismatch"
        );
        signed
            .verify()
            .unwrap_or_else(|_| panic!("case {index}: signed event must verify"));
    }
}

#[derive(Debug, Deserialize)]
struct FilterMatchCase {
    filter: Filter,
    event: Event,
    matches: bool,
}

#[derive(Debug, Deserialize)]
struct FilterMatchVector {
    cases: Vec<FilterMatchCase>,
}

#[test]
fn filter_match() {
    let vector: FilterMatchVector =
        serde_json::from_str(FILTER_MATCH).expect("filter-match.json must parse");
    assert!(!vector.cases.is_empty(), "filter-match.json has no cases");
    for case in &vector.cases {
        assert_eq!(
            case.filter.matches(&case.event),
            case.matches,
            "match mismatch for {case:?}"
        );
    }
}

#[derive(Debug, Deserialize)]
struct FilterLimitCase {
    filter: Filter,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FilterLimitVector {
    cases: Vec<FilterLimitCase>,
}

#[test]
fn filter_limit() {
    let vector: FilterLimitVector =
        serde_json::from_str(FILTER_LIMIT).expect("filter-limit.json must parse");
    assert!(!vector.cases.is_empty(), "filter-limit.json has no cases");
    for case in &vector.cases {
        assert_eq!(
            case.filter.limit_bound(),
            case.limit,
            "limit mismatch for {case:?}"
        );
    }
}

#[derive(Debug, Deserialize)]
struct FilterCanonicalizeCase {
    input: Filter,
    #[serde(rename = "canonicalJson")]
    canonical_json: String,
}

#[derive(Debug, Deserialize)]
struct FilterCanonicalizeVector {
    cases: Vec<FilterCanonicalizeCase>,
}

#[test]
fn filter_canonicalize() {
    let vector: FilterCanonicalizeVector =
        serde_json::from_str(FILTER_CANONICALIZE).expect("filter-canonicalize.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "filter-canonicalize.json has no cases"
    );
    for case in &vector.cases {
        // The serde wire form and the in-crate canonical writer must agree.
        assert_eq!(
            serde_json::to_string(&case.input).expect("filter must serialize"),
            case.canonical_json.as_str(),
            "serde canonical mismatch for {case:?}"
        );
        assert_eq!(
            case.input.canonical_json(),
            case.canonical_json.as_str(),
            "canonical writer mismatch for {case:?}"
        );
    }
}

#[derive(Debug, Deserialize)]
struct FilterFingerprintCase {
    filters: Vec<Filter>,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct FilterFingerprintVector {
    cases: Vec<FilterFingerprintCase>,
}

#[test]
fn filter_fingerprint() {
    let vector: FilterFingerprintVector =
        serde_json::from_str(FILTER_FINGERPRINT).expect("filter-fingerprint.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "filter-fingerprint.json has no cases"
    );
    for case in &vector.cases {
        assert_eq!(
            fingerprint(&case.filters),
            case.fingerprint.as_str(),
            "fingerprint mismatch for {case:?}"
        );
    }
}

/// Quotes `input` as a JSON string literal (hex inputs contain no escapes).
fn quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    out.push_str(input);
    out.push('"');
    out
}

const BUILDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/builder.json"
));

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
    meta: Option<ProfileMetadata>,
    pubkeys: Option<Vec<String>>,
    targets: Option<Vec<DeletionTargetCase>>,
    reason: Option<String>,
    target: Option<Event>,
    relay: Option<String>,
    p_pubkey: Option<String>,
    #[serde(rename = "unsignedJson")]
    unsigned_json: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BuilderVector {
    cases: Vec<BuilderCase>,
}

#[allow(
    clippy::panic_in_result_fn,
    reason = "fixture-shape violations are generator bugs, not case results"
)]
fn build_case(case: &BuilderCase, index: usize) -> nk_core::Result<EventBuilder> {
    match case.op.as_str() {
        "text_note" => Ok(EventBuilder::text_note(
            case.content.clone().unwrap_or_default(),
        )),
        "new" => {
            let tags = case
                .tags
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|items| {
                    Tag::new(items)
                        .unwrap_or_else(|_| panic!("case {index}: tag must be non-empty"))
                });
            Ok(EventBuilder::new(
                Kind::new(case.kind.unwrap_or_default()),
                case.content.clone().unwrap_or_default(),
            )
            .tags(tags))
        }
        "metadata" => Ok(EventBuilder::metadata(
            case.meta
                .as_ref()
                .unwrap_or_else(|| panic!("case {index}: meta missing")),
        )),
        "contacts" => Ok(EventBuilder::contacts(
            case.pubkeys.clone().unwrap_or_default().iter().map(|hex| {
                PublicKey::from_hex(hex)
                    .unwrap_or_else(|_| panic!("case {index}: pubkey {hex:?} must parse"))
            }),
        )),
        "deletion" => {
            let targets = case
                .targets
                .iter()
                .flatten()
                .map(|target| match target {
                    DeletionTargetCase::Id(id) => DeletionTarget::Event {
                        id: EventId::from_hex(id)
                            .unwrap_or_else(|_| panic!("case {index}: id {id:?} must parse")),
                        kind: None,
                    },
                    DeletionTargetCase::Object { id, kind } => DeletionTarget::Event {
                        id: EventId::from_hex(id)
                            .unwrap_or_else(|_| panic!("case {index}: id {id:?} must parse")),
                        kind: kind.map(Kind::new),
                    },
                    DeletionTargetCase::Address { address } => {
                        DeletionTarget::Address(address.parse::<EventAddress>().unwrap_or_else(
                            |_| panic!("case {index}: address {address:?} must parse"),
                        ))
                    }
                })
                .collect::<Vec<_>>();
            Ok(EventBuilder::deletion(
                targets,
                case.reason.clone().unwrap_or_default(),
            ))
        }
        "reaction" => {
            let target = case
                .target
                .as_ref()
                .unwrap_or_else(|| panic!("case {index}: target missing"));
            let hint = case.relay.as_deref().map(|raw| {
                RelayUrl::parse(raw)
                    .unwrap_or_else(|_| panic!("case {index}: relay {raw:?} must parse"))
            });
            EventBuilder::reaction(
                target,
                case.content.clone().unwrap_or_else(|| "+".to_owned()),
                hint.as_ref(),
            )
        }
        "repost" => {
            let target = case
                .target
                .as_ref()
                .unwrap_or_else(|| panic!("case {index}: target missing"));
            let hint = RelayUrl::parse(
                case.relay
                    .as_deref()
                    .unwrap_or_else(|| panic!("case {index}: relay missing")),
            )
            .unwrap_or_else(|_| panic!("case {index}: relay must parse"));
            EventBuilder::repost(target, &hint)
        }
        "generic_repost" => {
            let target = case
                .target
                .as_ref()
                .unwrap_or_else(|| panic!("case {index}: target missing"));
            let hint = RelayUrl::parse(
                case.relay
                    .as_deref()
                    .unwrap_or_else(|| panic!("case {index}: relay missing")),
            )
            .unwrap_or_else(|_| panic!("case {index}: relay must parse"));
            let p_pubkey = case.p_pubkey.as_deref().map(|hex| {
                PublicKey::from_hex(hex)
                    .unwrap_or_else(|_| panic!("case {index}: p_pubkey must parse"))
            });
            EventBuilder::generic_repost(target, &hint, p_pubkey)
        }
        op => panic!("case {index}: unknown op {op:?}"),
    }
}

const MESSAGE_CLIENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/message-client.json"
));
const MESSAGE_RELAY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/message-relay.json"
));
const COUNT_HLL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/count-hll.json"
));

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

fn check_message_cases<M>(vector: &str, name: &str, parse: fn(&str) -> nk_core::Result<M>)
where
    M: MessageEncode,
{
    let vector: MessageVector = serde_json::from_str(vector).expect("message vector must parse");
    assert!(!vector.cases.is_empty(), "{name} has no cases");
    for case in &vector.cases {
        match (parse(&case.raw), &case.error) {
            (Ok(msg), None) => assert_eq!(
                &msg.encode(),
                case.encoded.as_deref().unwrap_or(&case.raw),
                "encode mismatch for {:?}",
                case.raw
            ),
            (Err(error), Some(expected)) => {
                assert_eq!(expected.as_str(), "MessageError", "for {:?}", case.raw);
                assert_eq!(error.kind(), ErrorKind::Message, "for {:?}", case.raw);
            }
            (Ok(_), Some(expected)) => panic!("{name}: expected {expected} for {:?}", case.raw),
            (Err(error), None) => panic!("{name}: unexpected {error} for {:?}", case.raw),
        }
    }
}

/// Dispatch over the two message types without exposing a trait on them.
trait MessageEncode {
    fn encode(&self) -> String;
}

impl MessageEncode for ClientMessage<'_> {
    fn encode(&self) -> String {
        ClientMessage::encode(self)
    }
}

impl MessageEncode for RelayMessage<'_> {
    fn encode(&self) -> String {
        RelayMessage::encode(self)
    }
}

#[test]
fn builder() {
    let vector: BuilderVector = serde_json::from_str(BUILDER).expect("builder.json must parse");
    assert!(!vector.cases.is_empty(), "builder.json has no cases");
    let pubkey =
        PublicKey::from_hex("90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23")
            .expect("builder pubkey must parse");
    let created_at = Timestamp::from_secs(1_700_000_000);
    for (index, case) in vector.cases.iter().enumerate() {
        match (build_case(case, index), &case.error) {
            (Ok(builder), None) => {
                let unsigned = builder.build_at(pubkey, created_at);
                let wire = serde_json::to_string(&unsigned).expect("unsigned serializes");
                assert_eq!(
                    wire.as_str(),
                    case.unsigned_json
                        .as_deref()
                        .unwrap_or_else(|| panic!("case {index}: unsignedJson missing")),
                    "case {index}: unsigned wire JSON mismatch"
                );
            }
            (Err(error), Some(class)) => {
                assert_eq!(class.as_str(), "EventValidationError", "case {index}");
                assert_eq!(error.kind(), ErrorKind::EventValidation, "case {index}");
            }
            (Ok(_), Some(class)) => {
                panic!("case {index}: expected {class}, built successfully")
            }
            (Err(error), None) => panic!("case {index}: unexpected error {error:?}"),
        }
    }
}

#[test]
fn message_client() {
    check_message_cases(MESSAGE_CLIENT, "message-client.json", |raw| {
        ClientMessage::parse(raw)
    });
}

#[test]
fn message_relay() {
    check_message_cases(MESSAGE_RELAY, "message-relay.json", |raw| {
        RelayMessage::parse(raw)
    });
}

#[derive(Deserialize)]
struct CountHllVector {
    cases: Vec<CountHllCase>,
}

#[derive(Deserialize)]
struct CountHllCase {
    inputs: Vec<String>,
    output: Option<String>,
    error: Option<String>,
}

#[test]
fn count_hll() {
    let vector: CountHllVector =
        serde_json::from_str(COUNT_HLL).expect("count-hll.json must parse");
    assert!(!vector.cases.is_empty(), "count-hll.json has no cases");
    for case in &vector.cases {
        let merged: Result<CountHll, ErrorKind> =
            case.inputs
                .iter()
                .try_fold(CountHll::zero(), |mut acc, input| {
                    let sketch: CountHll = input.parse().map_err(|e: nk_core::Error| e.kind())?;
                    acc.merge(&sketch);
                    Ok(acc)
                });
        match (merged, &case.error) {
            (Ok(merged), None) => assert_eq!(
                merged.to_string(),
                case.output.as_deref().expect("valid case has output")
            ),
            (Err(kind), Some(expected)) => {
                assert_eq!(expected.as_str(), "MessageError");
                assert_eq!(kind, ErrorKind::Message);
            }
            (Ok(_), Some(expected)) => panic!("expected {expected} for {:?}", case.inputs),
            (Err(kind), None) => panic!("unexpected {kind:?} for {:?}", case.inputs),
        }
    }
}

const TAG_BUILD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/tag-build.json"
));
const EVENT_ORDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-order.json"
));
const EVENT_SIGNED_MATCHES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/core/event-signed-matches.json"
));

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
    rust: Option<bool>,
}

/// Number of tag-build cases the typed Rust API cannot express (`rust: false`
/// in the vector: non-URL relay strings, verbatim uppercase `a` coordinates,
/// string kinds).
const TAG_BUILD_RUST_SKIPS: u32 = 5;

fn build_tag(case: &TagBuildCase, index: usize) -> Tag {
    let relay = case.relay.as_deref().map(|raw| {
        RelayUrl::parse(raw).unwrap_or_else(|_| panic!("case {index}: relay {raw:?} must parse"))
    });
    match case.op.as_str() {
        "e" => {
            let id = EventId::from_hex(
                case.id
                    .as_deref()
                    .unwrap_or_else(|| panic!("case {index}: id missing")),
            )
            .unwrap_or_else(|_| panic!("case {index}: id must parse"));
            let pubkey = case.pubkey.as_deref().map(|hex| {
                PublicKey::from_hex(hex)
                    .unwrap_or_else(|_| panic!("case {index}: pubkey must parse"))
            });
            Tag::event(id, relay.as_ref(), case.marker.as_deref(), pubkey)
        }
        "p" => {
            let pubkey = PublicKey::from_hex(
                case.pubkey
                    .as_deref()
                    .unwrap_or_else(|| panic!("case {index}: pubkey missing")),
            )
            .unwrap_or_else(|_| panic!("case {index}: pubkey must parse"));
            Tag::public_key(pubkey, relay.as_ref(), case.petname.as_deref())
        }
        "a" => {
            let address = case
                .address
                .as_deref()
                .unwrap_or_else(|| panic!("case {index}: address missing"))
                .parse::<EventAddress>()
                .unwrap_or_else(|_| panic!("case {index}: address must parse"));
            Tag::address(&address, relay.as_ref())
        }
        "d" => Tag::identifier(
            case.identifier
                .clone()
                .unwrap_or_else(|| panic!("case {index}: identifier missing")),
        ),
        "t" => Tag::hashtag(
            case.hashtag
                .clone()
                .unwrap_or_else(|| panic!("case {index}: hashtag missing")),
        ),
        "r" => Tag::reference(
            case.url
                .clone()
                .unwrap_or_else(|| panic!("case {index}: url missing")),
            case.marker.as_deref(),
        ),
        "k" => {
            let kind = match case.kind.as_ref() {
                Some(serde_json::Value::Number(n)) => n
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .unwrap_or_else(|| panic!("case {index}: kind out of range")),
                other => panic!("case {index}: kind must be a number, got {other:?}"),
            };
            Tag::kind(Kind::new(kind))
        }
        op => panic!("case {index}: unknown op {op:?}"),
    }
}

#[test]
fn tag_build() {
    #[derive(Deserialize)]
    struct TagBuildVector {
        cases: Vec<TagBuildCase>,
    }
    let vector: TagBuildVector =
        serde_json::from_str(TAG_BUILD).expect("tag-build.json must parse");
    assert!(!vector.cases.is_empty(), "tag-build.json has no cases");
    let mut skipped = 0_u32;
    for (index, case) in vector.cases.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let tag = build_tag(case, index);
        assert_eq!(
            tag.as_slice(),
            case.tag.as_slice(),
            "case {index}: tag mismatch"
        );
    }
    assert_eq!(
        skipped, TAG_BUILD_RUST_SKIPS,
        "unexpected number of rust:false cases skipped"
    );
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
        events: Vec<Event>,
        order: Vec<String>,
    },
    #[serde(rename = "winner")]
    Winner {
        candidate: Box<Event>,
        incumbent: Box<Event>,
        wins: bool,
    },
}

#[test]
fn event_order() {
    #[derive(Deserialize)]
    struct EventOrderVector {
        cases: Vec<EventOrderCase>,
    }
    let vector: EventOrderVector =
        serde_json::from_str(EVENT_ORDER).expect("event-order.json must parse");
    assert!(!vector.cases.is_empty(), "event-order.json has no cases");
    for case in &vector.cases {
        match case {
            EventOrderCase::Sort { events, order } => {
                let mut sorted = events.clone();
                sorted.sort_by(cmp_newest_first);
                let ids: Vec<String> = sorted.iter().map(|e| e.id().to_hex()).collect();
                assert_eq!(&ids, order, "cmp_newest_first order mismatch");
            }
            EventOrderCase::Item { events, order } => {
                let mut sorted = events.clone();
                sorted.sort_by(cmp_oldest_first);
                let ids: Vec<String> = sorted.iter().map(|e| e.id().to_hex()).collect();
                assert_eq!(&ids, order, "cmp_oldest_first order mismatch");
            }
            EventOrderCase::Winner {
                candidate,
                incumbent,
                wins,
            } => {
                assert_eq!(candidate.supersedes(incumbent), *wins, "winner mismatch");
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct SignedMatchesCase {
    unsigned: serde_json::Value,
    event: serde_json::Value,
    matches: bool,
    rust: Option<bool>,
}

/// signed-matches cases the typed Rust API cannot express (`rust: false` in
/// the vector: uppercase/empty pubkeys — the TS side compares them leniently).
const SIGNED_MATCHES_RUST_SKIPS: u32 = 3;

#[test]
fn event_signed_matches() {
    #[derive(Deserialize)]
    struct SignedMatchesVector {
        cases: Vec<SignedMatchesCase>,
    }
    let vector: SignedMatchesVector =
        serde_json::from_str(EVENT_SIGNED_MATCHES).expect("event-signed-matches.json must parse");
    assert!(
        !vector.cases.is_empty(),
        "event-signed-matches.json has no cases"
    );
    let mut skipped = 0_u32;
    for (index, case) in vector.cases.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let unsigned: UnsignedEvent = serde_json::from_value(case.unsigned.clone())
            .unwrap_or_else(|e| panic!("case {index}: unsigned must parse: {e}"));
        let event: Event = serde_json::from_value(case.event.clone())
            .unwrap_or_else(|e| panic!("case {index}: event must parse: {e}"));
        assert_eq!(
            event.matches_unsigned(&unsigned),
            case.matches,
            "case {index}: matches_unsigned mismatch"
        );
    }
    assert_eq!(
        skipped, SIGNED_MATCHES_RUST_SKIPS,
        "unexpected number of rust:false cases skipped"
    );
}
