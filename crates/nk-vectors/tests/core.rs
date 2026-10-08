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
    ErrorKind, Event, EventAddress, EventId, Keys, Kind, KindClass, PublicKey, RelayUrl, SecretKey,
    UnsignedEvent,
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
    error: String,
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
        assert_eq!(
            case.error.as_str(),
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

/// Quotes `input` as a JSON string literal (hex inputs contain no escapes).
fn quoted(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    out.push_str(input);
    out.push('"');
    out
}
