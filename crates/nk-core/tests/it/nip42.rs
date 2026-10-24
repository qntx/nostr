//! vectors/nip42/codec.json — `nip42.auth-event`.

use nk_core::nips::nip42::is_auth_required;
use nk_core::{EventBuilder, PublicKey, RelayUrl, Timestamp};

use serde::Deserialize;

#[derive(Deserialize)]
struct AuthCase {
    relay: String,
    challenge: String,
    tags: Vec<Vec<String>>,
    content: String,
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct RequiredCase {
    reason: String,
    result: bool,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip42/codec.json"
));

#[test]
fn nip42_auth() {
    let doc: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<AuthCase> = serde_json::from_value(doc["auth"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        // `"rust": false` — `relay` is a raw non-URL string TS keeps
        // verbatim; `EventBuilder::auth` takes a `RelayUrl`, so the shape
        // cannot be expressed. Asserted as marked.
        if case.rust == Some(false) {
            continue;
        }
        let relay = RelayUrl::parse(&case.relay).unwrap();
        let unsigned = EventBuilder::auth(&relay, &case.challenge).build_at(
            PublicKey::from_hex(&"11".repeat(32)).unwrap(),
            Timestamp::from_secs(1),
        );
        let tags: Vec<Vec<String>> = unsigned
            .tags()
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        assert_eq!(tags, case.tags, "auth {i} tags");
        assert_eq!(
            unsigned.content(),
            case.content.as_str(),
            "auth {i} content"
        );
        assert_eq!(unsigned.kind().as_u16(), 22242, "auth {i} kind");
    }
}

#[test]
fn nip42_auth_required() {
    let doc: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<RequiredCase> = serde_json::from_value(doc["auth_required"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        assert_eq!(
            is_auth_required(&case.reason),
            case.result,
            "auth_required {i}"
        );
    }
}
