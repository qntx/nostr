//! vectors/nip98/codec.json — `nip98.http-auth`.

use nk_core::nips::nip98;
use nk_core::{Event, EventBuilder, Keys, SecretKey, Timestamp};

use serde::Deserialize;
use serde_json::Value;

use crate::common::{AuxRng, unhex_arr};

#[derive(Deserialize)]
struct Doc {
    secret_key: String,
    aux: String,
    auth: Vec<AuthCase>,
    unpack: Vec<UnpackCase>,
    validate: Vec<ValidateCase>,
}

#[derive(Deserialize)]
struct AuthCase {
    url: String,
    method: String,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_json: Option<Value>,
    content: String,
    created_at: u64,
    event: Value,
    token: String,
    header: String,
    #[serde(default)]
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct UnpackCase {
    token: String,
    #[serde(default)]
    event: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ValidateCase {
    event: Value,
    url: String,
    method: String,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_json: Option<Value>,
    now: u64,
    max_skew_secs: u64,
    result: bool,
    #[serde(default)]
    rust: Option<bool>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip98/codec.json"
));

#[test]
fn nip98_auth() {
    let doc: Doc = serde_json::from_str(JSON).unwrap();
    let keys = Keys::new(SecretKey::from_bytes(unhex_arr(&doc.secret_key).unwrap()).unwrap());
    let aux = unhex_arr(&doc.aux).unwrap();
    for (i, case) in doc.auth.iter().enumerate() {
        // `payload_json` is the TS object-payload form (`JSON.stringify`);
        // the byte-level API cannot express it — asserted as `rust: false`.
        if case.payload_json.is_some() {
            assert_eq!(case.rust, Some(false), "auth {i} rust marker");
            continue;
        }
        let payload = case
            .payload_hex
            .as_deref()
            .map(|h| crate::common::unhex(h).unwrap());
        let unsigned =
            EventBuilder::http_auth(&case.url, &case.method, payload.as_deref(), &case.content)
                .build_at(keys.public_key(), Timestamp::from_secs(case.created_at));
        let event = keys.sign_event(unsigned, &mut AuxRng(aux)).unwrap();
        assert_eq!(
            &serde_json::to_value(&event).unwrap(),
            &case.event,
            "auth {i} event"
        );
        assert_eq!(nip98::token(&event), case.token, "auth {i} token");
        assert_eq!(
            nip98::authorization_header(&event),
            case.header,
            "auth {i} header"
        );
    }
}

#[test]
fn nip98_unpack() {
    let doc: Doc = serde_json::from_str(JSON).unwrap();
    for (i, case) in doc.unpack.iter().enumerate() {
        match (&case.event, &case.error) {
            (Some(want), None) => {
                let event =
                    nip98::unpack_token(&case.token).unwrap_or_else(|e| panic!("unpack {i}: {e}"));
                assert_eq!(serde_json::to_value(&event).unwrap(), *want, "unpack {i}");
            }
            (None, Some(want)) => {
                let err = nip98::unpack_token(&case.token).unwrap_err().to_string();
                assert_eq!(&err, want, "unpack {i} error");
            }
            _ => panic!("unpack {i}: event xor error"),
        }
    }
}

#[test]
fn nip98_validate() {
    let doc: Doc = serde_json::from_str(JSON).unwrap();
    for (i, case) in doc.validate.iter().enumerate() {
        let event: Event = serde_json::from_value(case.event.clone()).unwrap();
        if case.payload_json.is_some() {
            assert_eq!(case.rust, Some(false), "validate {i} rust marker");
            continue;
        }
        let payload = case
            .payload_hex
            .as_deref()
            .map(|h| crate::common::unhex(h).unwrap());
        let got = nip98::validate(
            &event,
            &case.url,
            &case.method,
            payload.as_deref(),
            Timestamp::from_secs(case.now),
            case.max_skew_secs,
        )
        .is_ok();
        assert_eq!(got, case.result, "validate {i}");
    }
}
