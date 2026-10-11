//! Executes `vectors/nip98/codec.json` against rust-nostr's public API.

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

use base64::Engine;
use base64::engine::general_purpose;
use common::DivergenceCheck;
use nostr::nips::nip98::{self, HttpData, HttpMethod, Sha256Hash};
use nostr::prelude::{
    Event, FinalizeUnsignedEvent, IntoEventBuilder, Keys, SecretKey, Timestamp, UnsignedEvent,
};
use serde::Deserialize;
use sha2::Digest;
use std::str::FromStr;
use url::Url;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip98/codec.json"
));

#[derive(Debug, Deserialize)]
struct AuthCase {
    url: String,
    method: String,
    payload_hex: Option<String>,
    #[allow(dead_code, reason = "content is hashed into payload, not compared")]
    content: String,
    created_at: u64,
    event: serde_json::Value,
    token: String,
    header: String,
    rust: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(
    dead_code,
    reason = "rust-nostr has no public token-unpack entry point; the cases are skipped"
)]
struct UnpackCase {
    token: String,
    event: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidateCase {
    event: serde_json::Value,
    url: String,
    method: String,
    payload_hex: Option<String>,
    now: u64,
    #[allow(dead_code, reason = "rust-nostr hardcodes the skew window")]
    max_skew_secs: u64,
    result: bool,
    rust: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    secret_key: String,
    aux: String,
    auth: Vec<AuthCase>,
    unpack: Vec<UnpackCase>,
    validate: Vec<ValidateCase>,
}

fn sign_deterministic(keys: &Keys, unsigned: UnsignedEvent, aux: &[u8; 32]) -> Option<Event> {
    let id = unsigned.compute_id();
    let sig = keys.sign_schnorr_with_aux_rand(&secp256k1::Secp256k1::new(), id.as_bytes(), aux);
    unsigned.add_signature(sig).ok()
}

fn http_data(case_url: &str, case_method: &str, payload_hex: Option<&str>) -> Option<HttpData> {
    let url = Url::parse(case_url).ok()?;
    let method = HttpMethod::from_str(case_method).ok()?;
    let mut data = HttpData::new(url, method);
    if let Some(hex) = payload_hex {
        // `payload_hex` is the raw request body; the `payload` tag carries
        // its SHA-256.
        let body = common::unhex(hex)?;
        let digest = sha2::Sha256::digest(&body);
        data = data.payload(Sha256Hash::from_byte_array(digest.into()));
    }
    Some(data)
}

fn auth_event_token_header(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let keys = Keys::new(SecretKey::from_hex(&vector.secret_key).expect("vector secret key"));
    let aux = common::unhex_arr::<32>(&vector.aux).expect("vector aux hex");
    for (i, case) in vector.auth.iter().enumerate() {
        if case.rust == Some(false) {
            continue;
        }
        let outcome: Option<(Event, String, String)> = (|| {
            let data = http_data(&case.url, &case.method, case.payload_hex.as_deref())?;
            let mut builder = data.into_event_builder();
            builder.content.clone_from(&case.content);
            let unsigned = builder
                .custom_created_at(Timestamp::from_secs(case.created_at))
                .finalize_unsigned(keys.public_key());
            let event = sign_deterministic(&keys, unsigned, &aux)?;
            let token = general_purpose::STANDARD.encode(event.as_json());
            let header = format!("Nostr {token}");
            Some((event, token, header))
        })();
        let agrees = outcome.as_ref().is_some_and(|(event, token, header)| {
            serde_json::to_value(event).ok().as_ref() == Some(&case.event)
                && token == &case.token
                && header == &case.header
        });
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |(_, _, header)| format!("header={header}"),
        );
        check.check(&format!("auth/{i}"), agrees, &got);
    }
}

fn unpack_token_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    // rust-nostr has no public token-unpack entry point: the base64 decode
    // and prefix check are private inside `verify_auth_header`.
    for (i, _) in vector.unpack.iter().enumerate() {
        check.skip(&format!("unpack/{i}"));
    }
}

fn validate_auth_event_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.validate.iter().enumerate() {
        if case.rust == Some(false) {
            continue;
        }
        let outcome: Option<Result<(), ()>> = (|| {
            let event: Event = serde_json::from_value(case.event.clone()).ok()?;
            let url = Url::parse(&case.url).ok()?;
            let method = HttpMethod::from_str(&case.method).ok()?;
            let header = format!(
                "Nostr {}",
                general_purpose::STANDARD.encode(event.as_json())
            );
            let body: Option<Vec<u8>> = case
                .payload_hex
                .as_deref()
                .map(|hex| common::unhex(hex).expect("vector payload hex"));
            Some(
                nip98::verify_auth_header(
                    &header,
                    &url,
                    method,
                    Timestamp::from_secs(case.now),
                    body.as_deref(),
                )
                .map(|_| ())
                .map_err(|_| ()),
            )
        })();
        // rust-nostr hardcodes a 30s-future/60s-past window; the vector's
        // max_skew_secs parameter is not settable, so cases relying on a
        // different skew diverge.
        let agrees = outcome
            .as_ref()
            .is_some_and(|result| result.is_ok() == case.result);
        let got = match &outcome {
            Some(Ok(())) => "accepted".to_owned(),
            Some(Err(())) => "rejected".to_owned(),
            None => "input not expressible".to_owned(),
        };
        check.check(&format!("validate/{i}"), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip98.http-auth");
    auth_event_token_header(&mut check);
    unpack_token_cases(&mut check);
    validate_auth_event_cases(&mut check);
    check.finish();
}
