//! Executes `vectors/nip46/codec.json` against rust-nostr's public API.

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

use common::DivergenceCheck;
use nostr::nips::nip46::{
    NostrConnectMessage, NostrConnectMetadata, NostrConnectMethod, NostrConnectUri,
};
use nostr::prelude::{PublicKey, RelayUrl};
use serde::Deserialize;
use std::str::FromStr;
use url::Url;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip46/codec.json"
));

#[derive(Deserialize)]
struct Codec {
    bunker_parse: Vec<BunkerParseCase>,
    bunker: Vec<BunkerCase>,
    connect_parse: Vec<ConnectParseCase>,
    connect: Vec<ConnectCase>,
    request: Vec<RequestCase>,
    request_parse: Vec<RequestParseCase>,
    response: Vec<ResponseCase>,
    response_parse: Vec<ResponseParseCase>,
}

#[derive(Deserialize)]
struct BunkerParseCase {
    name: String,
    uri: String,
    out: Option<BunkerJson>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct BunkerJson {
    pubkey: String,
    relays: Vec<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
struct BunkerCase {
    name: String,
    pubkey: String,
    relays: Vec<String>,
    secret: Option<String>,
    out: String,
}

#[derive(Deserialize)]
struct ConnectParseCase {
    name: String,
    uri: String,
    out: Option<ConnectJson>,
    err: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectJson {
    client_pubkey: String,
    relays: Vec<String>,
    secret: String,
    perms: Vec<String>,
    name: Option<String>,
    url: Option<String>,
    image: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectInput {
    client_pubkey: String,
    relays: Vec<String>,
    secret: String,
    #[allow(dead_code, reason = "nostr's nostrconnect model has no perms param")]
    perms: Option<Vec<String>>,
    name: Option<String>,
    url: Option<String>,
    image: Option<String>,
}

#[derive(Deserialize)]
struct ConnectCase {
    name: String,
    input: ConnectInput,
    out: Option<String>,
    err: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct RequestJson {
    id: String,
    method: String,
    params: Vec<String>,
}

#[derive(Deserialize)]
struct RequestCase {
    name: String,
    request: RequestJson,
    json: String,
}

#[derive(Deserialize)]
struct RequestParseCase {
    name: String,
    json: String,
    out: Option<RequestJson>,
    err: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct ResponseJson {
    id: String,
    result: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ResponseCase {
    name: String,
    response: ResponseJson,
    json: String,
}

#[derive(Deserialize)]
struct ResponseParseCase {
    name: String,
    json: String,
    out: Option<ResponseJson>,
    err: Option<String>,
}

fn bunker_json(uri: &NostrConnectUri) -> Option<BunkerJson> {
    if let NostrConnectUri::Bunker {
        remote_signer_public_key,
        relays,
        secret,
    } = uri
    {
        Some(BunkerJson {
            pubkey: remote_signer_public_key.to_hex(),
            relays: relays.iter().map(ToString::to_string).collect(),
            secret: secret.clone(),
        })
    } else {
        None
    }
}

fn connect_json(uri: &NostrConnectUri) -> Option<ConnectJson> {
    if let NostrConnectUri::Client {
        public_key,
        relays,
        metadata,
        secret,
    } = uri
    {
        Some(ConnectJson {
            client_pubkey: public_key.to_hex(),
            relays: relays.iter().map(ToString::to_string).collect(),
            secret: secret.clone(),
            // rust-nostr's nostrconnect model carries a `metadata` JSON
            // blob; there are no perms/name/url/image query params.
            perms: Vec::new(),
            name: Some(metadata.name.clone()),
            url: metadata.url.as_ref().map(ToString::to_string),
            image: metadata
                .icons
                .as_ref()
                .and_then(|icons| icons.first().map(ToString::to_string)),
        })
    } else {
        None
    }
}

fn bunker_parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.bunker_parse {
        let outcome = NostrConnectUri::from_str(&case.uri)
            .ok()
            .and_then(|uri| bunker_json(&uri));
        let agrees = outcome.as_ref() == case.out.as_ref();
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |json| format!("parsed pubkey={}", json.pubkey),
        );
        check.check(&case.name, agrees, &got);
    }
}

fn bunker_encode_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.bunker {
        let outcome = (|| {
            let uri = NostrConnectUri::Bunker {
                remote_signer_public_key: PublicKey::from_hex(&case.pubkey).ok()?,
                relays: case
                    .relays
                    .iter()
                    .map(|r| RelayUrl::parse(r).ok())
                    .collect::<Option<Vec<_>>>()?,
                secret: case.secret.clone(),
            };
            Some(uri.to_string())
        })();
        let agrees = outcome.as_deref() == Some(case.out.as_str());
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&case.name, agrees, &got);
    }
}

fn connect_parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.connect_parse {
        let outcome = NostrConnectUri::from_str(&case.uri)
            .ok()
            .and_then(|uri| connect_json(&uri));
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(json)) => json == expected,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |json| format!("parsed client={}", json.client_pubkey),
        );
        check.check(&case.name, agrees, &got);
    }
}

fn connect_encode_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.connect {
        let input = &case.input;
        let outcome = (|| {
            let mut metadata = NostrConnectMetadata::new(input.name.clone().unwrap_or_default());
            if let Some(url) = &input.url {
                metadata = metadata.url(Url::parse(url).ok()?);
            }
            if let Some(image) = &input.image {
                metadata = metadata.icons(vec![Url::parse(image).ok()?]);
            }
            let uri = NostrConnectUri::Client {
                public_key: PublicKey::from_hex(&input.client_pubkey).ok()?,
                relays: input
                    .relays
                    .iter()
                    .map(|r| RelayUrl::parse(r).ok())
                    .collect::<Option<Vec<_>>>()?,
                metadata,
                secret: input.secret.clone(),
            };
            Some(uri.to_string())
        })();
        // rust-nostr serializes the whole metadata blob under `metadata=`;
        // the TS encoder emits `perms`/`name`/`url`/`image` query params.
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(uri)) => uri == expected,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&case.name, agrees, &got);
    }
}

fn request_json(message: &NostrConnectMessage) -> Option<RequestJson> {
    if let NostrConnectMessage::Request { id, method, params } = message {
        Some(RequestJson {
            id: id.clone(),
            method: method.to_string(),
            params: params.clone(),
        })
    } else {
        None
    }
}

fn request_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.request {
        let outcome = NostrConnectMethod::from_str(&case.request.method)
            .ok()
            .map(|method| {
                serde_json::to_string(&NostrConnectMessage::Request {
                    id: case.request.id.clone(),
                    method,
                    params: case.request.params.clone(),
                })
                .expect("request serializes")
            });
        let agrees = outcome.as_deref() == Some(case.json.as_str());
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&case.name, agrees, &got);
    }
}

fn request_parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.request_parse {
        let outcome = serde_json::from_str::<NostrConnectMessage>(&case.json)
            .ok()
            .and_then(|message| request_json(&message));
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(json)) => json == expected,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |json| format!("id={} method={}", json.id, json.method),
        );
        check.check(&case.name, agrees, &got);
    }
}

fn response_json(message: &NostrConnectMessage) -> Option<ResponseJson> {
    if let NostrConnectMessage::Response { id, result, error } = message {
        Some(ResponseJson {
            id: id.clone(),
            result: result.clone(),
            error: error.clone(),
        })
    } else {
        None
    }
}

fn response_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.response {
        let got = serde_json::to_string(&NostrConnectMessage::Response {
            id: case.response.id.clone(),
            result: case.response.result.clone(),
            error: case.response.error.clone(),
        })
        .expect("response serializes");
        check.check(&case.name, got == case.json, &got);
    }
}

fn response_parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.response_parse {
        let outcome = serde_json::from_str::<NostrConnectMessage>(&case.json)
            .ok()
            .and_then(|message| response_json(&message));
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(json)) => json == expected,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(|| "rejected".to_owned(), |json| format!("id={}", json.id));
        check.check(&case.name, agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip46.codec");
    bunker_parse_cases(&mut check);
    bunker_encode_cases(&mut check);
    connect_parse_cases(&mut check);
    connect_encode_cases(&mut check);
    request_cases(&mut check);
    request_parse_cases(&mut check);
    response_cases(&mut check);
    response_parse_cases(&mut check);
    check.finish();
}
