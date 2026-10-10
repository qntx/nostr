//! `vectors/nip46/codec.json` — NIP-46 `BunkerUri`/`NostrConnectUri` URI
//! codecs and `Request`/`Response` JSON codecs.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip46.test.ts`; regenerate with
//! `bun packages/nostr/scripts/parity/gen/all.ts`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use nk::PublicKey;
use nk::nips::ErrorKind;
use nk::nips::nip46::{BunkerUri, NostrConnectUri, Request, Response};
use serde::Deserialize;

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

fn codec() -> Codec {
    serde_json::from_str(CODEC).expect("parse codec.json")
}

#[derive(Deserialize)]
struct BunkerParseCase {
    name: String,
    uri: String,
    /// `null` records the TS `undefined` return.
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

fn pubkey(hex: &str, name: &str) -> PublicKey {
    PublicKey::from_hex(hex).unwrap_or_else(|_| panic!("{name}: bad pubkey {hex}"))
}

fn bunker_json(uri: &BunkerUri) -> BunkerJson {
    BunkerJson {
        pubkey: uri.pubkey.to_hex(),
        relays: uri.relays.clone(),
        secret: uri.secret.clone(),
    }
}

fn connect_json(uri: &NostrConnectUri) -> ConnectJson {
    ConnectJson {
        client_pubkey: uri.client_pubkey.to_hex(),
        relays: uri.relays.clone(),
        secret: uri.secret.clone(),
        perms: uri.perms.clone(),
        name: uri.name.clone(),
        url: uri.url.clone(),
        image: uri.image.clone(),
    }
}

fn expect_nip46(err: Option<&str>, name: &str) {
    match err {
        Some("Nip46Error") => {}
        Some(other) => panic!("{name}: unknown error class {other}"),
        None => panic!("{name}: expected an error"),
    }
}

#[test]
fn bunker_parse_cases() {
    for case in &codec().bunker_parse {
        match (BunkerUri::parse(&case.uri), &case.out) {
            (Some(uri), Some(expected)) => {
                assert_eq!(&bunker_json(&uri), expected, "{}", case.name);
            }
            (None, None) => {}
            (Some(uri), None) => panic!("{}: expected undefined, got {uri:?}", case.name),
            (None, Some(_)) => panic!("{}: Rust rejected a valid bunker URI", case.name),
        }
    }
}

#[test]
fn bunker_encode_cases() {
    for case in &codec().bunker {
        let uri = BunkerUri {
            pubkey: pubkey(&case.pubkey, &case.name),
            relays: case.relays.clone(),
            secret: case.secret.clone(),
        };
        assert_eq!(uri.to_string(), case.out, "{}", case.name);
    }
}

#[test]
fn connect_parse_cases() {
    for case in &codec().connect_parse {
        match (NostrConnectUri::parse(&case.uri), &case.out, &case.err) {
            (Ok(uri), Some(expected), _) => {
                assert_eq!(&connect_json(&uri), expected, "{}", case.name);
            }
            (Err(error), _, Some(_)) => {
                expect_nip46(case.err.as_deref(), &case.name);
                assert_eq!(error.kind(), ErrorKind::Nip46, "{}", case.name);
                // N11: error text must never carry the input URI.
                assert!(
                    !error.to_string().contains(&case.uri),
                    "{}: URI leaked into the error",
                    case.name
                );
            }
            (Ok(uri), None, _) => panic!("{}: expected error, got {uri:?}", case.name),
            (Err(error), Some(_), _) => {
                panic!("{}: expected a parsed URI, got {error}", case.name)
            }
            (Err(error), None, None) => panic!("{}: {error} with no expectation", case.name),
        }
    }
}

#[test]
fn connect_encode_cases() {
    for case in &codec().connect {
        let input = &case.input;
        // `createNostrConnectURI` gates on the *lowercased* hex — the typed
        // Rust side cannot carry a bad pubkey, so only the lowercasing shape
        // of the validation is reproducible here; run the same gate to keep
        // the error cases meaningful.
        let valid = input.client_pubkey.len() == 64
            && input.client_pubkey.bytes().all(|b| b.is_ascii_hexdigit());
        let uri = if valid {
            Some(NostrConnectUri {
                client_pubkey: pubkey(&input.client_pubkey, &case.name),
                relays: input.relays.clone(),
                secret: input.secret.clone(),
                perms: input.perms.clone().unwrap_or_default(),
                name: input.name.clone(),
                url: input.url.clone(),
                image: input.image.clone(),
            })
        } else {
            None
        };
        match (uri, &case.out, &case.err) {
            (Some(uri), Some(expected), _) => {
                assert_eq!(
                    &uri.to_uri().expect("valid uri encodes"),
                    expected,
                    "{}",
                    case.name
                );
            }
            (None, _, Some(_)) => {
                // TS throws `invalid client pubkey` before touching the rest.
                expect_nip46(case.err.as_deref(), &case.name);
            }
            (Some(uri), _, Some(_)) => {
                expect_nip46(case.err.as_deref(), &case.name);
                let error = uri.to_uri().expect_err("encode must fail");
                assert_eq!(error.kind(), ErrorKind::Nip46, "{}", case.name);
            }
            (None, Some(_), _) => panic!("{}: expected a URI, client was invalid", case.name),
            (Some(_) | None, None, None) => {
                panic!("{}: case has no expectation", case.name)
            }
        }
    }
}

#[test]
fn request_cases() {
    for case in &codec().request {
        let request = Request {
            id: case.request.id.clone(),
            method: case.request.method.clone(),
            params: case.request.params.clone(),
        };
        assert_eq!(request.to_json(), case.json, "{}", case.name);
        let decoded = Request::from_json(&case.json).expect("generated json decodes");
        assert_eq!(decoded, request, "{}", case.name);
    }
}

#[test]
fn request_parse_cases() {
    for case in &codec().request_parse {
        match (Request::from_json(&case.json), &case.out, &case.err) {
            (Ok(request), Some(expected), _) => {
                assert_eq!(
                    (
                        request.id.as_str(),
                        request.method.as_str(),
                        request.params.as_slice()
                    ),
                    (
                        expected.id.as_str(),
                        expected.method.as_str(),
                        expected.params.as_slice()
                    ),
                    "{}",
                    case.name
                );
            }
            (Err(error), _, Some(_)) => {
                expect_nip46(case.err.as_deref(), &case.name);
                assert_eq!(error.kind(), ErrorKind::Nip46, "{}", case.name);
            }
            (Ok(_), None, _) => panic!("{}: expected error, got a request", case.name),
            (Err(error), Some(_), _) => {
                panic!("{}: expected a request, got {error}", case.name)
            }
            (Err(error), None, None) => panic!("{}: {error} with no expectation", case.name),
        }
    }
}

#[test]
fn response_cases() {
    for case in &codec().response {
        let response = Response {
            id: case.response.id.clone(),
            result: case.response.result.clone(),
            error: case.response.error.clone(),
        };
        assert_eq!(response.to_json(), case.json, "{}", case.name);
        let decoded = Response::from_json(&case.json).expect("generated json decodes");
        assert_eq!(decoded, response, "{}", case.name);
    }
}

#[test]
fn response_parse_cases() {
    for case in &codec().response_parse {
        match (Response::from_json(&case.json), &case.out, &case.err) {
            (Ok(response), Some(expected), _) => {
                assert_eq!(
                    (
                        response.id.as_str(),
                        response.result.as_deref(),
                        response.error.as_deref()
                    ),
                    (
                        expected.id.as_str(),
                        expected.result.as_deref(),
                        expected.error.as_deref()
                    ),
                    "{}",
                    case.name
                );
            }
            (Err(error), _, Some(_)) => {
                expect_nip46(case.err.as_deref(), &case.name);
                assert_eq!(error.kind(), ErrorKind::Nip46, "{}", case.name);
            }
            (Ok(_), None, _) => panic!("{}: expected error, got a response", case.name),
            (Err(error), Some(_), _) => {
                panic!("{}: expected a response, got {error}", case.name)
            }
            (Err(error), None, None) => panic!("{}: {error} with no expectation", case.name),
        }
    }
}
