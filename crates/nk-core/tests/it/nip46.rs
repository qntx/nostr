//! vectors/nip46/codec.json — `nip46.codec`.

use core::str::FromStr;

use nk_core::PublicKey;
use nk_core::nips::nip46::{BunkerUri, Method, NostrConnectUri, Request, Response};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    uri: String,
    #[serde(default)]
    out: Option<Value>,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    #[serde(default)]
    pubkey: Option<String>,
    #[serde(default)]
    relays: Option<Vec<String>>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    input: Option<Value>,
    #[serde(default)]
    out: Option<String>,
    #[serde(default)]
    err: Option<String>,
    #[serde(default)]
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct MsgCase {
    name: String,
    #[serde(default)]
    json: Option<String>,
    #[serde(default)]
    request: Option<Value>,
    #[serde(default)]
    response: Option<Value>,
    #[serde(default)]
    out: Option<Value>,
    #[serde(default)]
    err: Option<String>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip46/codec.json"
));

fn bunker_json(u: &BunkerUri) -> Value {
    json!({
        "pubkey": u.remote_signer.to_hex(),
        "relays": u.relays,
        "secret": u.secret,
    })
}

#[test]
fn nip46_bunker_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ParseCase> = serde_json::from_value(doc["bunker_parse"].clone()).unwrap();
    for case in &cases {
        let parsed = BunkerUri::from_str(&case.uri);
        match &case.out {
            Some(want) => assert_eq!(&bunker_json(&parsed.unwrap()), want, "{}", case.name),
            None => assert!(parsed.is_err(), "{}", case.name),
        }
    }
}

#[test]
fn nip46_bunker_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<BuildCase> = serde_json::from_value(doc["bunker"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let uri = BunkerUri {
            remote_signer: PublicKey::from_hex(case.pubkey.as_ref().unwrap()).unwrap(),
            relays: case.relays.clone().unwrap_or_default(),
            secret: case.secret.clone(),
        };
        assert_eq!(
            uri.to_string(),
            case.out.as_deref().unwrap(),
            "{}",
            case.name
        );
    }
}

fn connect_json(u: &NostrConnectUri) -> Value {
    json!({
        "clientPubkey": u.client().to_hex(),
        "relays": u.relays(),
        "secret": u.secret(),
        "perms": u.perms(),
        "name": u.name(),
        "url": u.url(),
        "image": u.image(),
    })
}

#[test]
fn nip46_connect_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ParseCase> = serde_json::from_value(doc["connect_parse"].clone()).unwrap();
    for case in &cases {
        let parsed = NostrConnectUri::from_str(&case.uri);
        match &case.out {
            Some(want) => assert_eq!(&connect_json(&parsed.unwrap()), want, "{}", case.name),
            None => assert!(parsed.is_err(), "{}", case.name),
        }
    }
}

#[test]
fn nip46_connect_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<BuildCase> = serde_json::from_value(doc["connect"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let input = case.input.as_ref().unwrap();
        if case.err.is_some() {
            // invalid inputs must fail at construction
            let built = input["clientPubkey"]
                .as_str()
                .and_then(|s| PublicKey::from_hex(s).ok())
                .map(|pk| {
                    NostrConnectUri::new(
                        pk,
                        input["relays"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|s| s.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        input["secret"].as_str().unwrap_or("").to_owned(),
                    )
                });
            assert!(built.is_none() || built.unwrap().is_err(), "{}", case.name);
            continue;
        }
        let mut uri = NostrConnectUri::new(
            PublicKey::from_hex(input["clientPubkey"].as_str().unwrap()).unwrap(),
            input["relays"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            input["secret"].as_str().unwrap_or("").to_owned(),
        )
        .unwrap();
        uri = uri.with_perms(
            input["perms"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        );
        if let Some(n) = input.get("name").and_then(Value::as_str) {
            uri = uri.with_name(n);
        }
        if let Some(u) = input.get("url").and_then(Value::as_str) {
            uri = uri.with_url(u);
        }
        if let Some(i) = input.get("image").and_then(Value::as_str) {
            uri = uri.with_image(i);
        }
        assert_eq!(
            uri.to_string(),
            case.out.as_deref().unwrap(),
            "{}",
            case.name
        );
    }
}

#[test]
fn nip46_request() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<MsgCase> = serde_json::from_value(doc["request"].clone()).unwrap();
    for case in &cases {
        let input = case.request.as_ref().unwrap();
        let params: Vec<String> = input["params"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let req = Request {
            id: input["id"].as_str().unwrap().to_owned(),
            method: Method::from(input["method"].as_str().unwrap().to_owned()),
            params,
        };
        assert_eq!(req.to_json(), *case.json.as_ref().unwrap(), "{}", case.name);
    }
}

#[test]
fn nip46_request_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<MsgCase> = serde_json::from_value(doc["request_parse"].clone()).unwrap();
    for case in &cases {
        let parsed = Request::from_json(case.json.as_deref().unwrap_or(""));
        match (&case.out, &case.err) {
            (Some(want), None) => {
                let req = parsed.unwrap();
                let got = json!({
                    "id": req.id,
                    "method": req.method.as_str(),
                    "params": req.params,
                });
                assert_eq!(&got, want, "{}", case.name);
            }
            (None, Some(_)) => assert!(parsed.is_err(), "{}", case.name),
            _ => panic!("{}", case.name),
        }
    }
}

#[test]
fn nip46_response() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<MsgCase> = serde_json::from_value(doc["response"].clone()).unwrap();
    for case in &cases {
        let input = case.response.as_ref().unwrap();
        let resp = Response {
            id: input["id"].as_str().unwrap().to_owned(),
            result: input["result"].as_str().map(str::to_owned),
            error: input["error"].as_str().map(str::to_owned),
        };
        assert_eq!(
            resp.to_json(),
            *case.json.as_ref().unwrap(),
            "{}",
            case.name
        );
    }
}

#[test]
fn nip46_response_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<MsgCase> = serde_json::from_value(doc["response_parse"].clone()).unwrap();
    for case in &cases {
        let parsed = Response::from_json(case.json.as_deref().unwrap_or(""));
        match (&case.out, &case.err) {
            (Some(want), None) => {
                let resp = parsed.unwrap();
                let got = json!({
                    "id": resp.id,
                    "result": resp.result,
                    "error": resp.error,
                });
                assert_eq!(&got, want, "{}", case.name);
            }
            (None, Some(_)) => assert!(parsed.is_err(), "{}", case.name),
            _ => panic!("{}", case.name),
        }
    }
}
