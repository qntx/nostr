//! vectors/blossom/codec.json — `blossom.codec`.

use core::str::FromStr;

use nk_core::event::Event;
use nk_core::nips::blossom::{
    AuthVerb, Authorization, BlobDescriptor, BlobHash, Server, ServerList, authorization_header,
};
use nk_core::{EventBuilder, Keys, Kind, PublicKey, SecretKey, Tag, Timestamp};

use crate::common::AuxRng;

use serde_json::Value;

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/blossom/codec.json"
));

fn verb(s: &str) -> Option<AuthVerb> {
    match s {
        "upload" => Some(AuthVerb::Upload),
        "delete" => Some(AuthVerb::Delete),
        "list" => Some(AuthVerb::List),
        "get" => Some(AuthVerb::Get),
        "media" => Some(AuthVerb::Media),
        _ => None,
    }
}

/// The vector's tag arrays, as `Tag`s.
fn tags_of(v: &Value) -> Vec<Tag> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|tag| {
            let items: Vec<String> = tag
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i.as_str().unwrap().to_owned())
                .collect();
            Tag::new(items).unwrap()
        })
        .collect()
}

/// The vector's `{tags, content}` out shape.
fn template_out(template: EventBuilder, out: &Value) {
    let unsigned = template.build_at(
        PublicKey::from_hex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
            .unwrap(),
        Timestamp::from_secs(1_700_000_000),
    );
    let tags: Vec<Vec<String>> = unsigned
        .tags()
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect();
    assert_eq!(tags.len(), out["tags"].as_array().unwrap().len());
    for (i, want) in out["tags"].as_array().unwrap().iter().enumerate() {
        let items: Vec<String> = want
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(&tags[i], &items);
    }
    if let Some(content) = out.get("content") {
        assert_eq!(unsigned.content(), content.as_str().unwrap());
    }
}

#[test]
fn blossom_hash_from_url() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["hash_from_url"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        match &case["out"] {
            Value::Null => {
                assert!(BlobHash::from_url(input).is_none(), "{}", case["name"]);
            }
            out => {
                assert_eq!(
                    BlobHash::from_url(input).unwrap().to_string(),
                    out.as_str().unwrap(),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn blossom_server() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["server"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        match &case["out"] {
            Value::Null => {
                assert!(Server::from_str(input).is_err(), "{}", case["name"]);
            }
            out => {
                assert_eq!(
                    Server::from_str(input).unwrap().as_str(),
                    out.as_str().unwrap(),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn blossom_endpoint() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["endpoint"].as_array().unwrap() {
        let server = Server::from_str(case["base"].as_str().unwrap()).unwrap();
        assert_eq!(
            server.endpoint(case["path"].as_str().unwrap()),
            case["out"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn blossom_auth() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["auth"].as_array().unwrap() {
        if case["rust"] == Value::Bool(false) {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let Some(v) = verb(case["verb"].as_str().unwrap()) else {
            panic!("{name}: unknown verb without rust:false");
        };
        let auth = Authorization::new(
            v,
            Timestamp::from_secs(case["expiration"].as_u64().unwrap()),
        );
        let err_out = serde_json::json!({"err": true});
        let auth = if let Some(hex) = case.get("sha256") {
            if let Ok(hash) = BlobHash::from_str(hex.as_str().unwrap()) {
                auth.blob(hash)
            } else {
                assert_eq!(case["out"], err_out, "{name}");
                continue;
            }
        } else {
            auth
        };
        let auth = if let Some(message) = case.get("message") {
            if let Ok(auth) = auth.message(message.as_str().unwrap()) {
                auth
            } else {
                assert_eq!(case["out"], err_out, "{name}");
                continue;
            }
        } else {
            auth
        };
        let auth = if let Some(servers) = case.get("servers") {
            auth.servers(
                servers
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap()),
            )
        } else {
            auth
        };
        assert_ne!(
            case["out"].get("err"),
            Some(&Value::Bool(true)),
            "{name}: expected an error, template built"
        );
        template_out(EventBuilder::from(auth), &case["out"]);
    }
}

#[test]
fn blossom_header() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["header"].as_array().unwrap() {
        let event = Event::from_json(&serde_json::to_string(&case["event"]).unwrap()).unwrap();
        assert_eq!(
            authorization_header(&event),
            case["out"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn blossom_server_list_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["server_list_build"].as_array().unwrap() {
        let servers: Vec<String> = case["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        match ServerList::new(servers) {
            Ok(list) => template_out(EventBuilder::from(list), &case["out"]),
            Err(e) => {
                assert!(
                    matches!(e, nk_core::nips::blossom::Error::NoServers),
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    case["out"],
                    serde_json::json!({"err": true}),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn blossom_server_list_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let keys = Keys::new(
        SecretKey::from_hex("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
            .unwrap(),
    );
    for case in doc["server_list_parse"].as_array().unwrap() {
        let tags = tags_of(&case["tags"]);
        let unsigned = EventBuilder::new(Kind::new(case["kind"].as_u64().unwrap() as u16), "")
            .tags(tags)
            .build_at(keys.public_key(), Timestamp::from_secs(1_700_000_000));
        let event = keys.sign_event(unsigned, &mut AuxRng([7; 32])).unwrap();
        match ServerList::try_from(&event) {
            Ok(list) => {
                let got: Vec<String> = list.servers().iter().map(ToString::to_string).collect();
                let want: Vec<String> = case["out"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(got, want, "{}", case["name"]);
            }
            Err(_) => assert_eq!(
                case["out"],
                serde_json::json!({"err": true}),
                "{}",
                case["name"]
            ),
        }
    }
}

#[test]
fn blossom_descriptor() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    for case in doc["descriptor"].as_array().unwrap() {
        let json = case["json"].as_str().unwrap();
        let out = &case["out"];
        if out.get("err") == Some(&Value::Bool(true)) {
            assert!(BlobDescriptor::from_json(json).is_err(), "{}", case["name"]);
            continue;
        }
        let desc = BlobDescriptor::from_json(json).unwrap();
        let name = case["name"].as_str().unwrap();
        assert_eq!(desc.url, out["url"].as_str().unwrap(), "{name}");
        assert_eq!(
            desc.sha256.to_string(),
            out["sha256"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(desc.size, out["size"].as_u64().unwrap(), "{name}");
        assert_eq!(
            desc.mime_type.as_deref(),
            out.get("type").and_then(Value::as_str),
            "{name}"
        );
        assert_eq!(
            desc.uploaded.map(|t| t.as_secs()),
            out.get("uploaded").and_then(Value::as_u64),
            "{name}"
        );
    }
}
