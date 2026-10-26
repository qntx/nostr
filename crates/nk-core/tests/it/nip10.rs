//! vectors/nip10/codec.json — `nip10.thread`.

use nk_core::nips::nip10::{Quote, ThreadReferences};
use nk_core::nips::nip19::{AddressPointer, EventPointer};
use nk_core::{Event, EventBuilder, EventId, PublicKey, RelayUrl, Tags, Timestamp};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    tags: Value,
    out: Option<Value>,
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct ReplyCase {
    name: String,
    parent: Value,
    relay_hint: Option<String>,
    quotes: Vec<Value>,
    out_tags: Option<Vec<Vec<String>>>,
    err: Option<String>,
    rust: Option<bool>,
}

fn pointer_json(p: &EventPointer) -> Value {
    json!({
        "id": p.id.to_hex(),
        "relays": p.relays,
        "author": p.author.map(|a| a.to_hex()),
        "kind": p.kind.map(|k| k.as_u16()),
    })
}

fn address_json(p: &AddressPointer) -> Value {
    json!({
        "type": "address",
        "identifier": p.identifier,
        "pubkey": p.pubkey.to_hex(),
        "kind": p.kind.as_u16(),
        "relays": p.relays,
    })
}

fn quote_json(q: &Quote) -> Value {
    match q {
        Quote::Event(p) => {
            let mut v = pointer_json(p);
            v["type"] = json!("event");
            v
        }
        Quote::Address(p) => address_json(p),
    }
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip10/codec.json"
));

#[test]
fn nip10_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ParseCase> = serde_json::from_value(doc["parse"].clone()).unwrap();
    for case in &cases {
        // `"rust": false` — shapes the runner cannot express (non-string
        // tag elements trip serde's `Vec<String>` before the codec runs).
        if case.rust == Some(false) {
            continue;
        }
        let Some(out) = &case.out else {
            continue;
        };
        let raw: Vec<Vec<String>> = serde_json::from_value(case.tags.clone()).unwrap();
        let tags: Tags = raw
            .into_iter()
            .filter_map(|t| nk_core::Tag::new(t).ok())
            .collect();
        let refs = ThreadReferences::from(&tags);
        let got = json!({
            "root": refs.root.as_ref().map(pointer_json),
            "reply": refs.reply.as_ref().map(pointer_json),
            "mentions": refs.mentions.iter().map(pointer_json).collect::<Vec<_>>(),
            "quotes": refs.quotes.iter().map(quote_json).collect::<Vec<_>>(),
            "profiles": refs.profiles.iter().map(|p| json!({
                "pubkey": p.pubkey.to_hex(),
                "relays": p.relays,
            })).collect::<Vec<_>>(),
        });
        assert_eq!(&got, out, "{}", case.name);
    }
}

#[test]
fn nip10_reply() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ReplyCase> = serde_json::from_value(doc["reply"].clone()).unwrap();
    for case in &cases {
        // `"rust": false` — raw-string relay hints or bare-string quotes the
        // typed API cannot express; asserted as marked.
        if case.rust == Some(false) {
            continue;
        }
        let parent: Event = serde_json::from_value(case.parent.clone()).unwrap();
        let quotes: Vec<Quote> = case
            .quotes
            .iter()
            .map(|q| {
                if let Some(id) = q.get("id") {
                    Quote::Event(EventPointer {
                        id: EventId::from_hex(id.as_str().unwrap()).unwrap(),
                        relays: q
                            .get("relays")
                            .and_then(Value::as_array)
                            .map(|r| {
                                r.iter()
                                    .filter_map(|s| s.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        author: q
                            .get("author")
                            .and_then(Value::as_str)
                            .and_then(|s| PublicKey::from_hex(s).ok()),
                        kind: None,
                    })
                } else {
                    Quote::Address(AddressPointer {
                        identifier: q["identifier"].as_str().unwrap().to_owned(),
                        pubkey: PublicKey::from_hex(q["pubkey"].as_str().unwrap()).unwrap(),
                        kind: nk_core::Kind::new(q["kind"].as_u64().unwrap() as u16),
                        relays: q
                            .get("relays")
                            .and_then(Value::as_array)
                            .map(|r| {
                                r.iter()
                                    .filter_map(|s| s.as_str().map(str::to_owned))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                }
            })
            .collect();
        let relay_hint = case
            .relay_hint
            .as_deref()
            .and_then(|r| RelayUrl::parse(r).ok());
        match (&case.out_tags, &case.err, case.rust) {
            // `out_tags: null` — the kind check must reject the parent.
            (None, _, _) => {
                assert!(
                    EventBuilder::text_reply(&parent, "", relay_hint.as_ref(), &quotes).is_err(),
                    "{}",
                    case.name
                );
            }
            (Some(out), None, _) => {
                let unsigned = EventBuilder::text_reply(&parent, "", relay_hint.as_ref(), &quotes)
                    .unwrap()
                    .build_at(
                        PublicKey::from_hex(&"11".repeat(32)).unwrap(),
                        Timestamp::from_secs(1),
                    );
                let got: Vec<Vec<String>> = unsigned
                    .tags()
                    .iter()
                    .map(|t| t.as_slice().to_vec())
                    .collect();
                assert_eq!(&got, out, "{}", case.name);
            }
            _ => panic!("{}: malformed", case.name),
        }
    }
}
