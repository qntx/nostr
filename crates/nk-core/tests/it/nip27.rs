//! vectors/nip27/codec.json — `nip27.tokenize`.

use std::collections::BTreeMap;

use nk_core::nips::nip27::{ContentBlock, ParseOptions, Reference, parse_content};
use nk_core::{Tag, Tags};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    name: String,
    content: String,
    #[serde(default)]
    tags: Option<Vec<Vec<String>>>,
    #[serde(default)]
    imeta: Option<BTreeMap<String, String>>,
    #[serde(default)]
    legacy: Option<bool>,
    out: Vec<Value>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip27/codec.json"
));

fn reference_json(r: &Reference) -> Value {
    match r {
        Reference::Profile(p) => json!({
            "type": "profile",
            "pubkey": p.pubkey.to_hex(),
            "relays": p.relays,
        }),
        Reference::Event(p) => json!({
            "type": "event",
            "id": p.id.to_hex(),
            "relays": p.relays,
            "author": p.author.map(|a| a.to_hex()),
            "kind": p.kind.map(|k| k.as_u16()),
        }),
        Reference::Address(p) => json!({
            "type": "address",
            "identifier": p.identifier,
            "pubkey": p.pubkey.to_hex(),
            "kind": p.kind.as_u16(),
            "relays": p.relays,
        }),
    }
}

fn block_json(b: &ContentBlock<'_>) -> Value {
    match b {
        ContentBlock::Text(t) => json!({"type": "text", "text": t}),
        ContentBlock::Reference { reference, bare } => json!({
            "type": "reference",
            "bare": bare,
            "pointer": reference_json(reference),
        }),
        ContentBlock::Url(u) => json!({"type": "url", "url": u}),
        ContentBlock::Image(u) => json!({"type": "image", "url": u}),
        ContentBlock::Video(u) => json!({"type": "video", "url": u}),
        ContentBlock::Audio(u) => json!({"type": "audio", "url": u}),
        ContentBlock::Relay(u) => json!({"type": "relay", "url": u}),
        ContentBlock::Hashtag(t) => json!({"type": "hashtag", "value": t}),
        ContentBlock::Emoji { shortcode, url } => {
            json!({"type": "emoji", "shortcode": shortcode, "url": url})
        }
        ContentBlock::Invoice(s) => json!({"type": "invoice", "bolt11": s}),
        _ => unreachable!("ContentBlock is non_exhaustive"),
    }
}

#[test]
fn nip27_tokenize() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).unwrap();
    for case in &cases {
        let tags: Option<Tags> = case.tags.as_ref().map(|raw| {
            raw.iter()
                .filter_map(|t| Tag::new(t.clone()).ok())
                .collect()
        });
        let options = ParseOptions {
            legacy_bech32: case.legacy.unwrap_or(false),
            imeta: case.imeta.as_ref(),
        };
        let blocks = parse_content(&case.content, tags.as_ref(), options);
        let got: Vec<Value> = blocks.iter().map(block_json).collect();
        assert_eq!(got, case.out, "{}", case.name);
    }
}
