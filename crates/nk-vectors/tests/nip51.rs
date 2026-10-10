//! `vectors/nip51/codec.json` — NIP-51 list parsers, builders, and the
//! private-tag NIP-44 flow (`encrypt_private_tags_with_rng` under the recorded
//! nonce, `decrypt_private_tags`).
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip51.test.ts`; regenerate with
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

use std::string::ToString;

use nk_core::{EventAddress, EventId, Keys, PublicKey, RelayUrl, SecretKey, Tag, Timestamp};
use nk_nips::nip51::{
    MuteItem, bookmark_list, decrypt_private_tags, encrypt_private_tags_with_rng, mute_items,
    mute_list, parse_bookmark_list, parse_emoji_set, parse_favorite_relays, parse_follow_pack,
    parse_mute_list, parse_pin_list, parse_relay_set, parse_user_emoji_list, pin_list,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip51/codec.json"
));

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct Codec {
    parse: Vec<ParseCase>,
    build: Vec<BuildCase>,
    private: Private,
}

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    op: String,
    event: nk_core::Event,
    out: Option<Value>,
    err: Option<String>,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    op: String,
    #[serde(default = "default_true")]
    rust: bool,
    input: Value,
    builder: Option<BuilderExpect>,
    err: Option<String>,
}

#[derive(Deserialize)]
struct BuilderExpect {
    kind: u64,
    content: String,
    tags: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct Private {
    encrypt: Vec<EncryptCase>,
    decrypt: Vec<DecryptCase>,
}

#[derive(Deserialize)]
struct EncryptCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    secret_key: String,
    nonce: String,
    tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Deserialize)]
struct DecryptCase {
    name: String,
    secret_key: String,
    pubkey: String,
    content: String,
    out: Option<Vec<Vec<String>>>,
    items: Option<Vec<MuteItemJson>>,
    err: Option<String>,
}

/// The vector's `{"type","value"}` mute-item shape.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MuteItemJson {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// Replays the recorded `nonce` — the fixed draw the TS `Nip51Crypto` wrapper
/// passed to the real `nip44.encrypt`.
struct StreamRng<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl StreamRng<'_> {
    fn new(hex: &str) -> Self {
        Self {
            bytes: Box::leak(unhex(hex).expect("vector nonce hex").into_boxed_slice()),
            pos: 0,
        }
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl rand_core::TryRng for StreamRng<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut out = [0u8; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut out = [0u8; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.pos + dest.len();
        dest.copy_from_slice(
            self.bytes
                .get(self.pos..end)
                .expect("vector nonce stream exhausted"),
        );
        self.pos = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for StreamRng<'_> {}

fn keys(hex: &str) -> Keys {
    Keys::new(SecretKey::from_hex(hex).expect("vector secret key"))
}

fn tags_json(tags: &nk_core::Tags) -> Value {
    serde_json::to_value(tags).expect("tags serialize")
}

fn mute_items_json(items: &[MuteItem]) -> Vec<MuteItemJson> {
    items
        .iter()
        .map(|item| match item {
            MuteItem::PublicKey(pk) => MuteItemJson {
                kind: "pubkey".to_owned(),
                value: pk.to_hex(),
            },
            MuteItem::Event(id) => MuteItemJson {
                kind: "event".to_owned(),
                value: id.to_hex(),
            },
            MuteItem::Hashtag(hashtag) => MuteItemJson {
                kind: "hashtag".to_owned(),
                value: hashtag.clone(),
            },
            MuteItem::Word(word) => MuteItemJson {
                kind: "word".to_owned(),
                value: word.clone(),
            },
        })
        .collect()
}

fn parse_op(case: &ParseCase) -> Option<nk_nips::Result<Value>> {
    Some(match case.op.as_str() {
        "mute" => parse_mute_list(&case.event).map(|items| json!(mute_items_json(&items))),
        "pin" => parse_pin_list(&case.event)
            .map(|ids| json!(ids.iter().map(|id| id.to_hex()).collect::<Vec<_>>())),
        "bookmark" => parse_bookmark_list(&case.event).map(|list| {
            json!({
                "e": list
                    .events
                    .iter()
                    .map(|id| id.to_hex())
                    .collect::<Vec<_>>(),
                "a": list.addresses,
            })
        }),
        "user_emoji" => parse_user_emoji_list(&case.event).map(|list| {
            json!({
                "emoji": list.emoji.iter().map(|e| json!({"shortcode": e.shortcode, "url": e.url})).collect::<Vec<_>>(),
                "sets": list.sets,
            })
        }),
        "relay_set" => parse_relay_set(&case.event).map(|set| {
            json!({
                "d": set.identifier,
                "relays": set.relays.iter().map(RelayUrl::to_string).collect::<Vec<_>>(),
            })
        }),
        "favorite_relays" => parse_favorite_relays(&case.event).map(|set| {
            json!({
                "relays": set.relays.iter().map(RelayUrl::to_string).collect::<Vec<_>>(),
                "sets": set.sets,
            })
        }),
        "emoji_set" => parse_emoji_set(&case.event).map(|set| {
            let mut out = serde_json::Map::new();
            out.insert("d".to_owned(), json!(set.identifier));
            out.insert(
                "emoji".to_owned(),
                json!(set
                    .emoji
                    .iter()
                    .map(|e| json!({"shortcode": e.shortcode, "url": e.url}))
                    .collect::<Vec<_>>()),
            );
            if let Some(title) = set.title {
                out.insert("title".to_owned(), Value::String(title));
            }
            Value::Object(out)
        }),
        "follow_pack" => parse_follow_pack(&case.event).map(|pack| {
            json!({
                "d": pack.identifier,
                "pubkeys": pack
                    .pubkeys
                    .iter()
                    .map(|pk| pk.to_hex())
                    .collect::<Vec<_>>(),
            })
        }),
        _ => return None,
    })
}

fn build_op(case: &BuildCase) -> (u16, String, Vec<Vec<String>>) {
    let input = &case.input;
    let builder = match case.op.as_str() {
        "mute" => {
            let items = input
                .as_array()
                .expect("mute input is an array")
                .iter()
                .map(|item| {
                    let kind = item["type"].as_str().expect("mute item type");
                    let value = item["value"].as_str().expect("mute item value");
                    match kind {
                        "pubkey" => {
                            MuteItem::PublicKey(PublicKey::from_hex(value).expect("vector pubkey"))
                        }
                        "event" => MuteItem::Event(EventId::from_hex(value).expect("vector id")),
                        "hashtag" => MuteItem::Hashtag(value.to_owned()),
                        "word" => MuteItem::Word(value.to_owned()),
                        other => panic!("mute item type {other}"),
                    }
                })
                .collect::<Vec<_>>();
            mute_list(&items)
        }
        "pin" => {
            let ids = input
                .as_array()
                .expect("pin input is an array")
                .iter()
                .map(|v| EventId::from_hex(v.as_str().expect("pin id")).expect("vector id"))
                .collect::<Vec<_>>();
            pin_list(&ids)
        }
        "bookmark" => {
            let events = input["e"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .map(|v| {
                            EventId::from_hex(v.as_str().expect("bookmark id")).expect("vector id")
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let addresses = input["a"]
                .as_array()
                .map(|addrs| {
                    addrs
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .expect("bookmark a")
                                .parse::<EventAddress>()
                                .expect("vector address")
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            bookmark_list(&events, &addresses)
        }
        other => panic!("build {}: unknown op {other}", case.name),
    };
    let unsigned = builder.build_at(
        PublicKey::from_hex("166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99")
            .expect("pubkey"),
        Timestamp::from_secs(0),
    );
    (
        unsigned.kind().as_u16(),
        unsigned.content().to_owned(),
        unsigned
            .tags()
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect(),
    )
}

#[test]
fn parse_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        let got = parse_op(case).expect("known vector op");
        match (got, &case.out, &case.err) {
            (Ok(got), Some(expected), _) => {
                assert_eq!(&got, expected, "parse {}", case.name);
            }
            (Err(error), _, Some(err)) => {
                let kind = match err.as_str() {
                    "EventValidationError" => nk_nips::ErrorKind::EventValidation,
                    other => panic!("parse {}: unknown error class {other}", case.name),
                };
                assert_eq!(error.kind(), kind, "parse {}", case.name);
            }
            (Ok(_), None, _) => panic!("parse {}: expected error, got output", case.name),
            (Err(error), Some(_), _) => panic!("parse {}: expected output, got {error}", case.name),
            (Err(error), None, None) => {
                panic!("parse {}: {error} with no expectation", case.name)
            }
        }
    }
}

#[test]
fn build_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.build {
        if !case.rust {
            // TS-only inputs carry values the typed Rust API cannot express
            // (non-hex pubkeys/ids, malformed `a` coordinates).
            continue;
        }
        let (kind, content, tags) = build_op(case);
        let expect = case.builder.as_ref().expect("build case has builder");
        assert_eq!(u64::from(kind), expect.kind, "build {}", case.name);
        assert_eq!(content, expect.content, "build {}", case.name);
        assert_eq!(tags, expect.tags, "build {}", case.name);
        assert!(
            case.err.is_none(),
            "build {} unexpectedly errored",
            case.name
        );
    }
}

#[test]
fn encrypt_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.private.encrypt {
        if !case.rust {
            // `Tags` cannot carry the empty inner tag this case records.
            continue;
        }
        let tags: nk_core::Tags = case
            .tags
            .iter()
            .map(|items| Tag::new(items.iter().cloned()).expect("vector tag"))
            .collect();
        let mut rng = StreamRng::new(&case.nonce);
        let content = encrypt_private_tags_with_rng(&keys(&case.secret_key), &tags, &mut rng)
            .expect("encrypt");
        assert_eq!(content, case.content, "encrypt {}", case.name);
    }
}

#[test]
fn decrypt_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.private.decrypt {
        let keys = keys(&case.secret_key);
        // `decrypt_private_tags` only reads the declared author and content —
        // deserialize so the event carries `pubkey` verbatim (foreign-author
        // cases declare a key the signer does not hold). id/sig need only be
        // well-formed hex.
        let event: nk_core::Event = serde_json::from_value(json!({
            "id": "01".repeat(32),
            "pubkey": case.pubkey,
            "created_at": 0,
            "kind": 10000,
            "tags": [],
            "content": case.content,
            "sig": "02".repeat(64),
        }))
        .expect("vector event");
        match (decrypt_private_tags(&keys, &event), &case.out, &case.err) {
            (Ok(tags), Some(expected), _) => {
                let got = tags_json(&tags);
                let want = json!(expected);
                assert_eq!(got, want, "decrypt {}", case.name);
                let items = mute_items_json(&mute_items(&tags));
                let expected_items = case.items.as_ref().expect("decrypt case has items");
                assert_eq!(&items, expected_items, "items {}", case.name);
            }
            (Err(error), _, Some(err)) => {
                let kind = match err.as_str() {
                    "EventValidationError" => nk_nips::ErrorKind::EventValidation,
                    "CryptoError" => nk_nips::ErrorKind::Crypto,
                    other => panic!("decrypt {}: unknown error class {other}", case.name),
                };
                assert_eq!(error.kind(), kind, "decrypt {}", case.name);
            }
            (Ok(_), None, _) => panic!("decrypt {}: expected error, got tags", case.name),
            (Err(error), Some(_), _) => {
                panic!("decrypt {}: expected tags, got {error}", case.name)
            }
            (Err(error), None, None) => {
                panic!("decrypt {}: {error} with no expectation", case.name)
            }
        }
    }
}
