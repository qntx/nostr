//! vectors/nip51/codec.json — `nip51.lists`.

use nk_core::nips::nip51::{
    BookmarkList, EmojiSet, FavoriteRelays, FollowPack, MuteItem, MuteList, PinList, RelaySet,
    UserEmojiList,
};
#[cfg(feature = "nip44")]
use nk_core::nips::nip51::{decrypt_private_tags, encrypt_private_tags};
use nk_core::{Event, EventBuilder, EventId, PublicKey, Timestamp, UnsignedEvent};
#[cfg(feature = "nip44")]
use nk_core::{Keys, SecretKey, Tag, Tags};

use serde::Deserialize;
use serde_json::{Value, json};

#[cfg(feature = "nip44")]
use crate::common::{BytesRng, unhex_arr};

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    op: String,
    event: Value,
    #[serde(default)]
    out: Option<Value>,
    #[serde(default)]
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    op: String,
    input: Value,
    #[serde(default)]
    builder: Option<Value>,
    #[serde(default)]
    rust: Option<bool>,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct EncCase {
    name: String,
    secret_key: String,
    nonce: String,
    tags: Vec<Vec<String>>,
    content: String,
    #[serde(default)]
    rust: Option<bool>,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct DecCase {
    name: String,
    secret_key: String,
    pubkey: String,
    content: String,
    #[serde(default)]
    out: Option<Vec<Vec<String>>>,
    #[serde(default)]
    rust: Option<bool>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip51/codec.json"
));

fn event_from(v: &Value) -> Event {
    serde_json::from_value(v.clone()).unwrap()
}

fn mute_json(l: &MuteList) -> Value {
    json!(
        l.items()
            .iter()
            .map(|i| match i {
                MuteItem::PublicKey(p) => json!({"type": "pubkey", "value": p.to_hex()}),
                MuteItem::Event(e) => json!({"type": "event", "value": e.to_hex()}),
                MuteItem::Hashtag(t) => json!({"type": "hashtag", "value": t}),
                MuteItem::Word(w) => json!({"type": "word", "value": w}),
            })
            .collect::<Vec<_>>()
    )
}

#[test]
fn nip51_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ParseCase> = serde_json::from_value(doc["parse"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let event = event_from(&case.event);
        let got: Option<Value> = match case.op.as_str() {
            "mute" => MuteList::try_from(&event).ok().map(|l| mute_json(&l)),
            "pin" => PinList::try_from(&event)
                .ok()
                .map(|l| json!(l.ids().iter().map(|e| e.to_hex()).collect::<Vec<_>>())),
            "bookmark" => BookmarkList::try_from(&event).ok().map(|l| json!({
                "e": l.events.iter().map(|e| e.to_hex()).collect::<Vec<_>>(),
                "a": l.addresses,
            })),
            "user_emoji" => UserEmojiList::try_from(&event).ok().map(|l| json!({
                "emoji": l.emoji.iter().map(|e| json!({"shortcode": e.shortcode, "url": e.url})).collect::<Vec<_>>(),
                "sets": l.sets,
            })),
            "relay_set" => RelaySet::try_from(&event).ok().map(|l| json!({
                "d": l.identifier,
                "relays": l.relays.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
            })),
            "favorite_relays" => FavoriteRelays::try_from(&event).ok().map(|l| json!({
                "relays": l.relays.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
                "sets": l.sets,
            })),
            "emoji_set" => EmojiSet::try_from(&event).ok().map(|l| {
                let mut v = json!({
                    "d": l.identifier,
                    "emoji": l.emoji.iter().map(|e| json!({"shortcode": e.shortcode, "url": e.url})).collect::<Vec<_>>(),
                });
                if let Some(t) = &l.title {
                    v["title"] = json!(t);
                }
                v
            }),
            "follow_pack" => FollowPack::try_from(&event).ok().map(|l| json!({
                "d": l.identifier,
                "pubkeys": l.pubkeys.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
            })),
            other => panic!("unknown op {other}"),
        };
        match (&got, &case.out) {
            (Some(g), Some(w)) => assert_eq!(g, w, "{}", case.name),
            (None, None) => {}
            _ => panic!("{}: got {got:?}, want {:?}", case.name, case.out),
        }
    }
}

#[test]
fn nip51_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<BuildCase> = serde_json::from_value(doc["build"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let unsigned: UnsignedEvent = match case.op.as_str() {
            "mute" => {
                let items: Vec<MuteItem> = case
                    .input
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| {
                        let v = i["value"].as_str().unwrap();
                        match i["type"].as_str().unwrap() {
                            "pubkey" => MuteItem::PublicKey(PublicKey::from_hex(v).unwrap()),
                            "event" => MuteItem::Event(EventId::from_hex(v).unwrap()),
                            "hashtag" => MuteItem::Hashtag(v.to_owned()),
                            "word" => MuteItem::Word(v.to_owned()),
                            other => panic!("{}", other),
                        }
                    })
                    .collect();
                EventBuilder::from(MuteList::new(items)).build_at(
                    PublicKey::from_hex(&"11".repeat(32)).unwrap(),
                    Timestamp::from_secs(1),
                )
            }
            "pin" => {
                let ids: Vec<EventId> = case
                    .input
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| EventId::from_hex(s.as_str().unwrap()).unwrap())
                    .collect();
                EventBuilder::from(PinList::new(ids)).build_at(
                    PublicKey::from_hex(&"11".repeat(32)).unwrap(),
                    Timestamp::from_secs(1),
                )
            }
            "bookmark" => {
                let events: Vec<EventId> = case.input["e"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| EventId::from_hex(s.as_str().unwrap()).unwrap())
                    .collect();
                let addresses: Vec<String> = case.input["a"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect();
                EventBuilder::from(BookmarkList { events, addresses }).build_at(
                    PublicKey::from_hex(&"11".repeat(32)).unwrap(),
                    Timestamp::from_secs(1),
                )
            }
            other => panic!("{}", other),
        };
        let want = case
            .builder
            .as_ref()
            .unwrap_or_else(|| panic!("{}: builder", case.name));
        assert_eq!(
            u64::from(unsigned.kind().as_u16()),
            want["kind"].as_u64().unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            unsigned.content(),
            want["content"].as_str().unwrap(),
            "{}",
            case.name
        );
        let tags: Vec<Vec<String>> = unsigned
            .tags()
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        let want_tags: Vec<Vec<String>> = want["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                t.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_owned())
                    .collect()
            })
            .collect();
        assert_eq!(tags, want_tags, "{}", case.name);
    }
}

#[cfg(feature = "nip44")]
#[test]
fn nip51_private_encrypt() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<EncCase> = serde_json::from_value(doc["private"]["encrypt"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let keys = Keys::new(SecretKey::from_bytes(unhex_arr(&case.secret_key).unwrap()).unwrap());
        let tags: Tags = case
            .tags
            .iter()
            .filter_map(|t| Tag::new(t.clone()).ok())
            .collect();
        let mut rng = BytesRng(crate::common::unhex(&case.nonce).unwrap());
        let got = encrypt_private_tags(&keys, &tags, &mut rng).unwrap();
        assert_eq!(got, case.content, "{}", case.name);
    }
}

#[cfg(feature = "nip44")]
#[test]
fn nip51_private_decrypt() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<DecCase> = serde_json::from_value(doc["private"]["decrypt"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let keys = Keys::new(SecretKey::from_bytes(unhex_arr(&case.secret_key).unwrap()).unwrap());
        let event: Event = serde_json::from_value(json!({
            "pubkey": case.pubkey,
            "created_at": 1_700_000_000u64,
            "kind": 10000,
            "tags": [],
            "content": case.content,
            "id": "00".repeat(32),
            "sig": "11".repeat(64),
        }))
        .unwrap();
        match &case.out {
            Some(want) => {
                let tags = decrypt_private_tags(&keys, &event)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                let got: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
                assert_eq!(&got, want, "{}", case.name);
            }
            None => assert!(
                decrypt_private_tags(&keys, &event).is_err(),
                "{}",
                case.name
            ),
        }
    }
}
