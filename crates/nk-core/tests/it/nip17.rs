//! vectors/nip17/codec.json — `nip17.wrap`/`chat`/`normalize`/`relay_list`.

use nk_core::nips::nip17::DmRelayList;
use nk_core::{Event, PublicKey, Timestamp};

#[cfg(feature = "nip44")]
use serde::Deserialize;
use serde_json::Value;

#[cfg(feature = "nip44")]
use crate::common::{BytesRng, unhex, unhex_arr};
#[cfg(feature = "nip44")]
use nk_core::RelayUrl;
#[cfg(feature = "nip44")]
use nk_core::nips::nip17::{ChatMessage, Recipient, ReplyTo, wrap_direct_message};
#[cfg(feature = "nip44")]
use nk_core::nips::nip59::{Rumor, Timestamps, WrapOptions};
#[cfg(feature = "nip44")]
use nk_core::{Keys, SecretKey};
#[cfg(feature = "nip44")]
use serde_json::json;

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct WrapCase {
    name: String,
    #[serde(default)]
    rust: Option<bool>,
    sender_secret_key: String,
    recipients: Vec<Recip>,
    rumor: Value,
    options: Value,
    #[serde(default)]
    entropy: Option<String>,
    #[serde(default)]
    output: Option<Vec<WrapOut>>,
    #[serde(default)]
    error: Option<String>,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct Recip {
    pubkey: String,
    #[serde(default)]
    relay_hint: Option<String>,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct WrapOut {
    recipient: String,
    wrap: Value,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct ChatCase {
    name: String,
    #[serde(default)]
    rust: Option<bool>,
    sender: String,
    recipients: Vec<Recip>,
    content: String,
    created_at: u64,
    options: Value,
    #[serde(default)]
    rumor: Option<Value>,
}

#[cfg(feature = "nip44")]
#[derive(Deserialize)]
struct NormCase {
    name: String,
    input: Vec<Value>,
    output: Vec<Recip>,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip17/codec.json"
));

#[cfg(feature = "nip44")]
fn recipient(r: &Recip) -> Recipient {
    Recipient {
        pubkey: PublicKey::from_hex(&r.pubkey).unwrap(),
        relay_hint: r.relay_hint.as_deref().map(|s| RelayUrl::parse(s).unwrap()),
    }
}

#[cfg(feature = "nip44")]
fn wrap_options(v: &Value) -> WrapOptions {
    let timestamps = match &v["timestamps"] {
        t if t.is_object() => Timestamps::Fixed {
            seal: Timestamp::from_secs(t["seal"].as_u64().unwrap()),
            wrap: Timestamp::from_secs(t["wrap"].as_u64().unwrap()),
        },
        _ => Timestamps::Random {
            now: Timestamp::from_secs(v["now"].as_u64().unwrap()),
            scope: match v["randomize"].as_str().unwrap_or("seal+wrap") {
                "wrap" => nk_core::nips::nip59::RandomScope::WrapOnly,
                _ => nk_core::nips::nip59::RandomScope::SealAndWrap,
            },
        },
    };
    let mut o = WrapOptions::new(timestamps);
    if let Some(e) = v.get("ephemeral").and_then(Value::as_bool) {
        o = o.ephemeral(e);
    }
    if let Some(e) = v.get("expiration").and_then(Value::as_u64) {
        o = o.expiration(Timestamp::from_secs(e));
    }
    o
}

#[cfg(feature = "nip44")]
#[test]
fn nip17_wrap() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<WrapCase> = serde_json::from_value(doc["wrap"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let sender =
            Keys::new(SecretKey::from_bytes(unhex_arr(&case.sender_secret_key).unwrap()).unwrap());
        let recipients: Vec<Recipient> = case.recipients.iter().map(recipient).collect();
        let rumor = Rumor::new(serde_json::from_value(case.rumor.clone()).unwrap());
        let options = wrap_options(&case.options);
        let mut rng = BytesRng(unhex(case.entropy.as_deref().unwrap_or("")).unwrap());
        let got = wrap_direct_message(&sender, &recipients, &rumor, &options, &mut rng);
        match (&case.output, &case.error) {
            (Some(want), None) => {
                let out = got.unwrap_or_else(|e| panic!("{}: {e}", case.name));
                let got_pairs: Vec<(String, Value)> = out
                    .iter()
                    .map(|(pk, ev)| (pk.to_hex(), serde_json::to_value(ev).unwrap()))
                    .collect();
                let want_pairs: Vec<(String, Value)> = want
                    .iter()
                    .map(|w| (w.recipient.clone(), w.wrap.clone()))
                    .collect();
                assert_eq!(got_pairs, want_pairs, "{}", case.name);
            }
            (None, Some(_)) => assert!(got.is_err(), "{}", case.name),
            _ => panic!("{}: output xor error", case.name),
        }
    }
}

#[cfg(feature = "nip44")]
#[test]
fn nip17_chat() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ChatCase> = serde_json::from_value(doc["chat"].clone()).unwrap();
    for case in &cases {
        if case.rust == Some(false) {
            continue;
        }
        let recipients: Vec<Recipient> = case.recipients.iter().map(recipient).collect();
        let mut msg = ChatMessage::new(recipients, &case.content);
        if let Some(s) = case.options.get("subject").and_then(Value::as_str) {
            msg = msg.subject(s);
        }
        if let Some(r) = case.options.get("reply_to") {
            msg = msg.reply_to(ReplyTo {
                id: nk_core::EventId::from_hex(r["id"].as_str().unwrap()).unwrap(),
                relay_hint: r
                    .get("relay_hint")
                    .and_then(Value::as_str)
                    .map(|s| RelayUrl::parse(s).unwrap()),
            });
        }
        let rumor = msg.into_rumor(
            PublicKey::from_hex(&case.sender).unwrap(),
            Timestamp::from_secs(case.created_at),
        );
        let Some(want) = &case.rumor else {
            assert!(rumor.is_err(), "{}", case.name);
            continue;
        };
        let rumor = rumor.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let got = serde_json::to_value(rumor.unsigned()).unwrap();
        // The vector `rumor` includes a computed `id`; compare the unsigned
        // fields (kind/content/tags/created_at/pubkey).
        for key in ["kind", "content", "created_at", "pubkey"] {
            assert_eq!(&got[key], &want[key], "{} {key}", case.name);
        }
        assert_eq!(&got["tags"], &want["tags"], "{} tags", case.name);
    }
}

#[cfg(feature = "nip44")]
#[test]
fn nip17_normalize() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<NormCase> = serde_json::from_value(doc["normalize"].clone()).unwrap();
    for case in &cases {
        // Strings become bare recipients; objects carry relay hints.
        let recipients: Vec<Recipient> = case
            .input
            .iter()
            .map(|v| match v {
                Value::String(s) => Recipient {
                    pubkey: PublicKey::from_hex(s).unwrap(),
                    relay_hint: None,
                },
                Value::Object(_) => recipient(&serde_json::from_value::<Recip>(v.clone()).unwrap()),
                _ => panic!("{}: bad input", case.name),
            })
            .collect();
        // Normalization runs inside `ChatMessage::new`; the `p` tags of the
        // rumor carry the normalized recipients in order.
        let rumor = ChatMessage::new(recipients, "x")
            .into_rumor(
                PublicKey::from_hex(&"22".repeat(32)).unwrap(),
                Timestamp::from_secs(1_700_000_000),
            )
            .unwrap();
        let got: Vec<Value> = rumor
            .unsigned()
            .tags()
            .iter()
            .filter(|t| t.name() == "p")
            .map(|t| {
                let mut v = json!({"pubkey": t.value().unwrap()});
                if let Some(hint) = t.as_slice().get(2) {
                    v["relay_hint"] = json!(hint);
                }
                v
            })
            .collect();
        let want: Vec<Value> = case
            .output
            .iter()
            .map(|r| {
                let mut v = json!({"pubkey": r.pubkey});
                if let Some(h) = &r.relay_hint {
                    v["relay_hint"] = json!(h);
                }
                v
            })
            .collect();
        assert_eq!(got, want, "{}", case.name);
    }
}

#[test]
fn nip17_relay_list_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Value> = serde_json::from_value(doc["relay_list"]["build"].clone()).unwrap();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let urls: Vec<&str> = case["relays"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if case.get("error").is_some() {
            assert!(DmRelayList::from_urls(urls).is_err(), "{name}");
            continue;
        }
        let list = DmRelayList::from_urls(urls).unwrap();
        let unsigned = nk_core::EventBuilder::from(list).build_at(
            PublicKey::from_hex(&"33".repeat(32)).unwrap(),
            Timestamp::from_secs(1),
        );
        let tags: Vec<Vec<String>> = unsigned
            .tags()
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        let want: Vec<Vec<String>> = case["tags"]
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
        assert_eq!(tags, want, "{name}");
    }
}

#[test]
fn nip17_relay_list_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<Value> = serde_json::from_value(doc["relay_list"]["parse"].clone()).unwrap();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        let Some(relays) = case.get("relays") else {
            assert!(DmRelayList::try_from(&event).is_err(), "{name}");
            continue;
        };
        let list = DmRelayList::try_from(&event).unwrap();
        let want: Vec<String> = relays
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s.as_str().map(str::to_owned))
            .collect();
        let got: Vec<String> = list.relays().iter().map(|u| u.to_string()).collect();
        assert_eq!(got, want, "{name}");
    }
}
