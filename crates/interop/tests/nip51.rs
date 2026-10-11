//! Executes `vectors/nip51/codec.json` against rust-nostr's public API.

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
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip44::v2::{self, ConversationKey};
use nostr::nips::nip51::{Bookmarks, MuteList, PinnedNotes};
use nostr::prelude::{EventId, IntoEventBuilder, Keys, PublicKey, SecretKey};
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;

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
    #[allow(dead_code, reason = "nostr exposes no whole-event list parsers")]
    op: String,
    #[allow(dead_code, reason = "nostr exposes no whole-event list parsers")]
    event: Value,
    #[allow(dead_code, reason = "nostr exposes no whole-event list parsers")]
    out: Option<Value>,
    #[allow(dead_code, reason = "nostr exposes no whole-event list parsers")]
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
    #[allow(dead_code, reason = "the runner asserts only on success shape")]
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
    #[allow(dead_code, reason = "the declared author is not needed for decryption")]
    pubkey: String,
    content: String,
    out: Option<Vec<Vec<String>>>,
    #[allow(
        dead_code,
        reason = "the mute-item parse has no rust-nostr counterpart"
    )]
    items: Option<Vec<Value>>,
    err: Option<String>,
}

fn parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        check.skip(&format!("parse: {}", case.name));
    }
}

fn build_outcome(case: &BuildCase) -> Option<(u64, String, Vec<Vec<String>>)> {
    let input = &case.input;
    let builder = match case.op.as_str() {
        "mute" => {
            let items = input.as_array()?;
            let mut list = MuteList::default();
            for item in items {
                let kind = item["type"].as_str()?;
                let value = item["value"].as_str()?;
                match kind {
                    "pubkey" => list.public_keys.push(PublicKey::from_hex(value).ok()?),
                    "event" => list.event_ids.push(EventId::from_hex(value).ok()?),
                    "hashtag" => list.hashtags.push(value.to_owned()),
                    "word" => list.words.push(value.to_owned()),
                    _ => return None,
                }
            }
            list.into_event_builder()
        }
        "pin" => {
            let ids: Vec<EventId> = input
                .as_array()?
                .iter()
                .map(|v| EventId::from_hex(v.as_str()?).ok())
                .collect::<Option<_>>()?;
            PinnedNotes::new(ids).into_event_builder()
        }
        "bookmark" => {
            let events: Vec<EventId> = input["e"].as_array().and_then(|ids| {
                ids.iter()
                    .map(|v| EventId::from_hex(v.as_str()?).ok())
                    .collect::<Option<Vec<_>>>()
            })?;
            let coordinates: Vec<Coordinate> = input["a"].as_array().and_then(|addrs| {
                addrs
                    .iter()
                    .map(|v| Coordinate::from_str(v.as_str()?).ok())
                    .collect::<Option<Vec<_>>>()
            })?;
            Bookmarks {
                event_ids: events,
                coordinate: coordinates,
            }
            .into_event_builder()
        }
        _ => return None,
    };
    let tags: Vec<Vec<String>> = builder
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect();
    Some((u64::from(builder.kind.as_u16()), builder.content, tags))
}

fn build_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.build {
        if !case.rust {
            continue;
        }
        let outcome = build_outcome(case);
        let expect = case.builder.as_ref().expect("build case has builder");
        let agrees = outcome.as_ref().is_some_and(|(kind, content, tags)| {
            *kind == expect.kind && content == &expect.content && tags == &expect.tags
        });
        let got = outcome.map_or_else(
            || "input not expressible".to_owned(),
            |(_, _, tags)| format!("tags={tags:?}"),
        );
        check.check(&format!("build: {}", case.name), agrees, &got);
    }
}

fn conversation_key(secret_key: &str) -> Option<ConversationKey> {
    let keys = Keys::new(SecretKey::from_hex(secret_key).ok()?);
    ConversationKey::derive(keys.secret_key(), &keys.public_key()).ok()
}

fn private_encrypt_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.private.encrypt {
        if !case.rust {
            continue;
        }
        let outcome = (|| {
            let key = conversation_key(&case.secret_key)?;
            let nonce = common::unhex_arr::<32>(&case.nonce)?;
            let plaintext = serde_json::to_string(&case.tags).ok()?;
            let payload =
                v2::encrypt_to_bytes_with_nonce(&key, plaintext.as_bytes(), nonce).ok()?;
            Some(general_purpose::STANDARD.encode(&payload))
        })();
        let agrees = outcome.as_deref() == Some(case.content.as_str());
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&format!("encrypt: {}", case.name), agrees, &got);
    }
}

fn private_decrypt_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.private.decrypt {
        let outcome = (|| {
            let key = conversation_key(&case.secret_key)?;
            let payload = general_purpose::STANDARD.decode(&case.content).ok()?;
            let plaintext = v2::decrypt_to_bytes(&key, &payload).ok()?;
            serde_json::from_slice::<Vec<Vec<String>>>(&plaintext).ok()
        })();
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(tags)) => tags == expected,
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(|| "rejected".to_owned(), |tags| format!("tags={tags:?}"));
        check.check(&format!("decrypt: {}", case.name), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip51.lists");
    parse_cases(&mut check);
    build_cases(&mut check);
    private_encrypt_cases(&mut check);
    private_decrypt_cases(&mut check);
    check.finish();
}
