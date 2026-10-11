//! Executes `vectors/nip10/codec.json` against rust-nostr's public API.

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
use nostr::nips::nip10::TextNoteReplyBuilder;
use nostr::prelude::{
    Event, EventBuilder, FinalizeUnsignedEvent, IntoEventBuilder, PublicKey, RelayUrl, Timestamp,
};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip10/codec.json"
));

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct Codec {
    parse: Vec<ParseCase>,
    reply: Vec<ReplyCase>,
}

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    #[allow(dead_code, reason = "the parse direction has no rust-nostr API")]
    tags: Vec<serde_json::Value>,
    #[allow(dead_code, reason = "the parse direction has no rust-nostr API")]
    out: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ReplyToExpect {
    content: String,
    kind: u64,
}

#[derive(Deserialize)]
struct ReplyCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    parent: serde_json::Value,
    relay_hint: Option<String>,
    #[serde(default)]
    quotes: Vec<serde_json::Value>,
    reply_to: Option<ReplyToExpect>,
    out_tags: Option<Vec<Vec<String>>>,
    err: Option<String>,
}

fn parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        if !case.rust {
            continue;
        }
        // rust-nostr exposes `Marker`/`Nip10Tag` for building but no public
        // thread reconstruction from a tag list.
        check.skip(&case.name);
    }
}

fn pubkey() -> PublicKey {
    PublicKey::from_hex("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
        .expect("constant hex")
}

fn reply_builder(case: &ReplyCase, content: &str) -> Option<EventBuilder> {
    let parent: Event = serde_json::from_value(case.parent.clone()).ok()?;
    let mut builder = TextNoteReplyBuilder::new(content, &parent);
    if let Some(hint) = &case.relay_hint {
        builder = builder.relay_hint(RelayUrl::parse(hint).ok()?);
    }
    Some(builder.into_event_builder())
}

fn tag_rows(builder: &EventBuilder) -> Vec<Vec<String>> {
    builder
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect()
}

fn reply_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.reply {
        if !case.rust {
            continue;
        }
        if !case.quotes.is_empty() {
            // `TextNoteReplyBuilder` has no quote support.
            check.skip(&case.name);
            continue;
        }
        let got;
        let agrees;
        if let Some(expect) = &case.reply_to {
            if let Some(builder) = reply_builder(case, &expect.content) {
                let unsigned = builder
                    .custom_created_at(Timestamp::from_secs(0))
                    .finalize_unsigned(pubkey());
                let tags: Vec<Vec<String>> = unsigned
                    .tags
                    .iter()
                    .map(|tag| tag.as_slice().to_vec())
                    .collect();
                agrees = u64::from(unsigned.kind.as_u16()) == expect.kind
                    && unsigned.content == expect.content
                    && case.out_tags.as_ref().is_none_or(|e| &tags == e);
                got = format!("kind={} tags={tags:?}", unsigned.kind.as_u16());
            } else {
                agrees = false;
                got = "input not expressible".to_owned();
            }
        } else if case.err.is_some() {
            // The vector expects construction to fail;
            // TextNoteReplyBuilder is infallible.
            agrees = false;
            got = "builder has no error path".to_owned();
        } else if let Some(builder) = reply_builder(case, "") {
            let tags = tag_rows(&builder);
            agrees = case.out_tags.as_ref() == Some(&tags);
            got = format!("tags={tags:?}");
        } else {
            agrees = false;
            got = "input not expressible".to_owned();
        }
        check.check(&case.name, agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip10.thread");
    parse_cases(&mut check);
    reply_cases(&mut check);
    check.finish();
}
