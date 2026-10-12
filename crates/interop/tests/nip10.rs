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
    #[allow(dead_code, reason = "the parse direction has no rust-nostr API")]
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
        // rust-nostr exposes `Marker`/`Nip10Tag` for building but no public
        // thread reconstruction from a tag list.
        check.skip(&case.name);
    }
}

fn pubkey() -> PublicKey {
    PublicKey::from_hex("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
        .expect("constant hex")
}

/// The parent's NIP-10 root, when the parent is itself a reply: the `e` tag
/// marked `root`. `TextNoteReplyBuilder::root` takes a whole `Event`, so the
/// root is reconstructed from the tag's id (and pubkey, when present).
enum Root {
    /// The parent is not a reply; the reply's root is the parent itself.
    Parent,
    /// The parent's root `e` tag carries id and pubkey.
    Known { id: String, pubkey: String },
    /// The parent's root is known only by id; the builder API cannot
    /// express it.
    Unexpressible,
}

fn parent_root(parent: &Event) -> Root {
    let Some(tag) = parent.tags.iter().find(|tag| {
        let slice = tag.as_slice();
        slice.first().map(String::as_str) == Some("e")
            && slice.get(3).map(String::as_str) == Some("root")
    }) else {
        return Root::Parent;
    };
    // `root()` takes an `Event` — only the root's id and pubkey survive; a
    // root relay hint of its own cannot be expressed.
    let relay = tag.as_slice().get(2).is_none_or(String::is_empty);
    match (relay, tag.as_slice().get(1), tag.as_slice().get(4)) {
        (true, Some(id), Some(public_key)) => Root::Known {
            id: id.clone(),
            pubkey: public_key.clone(),
        },
        _ => Root::Unexpressible,
    }
}

/// A bare `Event` shell carrying `id`/`pubkey` — `TextNoteReplyBuilder`
/// reads only those two fields of the root.
fn stub_event(id: &str, pubkey: &str) -> Option<Event> {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": 0,
        "kind": 1,
        "tags": [],
        "content": "",
        "sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    }))
    .ok()
}

fn reply_builder(case: &ReplyCase, content: &str) -> Option<EventBuilder> {
    let parent: Event = serde_json::from_value(case.parent.clone()).ok()?;
    let mut builder = TextNoteReplyBuilder::new(content, &parent);
    let root = match parent_root(&parent) {
        Root::Parent => parent.clone(),
        Root::Known { id, pubkey } => stub_event(&id, &pubkey)?,
        Root::Unexpressible => return None,
    };
    builder = builder.root(&root);
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
            check.skip(&case.name);
            continue;
        }
        if !case.quotes.is_empty() {
            // `TextNoteReplyBuilder` has no quote support.
            check.skip(&case.name);
            continue;
        }
        if case.err.is_some() {
            // The vector expects construction to fail;
            // TextNoteReplyBuilder is infallible, so there is no rust
            // error path to compare.
            check.skip(&case.name);
            continue;
        }
        if let Some(expect) = &case.reply_to {
            match reply_builder(case, &expect.content) {
                Some(builder) => {
                    let unsigned = builder
                        .custom_created_at(Timestamp::from_secs(0))
                        .finalize_unsigned(pubkey());
                    let tags: Vec<Vec<String>> = unsigned
                        .tags
                        .iter()
                        .map(|tag| tag.as_slice().to_vec())
                        .collect();
                    let agrees = u64::from(unsigned.kind.as_u16()) == expect.kind
                        && unsigned.content == expect.content
                        && case
                            .out_tags
                            .as_ref()
                            .is_none_or(|e| common::same_tag_multiset(e, &tags));
                    check.check(
                        &case.name,
                        agrees,
                        &format!("kind={} tags={tags:?}", unsigned.kind.as_u16()),
                    );
                }
                None => check.skip(&case.name),
            }
        } else {
            match reply_builder(case, "") {
                Some(builder) => {
                    let tags = tag_rows(&builder);
                    check.check(
                        &case.name,
                        case.out_tags
                            .as_ref()
                            .is_some_and(|e| common::same_tag_multiset(e, &tags)),
                        &format!("tags={tags:?}"),
                    );
                }
                None => check.skip(&case.name),
            }
        }
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip10.thread");
    parse_cases(&mut check);
    reply_cases(&mut check);
    check.finish();
}
