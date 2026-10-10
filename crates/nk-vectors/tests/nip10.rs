//! `vectors/nip10/codec.json` — NIP-10 `parse_thread_tags`, `reply_tags`, and
//! `reply_to` cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip10.test.ts`; regenerate with
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

mod common;

use nk::nips::nip10::{Quote, parse_thread_tags, reply_tags, reply_to};
use nk::nips::nip19::{AddressPointer, EventPointer};
use nk::{Event, EventId, Kind, PublicKey, RelayUrl, Tags, Timestamp};
use serde::Deserialize;

use common::{ThreadJson, thread_json};

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
    tags: Vec<serde_json::Value>,
    out: Option<serde_json::Value>,
}

/// TS `QuoteInput` minus the raw-string convenience form (those cases are
/// `rust: false`): typed event and address pointers.
#[derive(Deserialize)]
#[serde(untagged)]
enum QuoteInput {
    Event {
        id: String,
        relays: Option<Vec<String>>,
        author: Option<String>,
    },
    Address {
        identifier: String,
        pubkey: String,
        kind: u64,
        relays: Option<Vec<String>>,
    },
}

impl QuoteInput {
    fn quote(&self) -> Quote {
        match self {
            Self::Event { id, relays, author } => Quote::Event(EventPointer {
                id: EventId::from_hex(id).expect("vector quote id"),
                relays: relays.clone().unwrap_or_default(),
                author: author
                    .as_deref()
                    .map(|a| PublicKey::from_hex(a).expect("vector quote author")),
                kind: None,
            }),
            Self::Address {
                identifier,
                pubkey,
                kind,
                relays,
            } => Quote::Address(AddressPointer {
                identifier: identifier.clone(),
                pubkey: PublicKey::from_hex(pubkey).expect("vector quote pubkey"),
                kind: Kind::new(u16::try_from(*kind).expect("vector quote kind")),
                relays: relays.clone().unwrap_or_default(),
            }),
        }
    }
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

/// TS accepts `{ tags }` with raw arrays; `nk`'s `Tags` only rejects the
/// empty inner arrays TS tolerates, so build it tag by tag (same rule the
/// `nip10.thread` diff replay uses). Cases marked `rust: false` carry
/// non-string elements and never reach here.
fn tags_of(raw: &[serde_json::Value]) -> Tags {
    raw.iter()
        .map(|items| {
            serde_json::from_value::<Vec<String>>(items.clone())
                .expect("rust-shared tags are string arrays")
        })
        .filter(|items| !items.is_empty())
        .map(|items| nk::Tag::new(items.iter().cloned()).expect("vector tag"))
        .collect()
}

fn relay_url(s: &str) -> RelayUrl {
    RelayUrl::parse(s).expect("vector relay hint must normalize")
}

#[test]
fn parse_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        if !case.rust {
            // TS-only inputs (null/non-string elements) cannot exist in a
            // `Tags` on the Rust side.
            continue;
        }
        let thread = parse_thread_tags(&tags_of(&case.tags));
        let expected: ThreadJson =
            serde_json::from_value(case.out.clone().expect("parse case without out"))
                .unwrap_or_else(|e| panic!("parse {}: bad out: {e}", case.name));
        assert_eq!(thread_json(&thread), expected, "parse {}", case.name);
    }
}

#[test]
fn reply_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.reply {
        if !case.rust {
            continue;
        }
        let parent: Event = serde_json::from_value(case.parent.clone())
            .unwrap_or_else(|e| panic!("reply {}: bad parent event: {e}", case.name));
        let quotes: Vec<Quote> = case
            .quotes
            .iter()
            .map(|raw| {
                serde_json::from_value::<QuoteInput>(raw.clone())
                    .unwrap_or_else(|e| panic!("reply {}: bad quote: {e}", case.name))
                    .quote()
            })
            .collect();
        let hint = case.relay_hint.as_deref().map(relay_url);

        let built = case.reply_to.as_ref().map_or_else(
            || reply_tags(&parent, hint.as_ref(), &quotes),
            |expect| match reply_to(&parent, &expect.content, hint.as_ref(), &quotes) {
                Ok(builder) => {
                    let unsigned = builder.build_at(
                        PublicKey::from_hex(
                            "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45",
                        )
                        .expect("pubkey"),
                        Timestamp::from_secs(0),
                    );
                    assert_eq!(
                        u64::from(unsigned.kind().as_u16()),
                        expect.kind,
                        "reply_to {} kind",
                        case.name
                    );
                    assert_eq!(
                        unsigned.content(),
                        expect.content,
                        "reply_to {} content",
                        case.name
                    );
                    Ok(unsigned.tags().clone())
                }
                Err(e) => Err(e),
            },
        );

        match (built, &case.out_tags, &case.err) {
            (Ok(tags), Some(expected), _) => {
                let got: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
                assert_eq!(&got, expected, "reply {}", case.name);
            }
            (Err(error), _, Some(err)) => {
                // The vector records the TS constructor name.
                let kind = match err.as_str() {
                    "EventValidationError" => nk::nips::ErrorKind::EventValidation,
                    other => panic!("reply {}: unknown error class {other}", case.name),
                };
                assert_eq!(error.kind(), kind, "reply {}", case.name);
            }
            (Ok(_), None, _) => panic!("reply {}: expected error, got tags", case.name),
            (Err(error), Some(_), _) => {
                panic!("reply {}: expected tags, got {error}", case.name)
            }
            (Err(error), None, None) => {
                panic!("reply {}: {error} with no expectation", case.name)
            }
        }
    }
}
