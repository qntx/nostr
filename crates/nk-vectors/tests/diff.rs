//! Differential replay for the TS ↔ `nk` parity harness (NK1-08).
//!
//! `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`
//! writes one JSONL file per capability (`{"capability","seed","count"}` meta
//! line, then `{"i","input","out"|"err"}` records). These tests replay every
//! input through `nk` and compare; a mismatch reports the capability id,
//! the seed, and the case index.
//!
//! Every test is `#[ignore]` so the regular `cargo test --workspace` does not
//! pass vacuously without inputs; run with `NK_DIFF_DIR=<dir> cargo test -p
//! nk-vectors --test diff -- --ignored`. `NK_DIFF_DIR` unset or empty fails.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a malformed fixture file or a divergence must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

mod common;

use nk::nips::nip10::parse_thread_tags;
use nk::nips::nip27::{ParseOptions, parse_content};
use nk::nips::nip46::{BunkerUri, NostrConnectUri};
use nk::nips::{nip19, nip44};
use nk::{ClientMessage, Event, Filter, PublicKey, RelayMessage, Tag, Tags, UnsignedEvent};
use serde::Deserialize;

use common::{EntityJson, blocks_json, encode_entity, entity_json, thread_json, unhex};

/// The generator's meta line; `seed` is reported on every mismatch.
#[derive(Deserialize)]
struct Meta {
    capability: String,
    seed: u64,
}

/// One generated case: `input` is raw JSON text; `out` is the TS output
/// (string or bool) and `err` the thrown error's class name.
#[derive(Deserialize)]
struct Case {
    i: u64,
    input: String,
    out: Option<serde_json::Value>,
    err: Option<String>,
}

struct Fixture {
    seed: u64,
    cases: Vec<Case>,
}

fn diff_dir() -> PathBuf {
    let dir = std::env::var("NK_DIFF_DIR").expect(
        "NK_DIFF_DIR is not set — generate cases with \
         `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`",
    );
    assert!(!dir.is_empty(), "NK_DIFF_DIR must not be empty");
    let path = PathBuf::from(dir);
    if path.is_absolute() {
        path
    } else {
        // Relative paths are taken from the workspace root: `cargo test` runs
        // integration tests with the package dir, not the workspace, as cwd.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    }
}

fn load(capability: &str) -> Fixture {
    let path = diff_dir().join(format!("{capability}.jsonl"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{capability}: cannot read {}: {error}", path.display()));
    let mut lines = text.lines();
    let meta: Meta = serde_json::from_str(
        lines
            .next()
            .unwrap_or_else(|| panic!("{capability}: {} is empty", path.display())),
    )
    .unwrap_or_else(|error| panic!("{capability}: bad meta line: {error}"));
    assert_eq!(
        meta.capability, capability,
        "{capability}: meta line names a different capability"
    );
    let cases = lines
        .map(|line| {
            serde_json::from_str::<Case>(line)
                .unwrap_or_else(|error| panic!("{capability}: bad case line {line:?}: {error}"))
        })
        .collect::<Vec<_>>();
    assert!(
        !cases.is_empty(),
        "{capability}: no cases in {}",
        path.display()
    );
    Fixture {
        seed: meta.seed,
        cases,
    }
}

fn fail(capability: &str, seed: u64, case: &Case, detail: &str) -> ! {
    panic!(
        "{capability} seed {} case {}: {detail}\ninput: {}",
        seed, case.i, case.input
    );
}

/// Recomputes one case: `run` returns `Some(output)` on success or `None`
/// when `nk` rejects the input (matching `err` on the TS side).
fn check<F>(capability: &str, seed: u64, case: &Case, run: F)
where
    F: FnOnce(&str) -> Option<serde_json::Value>,
{
    match (run(&case.input), &case.out) {
        (Some(got), Some(expected)) if &got == expected => {}
        (Some(got), Some(expected)) => fail(
            capability,
            seed,
            case,
            &format!("output mismatch: expected {expected}, got {got}"),
        ),
        (Some(got), None) => fail(
            capability,
            seed,
            case,
            &format!(
                "TS threw {} but Rust produced {got}",
                case.err.as_deref().unwrap_or("<none>")
            ),
        ),
        (None, Some(expected)) => fail(
            capability,
            seed,
            case,
            &format!("Rust rejected; TS produced {expected}"),
        ),
        (None, None) => {}
    }
}

const fn json_str(s: String) -> serde_json::Value {
    serde_json::Value::String(s)
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_event_serialize() {
    let fixture = load("core.event.serialize");
    for case in &fixture.cases {
        check("core.event.serialize", fixture.seed, case, |input| {
            serde_json::from_str::<UnsignedEvent>(input)
                .ok()
                .map(|unsigned| json_str(unsigned.canonical_json()))
        });
    }
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_event_id() {
    let fixture = load("core.event.id");
    for case in &fixture.cases {
        check("core.event.id", fixture.seed, case, |input| {
            serde_json::from_str::<UnsignedEvent>(input)
                .ok()
                .map(|unsigned| json_str(unsigned.id().to_hex()))
        });
    }
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_filter_match() {
    let fixture = load("core.filter.match");
    for case in &fixture.cases {
        check("core.filter.match", fixture.seed, case, |input| {
            #[derive(Deserialize)]
            struct MatchInput {
                filter: Filter,
                event: Event,
            }
            let parsed: MatchInput = serde_json::from_str(input).ok()?;
            Some(serde_json::Value::Bool(
                parsed.filter.matches(&parsed.event),
            ))
        });
    }
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_filter_canonicalize() {
    let fixture = load("core.filter.canonicalize");
    for case in &fixture.cases {
        check("core.filter.canonicalize", fixture.seed, case, |input| {
            serde_json::from_str::<Filter>(input)
                .ok()
                .map(|filter| json_str(filter.canonical_json()))
        });
    }
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_message_client() {
    let fixture = load("core.message.client");
    for case in &fixture.cases {
        check("core.message.client", fixture.seed, case, |input| {
            ClientMessage::from_json(input)
                .ok()
                .map(|message| json_str(message.to_json()))
        });
    }
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_message_relay() {
    let fixture = load("core.message.relay");
    for case in &fixture.cases {
        check("core.message.relay", fixture.seed, case, |input| {
            RelayMessage::from_json(input)
                .ok()
                .map(|message| json_str(message.to_json()))
        });
    }
}

/// One `nip19.codec` input: `{"op":"encode","entity":…}` or
/// `{"op":"decode","input":"…"}`.
/// `nip10.thread` inputs are `{"tags": [[…]]}` — raw arrays, so non-string or
/// non-array elements fail the `Vec<Vec<String>>` decode while TS throws
/// inside the scan (the `None`/`err` arms pair up). Empty inner arrays are
/// the holes `Tags` cannot carry and TS skips.
#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip10_thread() {
    let fixture = load("nip10.thread");
    for case in &fixture.cases {
        check("nip10.thread", fixture.seed, case, |input| {
            #[derive(Deserialize)]
            struct ThreadInput {
                tags: Vec<Vec<String>>,
            }
            let parsed: ThreadInput = serde_json::from_str(input).ok()?;
            let tags: Tags = parsed
                .tags
                .iter()
                .filter(|items| !items.is_empty())
                .map(|items| Tag::new(items.iter().cloned()).expect("diff tag"))
                .collect();
            Some(
                serde_json::to_value(thread_json(&parse_thread_tags(&tags)))
                    .expect("thread serializes"),
            )
        });
    }
}

/// `nip46.uri` inputs carry `{"client": …}` for the `nostrconnect://`
/// round-trip or `{"pubkey": …}` for `bunker://`; `out` records the produced
/// URI plus the fields the TS parse recovered from it.
#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip46_uri() {
    let fixture = load("nip46.uri");
    for case in &fixture.cases {
        check("nip46.uri", fixture.seed, case, |input| {
            #[derive(Deserialize)]
            struct UriInput {
                pubkey: Option<String>,
                client: Option<String>,
                relays: Vec<String>,
                secret: Option<String>,
                perms: Option<Vec<String>>,
                name: Option<String>,
                url: Option<String>,
                image: Option<String>,
            }
            let input: UriInput = serde_json::from_str(input).ok()?;
            if let Some(client) = &input.client {
                let uri = NostrConnectUri {
                    client_pubkey: PublicKey::from_hex(client).ok()?,
                    relays: input.relays.clone(),
                    secret: input.secret.clone().unwrap_or_default(),
                    perms: input.perms.clone().unwrap_or_default(),
                    name: input.name.clone(),
                    url: input.url.clone(),
                    image: input.image.clone(),
                }
                .to_uri()
                .ok()?;
                // Re-parse the URI like the TS side does: a serialization bug
                // must not hide behind a shared encoder.
                let parsed = NostrConnectUri::parse(&uri).ok()?;
                Some(serde_json::json!({
                    "uri": uri,
                    "parsed": {
                        "clientPubkey": parsed.client_pubkey.to_hex(),
                        "relays": parsed.relays,
                        "secret": parsed.secret,
                        "perms": parsed.perms,
                        "name": parsed.name,
                        "url": parsed.url,
                        "image": parsed.image,
                    },
                }))
            } else {
                let uri = BunkerUri {
                    pubkey: PublicKey::from_hex(input.pubkey.as_deref()?).ok()?,
                    relays: input.relays.clone(),
                    secret: input.secret.clone(),
                }
                .to_string();
                let parsed = BunkerUri::parse(&uri)?;
                Some(serde_json::json!({
                    "uri": uri,
                    "parsed": {
                        "pubkey": parsed.pubkey.to_hex(),
                        "relays": parsed.relays,
                        "secret": parsed.secret,
                    },
                }))
            }
        });
    }
}

#[derive(Deserialize)]
struct Nip19Case {
    op: String,
    entity: Option<EntityJson>,
    input: Option<String>,
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip19_codec() {
    let fixture = load("nip19.codec");
    for case in &fixture.cases {
        check("nip19.codec", fixture.seed, case, |input| {
            let req: Nip19Case = serde_json::from_str(input).ok()?;
            if req.op == "encode" {
                return encode_entity(&req.entity?).ok().map(json_str);
            }
            nip19::decode(&req.input?).ok().map(|entity| {
                serde_json::to_value(entity_json(&entity)).expect("entity serializes")
            })
        });
    }
}

/// One `nip27.tokenize` input: `{"content": "…", "tags"?: [[…]],
/// "legacy"?: bool, "imeta"?: {url: mime}}` — adversarial content fragments.
#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip27_tokenize() {
    let fixture = load("nip27.tokenize");
    for case in &fixture.cases {
        check("nip27.tokenize", fixture.seed, case, |input| {
            #[derive(Deserialize)]
            struct TokenizeInput {
                content: String,
                tags: Option<Vec<Vec<String>>>,
                legacy: Option<bool>,
                imeta: Option<BTreeMap<String, String>>,
            }
            let parsed: TokenizeInput = serde_json::from_str(input).ok()?;
            let tags: Option<Tags> = parsed.tags.map(|items| {
                items
                    .iter()
                    .filter(|tag| !tag.is_empty())
                    .map(|tag| Tag::new(tag.iter().cloned()).expect("diff tag"))
                    .collect()
            });
            let options = ParseOptions {
                legacy_bech32: parsed.legacy.unwrap_or(false),
                imeta: parsed.imeta.as_ref(),
            };
            let blocks = parse_content(&parsed.content, tags.as_ref(), options);
            Some(blocks_json(&blocks))
        });
    }
}

/// Like [`check`], but `run` reports the error class (the thrown error's
/// `constructor.name` on the TS side) so a HexError/CryptoError split is
/// compared, not just success/failure.
fn check_classed<F>(capability: &str, seed: u64, case: &Case, run: F)
where
    F: FnOnce(&str) -> Result<serde_json::Value, &'static str>,
{
    match (run(&case.input), &case.out, &case.err) {
        (Ok(got), Some(expected), _) if &got == expected => {}
        (Ok(got), Some(expected), _) => fail(
            capability,
            seed,
            case,
            &format!("output mismatch: expected {expected}, got {got}"),
        ),
        (Ok(got), None, err) => fail(
            capability,
            seed,
            case,
            &format!(
                "TS threw {} but Rust produced {got}",
                err.as_deref().unwrap_or("<none>")
            ),
        ),
        (Err(kind), Some(expected), _) => fail(
            capability,
            seed,
            case,
            &format!("Rust rejected ({kind}); TS produced {expected}"),
        ),
        (Err(kind), None, Some(expected)) if kind == expected.as_str() => {}
        (Err(kind), None, err) => fail(
            capability,
            seed,
            case,
            &format!(
                "error class mismatch: TS recorded {}, Rust rejected with {kind}",
                err.as_deref().unwrap_or("<none>")
            ),
        ),
    }
}

/// One `nip44.v2` input: `{"op":"encrypt","conversation_key","nonce",
/// "plaintext"}` or `{"op":"decrypt","conversation_key","payload"}`.
#[derive(Deserialize)]
struct Nip44Case {
    op: String,
    conversation_key: Option<String>,
    nonce: Option<String>,
    plaintext: Option<String>,
    payload: Option<String>,
}

fn crypto_err<E>(_: E) -> &'static str {
    "CryptoError"
}

/// Parses a hex field the way TS `hexToBytes` does: malformed hex is a
/// `HexError`; the width check is the caller's (`assert32` → `CryptoError`).
fn unhexed(field: Option<&str>) -> Result<Vec<u8>, &'static str> {
    unhex(field.unwrap_or("")).ok_or("HexError")
}

#[test]
#[ignore = "requires NK_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip44_v2() {
    let fixture = load("nip44.v2");
    for case in &fixture.cases {
        check_classed("nip44.v2", fixture.seed, case, |input| {
            let req: Nip44Case = serde_json::from_str(input).expect("generator emits valid JSON");
            match req.op.as_str() {
                // TS evaluates `hexToBytes` on both arguments before encrypt
                // asserts their widths, so all hex errors precede all length
                // errors.
                "encrypt" => {
                    let key = unhexed(req.conversation_key.as_deref())?;
                    let nonce = unhexed(req.nonce.as_deref())?;
                    let key: [u8; 32] = key.try_into().map_err(|_| "CryptoError")?;
                    let nonce: [u8; 32] = nonce.try_into().map_err(|_| "CryptoError")?;
                    nip44::encrypt_with_nonce(
                        req.plaintext.as_deref().unwrap_or(""),
                        &nip44::ConversationKey::from_bytes(key),
                        &nonce,
                    )
                    .map(json_str)
                    .map_err(crypto_err)
                }
                "decrypt" => {
                    let key: [u8; 32] = unhexed(req.conversation_key.as_deref())?
                        .try_into()
                        .map_err(|_| "CryptoError")?;
                    nip44::decrypt(
                        req.payload.as_deref().unwrap_or(""),
                        &nip44::ConversationKey::from_bytes(key),
                    )
                    .map(json_str)
                    .map_err(crypto_err)
                }
                _ => Err("Error"),
            }
        });
    }
}
