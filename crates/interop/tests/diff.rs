//! Differential replay of the TS parity streams against rust-nostr.
//!
//! `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`
//! writes one JSONL file per capability (`{"capability","seed","count"}` meta
//! line, then `{"i","input","out"|"err"}` records). These tests replay every
//! input through rust-nostr and count the divergences; the per-capability
//! summary (`{"capability","seed","total","diverged","samples"}`) is appended
//! to the file named by `INTEROP_DIFF_REPORT` and echoed on stderr. Stream
//! cases are generated, so they cannot be registered in `divergences.json`;
//! mismatches are reported, not asserted.
//!
//! Capabilities with no rust-nostr counterpart (`core.filter.canonicalize`,
//! `nip10.thread`, `nip27.tokenize`) have no replay here; `parity.json`
//! records them as `rust: null`.
//!
//! Every test is `#[ignore]` so the regular `cargo test --workspace` does not
//! pass vacuously without inputs; run with `INTEROP_DIFF_DIR=<dir> cargo test
//! -p qntx-nostr-interop --test diff -- --ignored`. `INTEROP_DIFF_DIR` unset
//! or empty fails.

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

use std::io::Write as _;
use std::path::PathBuf;

mod common;

use base64::Engine;
use base64::engine::general_purpose;
use nostr::nips::nip19::{FromBech32, Nip19};
use nostr::nips::nip44::v2::{self, ConversationKey};
use nostr::nips::nip46::{NostrConnectMetadata, NostrConnectUri};
use nostr::prelude::{
    ClientMessage, Event, Filter, MatchEventOptions, PublicKey, RelayMessage, RelayUrl, ToBech32,
    UnsignedEvent,
};
use serde::Deserialize;
use std::str::FromStr;
use url::Url;

use common::{EntityJson, entity_from_json, entity_json, unhex_arr};

/// The generator's meta line; `seed` is reported in the summary.
#[derive(Deserialize)]
struct Meta {
    capability: String,
    seed: u64,
}

/// One generated case: `input` is raw JSON text; `out` is the TS output
/// (string, bool or JSON) and `err` the thrown error's class name.
#[derive(Deserialize)]
struct Case {
    i: u64,
    input: String,
    out: Option<serde_json::Value>,
    #[allow(dead_code, reason = "rejection is signalled by a missing `out`")]
    err: Option<String>,
}

struct Fixture {
    seed: u64,
    cases: Vec<Case>,
}

fn diff_dir() -> PathBuf {
    let dir = std::env::var("INTEROP_DIFF_DIR").expect(
        "INTEROP_DIFF_DIR is not set — generate cases with \
         `bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out <dir>`",
    );
    assert!(!dir.is_empty(), "INTEROP_DIFF_DIR must not be empty");
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

/// Replays one capability: `run` returns `Some(output)` when rust-nostr
/// accepts the input, `None` on rejection — mirroring the TS `out`/`err`
/// split. Mismatches are counted and sampled, not asserted.
#[allow(
    clippy::print_stderr,
    reason = "the differential runner reports progress on stderr"
)]
fn replay<F>(capability: &str, run: F)
where
    F: Fn(&str) -> Option<serde_json::Value>,
{
    let fixture = load(capability);
    let mut diverged: u64 = 0;
    let mut samples: Vec<serde_json::Value> = Vec::new();
    for case in &fixture.cases {
        let agrees = match (run(&case.input), &case.out) {
            (Some(got), Some(expected)) => &got == expected,
            (None, None) => true,
            _ => false,
        };
        if !agrees {
            diverged += 1;
            if samples.len() < 5 {
                samples.push(serde_json::json!({
                    "i": case.i,
                    "input": case.input,
                }));
            }
        }
    }
    eprintln!(
        "{capability} seed {}: {diverged}/{} diverged",
        fixture.seed,
        fixture.cases.len()
    );
    if let Ok(path) = std::env::var("INTEROP_DIFF_REPORT") {
        use std::sync::Mutex;
        static REPORT_LOCK: Mutex<()> = Mutex::new(());
        let line = serde_json::json!({
            "capability": capability,
            "seed": fixture.seed,
            "total": fixture.cases.len(),
            "diverged": diverged,
            "samples": samples,
        });
        let _guard = REPORT_LOCK.lock();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("report file opens");
        writeln!(file, "{line}").expect("report line writes");
    }
}

const fn json_str(s: String) -> serde_json::Value {
    serde_json::Value::String(s)
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_event_serialize() {
    replay("core.event.serialize", |input| {
        // NIP-01 id preimage: `[0, pubkey, created_at, kind, tags, content]`.
        let unsigned: UnsignedEvent = serde_json::from_str(input).ok()?;
        serde_json::to_string(&(
            0,
            unsigned.pubkey.to_hex(),
            unsigned.created_at.as_secs(),
            unsigned.kind.as_u16(),
            &unsigned.tags,
            &unsigned.content,
        ))
        .ok()
        .map(json_str)
    });
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_event_id() {
    replay("core.event.id", |input| {
        serde_json::from_str::<UnsignedEvent>(input)
            .ok()
            .map(|unsigned| json_str(unsigned.compute_id().to_hex()))
    });
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_filter_match() {
    replay("core.filter.match", |input| {
        #[derive(Deserialize)]
        struct MatchInput {
            filter: Filter,
            event: Event,
        }
        let parsed: MatchInput = serde_json::from_str(input).ok()?;
        Some(serde_json::Value::Bool(
            parsed
                .filter
                .match_event(&parsed.event, MatchEventOptions::new()),
        ))
    });
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_message_client() {
    replay("core.message.client", |input| {
        ClientMessage::from_json(input)
            .ok()
            .map(|message| json_str(message.as_json()))
    });
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_message_relay() {
    replay("core.message.relay", |input| {
        RelayMessage::from_json(input)
            .ok()
            .map(|message| json_str(message.as_json()))
    });
}

/// `nip46.uri` inputs carry `{"client": …}` for the `nostrconnect://`
/// round-trip or `{"pubkey": …}` for `bunker://`; `out` records the produced
/// URI plus the fields the TS parse recovered from it.
#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip46_uri() {
    replay("nip46.uri", |input| {
        #[derive(Deserialize)]
        struct UriInput {
            pubkey: Option<String>,
            client: Option<String>,
            relays: Vec<String>,
            secret: Option<String>,
            #[allow(dead_code, reason = "nostr's nostrconnect model has no perms param")]
            perms: Option<Vec<String>>,
            name: Option<String>,
            url: Option<String>,
            image: Option<String>,
        }
        let input: UriInput = serde_json::from_str(input).ok()?;
        let relays: Vec<RelayUrl> = input
            .relays
            .iter()
            .map(|r| RelayUrl::parse(r).ok())
            .collect::<Option<_>>()?;
        if let Some(client) = &input.client {
            let mut metadata = NostrConnectMetadata::new(input.name.clone().unwrap_or_default());
            if let Some(url) = &input.url {
                metadata = metadata.url(Url::parse(url).ok()?);
            }
            if let Some(image) = &input.image {
                metadata = metadata.icons(vec![Url::parse(image).ok()?]);
            }
            let uri = NostrConnectUri::Client {
                public_key: PublicKey::from_hex(client).ok()?,
                relays,
                metadata,
                secret: input.secret.clone().unwrap_or_default(),
            }
            .to_string();
            // Re-parse like the TS side does: a serialization bug must not
            // hide behind a shared encoder.
            let parsed = NostrConnectUri::from_str(&uri).ok()?;
            let NostrConnectUri::Client {
                public_key,
                relays: parsed_relays,
                metadata: parsed_metadata,
                secret: parsed_secret,
            } = parsed
            else {
                return None;
            };
            Some(serde_json::json!({
                "uri": uri,
                "parsed": {
                    "clientPubkey": public_key.to_hex(),
                    "relays": parsed_relays.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "secret": parsed_secret,
                    "perms": Vec::<String>::new(),
                    "name": parsed_metadata.name,
                    "url": parsed_metadata.url.map(|u| u.to_string()),
                    "image": parsed_metadata.icons.and_then(|i| i.first().map(ToString::to_string)),
                },
            }))
        } else {
            let uri = NostrConnectUri::Bunker {
                remote_signer_public_key: PublicKey::from_hex(input.pubkey.as_deref()?).ok()?,
                relays,
                secret: input.secret.clone(),
            }
            .to_string();
            let parsed = NostrConnectUri::from_str(&uri).ok()?;
            let NostrConnectUri::Bunker {
                remote_signer_public_key,
                relays: parsed_relays,
                secret: parsed_secret,
            } = parsed
            else {
                return None;
            };
            Some(serde_json::json!({
                "uri": uri,
                "parsed": {
                    "pubkey": remote_signer_public_key.to_hex(),
                    "relays": parsed_relays.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "secret": parsed_secret,
                },
            }))
        }
    });
}

/// One `nip19.codec` input: `{"op":"encode","entity":…}` or
/// `{"op":"decode","input":"…"}`.
#[derive(Deserialize)]
struct Nip19Case {
    op: String,
    entity: Option<EntityJson>,
    input: Option<String>,
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip19_codec() {
    replay("nip19.codec", |input| {
        let req: Nip19Case = serde_json::from_str(input).ok()?;
        if req.op == "encode" {
            return entity_from_json(&req.entity?)
                .ok()
                .and_then(|entity| entity.to_bech32().ok())
                .map(json_str);
        }
        Nip19::from_bech32(&req.input?)
            .ok()
            .map(|entity| serde_json::to_value(entity_json(&entity)).expect("entity serializes"))
    });
}

/// One `nip44.v2` input: `{"op":"encrypt","conversation_key","nonce",
/// "plaintext"}` or `{"op":"decrypt","conversation_key","payload"}`.
/// `payload` is the base64-encoded NIP-44 payload.
#[derive(Deserialize)]
struct Nip44Case {
    op: String,
    conversation_key: Option<String>,
    nonce: Option<String>,
    plaintext: Option<String>,
    payload: Option<String>,
}

#[test]
#[ignore = "requires INTEROP_DIFF_DIR: bun packages/nostr/scripts/parity/diff.ts"]
fn diff_nip44_v2() {
    replay("nip44.v2", |input| {
        let req: Nip44Case = serde_json::from_str(input).ok()?;
        match req.op.as_str() {
            "encrypt" => {
                let key = ConversationKey::from_slice(&unhex_arr::<32>(
                    req.conversation_key.as_deref()?,
                )?)
                .ok()?;
                let nonce = unhex_arr::<32>(req.nonce.as_deref()?)?;
                let payload = v2::encrypt_to_bytes_with_nonce(
                    &key,
                    req.plaintext.as_deref().unwrap_or("").as_bytes(),
                    nonce,
                )
                .ok()?;
                Some(json_str(general_purpose::STANDARD.encode(&payload)))
            }
            "decrypt" => {
                let key = ConversationKey::from_slice(&unhex_arr::<32>(
                    req.conversation_key.as_deref()?,
                )?)
                .ok()?;
                let payload = general_purpose::STANDARD
                    .decode(req.payload.as_deref()?)
                    .ok()?;
                let plaintext = v2::decrypt_to_bytes(&key, &payload).ok()?;
                Some(json_str(String::from_utf8(plaintext).ok()?))
            }
            _ => None,
        }
    });
}
