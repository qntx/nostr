//! Executes `vectors/nip57/codec.json` against rust-nostr's public API.

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
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip57::ZapRequestData;
use nostr::prelude::{IntoEventBuilder, PublicKey, RelayUrl};
use serde::Deserialize;
use serde_json::Value;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip57/codec.json"
));

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct Codec {
    zap_request: Vec<ZapRequestCase>,
    bolt11: Vec<NamedCase>,
    receipt: Vec<NamedCase>,
}

#[derive(Deserialize)]
struct ZapRequestCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    input: ZapInput,
    amount: Option<Value>,
    relays: Vec<String>,
    comment: Option<String>,
    lnurl: Option<String>,
    out: Option<ZapOut>,
    err: Option<String>,
}

#[derive(Deserialize)]
struct ZapInput {
    pubkey: Option<String>,
    event: Option<Value>,
}

#[derive(Deserialize)]
struct ZapOut {
    kind: u64,
    #[allow(dead_code, reason = "the builder does not carry the timestamp")]
    created_at: u64,
    content: String,
    tags: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct NamedCase {
    name: String,
    #[allow(dead_code, reason = "extra vector fields are informational only")]
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}

fn zap_request_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.zap_request {
        if !case.rust {
            continue;
        }
        let outcome = (|| {
            // Event zap: `p` is the event author; kind-1 events get an `e`
            // tag, addressable events an `a` coordinate.
            let (pubkey, event_id, event_coordinate) = case.input.event.as_ref().map_or_else(
                || {
                    PublicKey::from_hex(case.input.pubkey.as_deref()?)
                        .ok()
                        .map(|key| (key, None, None))
                },
                event_zap_target,
            )?;
            let relays: Vec<RelayUrl> = case
                .relays
                .iter()
                .map(|r| RelayUrl::parse(r).ok())
                .collect::<Option<_>>()?;
            let mut data = ZapRequestData::new(pubkey, relays);
            if let Some(comment) = &case.comment {
                data = data.message(comment.clone());
            }
            if let Some(amount) = &case.amount {
                data = data.amount(amount.as_u64()?);
            }
            if let Some(lnurl) = &case.lnurl
                && !lnurl.is_empty()
            {
                data = data.lnurl(lnurl.clone());
            }
            if let Some(id) = event_id {
                data = data.event_id(id);
            }
            if let Some(coordinate) = event_coordinate {
                data = data.event_coordinate(coordinate);
            }
            let builder = data.into_event_builder();
            let tags: Vec<Vec<String>> = builder
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_vec())
                .collect();
            Some((u64::from(builder.kind.as_u16()), builder.content, tags))
        })();
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expect), _, Some((kind, content, tags))) => {
                *kind == expect.kind && content == &expect.content && tags == &expect.tags
            }
            (None, Some(_), None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |(_, _, tags)| format!("tags={tags:?}"),
        );
        check.check(&case.name, agrees, &got);
    }
}

// rust-nostr has no bolt11 invoice parser (that lives in lightning
// libraries) and no zap-receipt validator, so those cases are skipped.
fn bolt11_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.bolt11 {
        check.skip(&format!("bolt11: {}", case.name));
    }
}

fn receipt_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.receipt {
        check.skip(&format!("receipt: {}", case.name));
    }
}

fn event_zap_target(
    raw: &Value,
) -> Option<(
    PublicKey,
    Option<nostr::prelude::EventId>,
    Option<Coordinate>,
)> {
    let event = serde_json::from_value::<nostr::prelude::Event>(raw.clone()).ok()?;
    if u64::from(event.kind.as_u16()) >= 30000 && u64::from(event.kind.as_u16()) < 40000 {
        let coordinate = Coordinate {
            kind: event.kind,
            public_key: event.pubkey,
            identifier: d_tag(&event).unwrap_or_default(),
        };
        Some((event.pubkey, None, Some(coordinate)))
    } else {
        Some((event.pubkey, Some(event.id), None))
    }
}

fn d_tag(event: &nostr::prelude::Event) -> Option<String> {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().is_some_and(|t| t == "d"))
        .and_then(|tag| tag.as_slice().get(1).cloned())
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip57.zap");
    zap_request_cases(&mut check);
    bolt11_cases(&mut check);
    receipt_cases(&mut check);
    check.finish();
}
