//! `vectors/nip27/codec.json` — NIP-27 `parse_content` tokenization cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip27.test.ts`; regenerate with
//! `bun packages/nostr/scripts/parity/gen/all.ts`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file or a divergence must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use std::collections::BTreeMap;

use nk::nips::nip27::{ParseOptions, parse_content};
use nk::{Tag, Tags};
use serde::Deserialize;

use common::blocks_json;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip27/codec.json"
));

#[derive(Deserialize)]
struct Codec {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    content: String,
    tags: Option<Vec<Vec<String>>>,
    legacy: Option<bool>,
    imeta: Option<BTreeMap<String, String>>,
    out: serde_json::Value,
}

#[test]
fn tokenize_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("codec.json parses");
    assert!(!codec.cases.is_empty(), "no cases in codec.json");
    for case in &codec.cases {
        let tags: Option<Tags> = case.tags.as_ref().map(|items| {
            items
                .iter()
                .filter(|tag| !tag.is_empty())
                .map(|tag| Tag::new(tag.iter().cloned()).expect("vector tag"))
                .collect()
        });
        let options = ParseOptions {
            legacy_bech32: case.legacy.unwrap_or(false),
            imeta: case.imeta.as_ref(),
        };
        let blocks = parse_content(&case.content, tags.as_ref(), options);
        let got = blocks_json(&blocks);
        assert_eq!(got, case.out, "{}", case.name);
    }
}
