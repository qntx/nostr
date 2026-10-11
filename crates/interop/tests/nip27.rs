//! Executes `vectors/nip27/codec.json` against rust-nostr's public
//! `nostr::parser::NostrParser`.
//!
//! Glue is limited to token→block conversion: consecutive
//! `Text`/`Whitespace`/`LineBreak` tokens merge into one `text` block and
//! `Nostr`/`Url`/`Hashtag` tokens map to `reference`/`url`/`hashtag`. Block
//! kinds rust-nostr cannot produce (emoji, invoice, relay, media
//! classification, bare-bech32 references) diverge and are registered.

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

use common::{DivergenceCheck, content_blocks};
use serde::Deserialize;

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
    // `tags`/`legacy`/`imeta` have no `NostrParserOptions` counterpart and are
    // ignored; whatever rust-nostr produces for them diverges on its own.
    out: serde_json::Value,
}

#[test]
fn tokenize_cases() {
    let codec: Codec = serde_json::from_str(CODEC).expect("codec.json parses");
    assert!(!codec.cases.is_empty(), "no cases in codec.json");
    let mut check = DivergenceCheck::new("nip27.tokenize");
    for case in &codec.cases {
        let got = content_blocks(&case.content);
        check.check(&case.name, got == case.out, &got.to_string());
    }
    check.finish();
}
