//! Executes `vectors/nip27/codec.json` against rust-nostr's public
//! `nostr::parser::NostrParser`.
//!
//! `NostrParser` is not a rendering tokenizer, so both sides are projected
//! onto the shared vocabulary `text`/`reference`/`url`/`hashtag` before
//! comparing: rust tokens merge into text/url/hashtag/`nostr:`-references
//! via [`content_blocks`], and the vector's block list is folded the same
//! way by [`project_blocks`] (media and `nrelay:` become `url`; invoice,
//! emoji and bare references become `text`; adjacent text merges).

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

use common::{DivergenceCheck, content_blocks, project_blocks};
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
    // `tags`/`legacy`/`imeta` are folded away by the projection before
    // comparing.
    out: serde_json::Value,
}

#[test]
fn tokenize_cases() {
    let codec: Codec = serde_json::from_str(CODEC).expect("codec.json parses");
    assert!(!codec.cases.is_empty(), "no cases in codec.json");
    let mut check = DivergenceCheck::new("nip27.tokenize");
    for case in &codec.cases {
        let got = content_blocks(&case.content);
        check.check(
            &case.name,
            got == project_blocks(&case.content, &case.out),
            &got.to_string(),
        );
    }
    check.finish();
}
