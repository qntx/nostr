//! Executes `vectors/nip59/codec.json` against rust-nostr's public API.

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
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::{Event, Keys, SecretKey};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip59/codec.json"
));

#[derive(Deserialize)]
struct Vector {
    wrap: Vec<NamedCase>,
    seal: Vec<NamedCase>,
    gift: Vec<NamedCase>,
    unwrap: Vec<UnwrapCase>,
}

#[derive(Deserialize)]
struct NamedCase {
    name: String,
}

#[derive(Deserialize)]
struct UnwrapCase {
    name: String,
    gift_wrap: serde_json::Value,
    recipient_secret_key: String,
    rumor: Option<serde_json::Value>,
    error: Option<String>,
}

const DETERMINISTIC_UNEXPRESSIBLE: &str =
    "rust-nostr does not expose deterministic gift-wrap construction";

fn wrap_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in vector
        .wrap
        .iter()
        .chain(vector.seal.iter())
        .chain(vector.gift.iter())
    {
        check.check(&case.name, false, DETERMINISTIC_UNEXPRESSIBLE);
    }
}

fn unwrap_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.unwrap {
        let outcome: Option<(serde_json::Value, String)> = (|| {
            let gift_wrap: Event = serde_json::from_value(case.gift_wrap.clone()).ok()?;
            let keys = Keys::new(SecretKey::from_hex(&case.recipient_secret_key).ok()?);
            let gift = UnwrappedGift::from_gift_wrap(&keys, &gift_wrap).ok()?;
            let rumor = serde_json::to_value(&gift.rumor).ok()?;
            Some((rumor, gift.sender.to_hex()))
        })();
        let agrees = match (&case.rumor, &outcome) {
            (Some(expected), Some((rumor, _))) => {
                // The vector records the unsigned rumor fields; serde_json's
                // object comparison is order-insensitive but shape differs
                // (nostr serializes tags the same wire way).
                expected.get("id") == rumor.get("id")
                    && expected.get("pubkey") == rumor.get("pubkey")
                    && expected.get("created_at") == rumor.get("created_at")
                    && expected.get("kind") == rumor.get("kind")
                    && expected.get("tags") == rumor.get("tags")
                    && expected.get("content") == rumor.get("content")
            }
            (None, None) => case.error.is_some(),
            _ => false,
        };
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |(rumor, _)| format!("rumor={rumor}"),
        );
        check.check(&case.name, agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip59.wrap");
    wrap_cases(&mut check);
    unwrap_cases(&mut check);
    check.finish();
}
