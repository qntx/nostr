//! Executes `vectors/nip13/codec.json` against rust-nostr's public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use common::{DivergenceCheck, unhex_arr};
use nostr::nips::nip13::{SingleThreadPow, get_leading_zero_bits};
use nostr::prelude::{Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use serde::Deserialize;
use std::num::NonZeroU8;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip13/codec.json"
));

#[derive(Clone, Debug, Deserialize)]
struct UnsignedJson {
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

impl UnsignedJson {
    fn into_event(self) -> Option<UnsignedEvent> {
        Some(UnsignedEvent::new(
            PublicKey::from_hex(&self.pubkey).ok()?,
            Timestamp::from_secs(self.created_at),
            Kind::from_u16(self.kind),
            self.tags
                .into_iter()
                .map(|items| Tag::parse(items).ok())
                .collect::<Option<Vec<_>>>()?,
            self.content,
        ))
    }
}

#[derive(Debug, Deserialize)]
struct PowCase {
    id: Option<String>,
    input: Option<String>,
    bits: Option<u32>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MineCase {
    unsigned: UnsignedJson,
    difficulty: u32,
    now: u64,
    nonce: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct Vector {
    pow: Vec<PowCase>,
    mine: Vec<MineCase>,
}

fn pow_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.pow.iter().enumerate() {
        let raw = case.id.as_deref().or(case.input.as_deref());
        let outcome = raw
            .and_then(unhex_arr::<32>)
            .map(|bytes| u32::from(get_leading_zero_bits(bytes)));
        let agrees = match (&case.error, case.bits, outcome) {
            (None, Some(expected), Some(bits)) => bits == expected,
            (Some(_), _, None) => true,
            _ => false,
        };
        let got = outcome.map_or_else(|| "rejected".to_owned(), |bits| format!("bits={bits}"));
        check.check(&i.to_string(), agrees, &got);
    }
}

fn mine_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.mine.iter().enumerate() {
        let outcome = (|| -> Option<(String, String, u64)> {
            let mut unsigned = case.unsigned.clone().into_event()?;
            unsigned.created_at = Timestamp::from_secs(case.now);
            let difficulty = NonZeroU8::new(u8::try_from(case.difficulty).ok()?)?;
            let mined = unsigned.mine(&SingleThreadPow, difficulty).ok()?;
            let nonce_tag = mined
                .tags
                .iter()
                .find(|tag| tag.as_slice().first().map(String::as_str) == Some("nonce"))?;
            let nonce = nonce_tag.as_slice().get(1)?.clone();
            let id = mined.id?.to_hex();
            Some((id, nonce, mined.created_at.as_secs()))
        })();
        let agrees = outcome.as_ref().is_some_and(|(id, nonce, now)| {
            *id == case.id && *nonce == case.nonce && *now == case.now
        });
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |(id, nonce, now)| format!("id={id} nonce={nonce} created_at={now}"),
        );
        check.check(&format!("mine/{i}"), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip13.pow");
    pow_vectors(&mut check);
    mine_vectors(&mut check);
    check.finish();
}
