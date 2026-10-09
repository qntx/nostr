//! `vectors/nip13/codec.json` — NIP-13 `pow` and the deterministic core of
//! `PowMiner`: at a fixed `now`, nonce 1, 2, … until the id has enough
//! leading zero bits.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip13.test.ts`; regenerate with
//! `bun packages/nostr/scripts/parity/gen/all.ts`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use nk_core::{EventId, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use nk_nips::nip13::{self, PowMiner};
use serde::Deserialize;

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
    fn into_event(self) -> UnsignedEvent {
        UnsignedEvent::new(
            PublicKey::from_hex(&self.pubkey).expect("vector pubkey"),
            Timestamp::from_secs(self.created_at),
            Kind::from(self.kind),
            self.tags
                .into_iter()
                .map(|items| Tag::new(items).expect("vector tag"))
                .collect(),
            self.content,
        )
    }
}

/// `{id, bits}` runs on both sides; `{input, …, rust: false}` is TS-only
/// (`getPow` also takes hex strings — Rust's `pow` takes the bytes form).
#[derive(Debug, Deserialize)]
struct PowCase {
    id: Option<String>,
    bits: Option<u32>,
    rust: Option<bool>,
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

#[test]
fn pow_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let mut ran = 0;
    let mut skipped = 0;
    for (i, case) in vector.pow.iter().enumerate() {
        if case.rust == Some(false) {
            skipped += 1;
            continue;
        }
        let (Some(id), Some(bits)) = (&case.id, case.bits) else {
            panic!("case {i}: shared pow case needs id + bits")
        };
        assert_eq!(
            nip13::pow(&EventId::from_hex(id).expect("vector id")),
            bits,
            "case {i}: pow"
        );
        ran += 1;
    }
    assert_eq!(ran + skipped, vector.pow.len());
    assert!(skipped > 0, "expected some TS-only string-input cases");
}

#[test]
fn mine_vectors() {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.mine.iter().enumerate() {
        let n: u64 = case.nonce.parse().expect("vector nonce");
        let now = Timestamp::from_secs(case.now);
        let mut miner = PowMiner::new(case.unsigned.clone().into_event(), case.difficulty);

        // `nonce` is the first hit: `n - 1` attempts must not suffice…
        assert!(
            miner.mine(now, n - 1).is_none(),
            "case {i}: a smaller budget must not reach the nonce"
        );
        // …and the very next attempt does, proving the counter survives
        // between `mine` calls.
        let (event, id) = miner
            .mine(now, 1)
            .unwrap_or_else(|| panic!("case {i}: nonce {n} not reached"));
        assert_eq!(
            id,
            EventId::from_hex(&case.id).expect("vector id"),
            "case {i}: id"
        );
        assert_eq!(id, event.id(), "case {i}: id must hash the produced event");
        assert_eq!(event.created_at(), now, "case {i}: created_at follows now");
        let nonce = event
            .tags()
            .iter()
            .find(|tag| tag.name() == "nonce")
            .unwrap_or_else(|| panic!("case {i}: missing nonce tag"));
        assert_eq!(
            nonce.as_slice(),
            [
                String::from("nonce"),
                case.nonce.clone(),
                case.difficulty.to_string()
            ]
            .as_slice(),
            "case {i}: nonce tag"
        );
    }
}
