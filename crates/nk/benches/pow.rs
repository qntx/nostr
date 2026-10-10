//! NIP-13 mining benchmark: [`PowMiner`]'s paused-hash-state loop against a
//! naive baseline that reserializes the canonical JSON on every attempt.
//!
//! Both benches run at difficulty 32 with a 4096-attempt budget, so a hit is
//! rare and the measured iteration is effectively `BUDGET` hashes.

#![allow(clippy::expect_used, reason = "benches fail by panicking")]
#![allow(
    unused_crate_dependencies,
    reason = "benches link the lib target's dependencies but exercise only the public API"
)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nk::nips::nip13::{PowMiner, pow};
use nk::{EventId, Kind, PublicKey, Tag, Tags, Timestamp, UnsignedEvent};
use sha2::{Digest, Sha256};

const PUBKEY: &str = "79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6";
const BUDGET: u64 = 4096;
const DIFFICULTY: u32 = 32;
const NOW: u64 = 1_700_000_000;

fn unsigned() -> UnsignedEvent {
    UnsignedEvent::new(
        PublicKey::from_hex(PUBKEY).expect("valid bench key"),
        Timestamp::from_secs(NOW),
        Kind::TEXT_NOTE,
        Tags::from_iter([Tag::custom("t", ["pow"])]),
        "It's just me mining my own business",
    )
}

/// The naive approach: rebuild the mined event and reserialize its canonical
/// JSON on every attempt.
fn naive_attempts(unsigned: &UnsignedEvent, difficulty: u32, budget: u64) -> Option<EventId> {
    for n in 1..=budget {
        let mut tags = unsigned.tags().clone();
        tags.push(Tag::custom(
            "nonce",
            [n.to_string(), difficulty.to_string()],
        ));
        let probe = UnsignedEvent::new(
            unsigned.pubkey(),
            unsigned.created_at(),
            unsigned.kind(),
            tags,
            unsigned.content(),
        );
        let canonical = probe.canonical_json();
        let id = EventId::from_bytes(Sha256::digest(canonical.as_bytes()).into());
        if pow(&id) >= difficulty {
            return Some(id);
        }
    }
    None
}

fn bench_mining(c: &mut Criterion) {
    let unsigned = unsigned();
    let mut group = c.benchmark_group("nip13");
    group.throughput(Throughput::Elements(BUDGET));

    group.bench_function("pow_miner", |b| {
        let mut miner = PowMiner::new(unsigned.clone(), DIFFICULTY);
        let now = Timestamp::from_secs(NOW);
        b.iter(|| miner.mine(now, BUDGET));
    });

    group.bench_function("naive_reserialize", |b| {
        b.iter(|| naive_attempts(&unsigned, DIFFICULTY, BUDGET));
    });

    group.finish();
}

criterion_group!(benches, bench_mining);
criterion_main!(benches);
