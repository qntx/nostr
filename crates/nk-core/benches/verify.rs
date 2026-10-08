//! BIP-340 signing and verification benchmarks: `Event::verify` and
//! `Keys::sign_event_with_aux`. Run with default features (global context)
//! and `--no-default-features` (per-call context).

#![allow(clippy::expect_used, reason = "benches fail by panicking")]
#![allow(
    unused_crate_dependencies,
    reason = "benches link the lib target's dependencies but exercise only the public API"
)]

use criterion::{Criterion, criterion_group, criterion_main};
use nk_core::{Keys, Kind, SecretKey, Tags, Timestamp, UnsignedEvent};

const SECRET: &str = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef22";
const AUX: [u8; 32] = [0xa5; 32];

fn bench_sign_and_verify(c: &mut Criterion) {
    let keys = Keys::new(SecretKey::from_hex(SECRET).expect("valid bench key"));
    let unsigned = UnsignedEvent::new(
        keys.public_key(),
        Timestamp::from_secs(1_700_000_000),
        Kind::TEXT_NOTE,
        Tags::new(),
        "hello nostr",
    );
    let event = keys
        .sign_event_with_aux(unsigned.clone(), &AUX)
        .expect("pubkey matches");

    let mut group = c.benchmark_group("crypto");
    group.bench_function("sign_event_with_aux", |b| {
        b.iter(|| keys.sign_event_with_aux(unsigned.clone(), &AUX));
    });
    group.bench_function("event_verify", |b| {
        b.iter(|| event.verify());
    });
    group.finish();
}

criterion_group!(benches, bench_sign_and_verify);
criterion_main!(benches);
