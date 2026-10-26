//! `MemoryStore` planner benchmarks: 10k mixed events, three query shapes.

#![expect(
    unused_crate_dependencies,
    reason = "the bench target links the crate's dev-dependencies but uses only criterion"
)]
#![expect(
    clippy::unwrap_used,
    reason = "a bench setup failure must abort the benchmark"
)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use nk_core::rand_core::{TryCryptoRng, TryRng};
use nk_core::{
    Event, EventBuilder, Filter, Keys, Kind, SecretKey, SingleLetterTag, Tag, Timestamp,
};
use nk_store::{EventStore, MemoryStore};

/// A deterministic RNG — the signatures only need to be reproducible.
struct BenchRng(u64);

impl TryRng for BenchRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Ok((self.0 >> 33) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let n = self.try_next_u64()?;
            for (dst, src) in chunk.iter_mut().zip(n.to_be_bytes()) {
                *dst = src;
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for BenchRng {}

fn key(i: u64) -> Keys {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&(i + 1).to_be_bytes());
    Keys::new(SecretKey::from_bytes(bytes).unwrap())
}

fn event(i: u64) -> Event {
    let kind: u16 = match i % 4 {
        0 => 1,
        1 => 3,
        2 => 30023,
        _ => 7,
    };
    let mut builder = EventBuilder::new(Kind::new(kind), format!("content {i}"));
    if kind == 30023 {
        builder = builder.tag(Tag::identifier(format!("d{i}")));
    }
    if i.is_multiple_of(3) {
        builder = builder.tag(Tag::hashtag(format!("t{}", i % 10)));
    }
    let keys = key(i % 100);
    let unsigned = builder.build_at(keys.public_key(), Timestamp::from_secs(1_700_000_000 + i));
    keys.sign_event(unsigned, &mut BenchRng(i)).unwrap()
}

fn store() -> MemoryStore {
    let store = MemoryStore::new();
    let events: Vec<_> = (0..10_000).map(event).collect();
    store.put_many(&events).unwrap();
    store
}

fn query_authors_kinds(c: &mut Criterion) {
    let store = store();
    let filter = Filter::new()
        .kinds([Kind::new(1)])
        .unwrap()
        .authors([key(3).public_key(), key(7).public_key()])
        .unwrap();
    c.bench_function("memory/authors+kinds", |b| {
        b.iter(|| {
            store
                .query(black_box(std::slice::from_ref(&filter)))
                .unwrap()
        });
    });
}

fn query_tag(c: &mut Criterion) {
    let store = store();
    let letter = SingleLetterTag::new('t').unwrap();
    let filter = Filter::new().tag(letter, ["t5"]).unwrap();
    c.bench_function("memory/#t", |b| {
        b.iter(|| {
            store
                .query(black_box(std::slice::from_ref(&filter)))
                .unwrap()
        });
    });
}

fn query_since_limit(c: &mut Criterion) {
    let store = store();
    let filter = Filter::new()
        .since(Timestamp::from_secs(1_700_002_000))
        .until(Timestamp::from_secs(1_700_008_000))
        .limit(50);
    c.bench_function("memory/since+until+limit", |b| {
        b.iter(|| {
            store
                .query(black_box(std::slice::from_ref(&filter)))
                .unwrap()
        });
    });
}

criterion_group!(benches, query_authors_kinds, query_tag, query_since_limit);
criterion_main!(benches);
