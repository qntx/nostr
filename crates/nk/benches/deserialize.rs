//! Wire deserialization benchmarks: `serde_json::from_str::<Event>` on a
//! realistic event and `Filter` — the hottest path in the SDK (every
//! incoming event).

#![allow(clippy::expect_used, reason = "benches fail by panicking")]
#![allow(
    unused_crate_dependencies,
    reason = "benches link the lib target's dependencies but exercise only the public API"
)]

use criterion::{Criterion, criterion_group, criterion_main};
use nk::{Event, Filter};

/// A realistic signed event: five tags and ~200 chars of content with a
/// few JSON escapes.
const EVENT_JSON: &str = concat!(
    "{\"id\":\"791e76a4715f1514309947f51c1d20a6f80698833ecc97b7b3a9c56cc3063113\",",
    "\"pubkey\":\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\",",
    "\"created_at\":1700000000,\"kind\":1,",
    "\"tags\":[",
    "[\"e\",\"bb7e98f1f39a4b4d2b2f0f9a5a94d6d8c0a1b2c3d4e5f60718293a4b5c6d7e8f9a\",\"wss://relay.example\",\"root\"],",
    "[\"p\",\"82341f882b6eabcd2ba7f224ef126bcd961f217c3b11f05a5394a0e1d8b3c5a1\"],",
    "[\"t\",\"nostr\",\"extra\"],",
    "[\"r\",\"wss://relay.example\",\"read\"],",
    "[\"emoji\",\":gm:\",\"https://cdn.example/gm.png\"]",
    "],",
    "\"content\":\"gm nostr \\u263a\\ufe0f this is a longer note with \\\"quoted\\\" text, ",
    "a line break\\ninside the content and a \\u4e2d\\u6587 string so the parser walks ",
    "escape sequences while deserializing the real thing\",",
    "\"sig\":\"35931bdb21989c9049272418de0df733b0ebede3bcb45c54161511d8633cab516d6b25cd808ddb8cbba7600940678e3ba3fe655a830abbe631e640e9fc460ff1\"}"
);

/// A realistic subscription filter: `ids`, `authors`, `kinds`, and a `#t`
/// condition.
const FILTER_JSON: &str = concat!(
    "{\"ids\":[",
    "\"791e76a4715f1514309947f51c1d20a6f80698833ecc97b7b3a9c56cc3063113\",",
    "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
    "],",
    "\"authors\":[",
    "\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\",",
    "\"82341f882b6eabcd2ba7f224ef126bcd961f217c3b11f05a5394a0e1d8b3c5a1\"",
    "],",
    "\"kinds\":[1,6,7],",
    "\"#t\":[\"nostr\",\"dev\",\"rust\"]",
    "}"
);

fn bench_deserialize(c: &mut Criterion) {
    assert!(
        serde_json::from_str::<Event>(EVENT_JSON).is_ok(),
        "bench fixture event must parse"
    );
    assert!(
        serde_json::from_str::<Filter>(FILTER_JSON).is_ok(),
        "bench fixture filter must parse"
    );

    let mut group = c.benchmark_group("deserialize");
    group.bench_function("event", |b| {
        b.iter(|| serde_json::from_str::<Event>(EVENT_JSON).expect("valid event"));
    });
    group.bench_function("filter", |b| {
        b.iter(|| serde_json::from_str::<Filter>(FILTER_JSON).expect("valid filter"));
    });
    group.finish();
}

criterion_group!(benches, bench_deserialize);
criterion_main!(benches);
