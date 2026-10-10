//! NIP-27 tokenizer benchmark: [`parse_content`] over a 1,000-entry mixed
//! fixture touching every rule — references, URLs/media, relays, invoices,
//! hashtags, emoji, and plain text (including CJK and astral characters).

#![allow(clippy::expect_used, reason = "benches fail by panicking")]
#![allow(
    unused_crate_dependencies,
    reason = "benches link the lib target's dependencies but exercise only the public API"
)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nk::nips::nip27::{ParseOptions, parse_content};

const ENTRIES: usize = 1000;

const SAMPLES: &[&str] = &[
    "plain text only, nothing to tokenize here at all",
    "check this nostr:npub1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygse4sl3h out",
    "nostr:note1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qmtdh3n and text",
    "pic https://x.y/p.png and clip https://w.z/a.mp4 now",
    "relay list wss://r.io ws://alt.io/relay done",
    "pay lnbc10u1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq now",
    "#nostr #dev #日本語 #café mixed tags",
    "hi :wave: and :k: emojis",
    "cjk text 中文字符 and full width ＜ｓ＞ neighbors 😀🎉",
    "nostr:note1qqqqqqqqqqqq invalid bech32 stays text + lnbc trailing",
];

fn fixture() -> Vec<String> {
    (0..ENTRIES)
        .map(|i| {
            let base = SAMPLES
                .get(i % SAMPLES.len())
                .copied()
                .expect("index in range");
            // Vary every third entry so short-circuit paths (early rule
            // match, resume-from-failure) are all exercised.
            if i % 3 == 0 {
                format!("{base} {base}")
            } else {
                base.to_owned()
            }
        })
        .collect()
}

fn parse_content_bench(c: &mut Criterion) {
    let entries = fixture();
    let mut group = c.benchmark_group("nip27");
    group.throughput(Throughput::Elements(entries.len() as u64));
    group.bench_function("parse_content", |b| {
        b.iter(|| {
            for entry in &entries {
                let blocks = parse_content(entry, None, ParseOptions::default());
                std::hint::black_box(&blocks);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, parse_content_bench);
criterion_main!(benches);
