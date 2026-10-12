import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/event.ts";
import { MemoryIndex } from "../src/storage/memory-index.ts";

const N = 100_000;
const RUNS = 20;

// Deterministic PRNG for fabricated data (same shape as the ad-hoc bench).
/* oxlint-disable eslint/no-bitwise -- a PRNG is bit arithmetic by design */
let seed = 0x9e3779b9;
function rnd(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x1_00_00_00_00;
}
/* oxlint-enable eslint/no-bitwise */

function at<T>(items: ReadonlyArray<T>, i: number): T {
  const item = items[i];
  if (item === undefined) {
    throw new Error(`index ${i} out of bounds`);
  }
  return item;
}
function hex(bytes: number): string {
  let s = "";
  for (let i = 0; i < bytes; i++) {
    s += Math.floor(rnd() * 256)
      .toString(16)
      .padStart(2, "0");
  }
  return s;
}

const CONTENT = `GM nostr! Shipping a new release today — faster verification, smaller bundles 🚀. ${"Read more at https://example.com/blog/release and tell me what you think. #nostr #dev ".repeat(
  2,
)}`;

// The index does not verify signatures; fabricating rows keeps the measurement
// on the store and not on schnorr signing.
const PUBKEYS = Array.from({ length: 1000 }, () => hex(32));
const TOPIC_IDS = Array.from({ length: 2000 }, () => hex(32));
function fabricate(i: number): Event {
  const kindRoll = rnd();
  const kind = kindRoll < 0.7 ? 1 : kindRoll < 0.9 ? 7 : 6;
  return {
    id: hex(32),
    pubkey: at(PUBKEYS, Math.floor(rnd() * PUBKEYS.length)),
    created_at: 1_700_000_000 + i,
    kind,
    tags: [
      ["e", at(TOPIC_IDS, Math.floor(rnd() * TOPIC_IDS.length))],
      ["p", at(PUBKEYS, Math.floor(rnd() * PUBKEYS.length))],
      ["t", `t${i % 50}`],
    ],
    content: kind === 7 ? "+" : CONTENT,
    sig: hex(64),
  };
}

function fmtMs(us: number): string {
  return `${(us / 1000).toFixed(3)}ms`;
}

describe("memory index bench", () => {
  test(`put + query over ${N} fabricated events`, () => {
    const corpus = Array.from({ length: N }, (_, i) => fabricate(i));
    const index = new MemoryIndex();

    const p0 = performance.now();
    for (const event of corpus) {
      index.put(event);
    }
    const putUs = ((performance.now() - p0) * 1000) / N;
    console.log(`[memory-index bench] put: ${putUs.toFixed(2)}µs/op over ${N} events`);
    expect(index.size).toBe(N);

    const queries: Array<[string, Parameters<MemoryIndex["query"]>[0]]> = [
      [
        "kinds[1]+author limit 50",
        [{ kinds: [1], authors: [at(corpus, 12345).pubkey], limit: 50 }],
      ],
      ["kinds[1] limit 100", [{ kinds: [1], limit: 100 }]],
      ["#e limit 50", [{ "#e": [at(at(corpus, 777).tags, 0)[1] ?? ""], limit: 50 }]],
      [
        "follow feed 500 authors kinds[1,6] limit 200",
        [{ kinds: [1, 6], authors: PUBKEYS.slice(0, 500), limit: 200 }],
      ],
      ["#t limit 50", [{ "#t": ["t7"], limit: 50 }]],
      [
        "since/until window limit 100",
        [{ since: 1_700_050_000, until: 1_700_051_000, limit: 100 }],
      ],
    ];
    for (const [name, filters] of queries) {
      expect(index.query(filters).length).toBeGreaterThan(0);
      const q0 = performance.now();
      for (let i = 0; i < RUNS; i++) {
        index.query(filters);
      }
      const avgUs = ((performance.now() - q0) * 1000) / RUNS;
      console.log(`[memory-index bench] query ${name}: ${fmtMs(avgUs)} avg over ${RUNS} runs`);
    }

    // Live inserts: created_at above every existing event.
    const live = Array.from({ length: 1000 }, (_, i) => fabricate(N + i));
    const l0 = performance.now();
    for (const event of live) {
      index.put(event);
    }
    const liveUs = ((performance.now() - l0) * 1000) / live.length;
    console.log(`[memory-index bench] live insert (newer than all): ${liveUs.toFixed(2)}µs/op`);
  }, 300_000);
});
