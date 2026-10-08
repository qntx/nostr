import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/event.ts";
import { SqliteEventStore } from "../src/index.ts";
import { SqliteTestDriver } from "../tests/helpers/sqlite-driver.ts";

const N = 100_000;
const AUTHORS = 100;
const LIMIT = 50;
const SIG = "ab".repeat(64);

function hex32(n: number): string {
  return n.toString(16).padStart(64, "0");
}

function author(i: number): string {
  return hex32(0x1000 + (i % AUTHORS));
}

// Structural validation only checks hex id/sig, so fabricating rows keeps the
// measurement on the store and not on schnorr signing.
function event(i: number, pubkey: string): Event {
  return {
    id: hex32(i + 1),
    pubkey,
    kind: 1,
    created_at: 1_700_000_000 + i,
    tags: [],
    content: `note ${i}`,
    sig: SIG,
  };
}

describe("sqlite store bench", () => {
  test(`home feed query: ${N} events, ${AUTHORS} authors, kind 1, limit ${LIMIT}`, async () => {
    const driver = await SqliteTestDriver.open();
    const store = await SqliteEventStore.open(driver);
    const authors = Array.from({ length: AUTHORS }, (_, i) => author(i));

    const t0 = performance.now();
    const batch: Event[] = [];
    for (let i = 0; i < N; i++) {
      batch.push(event(i, author(i)));
      if (batch.length === 1000) {
        // oxlint-disable-next-line no-await-in-loop -- batched fill must serialize writes
        await store.putMany(batch.splice(0));
      }
    }
    if (batch.length > 0) {
      await store.putMany(batch);
    }
    const fillMs = performance.now() - t0;

    const filter = { authors, kinds: [1], limit: LIMIT };
    const warm = await store.query([filter]);
    expect(warm).toHaveLength(LIMIT);

    const RUNS = 20;
    const q0 = performance.now();
    for (let i = 0; i < RUNS; i++) {
      // oxlint-disable-next-line no-await-in-loop -- timed runs must be sequential
      await store.query([filter]);
    }
    const queryMs = (performance.now() - q0) / RUNS;

    console.log(
      `[sqlite-store bench] fill ${N} events: ${fillMs.toFixed(1)}ms, ` +
        `home-feed query (100 authors × kind 1, limit ${LIMIT}): ` +
        `${queryMs.toFixed(2)}ms avg over ${RUNS} runs`,
    );
    driver.close();
  }, 300_000);
});
