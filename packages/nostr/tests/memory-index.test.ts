import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/event.ts";
import { itemCompare } from "../src/core/event.ts";
import type { Filter } from "../src/core/filter.ts";
import { matchFilter } from "../src/core/filter.ts";
import { MemoryIndex } from "../src/storage/memory-index.ts";

/* oxlint-disable eslint/no-bitwise -- a PRNG is bit arithmetic by design */
let seed = 0x6d2b79f5;
function rnd(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x1_00_00_00_00;
}
/* oxlint-enable eslint/no-bitwise */

function hex32(n: number): string {
  return n.toString(16).padStart(64, "0");
}

const PUBKEYS = Array.from({ length: 50 }, (_, i) => hex32(0x1000 + i));
const T_VALUES = Array.from({ length: 30 }, (_, i) => `t${i}`);

function pick<T>(items: ReadonlyArray<T>): T {
  const item = items[Math.floor(rnd() * items.length)];
  if (item === undefined) {
    throw new Error("pick from empty array");
  }
  return item;
}

// Kinds exercising regular, replaceable (0, 3, 10002), addressable (30023) and deletion (5).
function fabricate(i: number, earlierIds: string[]): Event {
  const roll = rnd();
  const kind =
    roll < 0.5
      ? 1
      : roll < 0.62
        ? 7
        : roll < 0.7
          ? 6
          : roll < 0.78
            ? 0
            : roll < 0.84
              ? 3
              : roll < 0.9
                ? 10002
                : roll < 0.96
                  ? 30023
                  : 5;
  const pubkey = pick(PUBKEYS);
  const tags: string[][] = [];
  if (earlierIds.length > 0 && rnd() < 0.8) {
    let target = pick(earlierIds);
    if (rnd() < 0.08) {
      target = target.toUpperCase();
    }
    tags.push(["e", target]);
  }
  if (rnd() < 0.7) {
    let p = pick(PUBKEYS);
    if (rnd() < 0.1) {
      p = p.toUpperCase();
    }
    tags.push(["p", p]);
  }
  if (rnd() < 0.6) {
    tags.push(["t", pick(T_VALUES)]);
  }
  if (kind === 30023) {
    tags.push(["d", `article-${Math.floor(rnd() * 40)}`]);
  }
  if (kind === 5 && earlierIds.length > 0) {
    tags.push(["e", pick(earlierIds)]);
  }
  return {
    id: hex32(0x10_00_00 + i),
    pubkey,
    kind,
    created_at: 1_700_000_000 + i,
    tags,
    content: kind === 7 ? "+" : `note ${i}`,
    sig: "ab".repeat(64),
  };
}

const LIMITS = [undefined, 0, 1, 5, 50, 200, 2000];

function randomIds(corpus: Event[]): string[] | undefined {
  const roll = rnd();
  if (!(roll < 0.12 && corpus.length > 0)) {
    return undefined;
  }
  const ids: string[] = [];
  for (let i = 0; i < 1 + Math.floor(rnd() * 5); i++) {
    const id = rnd() < 0.85 ? pick(corpus).id : hex32(0xde_ad_00 + Math.floor(rnd() * 100));
    ids.push(rnd() < 0.15 ? id.toUpperCase() : id);
  }
  return ids;
}

function randomAuthors(): string[] | undefined {
  if (rnd() >= 0.4) {
    return undefined;
  }
  const authors: string[] = [];
  for (let i = 0; i < Math.floor(rnd() * 8); i++) {
    const pk = pick(PUBKEYS);
    authors.push(rnd() < 0.1 ? pk.toUpperCase() : pk);
  }
  return authors;
}

function randomKinds(): number[] | undefined {
  if (rnd() >= 0.4) {
    return undefined;
  }
  const kinds: number[] = [];
  for (let i = 0; i < Math.floor(rnd() * 4); i++) {
    kinds.push(pick([0, 1, 3, 5, 6, 7, 10002, 30023]));
  }
  return kinds;
}

function randomETags(corpus: Event[]): string[] | undefined {
  if (!(rnd() < 0.3 && corpus.length > 0)) {
    return undefined;
  }
  const values: string[] = [];
  for (let i = 0; i < 1 + Math.floor(rnd() * 3); i++) {
    const { id } = pick(corpus);
    values.push(rnd() < 0.2 ? id.toUpperCase() : id);
  }
  if (values.length > 1 && rnd() < 0.3) {
    // Same event reachable through two values exercises merge dedupe.
    const [first] = values;
    if (first !== undefined) {
      values.push(first);
    }
  }
  return values;
}

function randomPTags(): string[] | undefined {
  if (rnd() >= 0.25) {
    return undefined;
  }
  const values: string[] = [];
  for (let i = 0; i < 1 + Math.floor(rnd() * 3); i++) {
    const pk = pick(PUBKEYS);
    values.push(rnd() < 0.2 ? pk.toUpperCase() : pk);
  }
  return values;
}

function randomTTags(): string[] | undefined {
  if (rnd() >= 0.25) {
    return undefined;
  }
  const values: string[] = [];
  for (let i = 0; i < 1 + Math.floor(rnd() * 3); i++) {
    values.push(rnd() < 0.15 ? pick(T_VALUES).toUpperCase() : pick(T_VALUES));
  }
  return values;
}

function randomSince(corpus: Event[]): number | undefined {
  if (rnd() >= 0.35) {
    return undefined;
  }
  const a = Math.floor(rnd() * corpus.length);
  const b = Math.floor(rnd() * corpus.length);
  return 1_700_000_000 + Math.min(a, b);
}

function randomUntil(corpus: Event[]): number | undefined {
  if (rnd() >= 0.35) {
    return undefined;
  }
  const a = Math.floor(rnd() * corpus.length);
  const b = Math.floor(rnd() * corpus.length);
  return 1_700_000_000 + Math.max(a, b);
}

function randomLimit(): number | undefined {
  if (rnd() >= 0.5) {
    return undefined;
  }
  return LIMITS[Math.floor(rnd() * LIMITS.length)];
}

/** Properties are evaluated in declaration order, preserving the original rng sequence. */
function randomFilter(corpus: Event[]): Filter {
  return {
    ids: randomIds(corpus),
    authors: randomAuthors(),
    kinds: randomKinds(),
    "#e": randomETags(corpus),
    "#p": randomPTags(),
    "#t": randomTTags(),
    since: randomSince(corpus),
    until: randomUntil(corpus),
    limit: randomLimit(),
  };
}

/** Brute-force expectation: live events matching `filter`, newest first, capped at `limit`. */
function expectedMatches(live: Event[], filter: Filter): Event[] {
  const matched = live.filter((e) => matchFilter(filter, e));
  return filter.limit === undefined ? matched : matched.slice(0, filter.limit);
}

function expectedItems(expected: Event[]): Array<{ id: string; created_at: number }> {
  return expected.map(({ id, created_at }) => ({ id, created_at })).toSorted(itemCompare);
}

describe("MemoryIndex planner oracle", () => {
  test("query/count/negentropyItems match a brute-force oracle over random filters", () => {
    const index = new MemoryIndex();
    const corpus: Event[] = [];
    for (let i = 0; i < 3000; i++) {
      const event = fabricate(
        i,
        corpus.map((e) => e.id),
      );
      index.put(event);
      corpus.push(event);
    }
    // The live corpus is whatever the index itself exposes: replacements,
    // addressable winners and deletions are already resolved by put().
    const live = index.query([{}]);
    for (let i = 0; i < 600; i++) {
      const filter = randomFilter(corpus);
      const expected = expectedMatches(live, filter);
      expect(index.query([filter]).map((e) => e.id)).toStrictEqual(expected.map((e) => e.id));
      expect(index.count([filter])).toBe(expected.length);
      expect(index.negentropyItems(filter)).toStrictEqual(expectedItems(expected));
    }
  });
});
