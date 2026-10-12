import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/event.ts";
import { compareEventsDesc } from "../src/core/event.ts";
import { SortedEvents } from "../src/storage/sorted-events.ts";

/* oxlint-disable no-bitwise -- a PRNG is bit arithmetic by design */
let seed = 0x9e3779b9;
function rnd(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x1_00_00_00_00;
}
/* oxlint-enable no-bitwise */

let nextId = 0;
function fabricate(createdAt: number): Event {
  const id = (nextId++).toString(16).padStart(64, "0");
  return {
    id,
    pubkey: "ab".repeat(32),
    kind: 1,
    created_at: createdAt,
    tags: [],
    content: "",
    sig: "ab".repeat(64),
  };
}

function drain(list: SortedEvents, since?: number, until?: number): Event[] {
  const out: Event[] = [];
  const cursor = list.cursor(since, until);
  while (cursor.value !== undefined) {
    out.push(cursor.value);
    cursor.next();
  }
  return out;
}

function ids(events: Event[]): string[] {
  return events.map((e) => e.id);
}

function expectWindows(list: SortedEvents, live: Event[]): void {
  const reference = live.toSorted(compareEventsDesc);
  const times = live.map((e) => e.created_at);
  const min = Math.min(...times);
  const max = Math.max(...times);
  const windows: Array<[number | undefined, number | undefined]> = [
    [undefined, undefined],
    [undefined, max],
    [min, undefined],
    [min, max],
    [min + 1, max - 1],
    [max, max],
    [min, min],
    [min + 20, min + 20],
    [max + 1, max + 100],
    [min - 100, min - 1],
    [max, min],
  ];
  for (let i = 0; i < 60; i++) {
    const a = min + Math.floor(rnd() * (max - min + 1));
    const b = min + Math.floor(rnd() * (max - min + 1));
    windows.push([Math.min(a, b), Math.max(a, b)]);
  }
  for (const [since, until] of windows) {
    const expected = reference.filter(
      (e) =>
        (since === undefined || e.created_at >= since) &&
        (until === undefined || e.created_at <= until),
    );
    expect(ids(drain(list, since, until))).toStrictEqual(ids(expected));
  }
}

/** Phase 1: random `created_at` values force id tie-breaks inside chunks and chunk splits. */
function insertRandom(n: number): { list: SortedEvents; live: Event[] } {
  const list = new SortedEvents();
  const live: Event[] = [];
  for (let i = 0; i < n; i++) {
    const event = fabricate(1_700_000_000 + Math.floor(rnd() * 150));
    list.insert(event);
    live.push(event);
  }
  return { list, live };
}

/** Interleaved removes (chunk merges below the minimum) and inserts; returns each remove's result. */
function churn(list: SortedEvents, live: Event[], n: number): boolean[] {
  const removals: boolean[] = [];
  for (let i = 0; i < n; i++) {
    if (live.length > 0 && rnd() < 0.65) {
      const idx = Math.floor(rnd() * live.length);
      const event = live[idx];
      if (event === undefined) {
        throw new Error("unreachable");
      }
      live.splice(idx, 1);
      removals.push(list.remove(event));
    } else {
      const event = fabricate(1_700_000_000 + Math.floor(rnd() * 150));
      list.insert(event);
      live.push(event);
    }
  }
  return removals;
}

/** Ascending timestamps, then a middle range is drained so an inner chunk shrinks and merges. */
function mergeScenario(): {
  list: SortedEvents;
  live: Event[];
  removed: boolean[];
  absent: boolean[];
} {
  const list = new SortedEvents();
  const live: Event[] = [];
  for (let i = 0; i < 1400; i++) {
    const event = fabricate(1_700_000_000 + i);
    list.insert(event);
    live.push(event);
  }
  const drained = live.splice(500, 800);
  const removed = drained.map((event) => list.remove(event));
  const absent: boolean[] = [];
  const [again] = drained;
  if (again !== undefined) {
    absent.push(list.remove(again));
  }
  absent.push(list.remove(fabricate(1_700_000_500)));
  return { list, live, removed, absent };
}

function insertBackfill(n: number): { list: SortedEvents; live: Event[] } {
  const list = new SortedEvents();
  const live: Event[] = [];
  for (let i = 0; i < n; i++) {
    const event = fabricate(1_700_010_000 - i * 2);
    list.insert(event);
    live.push(event);
  }
  return { list, live };
}

describe("SortedEvents", () => {
  test("cursor order matches a sorted reference under random inserts and removes", () => {
    const { list, live } = insertRandom(6000);
    expect(ids(drain(list))).toStrictEqual(ids(live.toSorted(compareEventsDesc)));
    expect(list.size).toBe(live.length);
    expectWindows(list, live);

    const removals = churn(list, live, 4500);
    expect(removals.every(Boolean)).toBe(true);
    expect(ids(drain(list))).toStrictEqual(ids(live.toSorted(compareEventsDesc)));
    expect(list.size).toBe(live.length);
    expectWindows(list, live);
  });

  test("remove returns false for absent events and chunk merges keep order", () => {
    const { list, live, removed, absent } = mergeScenario();
    expect(removed.every(Boolean)).toBe(true);
    expect(absent.every((v) => !v)).toBe(true);
    expect(ids(drain(list))).toStrictEqual(ids(live.toSorted(compareEventsDesc)));
    expect(list.size).toBe(live.length);
    expectWindows(list, live);
  });

  test("backfill (oldest-first) inserts keep canonical order", () => {
    const { list, live } = insertBackfill(3000);
    expect(ids(drain(list))).toStrictEqual(ids(live.toSorted(compareEventsDesc)));
    expectWindows(list, live);
  });
});
