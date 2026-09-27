import { describe, expect, test } from "vite-plus/test";

import { EventBuilder, Keys, Pool, ReactiveEventStore, naddrEncode } from "../src/index.ts";
import type { Event, Filter } from "../src/index.ts";
import { LoaderContext } from "../src/loaders/context.ts";
import { createEventLoader } from "../src/loaders/event.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const ID1 = "11".repeat(32);
const ID2 = "22".repeat(32);
const RELAY = "wss://idx.example";
const FETCH_TIMEOUT_MS = 1500;

async function captureError(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => {
      throw new Error("expected reject");
    },
    (error: unknown) => error,
  );
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const elemAt = <T>(items: ReadonlyArray<T>, index: number): T => {
  const item = items[index];
  if (item === undefined) {
    throw new Error(`no element at index ${index}`);
  }
  return item;
};

const deliverOnCall = (
  call: number,
  n: number,
  event: Event,
  opts: { onevent?: ((event: Event, relayUrl: string) => void) | undefined } | undefined,
): void => {
  if (call === n) {
    opts?.onevent?.(event, RELAY);
  }
};

const lowerId = (x: Event, y: Event): Event => (x.id < y.id ? x : y);
const higherId = (x: Event, y: Event): Event => (x.id < y.id ? y : x);

async function waitUntil(pred: () => boolean, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling helper must sleep between checks
    await sleep(5);
  }
  throw new Error("timeout waiting for condition");
}

function idsOf(filters: Filter[]): string[] {
  const ids = filters[0]?.ids;
  if (!ids) {
    throw new Error("expected filter.ids");
  }
  return [...ids];
}

function makeCtx(pool: Pool, relays: string[] = [RELAY]): LoaderContext {
  return new LoaderContext({
    pool,
    relays,
    index: new ReactiveEventStore(),
    fetchTimeoutMs: FETCH_TIMEOUT_MS,
  });
}

describe("createEventLoader overlapping fetches", () => {
  test("two distinct ids load()ed in one tick overlap fetches", async () => {
    expect(ID1).not.toBe(ID2);
    const pool = new Pool();
    let inflight = 0;
    let maxInflight = 0;
    const calls: Array<{ ids: string[]; timeoutMs: number | undefined }> = [];
    let release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    pool.fetch = async (_relays, filters, opts) => {
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      calls.push({ ids: idsOf(filters), timeoutMs: opts?.timeoutMs });
      try {
        await hold;
        return [];
      } finally {
        inflight -= 1;
      }
    };
    const loader = createEventLoader(makeCtx(pool));

    const p1 = loader.load(ID1);
    const p2 = loader.load(ID2);
    await waitUntil(() => inflight === 2);
    expect(maxInflight).toBe(2);
    expect(calls).toHaveLength(2);
    expect(calls.flatMap((c) => c.ids).toSorted()).toStrictEqual([ID1, ID2].toSorted());
    expect(calls[0]!.timeoutMs).toBe(FETCH_TIMEOUT_MS);
    expect(calls[1]!.timeoutMs).toBe(FETCH_TIMEOUT_MS);

    release();
    await expect(Promise.all([p1, p2])).resolves.toStrictEqual([undefined, undefined]);
    expect(inflight).toBe(0);
  });

  test("same id load()ed twice in one tick shares one fetch", async () => {
    const pool = new Pool();
    let inflight = 0;
    let maxInflight = 0;
    const calls: string[][] = [];
    let release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    pool.fetch = async (_relays, filters) => {
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      calls.push(idsOf(filters));
      try {
        await hold;
        return [];
      } finally {
        inflight -= 1;
      }
    };
    const loader = createEventLoader(makeCtx(pool));

    const p1 = loader.load(ID1);
    const p2 = loader.load({ id: ID1, relays: ["wss://hint.example"] });
    await waitUntil(() => inflight === 1);
    expect(maxInflight).toBe(1);
    expect(calls).toStrictEqual([[ID1]]);

    release();
    await expect(Promise.all([p1, p2])).resolves.toStrictEqual([undefined, undefined]);
    expect(inflight).toBe(0);
  });

  test("hints change relay URLs; a miss is never cached", async () => {
    const pool = new Pool();
    const seen: string[][] = [];
    let fetchCalls = 0;
    pool.fetch = async (relays) => {
      await Promise.resolve();
      fetchCalls += 1;
      seen.push([...relays]);
      return [];
    };
    const loader = createEventLoader(makeCtx(pool));
    const hint = "wss://hint.example";
    await expect(loader.load({ id: ID1, relays: [hint] })).resolves.toBeUndefined();
    expect(fetchCalls).toBe(1);
    expect(seen).toStrictEqual([[hint, RELAY]]);
    await expect(loader.load(ID1)).resolves.toBeUndefined();
    expect(fetchCalls).toBe(2);
    expect(seen).toStrictEqual([[hint, RELAY], [RELAY]]);
  });

  test("a miss does not block a later fetch from resolving", async () => {
    const keys = Keys.fromSecretKey(SK);
    const event = EventBuilder.textNote("late").createdAt(1).signWithKeys(keys);
    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async (_relays, _filters, opts) => {
      await Promise.resolve();
      fetchCalls += 1;
      deliverOnCall(fetchCalls, 2, event, opts);
      return [];
    };
    const loader = createEventLoader(makeCtx(pool));
    await expect(loader.load(event.id)).resolves.toBeUndefined();
    expect(fetchCalls).toBe(1);
    const late = await loader.load(event.id);
    expect(late?.id).toBe(event.id);
    expect(fetchCalls).toBe(2);
    // Now the index holds it — no further fetch needed.
    await expect(loader.load(event.id)).resolves.toStrictEqual(event);
    expect(fetchCalls).toBe(2);
  });

  test("serial load() fetches keep maxInflight at 1", async () => {
    expect(ID1).not.toBe(ID2);
    const pool = new Pool();
    let inflight = 0;
    let maxInflight = 0;
    const calls: string[][] = [];
    pool.fetch = async (_relays, filters) => {
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      calls.push(idsOf(filters));
      try {
        await sleep(20);
        return [];
      } finally {
        inflight -= 1;
      }
    };
    const loader = createEventLoader(makeCtx(pool));

    await expect(loader.load(ID1)).resolves.toBeUndefined();
    expect(inflight).toBe(0);
    await expect(loader.load(ID2)).resolves.toBeUndefined();
    expect(inflight).toBe(0);
    expect(maxInflight).toBe(1);
    expect(calls).toStrictEqual([[ID1], [ID2]]);
  });

  test("no relays and no hints skips pool.fetch", async () => {
    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async () => {
      await Promise.resolve();
      fetchCalls += 1;
      return [];
    };
    const loader = createEventLoader(makeCtx(pool, []));
    await expect(loader.load(ID1)).resolves.toBeUndefined();
    expect(fetchCalls).toBe(0);
  });

  test("EventPointer hints fetch when ctx.relays is empty", async () => {
    const pool = new Pool();
    const seen: string[][] = [];
    pool.fetch = async (relays) => {
      await Promise.resolve();
      seen.push([...relays]);
      return [];
    };
    const loader = createEventLoader(makeCtx(pool, []));
    const hint = "wss://hint.example";
    await expect(loader.load({ id: ID1, relays: [hint] })).resolves.toBeUndefined();
    expect(seen).toStrictEqual([[hint]]);
  });

  test("index winner selection: newer version of an addressable ref wins", async () => {
    const keys = Keys.fromSecretKey(SK);
    const older = new EventBuilder(30023, "old").tag(["d", "x"]).createdAt(1).signWithKeys(keys);
    const newer = new EventBuilder(30023, "new").tag(["d", "x"]).createdAt(99).signWithKeys(keys);

    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async (_relays, _filters, opts) => {
      await Promise.resolve();
      fetchCalls += 1;
      opts?.onevent?.(older, RELAY);
      opts?.onevent?.(newer, RELAY);
      return [older, newer];
    };
    const loader = createEventLoader(makeCtx(pool));
    const result = await loader.load({ kind: 30023, pubkey: keys.publicKey, identifier: "x" });
    expect(fetchCalls).toBe(1);
    expect(result?.id).toBe(newer.id);
  });

  test("empty pool.fetch result is undefined", async () => {
    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async () => {
      await Promise.resolve();
      fetchCalls += 1;
      return [];
    };
    const loader = createEventLoader(makeCtx(pool));
    await expect(loader.load(ID1)).resolves.toBeUndefined();
    expect(fetchCalls).toBe(1);
  });

  test("pool.fetch throw rejects load", async () => {
    const boom = new Error("relay down");
    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async () => {
      await Promise.resolve();
      fetchCalls += 1;
      throw boom;
    };
    const loader = createEventLoader(makeCtx(pool));
    const err = await captureError(loader.load(ID1));
    expect(fetchCalls).toBe(1);
    expect(err).toBe(boom);
    const err2 = await captureError(loader.load(ID1));
    expect(fetchCalls).toBe(2);
    expect(err2).toBe(boom);
  });

  test('addressable kind 30023 with empty identifier sends #d:[""]', async () => {
    const keys = Keys.fromSecretKey(SK);
    const pool = new Pool();
    const seen: Filter[] = [];
    pool.fetch = async (_relays, filters) => {
      await Promise.resolve();
      seen.push(elemAt(filters, 0));
      return [];
    };
    const loader = createEventLoader(makeCtx(pool));
    const pubkey = keys.publicKey;
    await expect(loader.load({ kind: 30023, pubkey, identifier: "" })).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(Object.hasOwn(seen[0]!, "#d")).toBe(true);
    expect(seen[0]!["#d"]).toStrictEqual([""]);
    expect(seen[0]!.authors).toStrictEqual([pubkey.toLowerCase()]);
    expect(seen[0]!.kinds).toStrictEqual([30023]);

    const naddr = naddrEncode({ kind: 30023, pubkey, identifier: "" });
    await expect(loader.load(naddr)).resolves.toBeUndefined();
    expect(seen).toHaveLength(2);
    expect(Object.hasOwn(seen[1]!, "#d")).toBe(true);
    expect(seen[1]!["#d"]).toStrictEqual([""]);
    expect(seen[1]!.authors).toStrictEqual([pubkey.toLowerCase()]);
    expect(seen[1]!.kinds).toStrictEqual([30023]);
  });

  test("kind 0 AddressPointer omits #d", async () => {
    const keys = Keys.fromSecretKey(SK);
    const pool = new Pool();
    const seen: Filter[] = [];
    pool.fetch = async (_relays, filters) => {
      await Promise.resolve();
      seen.push(elemAt(filters, 0));
      return [];
    };
    const loader = createEventLoader(makeCtx(pool));
    const pubkey = keys.publicKey;
    await expect(loader.load({ kind: 0, pubkey, identifier: "" })).resolves.toBeUndefined();
    expect(seen).toHaveLength(1);
    expect(Object.hasOwn(seen[0]!, "#d")).toBe(false);
    expect(seen[0]!["#d"]).toBeUndefined();
    expect(seen[0]!.authors).toStrictEqual([pubkey.toLowerCase()]);
    expect(seen[0]!.kinds).toStrictEqual([0]);

    await expect(loader.load({ kind: 0, pubkey, identifier: "profile" })).resolves.toBeUndefined();
    expect(seen).toHaveLength(2);
    expect(Object.hasOwn(seen[1]!, "#d")).toBe(false);
    expect(seen[1]!["#d"]).toBeUndefined();
    expect(seen[1]!.kinds).toStrictEqual([0]);

    const naddr = naddrEncode({ kind: 0, pubkey, identifier: "" });
    await expect(loader.load(naddr)).resolves.toBeUndefined();
    expect(seen).toHaveLength(3);
    expect(Object.hasOwn(seen[2]!, "#d")).toBe(false);
    expect(seen[2]!["#d"]).toBeUndefined();
    expect(seen[2]!.authors).toStrictEqual([pubkey.toLowerCase()]);
    expect(seen[2]!.kinds).toStrictEqual([0]);
  });

  test("two addressable versions same created_at, lower id wins", async () => {
    const keys = Keys.fromSecretKey(SK);
    const a = new EventBuilder(30023, "a").tag(["d", "x"]).createdAt(50).signWithKeys(keys);
    const b = new EventBuilder(30023, "b").tag(["d", "x"]).createdAt(50).signWithKeys(keys);
    expect(a.id).not.toBe(b.id);
    const winner = lowerId(a, b);
    const loser = higherId(a, b);

    const pool = new Pool();
    let fetchCalls = 0;
    pool.fetch = async (_relays, _filters, opts) => {
      await Promise.resolve();
      fetchCalls += 1;
      opts?.onevent?.(loser, RELAY);
      opts?.onevent?.(winner, RELAY);
      return [loser, winner];
    };
    const loader = createEventLoader(makeCtx(pool));
    const result = await loader.load({ kind: 30023, pubkey: keys.publicKey, identifier: "x" });
    expect(fetchCalls).toBe(1);
    expect(result?.id).toBe(winner.id);
  });
});
