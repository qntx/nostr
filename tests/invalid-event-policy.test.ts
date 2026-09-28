import { afterEach, beforeEach, describe, expect, test, vi } from "vite-plus/test";

import {
  Client,
  EventBuilder,
  Keys,
  Pool,
  RelaySuspendedError,
  normalizeURL,
} from "../src/index.ts";
import type { Event } from "../src/index.ts";
import { createFakeRelayNetwork } from "../src/testing/index.ts";
import type { FakeRelayNetwork } from "../src/testing/index.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const A = "wss://a.example";
const B = "wss://b.example";
const POLICY = { limit: 2, windowMs: 300, cooldownMs: 200 };

const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const keys = Keys.fromSecretKey(SK);

/** A well-formed wire event whose id/signature no longer match its body. */
function forged(i: number): Event {
  const event = EventBuilder.textNote(`forged ${i}`)
    .createdAt(i + 1)
    .signWithKeys(keys);
  return { ...event, content: `${event.content} tampered` };
}

function makePool(extra: Partial<ConstructorParameters<typeof Pool>[0]> = {}) {
  const onRelaySuspended = vi.fn();
  const pool = new Pool({
    websocketImplementation: net.websocketImplementation,
    enableReconnect: false,
    invalidEventPolicy: POLICY,
    onRelaySuspended,
    ...extra,
  });
  return { pool, onRelaySuspended };
}

let net: FakeRelayNetwork;

describe("invalid-event policy", () => {
  beforeEach(() => {
    net = createFakeRelayNetwork();
  });

  afterEach(() => {
    net.close();
  });

  test("below the limit nothing is suspended", async () => {
    const { pool, onRelaySuspended } = makePool();
    pool.subscribe([A], [{}]);
    await sleep(20);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    await sleep(20);

    expect(onRelaySuspended).not.toHaveBeenCalled();
    expect(pool.getRelay(A)?.connected).toBe(true);
    pool.close();
  });

  test("limit+1 inside the window closes the connection and reports once", async () => {
    const { pool, onRelaySuspended } = makePool();
    pool.subscribe([A], [{}]);
    await sleep(20);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    net.relay(A).deliver(forged(3));
    await sleep(20);

    expect(onRelaySuspended).toHaveBeenCalledTimes(1);
    const [url, until] = onRelaySuspended.mock.calls[0] as unknown as [string, number];
    expect(url).toBe(normalizeURL(A));
    expect(until).toBeGreaterThan(Date.now());
    expect(pool.getRelay(A)?.connected).toBe(false);
    pool.close();
  });

  test("failures spread beyond the window do not accumulate", async () => {
    const { pool, onRelaySuspended } = makePool({
      invalidEventPolicy: { limit: 2, windowMs: 80, cooldownMs: 200 },
    });
    pool.subscribe([A], [{}]);
    await sleep(20);

    for (let i = 0; i < 5; i += 1) {
      net.relay(A).deliver(forged(i));
      // oxlint-disable-next-line no-await-in-loop -- spacing failures beyond the window is the test
      await sleep(120);
    }

    expect(onRelaySuspended).not.toHaveBeenCalled();
    expect(pool.getRelay(A)?.connected).toBe(true);
    pool.close();
  });

  test("during cooldown ensureRelay rejects while other relays keep working", async () => {
    const { pool } = makePool();
    pool.subscribe([A], [{}]);
    await sleep(20);
    const note = EventBuilder.textNote("from b").createdAt(9).signWithKeys(keys);
    net.relay(B).seed([note]);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    net.relay(A).deliver(forged(3));
    await sleep(20);

    const failure = await pool.ensureRelay(A).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(RelaySuspendedError);
    expect((failure as RelaySuspendedError).until).toBeGreaterThan(Date.now());

    const event = EventBuilder.textNote("publish").createdAt(10).signWithKeys(keys);
    const results = await pool.publish([A, B], event, { timeoutMs: 1000 });
    const resultA = results.find((r) => r.url === A);
    const resultB = results.find((r) => r.url === normalizeURL(B));
    expect(resultA?.error).toContain("suspended");
    expect(resultB?.result?.ok).toBe(true);

    const fetched = await pool.fetch([A, B], [{ ids: [note.id] }], { timeoutMs: 1000 });
    expect(fetched.map((e) => e.id)).toStrictEqual([note.id]);
    pool.close();
  });

  test("a live subscription resumes once the cooldown lifts", async () => {
    const { pool, onRelaySuspended } = makePool();
    const seen: string[] = [];
    pool.subscribe([A], [{}], {
      onevent: (event) => {
        seen.push(event.id);
      },
    });
    await sleep(20);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    net.relay(A).deliver(forged(3));
    await sleep(20);
    expect(onRelaySuspended).toHaveBeenCalledTimes(1);
    expect(pool.getRelay(A)?.connected).toBe(false);

    // During the cooldown the relay stays disconnected.
    await sleep(POLICY.cooldownMs / 2);
    expect(pool.getRelay(A)?.connected).toBe(false);

    // Past `until` the pool reconnects and replays the open REQ.
    await sleep(POLICY.cooldownMs);
    expect(pool.getRelay(A)?.connected).toBe(true);

    const live = EventBuilder.textNote("resumed").createdAt(11).signWithKeys(keys);
    net.relay(A).inject(live);
    await sleep(30);
    expect(seen).toStrictEqual([live.id]);
    pool.close();
  });

  test("pinned relays are suspended too", async () => {
    const { pool, onRelaySuspended } = makePool({ pinnedUrls: [A] });
    pool.subscribe([A], [{}]);
    await sleep(20);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    net.relay(A).deliver(forged(3));
    await sleep(20);

    expect(onRelaySuspended).toHaveBeenCalledTimes(1);
    await expect(pool.ensureRelay(A)).rejects.toBeInstanceOf(RelaySuspendedError);
    pool.close();
  });

  test("without a policy invalid events are just dropped", async () => {
    const pool = new Pool({
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    const seen: string[] = [];
    pool.subscribe([A], [{}], {
      onevent: (event) => {
        seen.push(event.id);
      },
    });
    await sleep(20);

    for (let i = 0; i < 6; i += 1) {
      net.relay(A).deliver(forged(i));
    }
    await sleep(30);

    expect(seen).toHaveLength(0);
    expect(pool.getRelay(A)?.connected).toBe(true);
    pool.close();
  });

  test("Client forwards invalidEventPolicy and onRelaySuspended", async () => {
    const onRelaySuspended = vi.fn();
    const client = new Client({
      websocketImplementation: net.websocketImplementation,
      relays: [A],
      invalidEventPolicy: POLICY,
      onRelaySuspended,
      enableReconnect: false,
    });
    await client.connect();
    client.subscribe([{}]);
    await sleep(20);

    net.relay(A).deliver(forged(1));
    net.relay(A).deliver(forged(2));
    net.relay(A).deliver(forged(3));
    await sleep(20);

    expect(onRelaySuspended).toHaveBeenCalledTimes(1);
    await expect(client.pool.ensureRelay(A)).rejects.toBeInstanceOf(RelaySuspendedError);
    await client.shutdown();
  });
});
