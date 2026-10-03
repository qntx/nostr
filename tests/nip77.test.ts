import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import {
  Client,
  EventBuilder,
  Gossip,
  Keys,
  MemoryEventStore,
  MessageError,
  Relay,
  RelayTimeoutError,
  SyncDirection,
  bytesToHex,
  encodeClientMessage,
  parseClientMessage,
  parseRelayMessage,
} from "../src/index.ts";
import type { Event, EventStore, Filter, Pool, PutResult } from "../src/index.ts";
import {
  MAX_NEG_ROUNDS,
  Negentropy,
  NegentropyStorageVector,
  Nip77Error,
  PROTOCOL_VERSION,
  runNegSession,
  storageFromEvents,
} from "../src/nips/nip77.ts";
import type { WebSocketConstructor } from "../src/relay/websocket.ts";
import { createFakeRelayNetwork } from "../src/testing/index.ts";
import type { FakeRelayNetwork } from "../src/testing/index.ts";

const SK_A = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const SK_B = "0000000000000000000000000000000000000000000000000000000000000001";

function note(sk: string, content: string, createdAt: number) {
  return EventBuilder.textNote(content).createdAt(createdAt).signWithKeys(Keys.fromSecretKey(sk));
}

function wrapEventStore(
  inner: EventStore,
  overrides: Partial<Pick<EventStore, "get" | "query" | "putMany">> = {},
): EventStore {
  return {
    put: async (event) => inner.put(event),
    putMany: overrides.putMany ?? (async (events) => inner.putMany(events)),
    get: overrides.get ?? (async (id) => inner.get(id)),
    query: overrides.query ?? (async (filters) => inner.query(filters)),
    count: async (filters) => inner.count(filters),
    negentropyItems: async (filter) => inner.negentropyItems(filter),
    remove: async (ids) => inner.remove(ids),
    clear: async () => inner.clear(),
    getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
    setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
  };
}

function varintBytes(n: number): number[] {
  if (n === 0) {
    return [0];
  }
  const digits: number[] = [];
  let value = n;
  while (value !== 0) {
    digits.push(value % 128);
    value = Math.floor(value / 128);
  }
  digits.reverse();
  return digits.map((digit, i) => (i === digits.length - 1 ? digit : digit + 0x80));
}

function runUntilDone(
  init: Negentropy,
  responder: Negentropy,
): {
  have: string[];
  need: string[];
  rounds: number;
} {
  const have = new Set<string>();
  const need = new Set<string>();
  const opening = init.initiate();
  const respond = (out: {
    have: string[];
    need: string[];
    nextMessage: string | undefined;
  }): typeof out =>
    out.nextMessage === undefined
      ? { have: out.have, need: out.need, nextMessage: PROTOCOL_VERSION.toString(16) }
      : out;
  let incoming = respond(responder.reconcile(opening));
  let rounds = 1;
  for (;;) {
    const message = incoming.nextMessage;
    if (message === undefined) {
      throw new Error("expected a next message");
    }
    const out = init.reconcile(message);
    for (const id of out.have) {
      have.add(id);
    }
    for (const id of out.need) {
      need.add(id);
    }
    rounds += 1;
    if (out.nextMessage === undefined) {
      return { have: [...have], need: [...need], rounds };
    }
    incoming = respond(responder.reconcile(out.nextMessage));
  }
}

const takeMessage = (get: () => string | undefined): string => {
  const message = get();
  if (message === undefined) {
    throw new Error("missing incoming");
  }
  return message;
};

const isNegFrame = (data: string): boolean => {
  const parsed: unknown = JSON.parse(data);
  return Array.isArray(parsed) && typeof parsed[0] === "string" && parsed[0].startsWith("NEG-");
};

const dropSend = (
  base: WebSocketConstructor,
  drop: (url: string, data: string) => boolean,
): WebSocketConstructor =>
  class extends base {
    constructor(url: string) {
      super(url);
      const inner = this.send.bind(this);
      this.send = (data: string) => {
        if (drop(url, data)) {
          return;
        }
        inner(data);
      };
    }
  };

const isSilentNegUrl = (url: string, _data: string): boolean => url.includes("silent-neg.example");

const nextOrVersion = (nextMessage: string | undefined): string =>
  nextMessage ?? PROTOCOL_VERSION.toString(16);

const exceptIndices =
  (dropped: ReadonlySet<number>) =>
  (_ev: Event, i: number): boolean =>
    !dropped.has(i);

const negFrameOnly = (_url: string, data: string): boolean => isNegFrame(data);

const putManyFailing =
  (inner: MemoryEventStore, failId: string) =>
  async (events: ReadonlyArray<Event>): Promise<PutResult[]> => {
    await Promise.resolve();
    if (events.some((event) => event.id === failId)) {
      throw new Error("disk full");
    }
    return inner.putMany(events);
  };

const publishFailing =
  (publish: Pool["publish"], failId: string): Pool["publish"] =>
  async (relays, event, opts) => {
    await Promise.resolve();
    if (event.id === failId) {
      throw new Error("boom");
    }
    return publish(relays, event, opts);
  };

async function captureError(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (error) {
    return error;
  }
  throw new Error("expected rejection");
}

describe("NIP-77 message codec", () => {
  test("encodes and parses 4-element NEG-OPEN", () => {
    const wire = encodeClientMessage(["NEG-OPEN", "n1", { kinds: [1] }, "61"]);
    expect(JSON.parse(wire)).toStrictEqual(["NEG-OPEN", "n1", { kinds: [1] }, "61"]);
    expect(parseClientMessage(wire)).toStrictEqual(["NEG-OPEN", "n1", { kinds: [1] }, "61"]);
  });

  test("rejects obsolete 5-element NEG-OPEN", () => {
    expect(() =>
      parseClientMessage(JSON.stringify(["NEG-OPEN", "n1", { kinds: [1] }, 32, "61"])),
    ).toThrow(MessageError);
    expect(() =>
      parseClientMessage(JSON.stringify(["NEG-OPEN", "n1", { kinds: [1] }, 32, "61"])),
    ).toThrow(/obsolete 5-element NEG-OPEN/);
  });

  test("parses NEG-MSG / NEG-CLOSE / NEG-ERR", () => {
    expect(parseClientMessage(JSON.stringify(["NEG-MSG", "n1", "61aa"]))).toStrictEqual([
      "NEG-MSG",
      "n1",
      "61aa",
    ]);
    expect(parseClientMessage(JSON.stringify(["NEG-CLOSE", "n1"]))).toStrictEqual([
      "NEG-CLOSE",
      "n1",
    ]);
    expect(parseRelayMessage(JSON.stringify(["NEG-MSG", "n1", "61"]))).toStrictEqual([
      "NEG-MSG",
      "n1",
      "61",
    ]);
    expect(parseRelayMessage(JSON.stringify(["NEG-ERR", "n1", "blocked: too big"]))).toStrictEqual([
      "NEG-ERR",
      "n1",
      "blocked: too big",
    ]);
  });

  test("parses 3- or 4-element NEG-ERR and ignores the optional 4th", () => {
    expect(
      parseRelayMessage(JSON.stringify(["NEG-ERR", "n1", "blocked: too big", 100])),
    ).toStrictEqual(["NEG-ERR", "n1", "blocked: too big"]);
    expect(
      parseRelayMessage(JSON.stringify(["NEG-ERR", "n1", "error: boom", "ignored"])),
    ).toStrictEqual(["NEG-ERR", "n1", "error: boom"]);
  });

  test("rejects NEG-ERR arity other than 3 or 4", () => {
    expect(() => parseRelayMessage(JSON.stringify(["NEG-ERR", "n1"]))).toThrow(MessageError);
    expect(() =>
      parseRelayMessage(JSON.stringify(["NEG-ERR", "n1", "blocked", 1, "extra"])),
    ).toThrow(MessageError);
    expect(() => parseRelayMessage(JSON.stringify(["NEG-ERR", 1, "blocked"]))).toThrow(
      MessageError,
    );
  });
});

describe("Negentropy algorithm", () => {
  test("empty sets converge with no delta", () => {
    const a = new NegentropyStorageVector();
    a.seal();
    const b = new NegentropyStorageVector();
    b.seal();
    const { have, need } = runUntilDone(new Negentropy(a), new Negentropy(b));
    expect(have).toStrictEqual([]);
    expect(need).toStrictEqual([]);
  });

  test("initiator learns local-only and remote-only ids", () => {
    const shared = note(SK_A, "shared", 10);
    const onlyA = note(SK_A, "alice", 11);
    const onlyB = note(SK_B, "bob", 12);
    const init = new Negentropy(storageFromEvents([shared, onlyA]));
    const resp = new Negentropy(storageFromEvents([shared, onlyB]));
    const { have, need } = runUntilDone(init, resp);
    expect(have).toStrictEqual([onlyA.id]);
    expect(need).toStrictEqual([onlyB.id]);
  });

  test("fingerprint path with >32 items still finds the delta", () => {
    const keys = Keys.fromSecretKey(SK_A);
    const alice = Array.from({ length: 40 }, (_, i) =>
      EventBuilder.textNote(`n${i}`)
        .createdAt(100 + i)
        .signWithKeys(keys),
    );
    const bob = alice.filter(exceptIndices(new Set([7, 33])));
    const extra = EventBuilder.textNote("remote")
      .createdAt(999)
      .signWithKeys(Keys.fromSecretKey(SK_B));
    bob.push(extra);
    const { have, need } = runUntilDone(
      new Negentropy(storageFromEvents(alice)),
      new Negentropy(storageFromEvents(bob)),
    );
    expect(have.toSorted()).toStrictEqual([alice[7]!.id, alice[33]!.id].toSorted());
    expect(need).toStrictEqual([extra.id]);
  });

  test("runNegSession collects have/need until nextMessage is null", async () => {
    const shared = note(SK_A, "shared", 10);
    const onlyA = note(SK_A, "alice", 11);
    const onlyB = note(SK_B, "bob", 12);
    const resp = new Negentropy(storageFromEvents([shared, onlyB]));
    let incoming: string | undefined;
    const { have, need } = await runNegSession({
      storage: storageFromEvents([shared, onlyA]),
      openingSend: (hex) => {
        incoming = nextOrVersion(resp.reconcile(hex).nextMessage);
      },
      msgSend: (hex) => {
        incoming = nextOrVersion(resp.reconcile(hex).nextMessage);
      },
      next: async () => {
        await Promise.resolve();
        return takeMessage(() => incoming);
      },
    });
    expect(have).toStrictEqual([onlyA.id]);
    expect(need).toStrictEqual([onlyB.id]);
  });

  test("runNegSession throws after MAX_NEG_ROUNDS", async () => {
    const storage = new NegentropyStorageVector();
    storage.seal();
    const mismatch = `61000001${"ff".repeat(16)}`;
    let nextCalls = 0;
    const err = await captureError(
      runNegSession({
        storage,
        openingSend: () => {},
        msgSend: () => {},
        next: async () => {
          await Promise.resolve();
          nextCalls += 1;
          return mismatch;
        },
      }),
    );
    expect(err).toBeInstanceOf(Nip77Error);
    expect((err as Nip77Error).message).toBe("negentropy exceeded max rounds");
    expect(nextCalls).toBe(MAX_NEG_ROUNDS);
  });

  test("reconcile replies with the supported version byte on version mismatch", () => {
    const storage = new NegentropyStorageVector();
    storage.seal();
    const neg = new Negentropy(storage);
    // Any 0x60..0x6f version other than 0x61 negotiates a downgrade to 0x61.
    for (const version of ["60", "62", "6f"]) {
      const out = neg.reconcile(version);
      expect(out.nextMessage).toBe("61");
      expect(out.have).toStrictEqual([]);
      expect(out.need).toStrictEqual([]);
    }
  });

  test("varint bound timestamps round-trip, including above 2^31", () => {
    const id = "ab".repeat(32);
    // The bound varint carries timestamp + 1; 0 is reserved for the infinity bound.
    for (const wire of [127, 128, 2 ** 31, 2 ** 32 + 5, Number.MAX_SAFE_INTEGER]) {
      const storage = new NegentropyStorageVector();
      storage.insert(1, id);
      storage.seal();
      const neg = new Negentropy(storage);
      // version byte, bound {ts: wire-1, id: ""}, mode IdList, numIds 0
      const query = bytesToHex(Uint8Array.from([0x61, ...varintBytes(wire), 0, 0x02, 0]));
      const out = neg.reconcile(query);
      // reply echoes the bound: version, ts varint, empty id prefix, IdList, count, id
      const expected = `61${bytesToHex(Uint8Array.from(varintBytes(wire)))}000201${id}`;
      expect(out.nextMessage).toBe(expected);
      expect(out.have).toStrictEqual([]);
      expect(out.need).toStrictEqual([]);
    }
  });

  test("rejects oversized and truncated varints", () => {
    const storage = new NegentropyStorageVector();
    storage.insert(1, "ab".repeat(32));
    storage.seal();
    const neg = new Negentropy(storage);
    // varint(2^53) exceeds Number.MAX_SAFE_INTEGER mid-decode
    const overflow = bytesToHex(Uint8Array.from([0x61, ...varintBytes(2 ** 53), 0, 0]));
    expect(() => neg.reconcile(overflow)).toThrow(Nip77Error);
    // continuation bit set but the buffer ends
    const truncated = bytesToHex(Uint8Array.from([0x61, 0x81]));
    expect(() => neg.reconcile(truncated)).toThrow(Nip77Error);
  });

  test("reconcile converges for items with created_at above 2^31", () => {
    const base = 2 ** 31 + 5000;
    const keys = Keys.fromSecretKey(SK_A);
    const events = Array.from({ length: 40 }, (_, i) =>
      EventBuilder.textNote(`big-ts-${i}`)
        .createdAt(base + i)
        .signWithKeys(keys),
    );
    const missing = events[17]!;
    const remote = events.filter((_, i) => i !== 17);
    remote.push(note(SK_B, "extra", base + 100));
    const extra = remote.at(-1)!;
    const { have, need } = runUntilDone(
      new Negentropy(storageFromEvents(events)),
      new Negentropy(storageFromEvents(remote)),
    );
    expect(have).toStrictEqual([missing.id]);
    expect(need).toStrictEqual([extra.id]);
  });

  test("reconcile throws on a version byte outside 0x60..0x6f", () => {
    const storage = new NegentropyStorageVector();
    storage.seal();
    const neg = new Negentropy(storage);
    expect(() => neg.reconcile("50")).toThrow(Nip77Error);
    expect(() => neg.reconcile("50")).toThrow(/protocol version/);
    expect(() => neg.reconcile("70")).toThrow(Nip77Error);
    // An empty query has no version byte at all.
    expect(() => neg.reconcile("")).toThrow(/parse ends prematurely/);
  });
});

describe("Relay.negReconcile + Client.sync", () => {
  let net: FakeRelayNetwork;

  beforeEach(() => {
    net = createFakeRelayNetwork();
  });

  afterEach(() => {
    net.close();
  });

  test("Relay.negReconcile reports have/need against seeded relay", async () => {
    const localOnly = note(SK_A, "local", 1);
    const remoteOnly = note(SK_B, "remote", 2);
    const shared = note(SK_A, "shared", 3);
    net.relay("wss://neg.example").seed([remoteOnly, shared]);

    const relay = await Relay.connect("wss://neg.example", {
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    const storage = storageFromEvents([localOnly, shared]);
    const { have, need } = await relay.negReconcile({ kinds: [1] }, storage, { timeoutMs: 2000 });
    expect(have).toStrictEqual([localOnly.id]);
    expect(need).toStrictEqual([remoteOnly.id]);
    relay.close();
  });

  test("fake relay answers an unsupported NEG version with NEG-MSG 61", async () => {
    net.relay("wss://neg.example");
    const ws = new net.websocketImplementation("wss://neg.example") as unknown as {
      addEventListener: (t: string, l: (ev: { data: string }) => void) => void;
      send: (data: string) => void;
      close: () => void;
    };
    const reply = new Promise<unknown>((resolve) => {
      ws.addEventListener("message", (ev) => resolve(JSON.parse(ev.data)));
      ws.addEventListener("open", () =>
        ws.send(JSON.stringify(["NEG-OPEN", "sub1", { kinds: [1] }, "62"])),
      );
    });
    await expect(reply).resolves.toStrictEqual(["NEG-MSG", "sub1", "61"]);
    ws.close();
  });

  test("Client.sync down downloads remote-only events", async () => {
    const remote = note(SK_B, "from-relay", 20);
    net.relay("wss://neg.example").seed([remote]);
    const store = new MemoryEventStore();
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    await expect(store.get(remote.id)).resolves.toBeDefined();
    await client.shutdown();
  });

  test("Client.sync up publishes local-only events", async () => {
    const local = note(SK_A, "to-relay", 21);
    const store = new MemoryEventStore();
    await store.put(local);
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(summary.local).toStrictEqual([local.id]);
    expect(summary.sent).toStrictEqual([local.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(
      net
        .relay("wss://neg.example")
        .events()
        .some((e) => e.id === local.id),
    ).toBe(true);
    await client.shutdown();
  });

  test("Client.syncToRelay up loads via query not get", async () => {
    const events = [note(SK_A, "a", 1), note(SK_A, "b", 2), note(SK_A, "c", 3)];
    const inner = new MemoryEventStore();
    await inner.putMany(events);
    let getCount = 0;
    let queryCount = 0;
    let queried: ReadonlyArray<Filter> | undefined;
    const store = wrapEventStore(inner, {
      get: async (id) => {
        getCount += 1;
        return inner.get(id);
      },
      query: async (filters) => {
        queryCount += 1;
        queried = filters;
        return inner.query(filters);
      },
    });
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: false,
    });
    await client.connect();
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(getCount).toBe(0);
    expect(queryCount).toBe(1);
    expect(queried).toBeDefined();
    expect(queried).toHaveLength(1);
    expect(queried![0]!.ids).toBeDefined();
    expect(queried![0]!.kinds).toBeUndefined();
    expect(new Set(queried![0]!.ids)).toStrictEqual(new Set(events.map((event) => event.id)));
    expect(new Set(summary.sent)).toStrictEqual(new Set(events.map((event) => event.id)));
    expect(summary.persistFailures).toStrictEqual({});
    await client.shutdown();
  });

  test("Client.syncToRelay up skips query when have is empty", async () => {
    const shared = note(SK_A, "shared", 1);
    net.relay("wss://neg.example").seed([shared]);
    const inner = new MemoryEventStore();
    await inner.put(shared);
    let getCount = 0;
    let queryCount = 0;
    const store = wrapEventStore(inner, {
      get: async (id) => {
        getCount += 1;
        return inner.get(id);
      },
      query: async (filters) => {
        queryCount += 1;
        return inner.query(filters);
      },
    });
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: false,
    });
    await client.connect();
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(summary.local).toStrictEqual([]);
    expect(summary.sent).toStrictEqual([]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(queryCount).toBe(0);
    expect(getCount).toBe(0);
    await client.shutdown();
  });

  test("Client.syncToRelay up publishes with concurrency 8", async () => {
    const events = Array.from({ length: 16 }, (_, i) => note(SK_A, `n${i}`, 100 + i));
    const store = new MemoryEventStore();
    await store.putMany(events);
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    let inflight = 0;
    let maxInflight = 0;
    const origPublish = client.pool.publish.bind(client.pool);
    client.pool.publish = async (relays, event, opts) => {
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      await new Promise((resolve) => setTimeout(resolve, 30));
      try {
        return await origPublish(relays, event, opts);
      } finally {
        inflight -= 1;
      }
    };
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(maxInflight).toBeGreaterThan(1);
    expect(maxInflight).toBe(8);
    expect(new Set(summary.sent)).toStrictEqual(new Set(events.map((event) => event.id)));
    expect(summary.persistFailures).toStrictEqual({});
    await client.shutdown();
  });

  test("Client.syncToRelay up records sendFailures for ids missing from query", async () => {
    const events = [note(SK_A, "a", 1), note(SK_A, "b", 2), note(SK_A, "c", 3)];
    const missing = events[1]!;
    const inner = new MemoryEventStore();
    await inner.putMany(events);
    let getCount = 0;
    let queryCount = 0;
    let queried: ReadonlyArray<Filter> | undefined;
    const store = wrapEventStore(inner, {
      get: async (id) => {
        getCount += 1;
        return inner.get(id);
      },
      query: async (filters) => {
        queryCount += 1;
        queried = filters;
        const found = await inner.query(filters);
        return found.filter((event) => event.id !== missing.id);
      },
    });
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: false,
    });
    await client.connect();
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(getCount).toBe(0);
    expect(queryCount).toBe(1);
    expect(queried).toBeDefined();
    expect(queried).toHaveLength(1);
    expect(queried![0]!.ids).toBeDefined();
    expect(queried![0]!.kinds).toBeUndefined();
    expect(new Set(queried![0]!.ids)).toStrictEqual(new Set(events.map((event) => event.id)));
    expect(summary.sendFailures[missing.id]).toBe("event not found in local store");
    expect(Object.keys(summary.sendFailures)).toStrictEqual([missing.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(new Set(summary.sent)).toStrictEqual(
      new Set(events.filter((event) => event.id !== missing.id).map((event) => event.id)),
    );
    await client.shutdown();
  });

  test("Client.syncToRelay up isolates a throwing publish in the chunk", async () => {
    const events = [note(SK_A, "a", 1), note(SK_A, "b", 2), note(SK_A, "c", 3)];
    const boom = events[1]!;
    const store = new MemoryEventStore();
    await store.putMany(events);
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    const origPublish = client.pool.publish.bind(client.pool);
    client.pool.publish = publishFailing(origPublish, boom.id);
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Up, timeoutMs: 2000 },
    );
    expect(summary.sendFailures[boom.id]).toBe("boom");
    expect(Object.keys(summary.sendFailures)).toStrictEqual([boom.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(new Set(summary.sent)).toStrictEqual(
      new Set(events.filter((event) => event.id !== boom.id).map((event) => event.id)),
    );
    await client.shutdown();
  });

  test("Client.sync dryRun does not exchange events", async () => {
    const remote = note(SK_B, "stay", 22);
    net.relay("wss://neg.example").seed([remote]);
    const store = new MemoryEventStore();
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Both, dryRun: true, timeoutMs: 2000 },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([]);
    expect(summary.persistFailures).toStrictEqual({});
    await expect(store.get(remote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.syncToRelay dryRun uses negentropyItems not query", async () => {
    const remote = note(SK_B, "stay", 22);
    const local = note(SK_A, "mine", 21);
    net.relay("wss://neg.example").seed([remote]);
    const inner = new MemoryEventStore();
    await inner.put(local);
    const store: EventStore = {
      put: async (event) => inner.put(event),
      putMany: async (events) => {
        const out = await inner.putMany(events);
        return out;
      },
      get: async (id) => inner.get(id),
      query: () => {
        throw new Error("query should not be called");
      },
      count: async (filters) => inner.count(filters),
      negentropyItems: async (filter) => inner.negentropyItems(filter),
      remove: async (ids) => inner.remove(ids),
      clear: async () => inner.clear(),
      getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
      setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
    };
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: false,
    });
    await client.connect();
    const summary = await client.syncToRelay(
      "wss://neg.example",
      { kinds: [1] },
      { direction: SyncDirection.Both, dryRun: true, timeoutMs: 2000 },
    );
    expect(summary.local).toStrictEqual([local.id]);
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.sent).toStrictEqual([]);
    expect(summary.received).toStrictEqual([]);
    expect(summary.persistFailures).toStrictEqual({});
    await client.shutdown();
  });

  test("Client.sync down observe false never putMany and still lists received", async () => {
    const remote = note(SK_B, "unsaved", 23);
    net.relay("wss://neg.example").seed([remote]);
    let method = "";
    const store: EventStore = {
      put: async (_event: Event): Promise<PutResult> => {
        method = "put";
        return Promise.reject(new Error("disk full"));
      },
      putMany: async (_events: ReadonlyArray<Event>): Promise<PutResult[]> => {
        method = "putMany";
        return Promise.reject(new Error("disk full"));
      },
      get: async () => Promise.resolve(undefined),
      query: async (_filters: ReadonlyArray<Filter>) => Promise.resolve([]),
      count: async () => Promise.resolve(0),
      negentropyItems: async () => Promise.resolve([]),
      remove: async () => Promise.resolve(0),
      clear: async () => Promise.resolve(),
      getOutboxBound: async () => Promise.resolve(undefined),
      setOutboxBound: async () => Promise.resolve(),
    };
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000, observe: false },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(method).toBe("");
    await expect(store.get(remote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.sync down does not list received when store.putMany throws", async () => {
    const remote = note(SK_B, "unsaved-default", 23);
    net.relay("wss://neg.example").seed([remote]);
    let method = "";
    const store: EventStore = {
      put: async (_event: Event): Promise<PutResult> => {
        method = "put";
        return Promise.reject(new Error("disk full"));
      },
      putMany: async (_events: ReadonlyArray<Event>): Promise<PutResult[]> => {
        method = "putMany";
        return Promise.reject(new Error("disk full"));
      },
      get: async () => Promise.resolve(undefined),
      query: async (_filters: ReadonlyArray<Filter>) => Promise.resolve([]),
      count: async () => Promise.resolve(0),
      negentropyItems: async () => Promise.resolve([]),
      remove: async () => Promise.resolve(0),
      clear: async () => Promise.resolve(),
      getOutboxBound: async () => Promise.resolve(undefined),
      setOutboxBound: async () => Promise.resolve(),
    };
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([]);
    expect(summary.persistFailures[remote.id]).toBe("disk full");
    expect(Object.keys(summary.persistFailures)).toStrictEqual([remote.id]);
    expect(method).toBe("putMany");
    await expect(store.get(remote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.sync down putMany throw does not fetch remaining need batches", async () => {
    const remotes: Event[] = [];
    for (let i = 0; i < 200; i++) {
      remotes.push(note(SK_B, `batch-${i}`, 1000 + i));
    }
    net.relay("wss://neg.example").seed(remotes);
    const inner = new MemoryEventStore();
    let putManyCalls = 0;
    const store = wrapEventStore(inner, {
      putMany: () => {
        putManyCalls += 1;
        throw new Error("disk full");
      },
    });
    const client = new Client({
      storage: store,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    let fetchCalls = 0;
    const fetchedIds: string[] = [];
    const origFetch = client.pool.fetch.bind(client.pool);
    client.pool.fetch = async (relays, filters, opts) => {
      fetchCalls += 1;
      const events = await origFetch(relays, filters, opts);
      fetchedIds.push(...events.map((event) => event.id));
      return events;
    };
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 5000 },
    );
    expect(fetchCalls).toBe(1);
    expect(putManyCalls).toBe(1);
    expect(fetchedIds).toHaveLength(100);
    expect(summary.received).toStrictEqual([]);
    expect(summary.remote).toHaveLength(200);
    expect(new Set(summary.remote)).toStrictEqual(new Set(remotes.map((event) => event.id)));
    expect(Object.keys(summary.persistFailures).toSorted()).toStrictEqual(
      [...fetchedIds].toSorted(),
    );
    for (const id of fetchedIds) {
      expect(summary.persistFailures[id]).toBe("disk full");
    }
    const unfetched = summary.remote.filter((id) => !Object.hasOwn(summary.persistFailures, id));
    expect(unfetched).toHaveLength(100);
    expect(new Set([...fetchedIds, ...unfetched])).toStrictEqual(new Set(summary.remote));
    await client.shutdown();
  });

  test("Client.sync merges persistFailures from a throwing relay with received from a successful relay", async () => {
    const failRemote = note(SK_B, "fail-persist", 40);
    const okRemote = note(SK_A, "ok-persist", 41);
    net.relay("wss://neg-fail.example").seed([failRemote]);
    net.relay("wss://neg-ok.example").seed([okRemote]);
    const inner = new MemoryEventStore();
    const store = wrapEventStore(inner, { putMany: putManyFailing(inner, failRemote.id) });
    const client = new Client({
      storage: store,
      relays: ["wss://neg-fail.example", "wss://neg-ok.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.persistFailures[failRemote.id]).toBe("disk full");
    expect(Object.keys(summary.persistFailures)).toStrictEqual([failRemote.id]);
    expect(summary.received).toStrictEqual([okRemote.id]);
    expect(new Set(summary.remote)).toStrictEqual(new Set([failRemote.id, okRemote.id]));
    await expect(inner.get(okRemote.id)).resolves.toBeDefined();
    await expect(inner.get(failRemote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.sync down persistEvents false skips putMany and still ingestMeta", async () => {
    const remote = note(SK_B, "once", 24);
    net.relay("wss://neg.example").seed([remote]);
    const inner = new MemoryEventStore();
    const persistCalls: string[] = [];
    let ingested = 0;
    const gossip = new Gossip();
    const origIngest = gossip.ingest.bind(gossip);
    gossip.ingest = (event) => {
      ingested += 1;
      return origIngest(event);
    };
    const store: EventStore = {
      put: async (event) => {
        persistCalls.push("put");
        return inner.put(event);
      },
      putMany: async (events) => {
        persistCalls.push(`putMany:${events.length}`);
        const out = await inner.putMany(events);
        return out;
      },
      get: async (id) => inner.get(id),
      query: async (filters) => inner.query(filters),
      count: async (filters) => inner.count(filters),
      negentropyItems: async (filter) => inner.negentropyItems(filter),
      remove: async (ids) => inner.remove(ids),
      clear: async () => inner.clear(),
      getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
      setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
    };
    const client = new Client({
      storage: store,
      gossip,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(persistCalls).toStrictEqual([]);
    expect(ingested).toBe(1);
    await expect(inner.get(remote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.sync down persistEvents true writes once via putMany then ingestMeta", async () => {
    const remote = note(SK_B, "once-persist", 24);
    net.relay("wss://neg.example").seed([remote]);
    const inner = new MemoryEventStore();
    const persistCalls: string[] = [];
    let ingested = 0;
    const gossip = new Gossip();
    const origIngest = gossip.ingest.bind(gossip);
    gossip.ingest = (event) => {
      ingested += 1;
      return origIngest(event);
    };
    const store: EventStore = {
      put: async (event) => {
        persistCalls.push("put");
        return inner.put(event);
      },
      putMany: async (events) => {
        persistCalls.push(`putMany:${events.length}`);
        const out = await inner.putMany(events);
        return out;
      },
      get: async (id) => inner.get(id),
      query: async (filters) => inner.query(filters),
      count: async (filters) => inner.count(filters),
      negentropyItems: async (filter) => inner.negentropyItems(filter),
      remove: async (ids) => inner.remove(ids),
      clear: async () => inner.clear(),
      getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
      setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
    };
    const client = new Client({
      storage: store,
      gossip,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(persistCalls).toStrictEqual([`putMany:1`]);
    expect(ingested).toBe(1);
    await expect(inner.get(remote.id)).resolves.toBeDefined();
    await client.shutdown();
  });

  test("Client.sync down observe false skips putMany and ingestMeta", async () => {
    const remote = note(SK_B, "no-meta", 25);
    net.relay("wss://neg.example").seed([remote]);
    const inner = new MemoryEventStore();
    const persistCalls: string[] = [];
    let ingested = 0;
    const gossip = new Gossip();
    const origIngest = gossip.ingest.bind(gossip);
    gossip.ingest = (event) => {
      ingested += 1;
      return origIngest(event);
    };
    const store: EventStore = {
      put: async (event) => {
        persistCalls.push("put");
        return inner.put(event);
      },
      putMany: async (events) => {
        persistCalls.push(`putMany:${events.length}`);
        const out = await inner.putMany(events);
        return out;
      },
      get: async (id) => inner.get(id),
      query: async (filters) => inner.query(filters),
      count: async (filters) => inner.count(filters),
      negentropyItems: async (filter) => inner.negentropyItems(filter),
      remove: async (ids) => inner.remove(ids),
      clear: async () => inner.clear(),
      getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
      setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
    };
    const client = new Client({
      storage: store,
      gossip,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000, observe: false },
    );
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(persistCalls).toStrictEqual([]);
    expect(ingested).toBe(0);
    await expect(inner.get(remote.id)).resolves.toBeUndefined();
    await client.shutdown();
  });

  test("Client.sync down skipped rejected putMany results", async () => {
    const remote = note(SK_B, "rej", 26);
    net.relay("wss://neg.example").seed([remote]);
    let ingested = 0;
    const gossip = new Gossip();
    gossip.ingest = () => {
      ingested += 1;
      return false;
    };
    const store: EventStore = {
      put: async () => Promise.resolve<PutResult>("rejected"),
      putMany: async (events) => Promise.resolve(events.map((): PutResult => "rejected")),
      get: async () => Promise.resolve(undefined),
      query: async () => Promise.resolve([]),
      count: async () => Promise.resolve(0),
      negentropyItems: async () => Promise.resolve([]),
      remove: async () => Promise.resolve(0),
      clear: async () => Promise.resolve(),
      getOutboxBound: async () => Promise.resolve(undefined),
      setOutboxBound: async () => Promise.resolve(),
    };
    const client = new Client({
      storage: store,
      gossip,
      relays: ["wss://neg.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
      persistEvents: true,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([]);
    expect(summary.persistFailures).toStrictEqual({});
    expect(ingested).toBe(0);
    await client.shutdown();
  });

  test("Client.sync mixed success does not throw; merges the good relay", async () => {
    const remote = note(SK_B, "from-good", 30);
    net.relay("wss://neg.example").seed([remote]);

    const store = new MemoryEventStore();
    const client = new Client({
      storage: store,
      relays: ["wss://silent-neg.example", "wss://neg.example"],
      websocketImplementation: dropSend(net.websocketImplementation, isSilentNegUrl),
      enableReconnect: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1] },
      { direction: SyncDirection.Down, timeoutMs: 150 },
    );
    expect(summary.remote).toStrictEqual([remote.id]);
    expect(summary.received).toStrictEqual([remote.id]);
    expect(summary.persistFailures).toStrictEqual({});
    await expect(store.get(remote.id)).resolves.toBeDefined();
    await client.shutdown();
  });
});

describe("Negentropy session timeout", () => {
  let net: FakeRelayNetwork;

  // Relay exists but never answers NEG-OPEN/NEG-MSG.
  const silentWs = (): WebSocketConstructor => dropSend(net.websocketImplementation, negFrameOnly);

  beforeEach(() => {
    net = createFakeRelayNetwork();
  });
  afterEach(() => {
    net.close();
  });

  test("Client.sync rejects on session deadline when the relay never sends NEG-MSG", async () => {
    const store = new MemoryEventStore();
    const client = new Client({
      storage: store,
      relays: ["wss://silent-neg.example"],
      websocketImplementation: silentWs(),
      enableReconnect: false,
    });
    await client.connect();
    const started = Date.now();
    await expect(
      client.sync({ kinds: [1] }, { direction: SyncDirection.Down, timeoutMs: 80 }),
    ).rejects.toThrow(RelayTimeoutError);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(70);
    expect(elapsed).toBeLessThan(1500);
    await client.shutdown();
  });

  test("Client.sync throws the first rejection in URL order when every relay rejects", async () => {
    const store = new MemoryEventStore();
    const client = new Client({
      storage: store,
      relays: ["wss://silent-a.example", "wss://silent-b.example"],
      websocketImplementation: silentWs(),
      enableReconnect: false,
    });
    await client.connect();
    const syncErr = await client
      .sync({ kinds: [1] }, { direction: SyncDirection.Down, timeoutMs: 80 })
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect(syncErr).toBeInstanceOf(RelayTimeoutError);
    expect((syncErr as Error).message).toMatch(
      /negentropy timed out \(wss:\/\/silent-a\.example\/\)/,
    );
    await client.shutdown();
  });
});

describe("issue #125", () => {
  let net: FakeRelayNetwork;

  beforeEach(() => {
    net = createFakeRelayNetwork();
  });

  afterEach(() => {
    net.close();
  });

  test("#4 NEG-OPEN honors the filter limit", async () => {
    const notes = [note(SK_A, "n1", 1), note(SK_A, "n2", 2), note(SK_A, "n3", 3)];
    net.relay("wss://neg-limit.example").seed(notes);
    const client = new Client({
      storage: new MemoryEventStore(),
      relays: ["wss://neg-limit.example"],
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    await client.connect();
    const summary = await client.sync(
      { kinds: [1], limit: 1 },
      { direction: SyncDirection.Down, timeoutMs: 2000 },
    );
    expect(summary.remote).toStrictEqual([notes[2]!.id]);
    expect(summary.received).toStrictEqual([notes[2]!.id]);
    await client.shutdown();
  });
});
