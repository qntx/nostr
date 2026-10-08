import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import {
  Client,
  EventBuilder,
  Gossip,
  Kind,
  Keys,
  KeysSigner,
  MemoryEventStore,
  relayListEventBuilder,
  StorageError,
  useWebSocketImplementation,
} from "../src/index.ts";
import type { Event, EventStore } from "../src/index.ts";
import { MockWebSocket, MockWebSocketCtor } from "./helpers/mock-ws.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

const gateOnce = (armed: { done: boolean }, gate: Promise<void>): Promise<void> | undefined => {
  if (armed.done) {
    return undefined;
  }
  armed.done = true;
  return gate;
};

const answerRelayListReqs = (list: Event): void => {
  for (const ws of MockWebSocket.instances) {
    for (const raw of ws.sent) {
      const msg = JSON.parse(raw) as unknown[];
      if (msg[0] !== "REQ") {
        continue;
      }
      const filter = msg[2] as { kinds?: number[] };
      if (filter.kinds?.includes(Kind.RelayList)) {
        ws.receive(JSON.stringify(["EVENT", msg[1], list]));
      }
      ws.receive(JSON.stringify(["EOSE", msg[1]]));
    }
  }
};

const delegatingStore = (
  inner: MemoryEventStore,
  overrides: Partial<EventStore> = {},
): EventStore => ({
  put: async (event) => inner.put(event),
  putMany: async (events) => inner.putMany(events),
  get: async (id) => inner.get(id),
  query: async (filters) => inner.query(filters),
  count: async (filters) => inner.count(filters),
  negentropyItems: async (filter) => inner.negentropyItems(filter),
  remove: async (ids) => inner.remove(ids),
  clear: async () => inner.clear(),
  getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
  setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
  ...overrides,
});

function stubStore(overrides: Partial<EventStore> = {}): EventStore {
  return {
    put: async () => {
      await Promise.resolve();
      return "accepted";
    },
    putMany: async (events) => {
      await Promise.resolve();
      return events.map(() => "accepted");
    },
    get: async () => {
      await Promise.resolve();
      return undefined;
    },
    query: async () => {
      await Promise.resolve();
      return [];
    },
    count: async () => {
      await Promise.resolve();
      return 0;
    },
    negentropyItems: async () => {
      await Promise.resolve();
      return [];
    },
    remove: async () => {
      await Promise.resolve();
      return 0;
    },
    clear: async () => {
      await Promise.resolve();
    },
    getOutboxBound: async () => {
      await Promise.resolve();
      return undefined;
    },
    setOutboxBound: async () => {
      await Promise.resolve();
    },
    ...overrides,
  };
}

beforeEach(() => {
  MockWebSocket.reset();
  useWebSocketImplementation(MockWebSocketCtor);
});

afterEach(() => {
  MockWebSocket.reset();
});

describe("Client storage + observe", () => {
  test("default MemoryEventStore; publish success observes into storage", async () => {
    const client = new Client({
      signer: new KeysSigner(SK),
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    expect(client.storage).toBeInstanceOf(MemoryEventStore);

    await client.connect();
    const publishP = client.publish(EventBuilder.textNote("stored").createdAt(10));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws = MockWebSocket.last();
    const eventMsg = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "EVENT") as [
      string,
      { id: string },
    ];
    ws.receive(JSON.stringify(["OK", eventMsg[1].id, true, ""]));
    await publishP;

    // allow fire-and-forget put
    await new Promise((resolve) => setTimeout(resolve, 5));
    const local = await client.queryLocal({ kinds: [Kind.TextNote] });
    expect(local).toHaveLength(1);
    expect(local[0]!.content).toBe("stored");
    await client.shutdown();
  });

  test("fetchEvents observes into storage and localFirst merges", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("from net").createdAt(5).signWithKeys(keys);

    const client = new Client({
      signer: new KeysSigner(SK),
      storage: store,
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    await client.connect();

    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [keys.publicKey] },
      { timeoutMs: 2000 },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    ws.receive(JSON.stringify(["EOSE", req[1]]));
    const remote = await fetchP;
    expect(remote).toHaveLength(1);

    await new Promise((resolve) => setTimeout(resolve, 5));
    await expect(store.get(note.id)).resolves.toBeDefined();

    // Second fetch with localFirst should return stored event even without network reply
    // (we still open REQ; answer EOSE empty)
    const fetch2 = client.fetchEvents(
      { kinds: [1], authors: [keys.publicKey] },
      { timeoutMs: 500, localFirst: true },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws2 = MockWebSocket.last();
    const reqs = ws2.sent.map((s) => JSON.parse(s)).filter((m) => m[0] === "REQ");
    const lastReq = reqs.at(-1) as [string, string];
    ws2.receive(JSON.stringify(["EOSE", lastReq[1]]));
    const merged = await fetch2;
    expect(merged.some((e) => e.id === note.id)).toBe(true);

    await client.shutdown();
  });

  test("fetchEvents localFirst query throw reports onstorageerror and still returns network events", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("from net").createdAt(5).signWithKeys(keys);
    const inner = new MemoryEventStore();
    let queryCalls = 0;
    const seen: StorageError[] = [];
    const store: EventStore = stubStore({
      put: async (event) => inner.put(event),
      putMany: async (events) => inner.putMany(events),
      get: async (id) => inner.get(id),
      query: () => {
        queryCalls += 1;
        throw new Error("query boom");
      },
      count: async (filters) => inner.count(filters),
      negentropyItems: async (filter) => inner.negentropyItems(filter),
      remove: async (ids) => inner.remove(ids),
      clear: async () => inner.clear(),
      getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
      setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
    });
    const client = new Client({
      storage: store,
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.on("storageerror", (err) => {
      seen.push(err);
    });

    await client.connect();
    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [keys.publicKey] },
      { timeoutMs: 2000, localFirst: true },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    ws.receive(JSON.stringify(["EOSE", req[1]]));
    const events = await fetchP;
    expect(queryCalls).toBe(1);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBeInstanceOf(StorageError);
    expect(seen[0]!.message).toBe("query boom");
    expect(seen[0]!.cause).toBeInstanceOf(Error);
    expect(events).toHaveLength(1);
    expect(events[0]!.id).toBe(note.id);
    await client.shutdown();
  });

  test("subscribe observes events", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("live").createdAt(1).signWithKeys(keys);

    const client = new Client({
      storage: store,
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    await client.connect();
    const got: string[] = [];
    const sub = client.subscribe([{ kinds: [1] }], {
      onevent: (e) => got.push(e.id),
    });

    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    expect(got).toStrictEqual([note.id]);
    await new Promise((resolve) => setTimeout(resolve, 5));
    await expect(store.get(note.id)).resolves.toBeDefined();
    sub.close();
    await client.shutdown();
  });

  test("hydrateGossip ingests relay list into gossip", async () => {
    const keys = Keys.fromSecretKey(SK);
    const list = relayListEventBuilder([{ url: "wss://out.example", marker: "both" }])
      .createdAt(3)
      .signWithKeys(keys);

    const gossip = new Gossip();
    const client = new Client({
      gossip,
      relays: ["wss://idx.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    // kick hydrate (will fetch); respond with list
    const hydrateP = client.hydrateGossip([keys.publicKey]);
    await new Promise((resolve) => setTimeout(resolve, 15));
    answerRelayListReqs(list);
    await hydrateP;

    expect(gossip.outboxRelays(keys.publicKey).length).toBeGreaterThan(0);
    await client.shutdown();
  });

  test("persistEvents false skips storage writes", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("no store").createdAt(1).signWithKeys(keys);

    const client = new Client({
      storage: store,
      persistEvents: false,
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    client.observe(note);
    await new Promise((resolve) => setTimeout(resolve, 5));
    await expect(store.get(note.id)).resolves.toBeUndefined();
    // gossip still runs for kind 10002 only — text notes are fine
    await client.shutdown();
  });

  test("observe batches into one putMany; shutdown awaits flush", async () => {
    const inner = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const batches: string[][] = [];
    let putCalls = 0;
    const store: EventStore = delegatingStore(inner, {
      put: async (event) => {
        putCalls += 1;
        return inner.put(event);
      },
      putMany: async (events) => {
        batches.push(events.map((e) => e.id));
        const out = await inner.putMany(events);
        return out;
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    client.observe(a);
    client.observe(b);
    await client.shutdown();
    expect(batches).toStrictEqual([[a.id, b.id]]);
    expect(putCalls).toBe(0);
    await expect(inner.get(a.id)).resolves.toBeDefined();
    await expect(inner.get(b.id)).resolves.toBeDefined();
  });

  test("observeAll queues unique events as one persist batch", async () => {
    const inner = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const batches: string[][] = [];
    const store: EventStore = delegatingStore(inner, {
      putMany: async (events) => {
        batches.push(events.map((e) => e.id));
        const out = await inner.putMany(events);
        return out;
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    client.observeAll([a, b, a]);
    await client.shutdown();
    expect(batches).toStrictEqual([[a.id, b.id]]);
  });

  test("single-flight flush does not overlap putMany", async () => {
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    let inFlight = 0;
    let maxInFlight = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const batches: string[][] = [];
    const firstCall = { done: false };
    const store: EventStore = stubStore({
      putMany: async (events) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        batches.push(events.map((e) => e.id));
        await gateOnce(firstCall, firstGate);
        inFlight -= 1;
        return events.map(() => "accepted");
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    client.observe(a);
    await Promise.resolve();
    await Promise.resolve();
    expect(batches).toStrictEqual([[a.id]]);
    client.observe(b);
    expect(batches).toStrictEqual([[a.id]]);
    expect(inFlight).toBe(1);
    releaseFirst();
    await client.shutdown();
    expect(batches).toStrictEqual([[a.id], [b.id]]);
    expect(maxInFlight).toBe(1);
  });

  test("shutdown waits for in-flight putMany", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("flush").createdAt(1).signWithKeys(keys);
    let finish!: () => void;
    const gate = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let putManyDone = false;
    const store: EventStore = stubStore({
      putMany: async (events) => {
        await gate;
        putManyDone = true;
        return events.map(() => "accepted");
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    client.observe(note);
    const done = client.shutdown();
    let shutdownDone = false;
    void done.then(() => {
      shutdownDone = true;
      return undefined;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(putManyDone).toBe(false);
    expect(shutdownDone).toBe(false);
    finish();
    await done;
    expect(putManyDone).toBe(true);
    expect(shutdownDone).toBe(true);
  });

  test("ingestMeta runs before persist completes", async () => {
    const keys = Keys.fromSecretKey(SK);
    const list = relayListEventBuilder([{ url: "wss://out.example", marker: "both" }])
      .createdAt(3)
      .signWithKeys(keys);
    const gossip = new Gossip();
    let finish!: () => void;
    const gate = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const store: EventStore = stubStore({
      putMany: async (events) => {
        await gate;
        return events.map(() => "accepted");
      },
    });
    const client = new Client({
      storage: store,
      gossip,
      enableReconnect: false,
    });
    client.observe(list);
    expect(gossip.outboxRelays(keys.publicKey).length).toBeGreaterThan(0);
    finish();
    await client.shutdown();
  });

  test("storageerror listener is invoked", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("fail").createdAt(1).signWithKeys(keys);
    const seen: StorageError[] = [];
    const fn = (err: StorageError) => {
      seen.push(err);
    };
    const store: EventStore = stubStore({
      put() {
        throw new Error("disk full");
      },
      putMany() {
        throw new Error("disk full");
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    client.on("storageerror", fn);
    client.observe(note);
    await client.shutdown();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBeInstanceOf(StorageError);
    expect(seen[0]!.cause).toBeInstanceOf(Error);
    expect(seen[0]!.message).toBe("disk full");
    expect(seen[0]!.message).not.toContain(note.content);
  });

  test("subscribe persist failure does not throw and still delivers onevent", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("live").createdAt(1).signWithKeys(keys);
    const seen: StorageError[] = [];
    const store: EventStore = stubStore({
      put() {
        throw new Error("disk full");
      },
      putMany() {
        throw new Error("disk full");
      },
    });
    const client = new Client({
      storage: store,
      relays: ["wss://a.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.on("storageerror", (err) => {
      seen.push(err);
    });
    await client.connect();
    const got: string[] = [];
    const sub = client.subscribe([{ kinds: [1] }], {
      onevent: (e) => got.push(e.id),
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    expect(got).toStrictEqual([note.id]);
    await client.shutdown();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBeInstanceOf(StorageError);
    sub.close();
  });

  test("persistEvents false does not call putMany", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("skip").createdAt(1).signWithKeys(keys);
    let putManyCalls = 0;
    const store: EventStore = stubStore({
      putMany: async (events) => {
        putManyCalls += 1;
        await Promise.resolve();
        return events.map(() => "accepted");
      },
    });
    const client = new Client({
      storage: store,
      persistEvents: false,
      enableReconnect: false,
    });
    client.observe(note);
    client.observeAll([note]);
    await client.shutdown();
    expect(putManyCalls).toBe(0);
  });

  test("no storageerror listener does not throw when putMany fails", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("x").createdAt(1).signWithKeys(keys);
    const store: EventStore = stubStore({
      put() {
        throw new Error("disk full");
      },
      putMany() {
        throw new Error("disk full");
      },
    });
    const client = new Client({
      storage: store,
      enableReconnect: false,
    });
    expect(() => client.observe(note)).not.toThrow();
    await expect(client.shutdown()).resolves.toBeUndefined();
  });
});
