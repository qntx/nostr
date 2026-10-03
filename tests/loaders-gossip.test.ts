import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import type { Filter } from "../src/core/filter.ts";
import { normalizeURL } from "../src/core/util.ts";
import {
  Client,
  EventBuilder,
  Gossip,
  Keys,
  Kind,
  Pool,
  ReactiveEventStore,
  bareNostrUser,
  createLoaders,
  relayListEventBuilder,
  useWebSocketImplementation,
} from "../src/index.ts";
import { dmRelayListEventBuilder, parseDmRelayList } from "../src/nips/nip17.ts";
import { createFakeRelayNetwork } from "../src/testing/index.ts";
import { MockWebSocket, MockWebSocketCtor } from "./helpers/mock-ws.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const SK2 = "0000000000000000000000000000000000000000000000000000000000000001";

beforeEach(() => {
  MockWebSocket.reset();
  useWebSocketImplementation(MockWebSocketCtor);
});

afterEach(() => {
  MockWebSocket.reset();
});

async function respondReplaceables(
  events: Array<{ kind: number; event: ReturnType<typeof EventBuilder.prototype.signWithKeys> }>,
) {
  // after microtasks, answer each REQ with matching events
  return new Promise<void>((resolve) => {
    setTimeout(() => {
      for (const ws of MockWebSocket.instances) {
        for (const raw of ws.sent) {
          const msg = JSON.parse(raw) as unknown[];
          if (msg[0] !== "REQ") {
            continue;
          }
          const subId = msg[1] as string;
          const filter = msg[2] as { kinds?: number[]; authors?: string[] };
          for (const { kind, event } of events) {
            if (filter.kinds && !filter.kinds.includes(kind)) {
              continue;
            }
            if (filter.authors && !filter.authors.includes(event.pubkey)) {
              continue;
            }
            ws.receive(JSON.stringify(["EVENT", subId, event]));
          }
          ws.receive(JSON.stringify(["EOSE", subId]));
        }
      }
      resolve();
    }, 15);
  });
}

async function waitUntil(pred: () => boolean, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling must wait between iterations
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timeout waiting for condition");
}

async function waitUntilAsync(pred: () => Promise<boolean>, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    // oxlint-disable-next-line no-await-in-loop -- polling must await each probe
    if (await pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling must wait between iterations
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timeout waiting for condition");
}

function requireRemainder(routed: { remainder?: Filter | undefined }): Filter {
  if (routed.remainder === undefined) {
    throw new Error("expected remainder");
  }
  return routed.remainder;
}

const isReq = (m: unknown): boolean => Array.isArray(m) && m[0] === "REQ";

describe("Gossip", () => {
  test("ingest NIP-65 and route by authors", () => {
    const keys = Keys.fromSecretKey(SK);
    const list = relayListEventBuilder([
      { url: "wss://write.example", marker: "write" },
      { url: "wss://read.example", marker: "read" },
      { url: "wss://both.example", marker: "both" },
    ])
      .createdAt(1)
      .signWithKeys(keys);

    const gossip = new Gossip();
    expect(gossip.ingest(list)).toBe(true);
    expect(gossip.outboxRelays(keys.publicKey).length).toBeGreaterThan(0);
    expect(gossip.inboxRelays(keys.publicKey).length).toBeGreaterThan(0);
    expect(gossip.dmRelays(keys.publicKey)).toStrictEqual([]);

    const routed = gossip.route({
      kinds: [1],
      authors: [keys.publicKey],
    });
    expect(routed.remainder).toBeUndefined();
    expect(routed.perRelay.size).toBeGreaterThan(0);
    for (const filter of routed.perRelay.values()) {
      expect(filter.authors).toStrictEqual([keys.publicKey]);
      expect(filter.kinds).toStrictEqual([1]);
    }

    const generic = gossip.route({ kinds: [1] });
    expect(generic.perRelay.size).toBe(0);
    expect(generic.remainder).toStrictEqual({ kinds: [1] });
  });

  test("route leftover authors become remainder", () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const gossip = new Gossip();
    gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const routed = gossip.route({
      kinds: [1],
      authors: [a.publicKey, b.publicKey],
    });
    const remainder = requireRemainder(routed);
    expect(remainder.authors).toStrictEqual([b.publicKey]);
    expect(remainder.kinds).toStrictEqual([1]);
    expect(routed.perRelay.size).toBe(1);
    const [url, filter] = [...routed.perRelay.entries()][0]!;
    expect(url).toContain("out-a.example");
    expect(filter.authors).toStrictEqual([a.publicKey]);
    expect(filter.kinds).toStrictEqual([1]);
  });

  test("route leftover #p values become remainder", () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const gossip = new Gossip();
    gossip.ingest(
      relayListEventBuilder([{ url: "wss://in-a.example", marker: "read" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const routed = gossip.route({
      kinds: [1],
      "#p": [a.publicKey, b.publicKey],
    });
    const remainder = requireRemainder(routed);
    expect(remainder["#p"]).toStrictEqual([b.publicKey]);
    expect(remainder.kinds).toStrictEqual([1]);
    expect(routed.perRelay.size).toBe(1);
    const [url, filter] = [...routed.perRelay.entries()][0]!;
    expect(url).toContain("in-a.example");
    expect(filter["#p"]).toStrictEqual([a.publicKey]);
  });

  test("route authors+#p leftover keeps the original filter as remainder", () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const gossip = new Gossip();
    gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const filter = {
      kinds: [1],
      authors: [a.publicKey, b.publicKey],
      "#p": [a.publicKey],
    };
    const routed = gossip.route(filter);
    expect(routed.remainder).toBe(filter);
    expect(routed.perRelay.size).toBe(1);
    const sub = [...routed.perRelay.values()][0]!;
    expect(sub.authors).toStrictEqual(filter.authors);
    expect(sub["#p"]).toStrictEqual(filter["#p"]);
  });

  test("ingest kind 10050 DM relays without clobbering NIP-65", () => {
    const keys = Keys.fromSecretKey(SK);
    const nip65 = relayListEventBuilder([{ url: "wss://out.example", marker: "write" }])
      .createdAt(10)
      .signWithKeys(keys);
    const dm = dmRelayListEventBuilder(["wss://dm-a.example", "wss://dm-b.example"])
      .createdAt(20)
      .signWithKeys(keys);
    expect(parseDmRelayList(dm).map((u) => u.replace(/\/$/, ""))).toStrictEqual([
      "wss://dm-a.example",
      "wss://dm-b.example",
    ]);

    const gossip = new Gossip();
    expect(gossip.ingest(nip65)).toBe(true);
    expect(gossip.ingest(dm)).toBe(true);

    expect(gossip.outboxRelays(keys.publicKey).some((u) => u.includes("out.example"))).toBe(true);
    expect(gossip.dmRelays(keys.publicKey).map((u) => u.replace(/\/$/, ""))).toStrictEqual([
      "wss://dm-a.example",
      "wss://dm-b.example",
    ]);

    // older dm list ignored
    const older = dmRelayListEventBuilder(["wss://old-dm.example"]).createdAt(5).signWithKeys(keys);
    expect(gossip.ingest(older)).toBe(false);
    expect(gossip.dmRelays(keys.publicKey).some((u) => u.includes("old-dm"))).toBe(false);

    // NIP-65 still intact after dm update
    expect(gossip.getRoutes(keys.publicKey)?.updatedAt).toBe(10);
    expect(gossip.getRoutes(keys.publicKey)?.dmUpdatedAt).toBe(20);
    const orphan = gossip.route({ authors: [Keys.fromSecretKey(SK2).publicKey] });
    expect(orphan.perRelay.size).toBe(0);
    expect(orphan.remainder?.authors).toStrictEqual([Keys.fromSecretKey(SK2).publicKey]);
  });

  test("routes are LRU-bounded by maxPubkeys; lookups and writes refresh recency", () => {
    const gossip = new Gossip({ maxPubkeys: 3 });
    const items = [{ url: "wss://r.example", marker: "both" as const }];
    const a = "a".repeat(64);
    const b = "b".repeat(64);
    const c = "c".repeat(64);
    const d = "d".repeat(64);
    const e = "e".repeat(64);
    gossip.setRoutes(a, items, 1);
    gossip.setRoutes(b, items, 1);
    gossip.setRoutes(c, items, 1);
    // a lookup moves "a" to the newest end
    expect(gossip.outboxRelays(a)).toStrictEqual(["wss://r.example/"]);
    // inserting "d" drops the oldest ("b")
    gossip.setRoutes(d, items, 1);
    expect(gossip.size).toBe(3);
    expect(gossip.getRoutes(b)).toBeUndefined();
    expect(gossip.getRoutes(a)).toBeDefined(); // this lookup refreshes "a"
    // a setDmRoutes write also refreshes recency; order is now d, a, c
    gossip.setDmRoutes(c, ["wss://dm.example"], 2);
    gossip.setRoutes(e, items, 1);
    expect(gossip.size).toBe(3);
    expect(gossip.getRoutes(d)).toBeUndefined();
    expect(gossip.getRoutes(c)?.dm).toStrictEqual(["wss://dm.example/"]);
    expect(gossip.getRoutes(a)).toBeDefined();
    expect(gossip.getRoutes(e)).toBeDefined();
  });
});

describe("Loaders", () => {
  test("follows and profile batch via pool", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.fromSecretKey(SK2);

    const follows = EventBuilder.contacts([other.publicKey, keys.publicKey])
      .createdAt(10)
      .signWithKeys(keys);
    const meta = EventBuilder.metadata({ name: "alice", picture: "https://x/y.png" })
      .createdAt(11)
      .signWithKeys(keys);

    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const loaders = createLoaders({
      pool,
      relays: ["wss://idx.example"],
      index: new ReactiveEventStore(),
    });

    const followsP = loaders.follows(keys.publicKey);
    const profileP = loaders.profile(keys.publicKey);
    await respondReplaceables([
      { kind: Kind.Contacts, event: follows },
      { kind: Kind.Metadata, event: meta },
    ]);

    const fl = await followsP;
    expect(fl.items).toContain(other.publicKey);
    expect(fl.event?.id).toBe(follows.id);

    const user = await profileP;
    expect(user.metadata.name).toBe("alice");
    expect(user.image).toBe("https://x/y.png");
    expect(user.shortName).toBe("alice");

    // cache hit (no extra network required for second call with default style)
    const fl2 = await loaders.follows(keys.publicKey);
    expect(fl2.fresh).toBe(false);
    expect(fl2.items).toStrictEqual(fl.items);

    pool.close();
  });

  test("profile falls back to name for an empty display_name", async () => {
    const keys = Keys.fromSecretKey(SK);
    const meta = EventBuilder.metadata({ display_name: "", name: "alice" })
      .createdAt(11)
      .signWithKeys(keys);

    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const loaders = createLoaders({
      pool,
      relays: ["wss://idx.example"],
      index: new ReactiveEventStore(),
    });

    const p = loaders.profile(keys.publicKey);
    await respondReplaceables([{ kind: Kind.Metadata, event: meta }]);
    const user = await p;
    expect(user.shortName).toBe("alice");

    pool.close();
  });

  test("profile metadata keeps only known string fields; arrays yield {}", async () => {
    const keys = Keys.fromSecretKey(SK);
    const meta = new EventBuilder(
      Kind.Metadata,
      JSON.stringify({ name: 5, picture: ["x"], about: "ok" }),
    )
      .createdAt(11)
      .signWithKeys(keys);
    const keys2 = Keys.fromSecretKey(SK2);
    const arrayMeta = new EventBuilder(Kind.Metadata, '["nope"]').createdAt(11).signWithKeys(keys2);

    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const loaders = createLoaders({
      pool,
      relays: ["wss://idx.example"],
      index: new ReactiveEventStore(),
    });

    const p = loaders.profile(keys.publicKey);
    await respondReplaceables([{ kind: Kind.Metadata, event: meta }]);
    const user = await p;
    expect(user.metadata).toStrictEqual({ about: "ok" });
    expect(user.image).toBeUndefined();

    const p2 = loaders.profile(keys2.publicKey);
    await respondReplaceables([{ kind: Kind.Metadata, event: arrayMeta }]);
    const user2 = await p2;
    expect(user2.metadata).toStrictEqual({});

    pool.close();
  });

  test("profile falls back to the npub when display_name and name are empty", async () => {
    const keys = Keys.fromSecretKey(SK);
    const meta = EventBuilder.metadata({ display_name: "", name: "" })
      .createdAt(11)
      .signWithKeys(keys);

    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const loaders = createLoaders({
      pool,
      relays: ["wss://idx.example"],
      index: new ReactiveEventStore(),
    });

    const p = loaders.profile(keys.publicKey);
    await respondReplaceables([{ kind: Kind.Metadata, event: meta }]);
    const user = await p;
    expect(user.shortName).toBe(bareNostrUser(keys.publicKey).shortName);

    pool.close();
  });

  test("muteList drops empty t and word values", async () => {
    const keys = Keys.fromSecretKey(SK);
    const mute = new EventBuilder(Kind.MuteList, "")
      .tags([
        ["t", ""],
        ["word", ""],
        ["t", "spam"],
        ["word", "nsfw"],
      ])
      .createdAt(12)
      .signWithKeys(keys);

    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const loaders = createLoaders({
      pool,
      relays: ["wss://idx.example"],
      index: new ReactiveEventStore(),
    });

    const p = loaders.muteList(keys.publicKey);
    await respondReplaceables([{ kind: Kind.MuteList, event: mute }]);
    const result = await p;
    expect(result.items).toStrictEqual([
      { type: "hashtag", value: "spam" },
      { type: "word", value: "nsfw" },
    ]);

    pool.close();
  });

  test("relayList loader + client.observe", async () => {
    const keys = Keys.fromSecretKey(SK);
    const list = relayListEventBuilder([{ url: "wss://out.example", marker: "both" }])
      .createdAt(5)
      .signWithKeys(keys);

    const client = new Client({
      relays: ["wss://idx.example"],
      websocketImplementation: MockWebSocketCtor,
    });

    const p = client.loaders.relayList(keys.publicKey);
    await respondReplaceables([{ kind: Kind.RelayList, event: list }]);
    const result = await p;
    expect(result.items.some((i) => i.marker !== "read")).toBe(true);

    client.observe(list);
    expect(client.gossip.outboxRelays(keys.publicKey).length).toBeGreaterThan(0);

    await client.shutdown();
  });

  test("dmRelayList loader + observe caches 10050", async () => {
    const keys = Keys.fromSecretKey(SK);
    const dm = dmRelayListEventBuilder(["wss://dm-a.example"]).createdAt(7).signWithKeys(keys);

    const client = new Client({
      relays: ["wss://idx.example"],
      websocketImplementation: MockWebSocketCtor,
    });

    const p = client.loaders.dmRelayList(keys.publicKey);
    await respondReplaceables([{ kind: Kind.DirectMessageRelaysList, event: dm }]);
    const result = await p;
    expect(result.items.some((u) => u.includes("dm-a.example"))).toBe(true);

    client.observe(dm);
    expect(client.gossip.dmRelays(keys.publicKey).some((u) => u.includes("dm-a.example"))).toBe(
      true,
    );
    expect(client.index.getReplaceable(Kind.DirectMessageRelaysList, keys.publicKey)?.id).toBe(
      dm.id,
    );

    await client.shutdown();
  });

  test("hydrateGossip loads 10002 and 10050", async () => {
    const keys = Keys.fromSecretKey(SK);
    const list = relayListEventBuilder([{ url: "wss://out.example", marker: "both" }])
      .createdAt(8)
      .signWithKeys(keys);
    const dm = dmRelayListEventBuilder(["wss://dm.example"]).createdAt(9).signWithKeys(keys);

    const client = new Client({
      relays: ["wss://idx.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });

    const hydrateP = client.hydrateGossip([keys.publicKey]);
    await respondReplaceables([
      { kind: Kind.RelayList, event: list },
      { kind: Kind.DirectMessageRelaysList, event: dm },
    ]);
    await hydrateP;

    expect(client.gossip.outboxRelays(keys.publicKey).some((u) => u.includes("out.example"))).toBe(
      true,
    );
    expect(client.gossip.dmRelays(keys.publicKey).some((u) => u.includes("dm.example"))).toBe(true);

    await client.shutdown();
  });
});

describe("loaders on the reactive index (issue #136)", () => {
  test("a profile arriving via subscribe is returned by profile cache-only", async () => {
    const net = createFakeRelayNetwork();
    try {
      const client = new Client({
        relays: ["wss://idx.example"],
        websocketImplementation: net.websocketImplementation,
        enableReconnect: false,
      });
      const keys = Keys.fromSecretKey(SK);
      const meta = EventBuilder.metadata({ name: "alice" }).createdAt(3).signWithKeys(keys);
      net.relay("wss://idx.example").seed([meta]);

      const closer = client.subscribe({ kinds: [0], authors: [keys.publicKey] });
      await waitUntil(() => client.index.getReplaceable(0, keys.publicKey) !== undefined);
      closer.close();

      const user = await client.loaders.profile(keys.publicKey, { style: "cache-only" });
      expect(user.event?.id).toBe(meta.id);
      expect(user.metadata.name).toBe("alice");
      expect(user.fresh).toBe(false);
      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("a loader network fetch records seenOn on the index", async () => {
    const net = createFakeRelayNetwork();
    try {
      const client = new Client({
        relays: ["wss://idx.example"],
        websocketImplementation: net.websocketImplementation,
        enableReconnect: false,
      });
      const keys = Keys.fromSecretKey(SK);
      const meta = EventBuilder.metadata({ name: "bob" }).createdAt(4).signWithKeys(keys);
      net.relay("wss://idx.example").seed([meta]);

      const res = await client.loaders.profile(keys.publicKey);
      expect(res.event?.id).toBe(meta.id);
      expect(res.fresh).toBe(true);
      expect(client.index.seenOn(meta.id)).toStrictEqual([normalizeURL("wss://idx.example")]);
      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("default style does not refetch within staleAfterSec, including after a miss", async () => {
    const net = createFakeRelayNetwork();
    try {
      const pool = new Pool({ websocketImplementation: net.websocketImplementation });
      const index = new ReactiveEventStore();
      const keys = Keys.fromSecretKey(SK);
      const reqs = () => net.relay("wss://idx.example").clientMessages().filter(isReq).length;

      const loaders = createLoaders({ pool, relays: ["wss://idx.example"], index });
      const miss = await loaders.profile(keys.publicKey);
      expect(miss.event).toBeUndefined();
      expect(miss.fresh).toBe(true);
      expect(reqs()).toBe(1);
      // a recent miss counts as fresh: no refetch
      const again = await loaders.profile(keys.publicKey);
      expect(again.event).toBeUndefined();
      expect(again.fresh).toBe(false);
      expect(reqs()).toBe(1);
      // force always fetches
      await loaders.profile(keys.publicKey, { style: "force" });
      expect(reqs()).toBe(2);

      // an expired record refetches: staleAfterSec 0 never counts as fresh
      const stale = createLoaders({
        pool,
        relays: ["wss://idx.example"],
        index,
        staleAfterSec: 0,
      });
      const meta = EventBuilder.metadata({ name: "alice" }).createdAt(5).signWithKeys(keys);
      net.relay("wss://idx.example").seed([meta]);
      const hit = await stale.profile(keys.publicKey);
      expect(hit.event?.id).toBe(meta.id);
      expect(hit.fresh).toBe(true);
      expect(reqs()).toBe(3);
      // same loader, same pubkey: the record is already expired → refetch
      await stale.profile(keys.publicKey);
      expect(reqs()).toBe(4);
      // cache-only resolves the fetched value from the shared index
      const cached = await stale.profile(keys.publicKey, { style: "cache-only" });
      expect(cached.event?.id).toBe(meta.id);
      pool.close();
    } finally {
      net.close();
    }
  });

  test("loaders.replaceable(10063) resolves a generic replaceable kind", async () => {
    const net = createFakeRelayNetwork();
    try {
      const pool = new Pool({ websocketImplementation: net.websocketImplementation });
      const keys = Keys.fromSecretKey(SK);
      const servers = new EventBuilder(10063, "")
        .tag(["server", "https://cdn.example"])
        .createdAt(7)
        .signWithKeys(keys);
      net.relay("wss://idx.example").seed([servers]);

      const loaders = createLoaders({
        pool,
        relays: ["wss://idx.example"],
        index: new ReactiveEventStore(),
      });
      expect(loaders.replaceable(10063)).toBe(loaders.replaceable(10063));
      const res = await loaders.replaceable(10063)(keys.publicKey);
      expect(res.event?.id).toBe(servers.id);
      expect(res.fresh).toBe(true);
      pool.close();
    } finally {
      net.close();
    }
  });

  test("default style refetches when the fetched winner was evicted", async () => {
    const net = createFakeRelayNetwork();
    try {
      const pool = new Pool({ websocketImplementation: net.websocketImplementation });
      const index = new ReactiveEventStore({ maxEvents: 2 });
      const keys = Keys.fromSecretKey(SK);
      const meta = EventBuilder.metadata({ name: "alice" }).createdAt(5).signWithKeys(keys);
      net.relay("wss://idx.example").seed([meta]);
      const reqs = () => net.relay("wss://idx.example").clientMessages().filter(isReq).length;

      const loaders = createLoaders({ pool, relays: ["wss://idx.example"], index });
      const first = await loaders.profile(keys.publicKey);
      expect(first.event?.id).toBe(meta.id);
      expect(reqs()).toBe(1);

      // evict the freshly fetched profile from the constrained index
      for (let i = 0; i < 3; i++) {
        index.add(
          EventBuilder.textNote(`filler${i}`)
            .createdAt(10 + i)
            .signWithKeys(keys),
        );
      }
      expect(index.getReplaceable(0, keys.publicKey)).toBeUndefined();

      // the fresh fetch record was a hit, but the winner is gone → refetch
      const second = await loaders.profile(keys.publicKey);
      expect(second.event?.id).toBe(meta.id);
      expect(second.fresh).toBe(true);
      expect(reqs()).toBe(2);
      pool.close();
    } finally {
      net.close();
    }
  });

  test("loader fetches flow through client ingest: persisted and feed gossip", async () => {
    const net = createFakeRelayNetwork();
    try {
      const client = new Client({
        relays: ["wss://idx.example"],
        websocketImplementation: net.websocketImplementation,
        enableReconnect: false,
      });
      const keys = Keys.fromSecretKey(SK);
      const meta = EventBuilder.metadata({ name: "alice" }).createdAt(5).signWithKeys(keys);
      const list = relayListEventBuilder([{ url: "wss://out.example", marker: "both" }])
        .createdAt(6)
        .signWithKeys(keys);
      net.relay("wss://idx.example").seed([meta, list]);

      // a fetched 10002 feeds gossip without a manual observe()
      const relayList = await client.loaders.relayList(keys.publicKey);
      expect(relayList.event?.id).toBe(list.id);
      expect(client.gossip.outboxRelays(keys.publicKey)).toStrictEqual(["wss://out.example/"]);

      // a fetched profile lands in persistent storage after the flush
      const user = await client.loaders.profile(keys.publicKey);
      expect(user.event?.id).toBe(meta.id);
      const stored = async (): Promise<boolean> => {
        const rows = await client.storage.query([{ ids: [meta.id] }]);
        return rows.length === 1;
      };
      await waitUntilAsync(stored);
      await expect(stored()).resolves.toBe(true);
      await client.shutdown();
    } finally {
      net.close();
    }
  });
});
