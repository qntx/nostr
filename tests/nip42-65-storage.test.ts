import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import { itemCompare, sortedEvents } from "../src/core/index.ts";
import {
  EventBuilder,
  EventValidationError,
  Keys,
  Kind,
  MemoryEventStore,
  Relay,
  isAuthRequired,
  isEphemeralKind,
  makeAuthEvent,
  parseRelayList,
  readRelays,
  relayListEventBuilder,
  relayListToTags,
  useWebSocketImplementation,
  writeRelays,
} from "../src/index.ts";
import type { Event } from "../src/index.ts";
import * as nip77 from "../src/nips/nip77.ts";
import { MockWebSocket, MockWebSocketCtor } from "./helpers/mock-ws.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

describe("nip42", () => {
  test("makeAuthEvent shape", () => {
    const t = makeAuthEvent("wss://relay.example", "challenge-token");
    expect(t.kind).toBe(Kind.ClientAuth);
    expect(t.tags).toStrictEqual([
      ["relay", "wss://relay.example"],
      ["challenge", "challenge-token"],
    ]);
    expect(isAuthRequired("auth-required: login")).toBe(true);
    expect(isAuthRequired("rate-limited")).toBe(false);
  });

  test("Relay.auth sends AUTH and waits for OK", async () => {
    MockWebSocket.reset();
    useWebSocketImplementation(MockWebSocketCtor);
    const relay = await Relay.connect("wss://auth.example");
    const keys = Keys.fromSecretKey(SK);

    let challengeSeen: string | undefined;
    relay.onauth = (c) => {
      challengeSeen = c;
    };

    MockWebSocket.last().receive(JSON.stringify(["AUTH", "abc-challenge"]));
    expect(challengeSeen).toBe("abc-challenge");
    expect(relay.challenge).toBe("abc-challenge");

    const authP = relay.auth(async (template) => {
      await Promise.resolve();
      return EventBuilder.textNote("")
        .kind(template.kind)
        .tags(template.tags)
        .content(template.content)
        .createdAt(template.created_at)
        .signWithKeys(keys);
    });

    // The async signer resolves on a microtask; a macrotask flush guarantees the AUTH frame.
    await new Promise((resolve) => setTimeout(resolve));
    const ws = MockWebSocket.last();
    const authMsg = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "AUTH") as [
      string,
      { id: string; kind: number },
    ];
    expect(authMsg[0]).toBe("AUTH");
    expect(authMsg[1].kind).toBe(Kind.ClientAuth);
    ws.receive(JSON.stringify(["OK", authMsg[1].id, true, ""]));

    const result = await authP;
    expect(result.ok).toBe(true);
    relay.close();
    MockWebSocket.reset();
  });

  test("CLOSED auth-required retries REQ after AUTH", async () => {
    MockWebSocket.reset();
    useWebSocketImplementation(MockWebSocketCtor);
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-retry.example", {
      authSigner: async (template) => {
        await Promise.resolve();
        return EventBuilder.textNote("")
          .kind(template.kind)
          .tags(template.tags)
          .content(template.content)
          .createdAt(template.created_at)
          .signWithKeys(keys);
      },
    });

    const got: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => {
        got.push(e.id);
      },
    });

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "retry-challenge"]));
    ws.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));

    await new Promise((resolve) => setTimeout(resolve, 20));
    const authFrame = ws.sent
      .map((s) => JSON.parse(s) as unknown[])
      .find((m) => m[0] === "AUTH") as [string, { id: string }] | undefined;
    expect(authFrame?.[0]).toBe("AUTH");
    ws.receive(JSON.stringify(["OK", authFrame![1].id, true, ""]));
    await new Promise((resolve) => setTimeout(resolve, 20));

    const reqs = ws.sent.map((s) => JSON.parse(s) as unknown[]).filter((m) => m[0] === "REQ");
    expect(reqs.length).toBeGreaterThanOrEqual(2);

    const note = EventBuilder.textNote("after auth").createdAt(1).signWithKeys(keys);
    ws.receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(got).toStrictEqual([note.id]);
    relay.close();
    MockWebSocket.reset();
  });
});

describe("nip65", () => {
  test("parse and encode relay list", () => {
    const keys = Keys.fromSecretKey(SK);
    const event = relayListEventBuilder([
      { url: "wss://a.example", read: true, write: true },
      { url: "wss://b.example", read: true, write: false },
      { url: "wss://c.example", read: false, write: true },
    ]).signWithKeys(keys);

    const items = parseRelayList(event);
    expect(items).toStrictEqual([
      { url: "wss://a.example/", read: true, write: true },
      { url: "wss://b.example/", read: true, write: false },
      { url: "wss://c.example/", read: false, write: true },
    ]);
    // normalizeURL may add trailing slash depending on URL parser — accept both
    expect(readRelays(items)).toHaveLength(2);
    expect(writeRelays(items)).toHaveLength(2);

    const tags = relayListToTags([
      { url: "wss://x.example", read: true, write: true },
      { url: "wss://y.example", read: true, write: false },
    ]);
    expect(tags).toStrictEqual([
      ["r", "wss://x.example"],
      ["r", "wss://y.example", "read"],
    ]);
  });

  test("relayListToTags both-false throws", () => {
    expect(() => relayListToTags([{ url: "wss://z.example", read: false, write: false }])).toThrow(
      EventValidationError,
    );
    expect(relayListToTags([{ url: "wss://z.example", read: true, write: true }])).toStrictEqual([
      ["r", "wss://z.example"],
    ]);
    const keys = Keys.fromSecretKey(SK);
    const event = relayListEventBuilder([
      { url: "wss://z.example", read: true, write: true },
    ]).signWithKeys(keys);
    expect(event.tags).toStrictEqual([["r", "wss://z.example"]]);
    expect(parseRelayList(event)).toStrictEqual([
      { url: "wss://z.example/", read: true, write: true },
    ]);
  });
});

describe("MemoryEventStore", () => {
  test("put query replaceable and deletion", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);

    const meta1 = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await expect(store.put(meta1)).resolves.toBe("accepted");
    await expect(store.put(meta2)).resolves.toBe("replaced");
    await expect(store.get(meta1.id)).resolves.toBeUndefined();
    const v1 = await store.get(meta2.id);
    expect(v1?.content).toContain("v2");

    const note = EventBuilder.textNote("keep").createdAt(1).signWithKeys(keys);
    await store.put(note);
    const del = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeUndefined();

    const found = await store.query([{ kinds: [0], authors: [keys.publicKey] }]);
    expect(found).toHaveLength(1);
    expect(found[0]!.id).toBe(meta2.id);
  });

  test("query applies limit per filter then unions", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const notes = [
      EventBuilder.textNote("a").createdAt(1).signWithKeys(keys),
      EventBuilder.textNote("b").createdAt(2).signWithKeys(keys),
    ];
    const meta = EventBuilder.metadata({ name: "n" }).createdAt(3).signWithKeys(keys);
    await store.putMany(notes);
    await store.put(meta);
    const found = await store.query([
      { kinds: [1], limit: 10 },
      { kinds: [0], limit: 1 },
    ]);
    expect(found.filter((e) => e.kind === 1)).toHaveLength(2);
    expect(found.filter((e) => e.kind === 0)).toHaveLength(1);
  });

  test("NIP-09 a-tag deletes replaceable versions up to created_at", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const meta = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    await store.put(meta);
    const del = EventBuilder.deletion([{ address: `0:${keys.publicKey}:` }], "gone")
      .createdAt(15)
      .signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    await expect(store.get(meta.id)).resolves.toBeUndefined();

    const older = EventBuilder.metadata({ name: "old" }).createdAt(12).signWithKeys(keys);
    await expect(store.put(older)).resolves.toBe("duplicate");

    const newer = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await expect(store.put(newer)).resolves.toBe("accepted");
    const v2 = await store.get(newer.id);
    expect(v2?.content).toContain("v2");
  });

  test("NIP-09 e-tag requires matching pubkey; deletion of deletion is a no-op", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const note = EventBuilder.textNote("keep").createdAt(1).signWithKeys(keys);
    await store.put(note);

    const foreign = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(other);
    await expect(store.put(foreign)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeDefined();

    const first = EventBuilder.deletion([note.id]).createdAt(3).signWithKeys(keys);
    await expect(store.put(first)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeUndefined();

    const undo = EventBuilder.deletion([first.id]).createdAt(4).signWithKeys(keys);
    await expect(store.put(undo)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeUndefined();
    await expect(store.get(first.id)).resolves.toBeDefined();
  });

  test("NIP-09 pending e-tag hides the event when it arrives later", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("late").createdAt(1).signWithKeys(keys);
    const del = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    await expect(store.put(note)).resolves.toBe("duplicate");
    await expect(store.get(note.id)).resolves.toBeUndefined();
  });

  test("replace kind 0 and 10002 drops old id from query/count/negentropyItems", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);

    const meta1 = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await expect(store.put(meta1)).resolves.toBe("accepted");
    await expect(store.put(meta2)).resolves.toBe("replaced");

    const list1 = relayListEventBuilder([{ url: "wss://a.example", read: true, write: true }])
      .createdAt(10)
      .signWithKeys(keys);
    const list2 = relayListEventBuilder([{ url: "wss://b.example", read: true, write: true }])
      .createdAt(20)
      .signWithKeys(keys);
    await expect(store.put(list1)).resolves.toBe("accepted");
    await expect(store.put(list2)).resolves.toBe("replaced");

    const q0 = await store.query([{ kinds: [Kind.Metadata] }]);
    expect(q0.map((e) => e.id)).toStrictEqual([meta2.id]);
    await expect(store.count([{ kinds: [Kind.Metadata] }])).resolves.toBe(1);
    const items0 = await store.negentropyItems({ kinds: [Kind.Metadata] });
    expect(items0).toStrictEqual([{ id: meta2.id, created_at: 20 }]);
    expect(items0.some((i) => i.id === meta1.id)).toBe(false);

    const q65 = await store.query([{ kinds: [Kind.RelayList] }]);
    expect(q65.map((e) => e.id)).toStrictEqual([list2.id]);
    await expect(store.count([{ kinds: [Kind.RelayList] }])).resolves.toBe(1);
    const items65 = await store.negentropyItems({ kinds: [Kind.RelayList] });
    expect(items65.map((i) => i.id)).toStrictEqual([list2.id]);
    expect(items65.some((i) => i.id === list1.id)).toBe(false);
  });

  test("count equals query length", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const meta = EventBuilder.metadata({ name: "n" }).createdAt(3).signWithKeys(keys);
    await store.put(a);
    await store.put(b);
    await store.put(meta);

    const filters = [
      { kinds: [1], limit: 10 },
      { kinds: [0], limit: 1 },
      { authors: [keys.publicKey] },
    ];
    const v3 = await store.query(filters);
    await expect(store.count(filters)).resolves.toBe(v3.length);
    const v4 = await store.query([{ kinds: [1] }]);
    await expect(store.count([{ kinds: [1] }])).resolves.toBe(v4.length);
    await expect(store.count([{ kinds: [1], limit: 1 }])).resolves.toBe(1);

    const items = await store.negentropyItems({ kinds: [1] });
    expect(items).toStrictEqual([
      { id: a.id, created_at: 1 },
      { id: b.id, created_at: 2 },
    ]);
  });

  test("non-canonical events are invalid; uppercase filter args still match", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("n").createdAt(1).signWithKeys(keys);
    const mixed = { ...note, id: note.id.toUpperCase(), pubkey: note.pubkey.toUpperCase() };
    await expect(store.put(mixed)).resolves.toBe("invalid");
    await expect(store.get(note.id)).resolves.toBeUndefined();

    await expect(store.put(note)).resolves.toBe("accepted");
    const v5 = await store.get(note.id.toUpperCase());
    expect(v5?.id).toBe(note.id);
    const v6 = await store.query([{ ids: [note.id.toUpperCase()] }]);
    expect(v6.map((e) => e.id)).toStrictEqual([note.id]);
    await expect(store.count([{ ids: [note.id.toUpperCase()] }])).resolves.toBe(1);
    await expect(store.negentropyItems({ ids: [note.id.toUpperCase()] })).resolves.toStrictEqual([
      { id: note.id, created_at: 1 },
    ]);
  });

  test("ids+limit keeps newest, not ids-array order", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const older = EventBuilder.textNote("old").createdAt(1).signWithKeys(keys);
    const newer = EventBuilder.textNote("new").createdAt(2).signWithKeys(keys);
    await store.put(older);
    await store.put(newer);
    const filter = { ids: [older.id, newer.id], limit: 1 };
    const v7 = await store.query([filter]);
    expect(v7.map((e) => e.id)).toStrictEqual([newer.id]);
    await expect(store.count([filter])).resolves.toBe(1);
    const v8 = await store.negentropyItems(filter);
    expect(v8.map((i) => i.id)).toStrictEqual([newer.id]);
  });

  test("negentropyItems 10k authors+kinds has no content and matches itemCompare", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const events: Event[] = [];
    for (let i = 0; i < 10_000; i++) {
      events.push({
        id: i.toString(16).padStart(64, "0"),
        pubkey: keys.publicKey,
        kind: Kind.TextNote,
        created_at: i,
        tags: [],
        content: "payload-should-not-appear-on-items",
        sig: "ab".repeat(64),
      });
    }
    await store.putMany(events);
    const filter = { authors: [keys.publicKey], kinds: [Kind.TextNote] };
    const items = await store.negentropyItems(filter);
    expect(items).toHaveLength(10_000);
    for (const item of items) {
      expect(Object.keys(item).toSorted()).toStrictEqual(["created_at", "id"]);
    }
    const expected = events
      .map((e) => ({ id: e.id, created_at: e.created_at }))
      .toSorted(itemCompare);
    expect(items).toStrictEqual(expected);
    const v9 = await store.query([filter]);
    await expect(store.count([filter])).resolves.toBe(v9.length);
  });

  test("ephemeral kinds are not inserted", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const auth = new EventBuilder(Kind.ClientAuth, "")
      .tag(["relay", "wss://r.example"])
      .createdAt(1)
      .signWithKeys(keys);
    const wrap = new EventBuilder(Kind.GiftWrapEphemeral, "x")
      .tag(["p", keys.publicKey])
      .createdAt(2)
      .signWithKeys(keys);
    const lo = new EventBuilder(20_000, "lo").createdAt(3).signWithKeys(keys);
    const hi = new EventBuilder(29_999, "hi").createdAt(4).signWithKeys(keys);
    expect(isEphemeralKind(auth.kind)).toBe(true);
    await expect(store.put(auth)).resolves.toBe("ephemeral");
    await expect(store.put(wrap)).resolves.toBe("ephemeral");
    await expect(store.put(lo)).resolves.toBe("ephemeral");
    await expect(store.put(hi)).resolves.toBe("ephemeral");
    expect(store.size).toBe(0);
    await expect(store.get(auth.id)).resolves.toBeUndefined();
    await expect(store.get(wrap.id)).resolves.toBeUndefined();
    await expect(store.query([{ kinds: [Kind.ClientAuth] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ kinds: [Kind.GiftWrapEphemeral] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#p": [keys.publicKey] }])).resolves.toStrictEqual([]);
    await expect(store.count([{ kinds: [Kind.ClientAuth] }])).resolves.toBe(0);
    await expect(store.negentropyItems({ kinds: [Kind.ClientAuth] })).resolves.toStrictEqual([]);

    const below = new EventBuilder(19_999, "below").createdAt(5).signWithKeys(keys);
    const note = EventBuilder.textNote("keep").createdAt(6).signWithKeys(keys);
    await expect(store.put(below)).resolves.toBe("accepted");
    await expect(store.put(note)).resolves.toBe("accepted");
    expect(store.size).toBe(2);
    const v10 = await store.get(note.id);
    expect(v10?.id).toBe(note.id);
    const v11 = await store.query([{ kinds: [1] }]);
    expect(v11.map((e) => e.id)).toStrictEqual([note.id]);
  });

  test("putMany empty and sequential replaceable input order", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    await expect(store.putMany([])).resolves.toStrictEqual([]);
    const old = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const neu = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await expect(store.putMany([old, neu])).resolves.toStrictEqual(["accepted", "replaced"]);
    await expect(store.get(old.id)).resolves.toBeUndefined();
    const v12 = await store.get(neu.id);
    expect(v12?.content).toContain("v2");
    const older = EventBuilder.metadata({ name: "v0" }).createdAt(5).signWithKeys(keys);
    await expect(store.putMany([older])).resolves.toStrictEqual(["rejected"]);
    expect(store.size).toBe(1);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    await expect(store.putMany([a, b])).resolves.toStrictEqual(["accepted", "accepted"]);
    expect(store.size).toBe(3);
  });

  test("negentropyItems same created_at sorts by id lexicographically", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const high: Event = {
      id: "ff".repeat(32),
      pubkey: keys.publicKey,
      kind: Kind.TextNote,
      created_at: 5,
      tags: [],
      content: "",
      sig: "ab".repeat(64),
    };
    const low: Event = { ...high, id: "00".repeat(32) };
    await store.put(high);
    await store.put(low);
    await expect(store.negentropyItems({ kinds: [Kind.TextNote] })).resolves.toStrictEqual([
      { id: low.id, created_at: 5 },
      { id: high.id, created_at: 5 },
    ]);
  });

  test("authors×kinds uses kind+pubkey sets then sortEvents+slice", async () => {
    const store = new MemoryEventStore();
    const a = Keys.fromSecretKey(SK);
    const b = Keys.generate();
    const outsider = Keys.generate();

    const aMeta = EventBuilder.metadata({ name: "a" }).createdAt(50).signWithKeys(a);
    const aOld = EventBuilder.textNote("a-old").createdAt(10).signWithKeys(a);
    const aNew = EventBuilder.textNote("a-new").createdAt(30).signWithKeys(a);
    const bNote = EventBuilder.textNote("b").createdAt(40).signWithKeys(b);
    const bMeta = EventBuilder.metadata({ name: "b" }).createdAt(60).signWithKeys(b);
    const outNote = EventBuilder.textNote("out").createdAt(90).signWithKeys(outsider);
    const results = await store.putMany([aMeta, aOld, aNew, bNote, bMeta, outNote]);
    expect(results).toStrictEqual(Array.from({ length: 6 }, () => "accepted"));

    const filter = { authors: [a.publicKey, b.publicKey], kinds: [Kind.TextNote], limit: 2 };
    const v13 = await store.query([filter]);
    expect(v13.map((e) => e.id)).toStrictEqual([bNote.id, aNew.id]);
    await expect(store.count([filter])).resolves.toBe(2);
    const v14 = await store.negentropyItems(filter);
    expect(v14.map((i) => i.id)).toStrictEqual([aNew.id, bNote.id]);

    const metaFilter = {
      authors: [a.publicKey.toUpperCase(), b.publicKey],
      kinds: [Kind.Metadata],
    };
    const v15 = await store.query([metaFilter]);
    expect(v15.map((e) => e.id)).toStrictEqual([bMeta.id, aMeta.id]);
    await expect(store.count([metaFilter])).resolves.toBe(2);

    await expect(store.query([{ authors: [], kinds: [Kind.TextNote] }])).resolves.toStrictEqual([]);
    await expect(store.count([{ authors: [a.publicKey], kinds: [] }])).resolves.toBe(0);
    await expect(
      store.query([{ authors: [outsider.publicKey], kinds: [Kind.TextNote, Kind.Metadata] }]),
    ).resolves.toStrictEqual([outNote]);
  });

  test("authors×kinds same created_at keeps lowest id first under limit", async () => {
    const store = new MemoryEventStore();
    const a = Keys.fromSecretKey(SK);
    const b = Keys.generate();
    const low: Event = {
      id: "00".repeat(32),
      pubkey: a.publicKey,
      kind: Kind.TextNote,
      created_at: 5,
      tags: [],
      content: "low",
      sig: "ab".repeat(64),
    };
    const mid: Event = { ...low, id: "80".repeat(32), pubkey: b.publicKey, content: "mid" };
    const high: Event = { ...low, id: "ff".repeat(32), content: "high" };
    const results = await store.putMany([high, mid, low]);
    expect(results).toStrictEqual(["accepted", "accepted", "accepted"]);
    const filter = { authors: [a.publicKey, b.publicKey], kinds: [Kind.TextNote], limit: 2 };
    const v16 = await store.query([filter]);
    expect(v16.map((e) => e.id)).toStrictEqual([low.id, mid.id]);
    await expect(store.count([filter])).resolves.toBe(2);
  });

  test("tag-only #e/#p indexes union then matchFilter AND; empty #e is no match", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const eid = "aa".repeat(32);
    const eidOther = "bb".repeat(32);
    const both = EventBuilder.textNote("both")
      .tag(["e", eid])
      .tag(["p", keys.publicKey])
      .createdAt(30)
      .signWithKeys(keys);
    const onlyE = EventBuilder.textNote("only-e").tag(["e", eid]).createdAt(20).signWithKeys(keys);
    const onlyP = EventBuilder.textNote("only-p")
      .tag(["p", keys.publicKey])
      .createdAt(10)
      .signWithKeys(keys);
    const mentioned = EventBuilder.textNote("mention")
      .tag(["p", other.publicKey])
      .createdAt(5)
      .signWithKeys(keys);
    const otherE = EventBuilder.textNote("other-e")
      .tag(["e", eidOther])
      .createdAt(40)
      .signWithKeys(other);
    const untagged = EventBuilder.textNote("none").createdAt(50).signWithKeys(keys);
    const results = await store.putMany([both, onlyE, onlyP, mentioned, otherE, untagged]);
    expect(results).toStrictEqual(Array.from({ length: 6 }, () => "accepted"));

    const byE = { "#e": [eid] as const };
    const v17 = await store.query([byE]);
    expect(v17.map((e) => e.id)).toStrictEqual([both.id, onlyE.id]);
    await expect(store.count([byE])).resolves.toBe(2);
    const v18 = await store.negentropyItems(byE);
    expect(v18.map((i) => i.id)).toStrictEqual([onlyE.id, both.id]);

    const byP = { "#p": [keys.publicKey] as const };
    const v19 = await store.query([byP]);
    expect(v19.map((e) => e.id)).toStrictEqual([both.id, onlyP.id]);
    const v20 = await store.query([{ "#p": [other.publicKey] }]);
    expect(v20.map((e) => e.id)).toStrictEqual([mentioned.id]);

    const andBoth = { "#e": [eid] as const, "#p": [keys.publicKey] as const };
    const v21 = await store.query([andBoth]);
    expect(v21.map((e) => e.id)).toStrictEqual([both.id]);
    await expect(store.count([andBoth])).resolves.toBe(1);

    await expect(store.query([{ "#e": [eid], "#p": [other.publicKey] }])).resolves.toStrictEqual(
      [],
    );
    await expect(
      store.query([{ "#e": [eidOther], "#p": [keys.publicKey] }]),
    ).resolves.toStrictEqual([]);
    await expect(store.query([{ "#e": [eidOther] }])).resolves.toStrictEqual([otherE]);
    await expect(store.query([{ "#e": [] }])).resolves.toStrictEqual([]);
    await expect(store.count([{ "#e": [] }])).resolves.toBe(0);
    await expect(store.query([{ "#p": [] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#e": [eid], limit: 0 }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#e": [eid], since: 25, until: 35 }])).resolves.toStrictEqual([
      both,
    ]);
    await expect(store.query([{ "#e": [eid], since: 40, until: 10 }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#e": [eid], limit: 1 }])).resolves.toStrictEqual([both]);
  });

  test("tag-only mixed-case #e/#p and dual #e tags do not double-count", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const eid = "aa".repeat(32);
    const root = "11".repeat(32);
    const parent = "22".repeat(32);
    // Tag values are arbitrary content: uppercase e/p values stay canonical-indexed.
    const stored = EventBuilder.textNote("mixed")
      .tag(["e", eid.toUpperCase()])
      .tag(["p", keys.publicKey.toUpperCase()])
      .createdAt(1)
      .signWithKeys(keys);
    const mixed = stored;
    await expect(store.put(stored)).resolves.toBe("accepted");
    const v22 = await store.query([{ "#e": [eid.toUpperCase()] }]);
    expect(v22.map((e) => e.id)).toStrictEqual([mixed.id]);
    const v23 = await store.query([{ "#p": [keys.publicKey.toUpperCase()] }]);
    expect(v23.map((e) => e.id)).toStrictEqual([mixed.id]);

    const reply = EventBuilder.textNote("reply")
      .tag(["e", root])
      .tag(["e", parent])
      .createdAt(10)
      .signWithKeys(keys);
    const other = EventBuilder.textNote("other").tag(["e", parent]).createdAt(5).signWithKeys(keys);
    await expect(store.put(reply)).resolves.toBe("accepted");
    await expect(store.put(other)).resolves.toBe("accepted");
    const dual = { "#e": [root, parent] as const, limit: 2 };
    const v24 = await store.query([dual]);
    expect(v24.map((e) => e.id)).toStrictEqual([reply.id, other.id]);
    await expect(store.count([dual])).resolves.toBe(2);
  });

  test("#t tag-only still matches via full scan; defined miss is empty", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const eid = "aa".repeat(32);
    const nostr = EventBuilder.textNote("n")
      .tag(["t", "nostr"])
      .tag(["e", eid])
      .createdAt(3)
      .signWithKeys(keys);
    const bitcoin = EventBuilder.textNote("b")
      .tag(["t", "bitcoin"])
      .createdAt(2)
      .signWithKeys(keys);
    const noT = EventBuilder.textNote("plain").tag(["e", eid]).createdAt(1).signWithKeys(keys);
    const results = await store.putMany([nostr, bitcoin, noT]);
    expect(results).toStrictEqual(["accepted", "accepted", "accepted"]);

    const v25 = await store.query([{ "#t": ["nostr"] }]);
    expect(v25.map((e) => e.id)).toStrictEqual([nostr.id]);
    await expect(store.count([{ "#t": ["nostr"] }])).resolves.toBe(1);
    await expect(store.query([{ "#t": ["absent-hashtag"] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#t": ["bitcoin"] }])).resolves.toStrictEqual([bitcoin]);
    const v26 = await store.query([{ "#e": [eid], "#t": ["nostr"] }]);
    expect(v26.map((e) => e.id)).toStrictEqual([nostr.id]);
    await expect(store.query([{ "#e": [eid], "#t": ["bitcoin"] }])).resolves.toStrictEqual([]);
    const v27 = await store.negentropyItems({ "#t": ["nostr"] });
    expect(v27.map((i) => i.id)).toStrictEqual([nostr.id]);
  });

  test("replace/remove/clear keep live siblings on the same index keys", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const mentioned = Keys.generate();
    const eid = "aa".repeat(32);
    const meta1 = EventBuilder.metadata({ name: "v1" })
      .tag(["e", eid])
      .createdAt(10)
      .signWithKeys(keys);
    const keepE = EventBuilder.textNote("keep-e").tag(["e", eid]).createdAt(15).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" })
      .tag(["e", eid])
      .createdAt(20)
      .signWithKeys(keys);
    await expect(store.put(meta1)).resolves.toBe("accepted");
    await expect(store.put(keepE)).resolves.toBe("accepted");
    await expect(store.put(meta2)).resolves.toBe("replaced");
    const v28 = await store.query([{ "#e": [eid] }]);
    expect(v28.map((e) => e.id)).toStrictEqual([meta2.id, keepE.id]);
    const v29 = await store.query([{ authors: [keys.publicKey], kinds: [Kind.Metadata] }]);
    expect(v29.map((e) => e.id)).toStrictEqual([meta2.id]);

    const dropE = EventBuilder.textNote("drop-e").tag(["e", eid]).createdAt(12).signWithKeys(keys);
    await expect(store.put(dropE)).resolves.toBe("accepted");
    await expect(store.remove([dropE.id])).resolves.toBe(1);
    const v30 = await store.query([{ "#e": [eid] }]);
    expect(v30.map((e) => e.id)).toStrictEqual([meta2.id, keepE.id]);
    const v31 = await store.query([{ authors: [keys.publicKey], kinds: [Kind.TextNote] }]);
    expect(v31.map((e) => e.id)).toStrictEqual([keepE.id]);

    const keepP = EventBuilder.textNote("keep-p")
      .tag(["p", mentioned.publicKey])
      .createdAt(5)
      .signWithKeys(keys);
    const dropP = EventBuilder.textNote("drop-p")
      .tag(["p", mentioned.publicKey])
      .createdAt(4)
      .signWithKeys(keys);
    await expect(store.put(keepP)).resolves.toBe("accepted");
    await expect(store.put(dropP)).resolves.toBe("accepted");
    await expect(store.remove([dropP.id])).resolves.toBe(1);
    const v32 = await store.query([{ "#p": [mentioned.publicKey] }]);
    expect(v32.map((e) => e.id)).toStrictEqual([keepP.id]);
    const v33 = await store.query([{ authors: [keys.publicKey], kinds: [Kind.TextNote] }]);
    expect(v33.map((e) => e.id)).toStrictEqual([keepE.id, keepP.id]);

    await store.clear();
    expect(store.size).toBe(0);
    const fresh = EventBuilder.textNote("fresh").tag(["e", eid]).createdAt(1).signWithKeys(keys);
    await expect(store.put(fresh)).resolves.toBe("accepted");
    const v34 = await store.query([{ "#e": [eid] }]);
    expect(v34.map((e) => e.id)).toStrictEqual([fresh.id]);
    const v35 = await store.query([{ authors: [keys.publicKey], kinds: [Kind.TextNote] }]);
    expect(v35.map((e) => e.id)).toStrictEqual([fresh.id]);
    await expect(store.query([{ "#p": [mentioned.publicKey] }])).resolves.toStrictEqual([]);
  });

  test("valueless e tag is not indexed; empty-string e tag is", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const bare = EventBuilder.textNote("bare").tag(["e"]).createdAt(1).signWithKeys(keys);
    const empty = EventBuilder.textNote("empty").tag(["e", ""]).createdAt(2).signWithKeys(keys);
    await expect(store.put(bare)).resolves.toBe("accepted");
    await expect(store.put(empty)).resolves.toBe("accepted");
    await expect(store.query([{ "#e": ["undefined"] }])).resolves.toStrictEqual([]);
    const v36 = await store.query([{ "#e": [""] }]);
    expect(v36.map((e) => e.id)).toStrictEqual([empty.id]);
    const v37 = await store.query([{ kinds: [Kind.TextNote] }]);
    expect(v37.map((e) => e.id)).toStrictEqual([empty.id, bare.id]);
  });

  test("ids candidate path still AND-matches defined #e", async () => {
    const store = new MemoryEventStore();
    const keys = Keys.fromSecretKey(SK);
    const eid = "aa".repeat(32);
    const other = "bb".repeat(32);
    const note = EventBuilder.textNote("n").tag(["e", eid]).createdAt(1).signWithKeys(keys);
    await expect(store.put(note)).resolves.toBe("accepted");
    const v38 = await store.query([{ ids: [note.id], "#e": [eid] }]);
    expect(v38.map((e) => e.id)).toStrictEqual([note.id]);
    await expect(store.query([{ ids: [note.id], "#e": [other] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ ids: [] }])).resolves.toStrictEqual([]);
  });
});

describe("itemCompare", () => {
  test("created_at ascending, then id lexicographic; equal items are 0", () => {
    const a = { id: "aa", created_at: 1 };
    const b = { id: "bb", created_at: 1 };
    const c = { id: "aa", created_at: 2 };
    expect(itemCompare(a, c)).toBeLessThan(0);
    expect(itemCompare(c, a)).toBeGreaterThan(0);
    expect(itemCompare(a, b)).toBeLessThan(0);
    expect(itemCompare(b, a)).toBeGreaterThan(0);
    expect(itemCompare(a, a)).toBe(0);
    expect(itemCompare({ id: "", created_at: 0 }, { id: "", created_at: 0 })).toBe(0);
    expect(itemCompare({ id: "a", created_at: -1 }, { id: "a", created_at: 0 })).toBeLessThan(0);
    expect(itemCompare({ id: "A", created_at: 1 }, { id: "a", created_at: 1 })).toBeLessThan(0);
  });

  test("is not the inverse of sortEvents: id tie-break stays ascending", () => {
    const olderLow: Event = {
      id: "aa",
      created_at: 1,
      pubkey: "00".repeat(32),
      kind: 1,
      tags: [],
      content: "",
      sig: "00".repeat(64),
    };
    const olderHigh: Event = { ...olderLow, id: "zz" };
    const newer: Event = { ...olderLow, id: "mm", created_at: 2 };
    expect([newer, olderHigh, olderLow].toSorted(itemCompare).map((e) => e.id)).toStrictEqual([
      "aa",
      "zz",
      "mm",
    ]);
    expect(sortedEvents([newer, olderHigh, olderLow]).map((e) => e.id)).toStrictEqual([
      "mm",
      "aa",
      "zz",
    ]);
  });

  test("nip77 module export has no itemCompare", async () => {
    expect("itemCompare" in nip77).toBe(false);
    const root = await import("../src/index.ts");
    expect(root.itemCompare).toBe(itemCompare);
  });
});

beforeEach(() => {
  MockWebSocket.reset();
});
afterEach(() => {
  MockWebSocket.reset();
});
