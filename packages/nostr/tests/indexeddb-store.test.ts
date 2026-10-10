import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import { markVerified } from "../src/core/event.ts";
import { itemCompare } from "../src/core/index.ts";
import {
  CryptoError,
  EventBuilder,
  IndexedDbEventStore,
  Keys,
  Kind,
  MemoryEventStore,
  StorageError,
} from "../src/index.ts";
import type { Event } from "../src/index.ts";
import { MAX_MERGE_CURSORS } from "../src/storage/idb-query.ts";
import { IDB_VERSION } from "../src/storage/idb-schema.ts";
import { installIdbMock, seedIdbV1, seedIdbV2, seedIdbV3 } from "./helpers/idb-mock.ts";
import type { IdbMock } from "./helpers/idb-mock.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const EID = "aa".repeat(32);

async function tickUntil(pred: () => boolean): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling helper must yield between checks
    await Promise.resolve();
  }
  throw new Error("timed out waiting for IndexedDB mock");
}

async function idbGet(dbName: string, storeName: string, key: string): Promise<unknown> {
  type Req<T> = {
    result: T;
    error: Error | null;
    onsuccess: ((ev: unknown) => void) | null;
    onerror: ((ev: unknown) => void) | null;
  };
  const factory = (
    globalThis as unknown as {
      indexedDB: {
        open: (name: string) => Req<{
          transaction: (
            name: string,
            mode?: "readonly",
          ) => {
            objectStore: (name: string) => { get: (key: string) => Req<unknown> };
          };
          close: () => void;
        }>;
      };
    }
  ).indexedDB;
  return new Promise((resolve, reject) => {
    const open = factory.open(dbName);
    // oxlint-disable-next-line prefer-add-event-listener -- fake IDBOpenDBRequest mirrors the on* handler API
    open.onerror = () => reject(open.error ?? new Error("idbGet open failed"));
    open.onsuccess = () => {
      const db = open.result;
      const get = db.transaction(storeName, "readonly").objectStore(storeName).get(key);
      // oxlint-disable-next-line prefer-add-event-listener -- fake IDBRequest mirrors the on* handler API
      get.onerror = () => {
        db.close();
        reject(get.error ?? new Error("idbGet failed"));
      };
      get.onsuccess = () => {
        const value = get.result;
        db.close();
        resolve(value);
      };
    };
  });
}

describe("IndexedDbEventStore", () => {
  let mock: IdbMock;

  beforeEach(() => {
    mock = installIdbMock();
  });

  afterEach(() => {
    mock.uninstall();
  });

  test("open throws StorageError when IndexedDB is unavailable", async () => {
    const g = globalThis as { indexedDB?: unknown };
    const prev = g.indexedDB;
    delete g.indexedDB;
    try {
      expect(IndexedDbEventStore.isAvailable()).toBe(false);
      const err = await new IndexedDbEventStore({ dbName: "no-idb" }).open().then(
        () => {
          throw new Error("expected reject");
        },
        (error: unknown) => error,
      );
      expect(err).toBeInstanceOf(StorageError);
      expect(err).not.toBeInstanceOf(CryptoError);
      expect((err as StorageError).message).toBe("IndexedDB is not available in this environment");
    } finally {
      g.indexedDB = prev;
    }
  });

  test("put query replaceable and deletion", async () => {
    expect(IndexedDbEventStore.isAvailable()).toBe(true);
    const store = new IndexedDbEventStore({ dbName: "test-nostr" });
    await store.open();
    const keys = Keys.fromSecretKey(SK);

    const meta1 = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await expect(store.put(meta1)).resolves.toBe("accepted");
    await expect(store.put(meta2)).resolves.toBe("replaced");
    await expect(store.get(meta1.id)).resolves.toBeUndefined();
    const got1 = await store.get(meta2.id);
    expect(got1?.content).toContain("v2");

    const note = EventBuilder.textNote("keep").createdAt(1).signWithKeys(keys);
    await store.put(note);
    const del = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeUndefined();

    const found = await store.query([{ kinds: [Kind.Metadata], authors: [keys.publicKey] }]);
    expect(found).toHaveLength(1);
    expect(found[0]!.id).toBe(meta2.id);

    store.close();
  });

  test("NIP-09 a-tag and pubkey check survive reopen", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "del-db" });
    await store.open();

    const meta = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    await store.put(meta);
    const note = EventBuilder.textNote("x").createdAt(1).signWithKeys(keys);
    await store.put(note);

    const foreign = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(other);
    await store.put(foreign);
    await expect(store.get(note.id)).resolves.toBeDefined();

    const del = EventBuilder.deletion([{ address: `0:${keys.publicKey}:` }], "gone")
      .createdAt(15)
      .signWithKeys(keys);
    await store.put(del);
    await expect(store.get(meta.id)).resolves.toBeUndefined();
    store.close();

    const reopened = new IndexedDbEventStore({ dbName: "del-db" });
    await reopened.open();
    await expect(reopened.get(meta.id)).resolves.toBeUndefined();
    await expect(reopened.get(note.id)).resolves.toBeDefined();
    const older = EventBuilder.metadata({ name: "old" }).createdAt(12).signWithKeys(keys);
    await expect(reopened.put(older)).resolves.toBe("duplicate");
    reopened.close();
  });

  test("survives close and reopen on same db name", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("persist").createdAt(7).signWithKeys(keys);

    const a = new IndexedDbEventStore({ dbName: "persist-db" });
    await a.open();
    await expect(a.put(note)).resolves.toBe("accepted");
    a.close();

    const b = new IndexedDbEventStore({ dbName: "persist-db" });
    await b.open();
    const got2 = await b.get(note.id);
    expect(got2?.content).toBe("persist");
    const q = await b.query([{ kinds: [Kind.TextNote], authors: [keys.publicKey] }]);
    expect(q.map((e) => e.id)).toStrictEqual([note.id]);
    b.close();
  });

  test("upgrades v1 to v2; query and kind-5 put do not getAll events", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const note = EventBuilder.textNote("v1").createdAt(1).signWithKeys(keys);
    const meta = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const foreign = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(other);
    const del = EventBuilder.deletion([note.id]).createdAt(3).signWithKeys(keys);
    await seedIdbV1("upgrade-db", [note, meta, foreign, del]);

    const store = new IndexedDbEventStore({ dbName: "upgrade-db" });
    await store.open();
    await expect(store.get(note.id)).resolves.toBeUndefined();
    await expect(store.get(del.id)).resolves.toBeDefined();
    await expect(store.get(meta.id)).resolves.toBeDefined();

    mock.resetStats();
    const found = await store.query([{ kinds: [1], authors: [keys.publicKey] }]);
    expect(found).toHaveLength(0);
    expect(mock.eventsGetAllCount()).toBe(0);

    const extra = EventBuilder.textNote("after").createdAt(4).signWithKeys(keys);
    await store.put(extra);
    mock.resetStats();
    const kill = EventBuilder.deletion([extra.id]).createdAt(5).signWithKeys(keys);
    await expect(store.put(kill)).resolves.toBe("deleted");
    expect(mock.eventsGetAllCount()).toBe(0);
    await expect(store.get(extra.id)).resolves.toBeUndefined();
    store.close();
  });

  test("replaceable replace deletes old tag_refs and addresses", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "repl-tags" });
    await store.open();
    const a = EventBuilder.metadata({ name: "v1" })
      .tag(["e", EID])
      .createdAt(10)
      .signWithKeys(keys);
    const b = EventBuilder.metadata({ name: "v2" })
      .tag(["e", EID])
      .createdAt(20)
      .signWithKeys(keys);
    await expect(store.put(a)).resolves.toBe("accepted");
    await expect(store.put(b)).resolves.toBe("replaced");
    await expect(store.get(a.id)).resolves.toBeUndefined();
    const byE = await store.query([{ "#e": [EID] }]);
    expect(byE.map((e) => e.id)).toStrictEqual([b.id]);
    store.close();
  });

  test("remove and kind-5 update all four stores in one tx", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "four-store" });
    await store.open();
    const note = EventBuilder.textNote("n").tag(["e", EID]).createdAt(1).signWithKeys(keys);
    const meta = EventBuilder.metadata({ name: "m" }).createdAt(2).signWithKeys(keys);
    await store.put(note);
    await store.put(meta);

    mock.resetStats();
    await expect(store.remove([note.id])).resolves.toBe(1);
    expect(mock.readwriteTransactions().at(-1)).toStrictEqual([
      "events",
      "tag_refs",
      "addresses",
      "tombstones",
    ]);
    await expect(store.get(note.id)).resolves.toBeUndefined();
    await expect(store.query([{ "#e": [EID] }])).resolves.toStrictEqual([]);

    mock.resetStats();
    const del = EventBuilder.deletion([meta.id]).createdAt(3).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    expect(mock.readwriteTransactions()).toHaveLength(1);
    expect(mock.readwriteTransactions()[0]).toStrictEqual([
      "events",
      "tag_refs",
      "addresses",
      "tombstones",
    ]);
    await expect(store.get(meta.id)).resolves.toBeUndefined();
    store.close();
  });

  test("tombstones survive close and a new instance", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "tomb-db" });
    await store.open();
    const note = EventBuilder.textNote("late").createdAt(1).signWithKeys(keys);
    const del = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    store.close();

    const reopened = new IndexedDbEventStore({ dbName: "tomb-db" });
    await reopened.open();
    await expect(reopened.put(note)).resolves.toBe("duplicate");
    await expect(reopened.get(note.id)).resolves.toBeUndefined();
    reopened.close();
  });

  test("pending kind 5 then target persists id tombstone across reopen", async () => {
    const keys = Keys.fromSecretKey(SK);
    const dbName = "pending-apply-tomb";
    const store = new IndexedDbEventStore({ dbName });
    await store.open();
    const note = EventBuilder.textNote("late").createdAt(1).signWithKeys(keys);
    const del = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    await expect(store.put(note)).resolves.toBe("duplicate");
    await expect(store.get(note.id)).resolves.toBeUndefined();
    await expect(idbGet(dbName, "tombstones", `id:${note.id}`)).resolves.toStrictEqual({
      key: `id:${note.id}`,
      type: "id",
    });
    await expect(idbGet(dbName, "tombstones", `pending:${note.id}`)).resolves.toBeUndefined();
    store.close();

    const reopened = new IndexedDbEventStore({ dbName });
    await reopened.open();
    await expect(reopened.put(note)).resolves.toBe("duplicate");
    await expect(reopened.get(note.id)).resolves.toBeUndefined();
    await expect(idbGet(dbName, "tombstones", `id:${note.id}`)).resolves.toStrictEqual({
      key: `id:${note.id}`,
      type: "id",
    });
    reopened.close();
  });

  test("foreign kind 5 does not delete", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "foreign-del" });
    await store.open();
    const note = EventBuilder.textNote("keep").createdAt(1).signWithKeys(keys);
    await store.put(note);
    const foreign = EventBuilder.deletion([note.id]).createdAt(2).signWithKeys(other);
    await expect(store.put(foreign)).resolves.toBe("deleted");
    await expect(store.get(note.id)).resolves.toBeDefined();
    store.close();
  });

  test("limit since until #e #p and ids", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "filters" });
    await store.open();
    const notes = [1, 2, 3, 4, 5].map((t) =>
      EventBuilder.textNote(String(t))
        .tag(["e", EID])
        .tag(["p", keys.publicKey])
        .createdAt(t)
        .signWithKeys(keys),
    );
    await store.putMany(notes);

    const windowed = await store.query([{ since: 2, until: 4 }]);
    expect(windowed.map((e) => e.created_at)).toStrictEqual([4, 3, 2]);
    await expect(store.query([{ since: 5, until: 1 }])).resolves.toStrictEqual([]);
    await expect(store.query([{ kinds: [1], limit: 0 }])).resolves.toStrictEqual([]);

    const limited = await store.query([{ kinds: [1], limit: 2 }]);
    expect(limited).toHaveLength(2);
    expect(limited.map((e) => e.created_at)).toStrictEqual([5, 4]);

    const byE = await store.query([{ "#e": [EID], limit: 1 }]);
    expect(byE).toHaveLength(1);
    expect(byE[0]!.created_at).toBe(5);

    const byP = await store.query([{ "#p": [keys.publicKey], since: 3, until: 3 }]);
    expect(byP).toHaveLength(1);
    expect(byP[0]!.created_at).toBe(3);

    const byId = await store.query([{ ids: [notes[0]!.id] }]);
    expect(byId.map((e) => e.id)).toStrictEqual([notes[0]!.id]);
    store.close();
  });

  test("authors+kinds prefix cursor does not visit other authors", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "prefix" });
    await store.open();
    await store.putMany(
      Array.from({ length: 30 }, (_, i) =>
        EventBuilder.textNote(`o${i}`)
          .createdAt(100 + i)
          .signWithKeys(other),
      ),
    );
    await store.putMany(
      Array.from({ length: 3 }, (_, i) =>
        EventBuilder.textNote(`m${i}`)
          .createdAt(10 + i)
          .signWithKeys(keys),
      ),
    );

    mock.resetStats();
    const one = await store.query([{ authors: [keys.publicKey], kinds: [1], limit: 1 }]);
    expect(one).toHaveLength(1);
    expect(one[0]!.pubkey).toBe(keys.publicKey);
    expect(mock.cursorVisitCount()).toBeLessThan(30);
    expect(mock.eventsGetAllCount()).toBe(0);

    mock.resetStats();
    const many = await store.query([{ authors: [keys.publicKey], kinds: [1], limit: 50 }]);
    expect(many).toHaveLength(3);
    expect(mock.cursorVisitCount()).toBeLessThan(30);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("search in local filter does not throw and does not restrict", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "search" });
    await store.open();
    const a = EventBuilder.textNote("alpha").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("beta").createdAt(2).signWithKeys(keys);
    await store.put(a);
    await store.put(b);
    const found = await store.query([{ kinds: [1], search: "nope" }]);
    expect(found.map((e) => e.id)).toStrictEqual([b.id, a.id]);
    store.close();
  });

  test("fresh v2 open never getAlls events", async () => {
    const store = new IndexedDbEventStore({ dbName: "fresh" });
    await store.open();
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("NIP-10 dual #e tags do not double-count toward limit", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "nip10-limit" });
    await store.open();
    const root = "11".repeat(32);
    const parent = "22".repeat(32);
    const reply = EventBuilder.textNote("reply")
      .tag(["e", root])
      .tag(["e", parent])
      .createdAt(10)
      .signWithKeys(keys);
    const other = EventBuilder.textNote("other").tag(["e", parent]).createdAt(5).signWithKeys(keys);
    await store.put(reply);
    await store.put(other);
    const found = await store.query([{ "#e": [root, parent], limit: 2 }]);
    expect(found.map((e) => e.id)).toStrictEqual([reply.id, other.id]);
    store.close();
  });

  test("mixed-case authors and #e/#p match like matchFilter", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "case-hex" });
    await store.open();
    // Tag values are arbitrary content: uppercase e/p values are indexed
    // case-insensitively while the event itself stays canonical.
    const note = EventBuilder.textNote("n")
      .tag(["e", EID.toUpperCase()])
      .tag(["p", keys.publicKey.toUpperCase()])
      .createdAt(1)
      .signWithKeys(keys);
    const mixed = { ...note, id: note.id.toUpperCase(), pubkey: note.pubkey.toUpperCase() };
    await expect(store.put(mixed)).resolves.toBe("invalid");
    await expect(store.put(note)).resolves.toBe("accepted");
    const got3 = await store.get(note.id.toUpperCase());
    expect(got3?.id).toBe(note.id);
    await expect(
      store.query([{ authors: [keys.publicKey.toUpperCase()], kinds: [1] }]),
    ).resolves.toHaveLength(1);
    await expect(store.query([{ "#e": [EID.toUpperCase()] }])).resolves.toHaveLength(1);
    await expect(store.query([{ "#p": [keys.publicKey.toUpperCase()] }])).resolves.toHaveLength(1);
    store.close();
  });

  test("negentropyItems and count do not getAll events", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "neg-items" });
    await store.open();
    const older = EventBuilder.textNote("old").createdAt(1).signWithKeys(keys);
    const newer = EventBuilder.textNote("new").createdAt(2).signWithKeys(keys);
    const foreign = EventBuilder.textNote("other").createdAt(3).signWithKeys(other);
    const meta1 = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await store.put(older);
    await store.put(newer);
    await store.put(foreign);
    await expect(store.put(meta1)).resolves.toBe("accepted");
    await expect(store.put(meta2)).resolves.toBe("replaced");

    mock.resetStats();
    const items = await store.negentropyItems({ kinds: [1], authors: [keys.publicKey] });
    expect(items.map((i) => i.id)).toStrictEqual([older.id, newer.id]);
    expect(items.map((i) => i.created_at)).toStrictEqual([1, 2]);
    expect(mock.eventsGetAllCount()).toBe(0);

    mock.resetStats();
    const n = await store.count([{ kinds: [1], authors: [keys.publicKey] }]);
    expect(n).toBe(2);
    const got4 = await store.query([{ kinds: [1], authors: [keys.publicKey] }]);
    expect(n).toBe(got4.length);
    expect(mock.eventsGetAllCount()).toBe(0);

    mock.resetStats();
    const metaItems = await store.negentropyItems({ kinds: [Kind.Metadata] });
    expect(metaItems.map((i) => i.id)).toStrictEqual([meta2.id]);
    await expect(store.count([{ kinds: [Kind.Metadata] }])).resolves.toBe(1);
    expect(mock.eventsGetAllCount()).toBe(0);

    const tagged = EventBuilder.textNote("tag").tag(["e", EID]).createdAt(4).signWithKeys(keys);
    await store.put(tagged);
    mock.resetStats();
    const byE = await store.negentropyItems({ "#e": [EID] });
    expect(byE.map((i) => i.id)).toStrictEqual([tagged.id]);
    await expect(store.count([{ "#e": [EID] }])).resolves.toBe(1);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("v1 superseded replaceable is omitted after a-tag deletion", async () => {
    const keys = Keys.fromSecretKey(SK);
    const meta1 = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    await seedIdbV1("coord-leak", [meta1, meta2]);
    const store = new IndexedDbEventStore({ dbName: "coord-leak" });
    await store.open();
    const del = EventBuilder.deletion([{ address: `0:${keys.publicKey}:` }], "gone")
      .createdAt(25)
      .signWithKeys(keys);
    await expect(store.put(del)).resolves.toBe("deleted");
    mock.resetStats();
    const filter = { kinds: [Kind.Metadata], authors: [keys.publicKey] };
    await expect(store.query([filter])).resolves.toStrictEqual([]);
    await expect(store.count([filter])).resolves.toBe(0);
    await expect(store.negentropyItems(filter)).resolves.toStrictEqual([]);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("ids+limit still applies authors matchFilter", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "ids-authors-limit" });
    await store.open();
    const older = EventBuilder.textNote("old").createdAt(1).signWithKeys(keys);
    const newer = EventBuilder.textNote("new").createdAt(2).signWithKeys(keys);
    await store.put(older);
    await store.put(newer);
    const filter = { ids: [older.id, newer.id], authors: [other.publicKey], limit: 1 };
    expect(filter.authors).toStrictEqual([other.publicKey]);
    await expect(store.query([filter])).resolves.toStrictEqual([]);
    await expect(store.count([filter])).resolves.toBe(0);
    await expect(store.negentropyItems(filter)).resolves.toStrictEqual([]);
    store.close();
  });

  test("same-second k-way drain emits lowest ids", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "same-second" });
    await store.open();
    const mk = (id: string, pubkey: string) => ({
      id,
      pubkey,
      kind: Kind.TextNote,
      created_at: 5,
      tags: [] as [],
      content: "",
      sig: "ab".repeat(64),
    });
    const e00 = mk("00".repeat(32), a.publicKey);
    const e80 = mk("80".repeat(32), b.publicKey);
    const eff = mk("ff".repeat(32), a.publicKey);
    await store.put(eff);
    await store.put(e00);
    await store.put(e80);
    const filter = { authors: [a.publicKey, b.publicKey], kinds: [1], limit: 2 };
    const found = await store.query([filter]);
    expect(found.map((e) => e.id)).toStrictEqual([e00.id, e80.id]);
    await expect(store.count([filter])).resolves.toBe(2);
    const got5 = await store.negentropyItems(filter);
    expect(got5.map((i) => i.id)).toStrictEqual([e00.id, e80.id]);

    const oneAuthor = Keys.generate();
    const p00 = mk("01".repeat(32), oneAuthor.publicKey);
    const p80 = mk("81".repeat(32), oneAuthor.publicKey);
    const pff = mk("fe".repeat(32), oneAuthor.publicKey);
    await store.put(pff);
    await store.put(p00);
    await store.put(p80);
    const inner = { authors: [oneAuthor.publicKey], kinds: [1], limit: 2 };
    const got6 = await store.query([inner]);
    expect(got6.map((e) => e.id)).toStrictEqual([p00.id, p80.id]);
    store.close();
  });

  test("deleted heads do not count toward limit", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "skip-deleted-limit" });
    await store.open();
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const c = EventBuilder.textNote("c").createdAt(3).signWithKeys(keys);
    await store.put(a);
    await store.put(b);
    await store.put(c);
    await store.remove([c.id]);
    const filter = { authors: [keys.publicKey], kinds: [1], limit: 1 };
    const got7 = await store.query([filter]);
    expect(got7.map((e) => e.id)).toStrictEqual([b.id]);
    await expect(store.count([filter])).resolves.toBe(1);
    store.close();
  });

  test("authors+kinds+#t skips non-matching heads toward limit", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "skip-tag-limit" });
    await store.open();
    const tagged = EventBuilder.textNote("hit").tag(["t", "nostr"]).createdAt(1).signWithKeys(keys);
    const newer = EventBuilder.textNote("miss").createdAt(2).signWithKeys(keys);
    await store.put(tagged);
    await store.put(newer);
    const filter = { authors: [keys.publicKey], kinds: [1], "#t": ["nostr"], limit: 1 };
    expect(filter["#t"]).toStrictEqual(["nostr"]);
    const got8 = await store.query([filter]);
    expect(got8.map((e) => e.id)).toStrictEqual([tagged.id]);
    await expect(store.count([filter])).resolves.toBe(1);
    store.close();
  });

  test("two-prefix limit does not throw continue-after-complete", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "tx-lifetime" });
    await store.open();
    await store.putMany(
      [1, 2, 3, 4, 5].flatMap((t) => [
        EventBuilder.textNote(`a${t}`).createdAt(t).signWithKeys(a),
        EventBuilder.textNote(`b${t}`)
          .createdAt(t + 10)
          .signWithKeys(b),
      ]),
    );
    mock.resetStats();
    const n = 3;
    const found = await store.query([
      { authors: [a.publicKey, b.publicKey], kinds: [1], limit: n },
    ]);
    expect(found).toHaveLength(n);
    expect(found.map((e) => e.created_at)).toStrictEqual([15, 14, 13]);
    expect(mock.cursorVisitCount()).toBeLessThan(10);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("v3 compact deletes leftover kind 0 and tag_refs", async () => {
    const keys = Keys.fromSecretKey(SK);
    const meta1 = EventBuilder.metadata({ name: "v1" })
      .tag(["e", EID])
      .tag(["p", keys.publicKey])
      .createdAt(10)
      .signWithKeys(keys);
    const meta2 = EventBuilder.metadata({ name: "v2" })
      .tag(["e", EID])
      .createdAt(20)
      .signWithKeys(keys);
    await seedIdbV1("compact-k0", [meta1, meta2]);
    const store = new IndexedDbEventStore({ dbName: "compact-k0" });
    await store.open();
    mock.resetStats();
    const found = await store.query([{ kinds: [Kind.Metadata] }]);
    expect(found).toHaveLength(1);
    expect(found[0]!.id).toBe(meta2.id);
    await expect(store.count([{ kinds: [Kind.Metadata] }])).resolves.toBe(1);
    await expect(store.get(meta1.id)).resolves.toBeUndefined();
    expect(mock.eventsGetAllCount()).toBe(0);
    const got9 = await store.query([{ "#e": [EID] }]);
    expect(got9.map((e) => e.id)).toStrictEqual([meta2.id]);
    await expect(store.query([{ "#p": [keys.publicKey] }])).resolves.toStrictEqual([]);
    store.close();
  });

  test("v2 leftover kind 0 is compacted on open", async () => {
    const keys = Keys.fromSecretKey(SK);
    const loser = EventBuilder.metadata({ name: "v1" })
      .tag(["e", EID])
      .tag(["p", keys.publicKey])
      .createdAt(10)
      .signWithKeys(keys);
    const winner = EventBuilder.metadata({ name: "v2" })
      .tag(["e", EID])
      .createdAt(20)
      .signWithKeys(keys);
    const eVal = EID.toLowerCase();
    const pVal = keys.publicKey.toLowerCase();
    await seedIdbV2("v2-compact", {
      events: [loser, winner],
      addresses: [
        { address: `0:${keys.publicKey}:`, id: winner.id, created_at: winner.created_at },
      ],
      tagRefs: [
        {
          key: `e:${eVal}:${loser.id.toLowerCase()}`,
          name: "e",
          value: eVal,
          id: loser.id.toLowerCase(),
          created_at: loser.created_at,
        },
        {
          key: `p:${pVal}:${loser.id.toLowerCase()}`,
          name: "p",
          value: pVal,
          id: loser.id.toLowerCase(),
          created_at: loser.created_at,
        },
        {
          key: `e:${eVal}:${winner.id.toLowerCase()}`,
          name: "e",
          value: eVal,
          id: winner.id.toLowerCase(),
          created_at: winner.created_at,
        },
      ],
    });
    const store = new IndexedDbEventStore({ dbName: "v2-compact" });
    await store.open();
    const found = await store.query([{ kinds: [0] }]);
    expect(found).toHaveLength(1);
    expect(found[0]!.id).toBe(winner.id);
    await expect(store.get(loser.id)).resolves.toBeUndefined();
    const got10 = await store.query([{ "#e": [EID] }]);
    expect(got10.map((e) => e.id)).toStrictEqual([winner.id]);
    await expect(store.query([{ "#p": [keys.publicKey] }])).resolves.toStrictEqual([]);
    mock.resetStats();
    await store.query([{ kinds: [0] }]);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("#e and #p k-way merge is AND and respects limit", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "ep-and" });
    await store.open();
    const both = EventBuilder.textNote("both")
      .tag(["e", EID])
      .tag(["p", keys.publicKey])
      .createdAt(10)
      .signWithKeys(keys);
    const onlyE = EventBuilder.textNote("e").tag(["e", EID]).createdAt(20).signWithKeys(keys);
    const onlyP = EventBuilder.textNote("p")
      .tag(["p", keys.publicKey])
      .createdAt(30)
      .signWithKeys(keys);
    await store.put(both);
    await store.put(onlyE);
    await store.put(onlyP);
    const filter = { "#e": [EID], "#p": [keys.publicKey], limit: 2 };
    expect(filter["#e"]).toStrictEqual([EID]);
    expect(filter["#p"]).toStrictEqual([keys.publicKey]);
    const found = await store.query([filter]);
    expect(found.map((e) => e.id)).toStrictEqual([both.id]);
    await expect(store.count([filter])).resolves.toBe(1);
    store.close();
  });

  test("#t-only queries scan created_at and matchFilter", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "t-tag" });
    await store.open();
    const hit = EventBuilder.textNote("hit").tag(["t", "nostr"]).createdAt(1).signWithKeys(keys);
    const miss = EventBuilder.textNote("miss").tag(["t", "other"]).createdAt(2).signWithKeys(keys);
    await store.put(hit);
    await store.put(miss);
    const got11 = await store.query([{ "#t": ["nostr"] }]);
    expect(got11.map((e) => e.id)).toStrictEqual([hit.id]);
    const got12 = await store.query([{ "#t": ["other"] }]);
    expect(got12.map((e) => e.id)).toStrictEqual([miss.id]);
    store.close();
  });

  test("ids+limit on negentropyItems keeps newest not ids-array order", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "ids-limit" });
    await store.open();
    const older = EventBuilder.textNote("old").createdAt(1).signWithKeys(keys);
    const newer = EventBuilder.textNote("new").createdAt(2).signWithKeys(keys);
    await store.put(older);
    await store.put(newer);
    mock.resetStats();
    const items = await store.negentropyItems({ ids: [older.id, newer.id], limit: 1 });
    expect(items.map((i) => i.id)).toStrictEqual([newer.id]);
    const got13 = await store.query([{ ids: [older.id, newer.id], limit: 1 }]);
    expect(got13.map((e) => e.id)).toStrictEqual([newer.id]);
    await expect(store.count([{ ids: [older.id, newer.id], limit: 1 }])).resolves.toBe(1);
    await expect(store.query([{ ids: ["ab".repeat(32)], limit: 1 }])).resolves.toStrictEqual([]);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("count equals query length under multi-prefix limit; items are global recency", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "multi-prefix" });
    await store.open();
    const aNotes = [1, 2, 3].map((t) =>
      EventBuilder.textNote(`a${t}`).createdAt(t).signWithKeys(a),
    );
    const bNotes = [10, 11, 12].map((t) =>
      EventBuilder.textNote(`b${t}`).createdAt(t).signWithKeys(b),
    );
    await store.putMany([...aNotes, ...bNotes]);

    const filter = { authors: [a.publicKey, b.publicKey], kinds: [1], limit: 2 };
    mock.resetStats();
    const queried = await store.query([filter]);
    await expect(store.count([filter])).resolves.toBe(queried.length);
    expect(queried.map((e) => e.created_at)).toStrictEqual([12, 11]);
    expect(queried.map((e) => e.id)).toStrictEqual([bNotes[2]!.id, bNotes[1]!.id]);

    const items = await store.negentropyItems(filter);
    expect(items.map((i) => i.created_at)).toStrictEqual([11, 12]);
    expect(items.map((i) => i.id)).toStrictEqual(
      [bNotes[1]!, bNotes[2]!].toSorted((x, y) => itemCompare(x, y)).map((e) => e.id),
    );
    expect(items.map((i) => i.id).toSorted()).toStrictEqual(queried.map((e) => e.id).toSorted());
    const got14 = await store.query([{ authors: [a.publicKey, b.publicKey], limit: 2 }]);
    expect(got14.map((e) => e.created_at)).toStrictEqual([12, 11]);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("ephemeral kinds are not inserted", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "ephemeral-db" });
    await store.open();
    const auth = new EventBuilder(Kind.ClientAuth, "")
      .tag(["relay", "wss://r.example"])
      .createdAt(1)
      .signWithKeys(keys);
    const wrap = new EventBuilder(Kind.GiftWrapEphemeral, "x")
      .tag(["p", keys.publicKey])
      .tag(["e", EID])
      .createdAt(2)
      .signWithKeys(keys);
    await expect(store.put(auth)).resolves.toBe("ephemeral");
    await expect(store.put(wrap)).resolves.toBe("ephemeral");
    await expect(store.get(auth.id)).resolves.toBeUndefined();
    await expect(store.get(wrap.id)).resolves.toBeUndefined();
    await expect(store.query([{ kinds: [Kind.ClientAuth] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ kinds: [Kind.GiftWrapEphemeral] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#p": [keys.publicKey] }])).resolves.toStrictEqual([]);
    await expect(store.query([{ "#e": [EID] }])).resolves.toStrictEqual([]);
    await expect(store.count([{ kinds: [Kind.ClientAuth, Kind.GiftWrapEphemeral] }])).resolves.toBe(
      0,
    );
    await expect(store.negentropyItems({ kinds: [Kind.ClientAuth] })).resolves.toStrictEqual([]);

    const note = EventBuilder.textNote("keep").tag(["e", EID]).createdAt(3).signWithKeys(keys);
    await expect(store.put(note)).resolves.toBe("accepted");
    const got15 = await store.get(note.id);
    expect(got15?.id).toBe(note.id);
    const got16 = await store.query([{ "#e": [EID] }]);
    expect(got16.map((e) => e.id)).toStrictEqual([note.id]);
    store.close();
  });

  test("negentropyItems same created_at sorts by id lexicographically", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "same-ts" });
    await store.open();
    const high = {
      id: "ff".repeat(32),
      pubkey: keys.publicKey,
      kind: Kind.TextNote,
      created_at: 5,
      tags: [] as [],
      content: "",
      sig: "ab".repeat(64),
    };
    const low = { ...high, id: "00".repeat(32) };
    await store.put(high);
    await store.put(low);
    await expect(store.negentropyItems({ kinds: [Kind.TextNote] })).resolves.toStrictEqual([
      { id: low.id, created_at: 5 },
      { id: high.id, created_at: 5 },
    ]);
    expect(itemCompare(low, high)).toBeLessThan(0);
    store.close();
  });

  test("v1 non-canonical rows are dropped on upgrade", async () => {
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("v1").tag(["e", EID]).createdAt(1).signWithKeys(keys);
    const bad = { ...note, pubkey: note.pubkey.toUpperCase() };
    const good = EventBuilder.textNote("ok").createdAt(2).signWithKeys(keys);
    await seedIdbV1("case-upgrade", [bad, good]);
    const store = new IndexedDbEventStore({ dbName: "case-upgrade" });
    await store.open();
    mock.resetStats();
    await expect(store.query([{ kinds: [1] }])).resolves.toHaveLength(1);
    await expect(store.get(bad.id)).resolves.toBeUndefined();
    const got17 = await store.get(good.id);
    expect(got17?.id).toBe(good.id);
    expect(mock.eventsGetAllCount()).toBe(0);
    store.close();
  });

  test("putMany empty does not open a transaction", async () => {
    const store = new IndexedDbEventStore({ dbName: "putmany-empty" });
    await store.open();
    mock.resetStats();
    await expect(store.putMany([])).resolves.toStrictEqual([]);
    expect(mock.readwriteTransactions()).toStrictEqual([]);
    store.close();
  });

  test("putMany writes N events in one transaction", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-one-tx" });
    await store.open();
    const notes = [1, 2, 3].map((t) =>
      EventBuilder.textNote(String(t)).createdAt(t).signWithKeys(keys),
    );
    mock.resetStats();
    await expect(store.putMany(notes)).resolves.toStrictEqual(["accepted", "accepted", "accepted"]);
    expect(mock.readwriteTransactions()).toHaveLength(1);
    expect(mock.readwriteTransactions()[0]).toStrictEqual([
      "events",
      "tag_refs",
      "addresses",
      "tombstones",
    ]);
    const got18 = await store.query([{ kinds: [1] }]);
    expect(got18.map((e) => e.created_at)).toStrictEqual([3, 2, 1]);
    store.close();
  });

  test("putMany applies replaceable semantics in input order", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-repl" });
    await store.open();
    const old = EventBuilder.metadata({ name: "v1" }).createdAt(10).signWithKeys(keys);
    const neu = EventBuilder.metadata({ name: "v2" }).createdAt(20).signWithKeys(keys);
    mock.resetStats();
    await expect(store.putMany([old, neu])).resolves.toStrictEqual(["accepted", "replaced"]);
    expect(mock.readwriteTransactions()).toHaveLength(1);
    await expect(store.get(old.id)).resolves.toBeUndefined();
    const got19 = await store.get(neu.id);
    expect(got19?.content).toContain("v2");

    const older = EventBuilder.metadata({ name: "v0" }).createdAt(5).signWithKeys(keys);
    await expect(store.putMany([older])).resolves.toStrictEqual(["rejected"]);
    const got20 = await store.get(neu.id);
    expect(got20?.id).toBe(neu.id);
    store.close();
  });

  test("putMany abort rejects StorageError and persists nothing", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-abort" });
    await store.open();
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    mock.failGetOnCall(2);
    await expect(store.putMany([a, b])).rejects.toBeInstanceOf(StorageError);
    await expect(store.get(a.id)).resolves.toBeUndefined();
    await expect(store.get(b.id)).resolves.toBeUndefined();
    await expect(store.query([{ kinds: [1] }])).resolves.toStrictEqual([]);
    store.close();
  });

  test("overlapping putMany waits for the in-flight write", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-serial" });
    await store.open();
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const c = EventBuilder.textNote("c").createdAt(3).signWithKeys(keys);
    mock.resetStats();
    const gate = mock.gateGetOnCall(1);
    const first = store.putMany([a]);
    await tickUntil(() => mock.readwriteTransactions().length === 1);
    const second = store.putMany([b, c]);
    await Promise.resolve();
    await Promise.resolve();
    expect(mock.readwriteTransactions()).toHaveLength(1);
    gate.release();
    await expect(first).resolves.toStrictEqual(["accepted"]);
    await expect(second).resolves.toStrictEqual(["accepted", "accepted"]);
    expect(mock.readwriteTransactions()).toHaveLength(2);
    const got21 = await store.query([{ kinds: [1] }]);
    expect(got21.map((e) => e.id)).toStrictEqual([c.id, b.id, a.id]);
    store.close();
  });

  test("setOutboxBound waits behind an in-flight putMany", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "bound-behind-put" });
    await store.open();
    const note = EventBuilder.textNote("n").createdAt(50).signWithKeys(keys);
    mock.resetStats();
    const gate = mock.gateGetOnCall(1);
    const put = store.putMany([note]);
    await tickUntil(() => mock.readwriteTransactions().length === 1);
    const boundP = store.setOutboxBound(keys.publicKey, 1, { oldest: 1, newest: 2 });
    await Promise.resolve();
    await Promise.resolve();
    expect(mock.readwriteTransactions()).not.toContainEqual(["outbox_bounds"]);
    gate.release();
    await expect(put).resolves.toStrictEqual(["accepted"]);
    await boundP;
    expect(mock.readwriteTransactions()).toContainEqual(["outbox_bounds"]);
    await expect(store.getOutboxBound(keys.publicKey, 1)).resolves.toStrictEqual({
      oldest: 1,
      newest: 2,
    });
    store.close();
  });

  test("clear then setOutboxBound keeps the bound; reverse drops it", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "bound-vs-clear" });
    await store.open();
    const note = EventBuilder.textNote("n").createdAt(50).signWithKeys(keys);
    mock.resetStats();
    const gate1 = mock.gateGetOnCall(1);
    const put1 = store.putMany([note]);
    await tickUntil(() => mock.readwriteTransactions().length === 1);
    const clear1 = store.clear();
    const bound1 = store.setOutboxBound(keys.publicKey, 1, { oldest: 1, newest: 2 });
    await Promise.resolve();
    await Promise.resolve();
    expect(mock.readwriteTransactions()).not.toContainEqual(["outbox_bounds"]);
    gate1.release();
    await put1;
    await clear1;
    await bound1;
    await expect(store.getOutboxBound(keys.publicKey, 1)).resolves.toStrictEqual({
      oldest: 1,
      newest: 2,
    });

    const later = EventBuilder.textNote("m").createdAt(51).signWithKeys(keys);
    mock.resetStats();
    const gate2 = mock.gateGetOnCall(1);
    const put2 = store.putMany([later]);
    await tickUntil(() => mock.readwriteTransactions().length === 1);
    const bound2 = store.setOutboxBound(keys.publicKey, 1, { oldest: 3, newest: 4 });
    const clear2 = store.clear();
    await Promise.resolve();
    await Promise.resolve();
    expect(mock.readwriteTransactions()).not.toContainEqual(["outbox_bounds"]);
    gate2.release();
    await put2;
    await bound2;
    await clear2;
    await expect(store.getOutboxBound(keys.publicKey, 1)).resolves.toBeUndefined();
    store.close();
  });

  test("outbox bound persist survives close and reopen", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "bounds-persist" });
    await store.open();
    await store.setOutboxBound(keys.publicKey, Kind.TextNote, { oldest: 10, newest: 20 });
    await expect(store.getOutboxBound(keys.publicKey, Kind.TextNote)).resolves.toStrictEqual({
      oldest: 10,
      newest: 20,
    });
    mock.resetStats();
    await store.setOutboxBound(keys.publicKey, Kind.TextNote, { oldest: 10, newest: 30 });
    expect(mock.readwriteTransactions()).toStrictEqual([["outbox_bounds"]]);
    store.close();

    const reopened = new IndexedDbEventStore({ dbName: "bounds-persist" });
    await reopened.open();
    await expect(reopened.getOutboxBound(keys.publicKey, Kind.TextNote)).resolves.toStrictEqual({
      oldest: 10,
      newest: 30,
    });
    await reopened.clear();
    await expect(reopened.getOutboxBound(keys.publicKey, Kind.TextNote)).resolves.toBeUndefined();
    reopened.close();
  });

  test("v3 db gains outbox_bounds on open", async () => {
    const keys = Keys.fromSecretKey(SK);
    await seedIdbV3("v3-bounds");
    const store = new IndexedDbEventStore({ dbName: "v3-bounds" });
    await store.open();
    await store.setOutboxBound(keys.publicKey, 1, { oldest: 4, newest: 8 });
    await expect(store.getOutboxBound(keys.publicKey, 1)).resolves.toStrictEqual({
      oldest: 4,
      newest: 8,
    });
    store.close();
  });

  test("outbox bound derive uses prefix heads not getAll", async () => {
    const keys = Keys.fromSecretKey(SK);
    const other = Keys.generate();
    const store = new IndexedDbEventStore({ dbName: "bounds-derive" });
    await store.open();
    await store.putMany(
      Array.from({ length: 20 }, (_, i) =>
        EventBuilder.textNote(`n${i}`).createdAt(i).signWithKeys(keys),
      ),
    );
    await store.putMany(
      Array.from({ length: 10 }, (_, i) =>
        EventBuilder.textNote(`o${100 + i}`)
          .createdAt(100 + i)
          .signWithKeys(other),
      ),
    );
    mock.resetStats();
    await expect(store.getOutboxBound(keys.publicKey, Kind.TextNote)).resolves.toStrictEqual({
      oldest: 0,
      newest: 19,
    });
    expect(mock.eventsGetAllCount()).toBe(0);
    expect(mock.cursorVisitCount()).toBe(2);
    await expect(store.getOutboxBound(other.publicKey, Kind.TextNote)).resolves.toStrictEqual({
      oldest: 100,
      newest: 109,
    });
    store.close();
  });

  test("open with null req.error throws StorageError fallback", async () => {
    mock.failOpen(null);
    const store = new IndexedDbEventStore({ dbName: "open-null-err" });
    const err = await store.open().then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB open failed");
    expect((err as StorageError).cause).toBeUndefined();
  });

  test("get with null req.error throws StorageError fallback", async () => {
    const store = new IndexedDbEventStore({ dbName: "get-null-err" });
    await store.open();
    mock.failGetOnCall(1, null);
    const err = await store.get(EID).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB request failed");
    expect((err as StorageError).cause).toBeUndefined();
    store.close();
  });

  test("tag query get with null req.error throws IndexedDB get failed", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "tag-get-null-err" });
    await store.open();
    const note = EventBuilder.textNote("n").tag(["e", EID]).createdAt(1).signWithKeys(keys);
    await expect(store.put(note)).resolves.toBe("accepted");
    mock.failGetOnCall(1, null);
    const err = await store.query([{ "#e": [EID] }]).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB get failed");
    expect((err as StorageError).cause).toBeUndefined();
    store.close();
  });

  test("query cursor open with null req.error throws IndexedDB cursor failed", async () => {
    const store = new IndexedDbEventStore({ dbName: "cursor-null-err" });
    await store.open();
    mock.failCursor(null);
    const err = await store.query([{ kinds: [Kind.TextNote] }]).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB cursor failed");
    expect((err as StorageError).cause).toBeUndefined();
    store.close();
  });

  test("putMany tx abort with null tx.error is StorageError without cause", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-abort-null" });
    await store.open();
    const note = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    mock.failNextTxComplete("abort", null);
    const err = await store.putMany([note]).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB transaction aborted");
    expect((err as StorageError).cause).toBeUndefined();
    await expect(store.get(note.id)).resolves.toBeUndefined();
    store.close();
  });

  test("putMany tx onerror with null tx.error is StorageError without cause", async () => {
    const keys = Keys.fromSecretKey(SK);
    const store = new IndexedDbEventStore({ dbName: "putmany-error-null" });
    await store.open();
    const note = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    mock.failNextTxComplete("error", null);
    const err = await store.putMany([note]).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB transaction failed");
    expect((err as StorageError).cause).toBeUndefined();
    await expect(store.get(note.id)).resolves.toBeUndefined();
    store.close();
  });
});

describe("IndexedDbEventStore version contention", () => {
  let mock: IdbMock;

  type RawDb = {
    close: () => void;
    onversionchange: ((ev: unknown) => void) | null;
    objectStoreNames: { contains: (name: string) => boolean };
    createObjectStore: (name: string, options?: { keyPath?: string }) => unknown;
  };

  async function rawOpen(dbName: string, version: number): Promise<RawDb> {
    type RawReq = {
      result: RawDb;
      error: Error | null;
      onsuccess: ((ev: unknown) => void) | null;
      onerror: ((ev: unknown) => void) | null;
      onblocked: ((ev: unknown) => void) | null;
      onupgradeneeded: ((ev: unknown) => void) | null;
    };
    const factory = (
      globalThis as unknown as {
        indexedDB: { open: (name: string, version?: number) => RawReq };
      }
    ).indexedDB;
    return new Promise((resolve, reject) => {
      const req = factory.open(dbName, version);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains("events")) {
          db.createObjectStore("events", { keyPath: "id" });
        }
      };
      // oxlint-disable-next-line unicorn/prefer-add-event-listener -- fake IDBOpenDBRequest mirrors the on* handler API
      req.onerror = () => reject(req.error ?? new Error("raw open failed"));
      req.onblocked = () => reject(new Error("raw open blocked"));
      req.onsuccess = () => resolve(req.result);
    });
  }

  beforeEach(() => {
    mock = installIdbMock();
  });

  afterEach(() => {
    mock.uninstall();
  });

  test("open rejects with StorageError when an older connection stays open", async () => {
    const raw = await rawOpen("blocked-db", 1);
    const err = await new IndexedDbEventStore({ dbName: "blocked-db" }).open().then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB open blocked by another connection");
    raw.close();
  });

  test("an open store yields to a newer-version open instead of blocking it", async () => {
    const store = new IndexedDbEventStore({ dbName: "yield-db" });
    await store.open();
    const newer = await rawOpen("yield-db", IDB_VERSION + 1);
    expect(newer.objectStoreNames.contains("events")).toBe(true);
    newer.close();
    store.close();
  });

  test("operations fail with StorageError after yielding to a newer version", async () => {
    const store = new IndexedDbEventStore({ dbName: "yield-ops" });
    await store.open();
    const newer = await rawOpen("yield-ops", IDB_VERSION + 1);
    const err = await store.get(EID).then(
      () => {
        throw new Error("expected reject");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).message).toBe("IndexedDB connection closed by a newer version");
    newer.close();
    store.close();
  });
});

describe("scanFilter merge cursor cap (issue #134)", () => {
  let mock: IdbMock;

  beforeEach(() => {
    mock = installIdbMock();
  });

  afterEach(() => {
    mock.uninstall();
  });

  test("over-cap authors × 1 kind falls back to wide cursors with identical results", async () => {
    // The query path does not care about signatures, so the fixture uses
    // markVerified fabricated events: real key generation and signing for
    // hundreds of events made this test exceed the timeout under suite load.
    const authors = Array.from({ length: MAX_MERGE_CURSORS + 6 }, (_, i) =>
      (0x100 + i).toString(16).padStart(64, "0"),
    );
    const events = authors.flatMap((pk, i) =>
      [0, 1, 2].map((j) => {
        const event: Event = {
          id: (i * 3 + j + 1).toString(16).padStart(64, "0"),
          pubkey: pk,
          kind: Kind.TextNote,
          created_at: 1000 + i * 10 + j,
          tags: [],
          content: `a${i}-${j}`,
          sig: "ab".repeat(64),
        };
        markVerified(event);
        return event;
      }),
    );
    const idb = new IndexedDbEventStore({ dbName: "merge-cap" });
    const mem = new MemoryEventStore();
    await idb.putMany(events);
    await mem.putMany(events);

    const pks = authors;
    // authors × kinds exceeds MAX_MERGE_CURSORS → one cursor per kind.
    const filter = { authors: pks, kinds: [Kind.TextNote] };
    const got22 = await idb.query([filter]);
    const got23 = await mem.query([filter]);
    expect(got22.map((e) => e.id)).toStrictEqual(got23.map((e) => e.id));
    // Per-filter limit still applies on the fallback path (newest-first).
    const limited = { ...filter, limit: 25 };
    const got24 = await idb.query([limited]);
    const got25 = await mem.query([limited]);
    expect(got24.map((e) => e.id)).toStrictEqual(got25.map((e) => e.id));
    // Authors alone over the cap collapse to a single created_at cursor.
    const authorsOnly = { authors: pks, limit: 40 };
    const got26 = await idb.query([authorsOnly]);
    const got27 = await mem.query([authorsOnly]);
    expect(got26.map((e) => e.id)).toStrictEqual(got27.map((e) => e.id));
    idb.close();
  });
});
