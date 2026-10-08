import { describe, expect, test } from "vite-plus/test";

import { EventBuilder, Keys, SqliteEventStore, StorageError } from "../src/index.ts";
import type { Event, SqlDriver, SqlValue } from "../src/index.ts";
import { eventStoreConformanceCases } from "../src/testing/index.ts";
import { SqliteTestDriver } from "./helpers/sqlite-driver.ts";

const ALICE_SK = "0000000000000000000000000000000000000000000000000000000000000101";
const BOB_SK = "0000000000000000000000000000000000000000000000000000000000000102";

function alice(): Keys {
  return Keys.fromSecretKey(ALICE_SK);
}
function bob(): Keys {
  return Keys.fromSecretKey(BOB_SK);
}

function note(keys: Keys, content: string, createdAt: number, tags: string[][] = []): Event {
  return new EventBuilder(1, content).tags(tags).createdAt(createdAt).signWithKeys(keys);
}

async function openStore(): Promise<{ driver: SqliteTestDriver; store: SqliteEventStore }> {
  const driver = await SqliteTestDriver.open();
  return { driver, store: await SqliteEventStore.open(driver) };
}

/**
 * Wraps a driver so a second exec/run/all starting before the previous one settles is recorded —
 * the store's sequential-statement contract must hold inside and outside transactions.
 */
function serializedDriver(inner: SqlDriver): SqlDriver & { overlapped: () => boolean } {
  let inflight = 0;
  let overlap = false;
  const track = async <T>(call: () => Promise<T>): Promise<T> => {
    if (inflight > 0) {
      overlap = true;
    }
    inflight += 1;
    try {
      return await call();
    } finally {
      inflight -= 1;
    }
  };
  const wrap = (driver: SqlDriver): SqlDriver => ({
    exec: async (sql) => track(async () => driver.exec(sql)),
    run: async (sql, params?: ReadonlyArray<SqlValue>) =>
      track(async () => driver.run(sql, params)),
    all: async <Row>(sql: string, params?: ReadonlyArray<SqlValue>) =>
      track(async () => driver.all<Row>(sql, params)),
    transaction: async (fn) => driver.transaction(async (tx) => fn(wrap(tx))),
  });
  const wrapped = wrap(inner);
  return { ...wrapped, overlapped: () => overlap };
}

describe("SqliteEventStore conformance", () => {
  // oxlint-disable-next-line expect-expect -- assertions live inside each case's run()
  test.each(eventStoreConformanceCases)("$name", async (c) => {
    const { driver, store } = await openStore();
    try {
      await c.run(store);
    } finally {
      driver.close();
    }
  });
});

describe("SqliteEventStore", () => {
  test("putMany rolls back the whole batch on a mid-batch driver failure", async () => {
    const { driver, store } = await openStore();
    try {
      const first = note(alice(), "first", 1);
      const second = note(alice(), "second", 2, [["e", "aa".repeat(32)]]);
      // Fail the second event insert; the batch transaction must roll back.
      driver.failOn(/^INSERT INTO events/, { skip: 1 });
      let err: unknown;
      try {
        await store.putMany([first, second]);
      } catch (error) {
        err = error;
      }
      expect(err).toBeInstanceOf(StorageError);
      await expect(store.get(first.id)).resolves.toBeUndefined();
      await expect(store.get(second.id)).resolves.toBeUndefined();
      await expect(store.count([{ kinds: [1] }])).resolves.toBe(0);
      // The driver recovers and the store keeps working.
      await expect(store.put(first)).resolves.toBe("accepted");
    } finally {
      driver.close();
    }
  });

  test("reopen on the same database preserves data and tombstones", async () => {
    const { driver } = await openStore();
    try {
      const first = await SqliteEventStore.open(driver);
      const kept = note(alice(), "kept", 1);
      // Deleted before arrival: leaves a `pending` tombstone, not a row.
      const pending = note(alice(), "pending target", 5);
      const removed = note(alice(), "removed", 3, [["d", "x"]]);
      const addressable = new EventBuilder(30001, "v")
        .tags([["d", "x"]])
        .createdAt(2)
        .signWithKeys(alice());
      await first.putMany([kept, removed, addressable]);
      await first.remove([removed.id]);

      const delPending = EventBuilder.deletion([pending.id]).createdAt(4).signWithKeys(alice());
      // The coordinate tombstone must be authored by the address owner.
      const coord = `30001:${alice().publicKey}:x`;
      const delCoord = EventBuilder.deletion([{ address: coord }], "")
        .createdAt(4)
        .signWithKeys(alice());
      await first.putMany([delPending, delCoord]);

      const second = await SqliteEventStore.open(driver);
      await expect(second.get(kept.id)).resolves.toStrictEqual(kept);
      await expect(second.put(kept)).resolves.toBe("duplicate");
      // Pending tombstone: the deleted-before-arrival event is rejected.
      await expect(second.put(pending)).resolves.toBe("duplicate");
      // Coordinate tombstone: a stale version of the address cannot return.
      const stale = new EventBuilder(30001, "stale")
        .tags([["d", "x"]])
        .createdAt(3)
        .signWithKeys(alice());
      await expect(second.put(stale)).resolves.toBe("duplicate");
      // Removed ids stay tombstoned across reopen.
      await expect(second.put(removed)).resolves.toBe("duplicate");
      // A newer version newer than the tombstone is still accepted.
      const fresh = new EventBuilder(30001, "fresh")
        .tags([["d", "x"]])
        .createdAt(9)
        .signWithKeys(alice());
      await expect(second.put(fresh)).resolves.toBe("accepted");
      const freshRow = await second.get(fresh.id);
      expect(freshRow?.content).toBe("fresh");
    } finally {
      driver.close();
    }
  });

  test("#e and #p tag filters match case-insensitively", async () => {
    const { driver, store } = await openStore();
    try {
      const refId = "AB".repeat(32);
      const refPk = "CD".repeat(32);
      const tagged = note(alice(), "tagged", 1, [
        ["e", refId.toLowerCase()],
        ["p", refPk.toLowerCase()],
      ]);
      await store.put(tagged);
      await expect(store.query([{ "#e": [refId] }])).resolves.toHaveLength(1);
      await expect(store.query([{ "#p": [refPk] }])).resolves.toHaveLength(1);
      await expect(store.query([{ "#e": [refId.toLowerCase()] }])).resolves.toHaveLength(1);
      await expect(store.query([{ "#e": ["00".repeat(32)] }])).resolves.toHaveLength(0);
    } finally {
      driver.close();
    }
  });

  test("filters with more than 500 ids or authors are chunked", async () => {
    const { driver, store } = await openStore();
    try {
      const mine = note(alice(), "mine", 1);
      const theirs = note(bob(), "theirs", 2);
      await store.putMany([mine, theirs]);
      const filler = (n: number): string[] =>
        Array.from({ length: n }, (_, i) => (i + 1).toString(16).padStart(64, "0"));
      const manyIds = [...filler(600), mine.id];
      const idRows = await store.query([{ ids: manyIds }]);
      expect(idRows.map((e) => e.id)).toStrictEqual([mine.id]);
      const manyAuthors = [...filler(600), alice().publicKey];
      const authorRows = await store.query([{ authors: manyAuthors }]);
      expect(authorRows.map((e) => e.id)).toStrictEqual([mine.id]);
      await expect(store.count([{ ids: manyIds, kinds: [1] }])).resolves.toBe(1);
      const negRows = await store.negentropyItems({ ids: manyIds });
      expect(negRows.map((i) => i.id)).toStrictEqual([mine.id]);
    } finally {
      driver.close();
    }
  });

  test("addressable replacement keeps exactly one row per address", async () => {
    const { driver, store } = await openStore();
    try {
      const put = (content: string, createdAt: number): Event =>
        new EventBuilder(30001, content)
          .tags([["d", "x"]])
          .createdAt(createdAt)
          .signWithKeys(alice());
      const v1 = put("v1", 1);
      const v2 = put("v2", 2);
      const v3 = put("v3", 3);
      await expect(store.putMany([v1, v2, v3])).resolves.toStrictEqual([
        "accepted",
        "replaced",
        "replaced",
      ]);
      const rows = await driver.all<{ id: string }>(`SELECT id FROM events WHERE address = ?`, [
        `30001:${alice().publicKey}:x`,
      ]);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(v3.id);
      const kindRows = await store.query([{ kinds: [30001] }]);
      expect(kindRows.map((e) => e.id)).toStrictEqual([v3.id]);
      await expect(store.get(v1.id)).resolves.toBeUndefined();
    } finally {
      driver.close();
    }
  });

  test("kind-5 deletion with more than 500 a tags is chunked", async () => {
    const { driver, store } = await openStore();
    try {
      const target = new EventBuilder(30001, "target")
        .tags([["d", "x"]])
        .createdAt(1)
        .signWithKeys(alice());
      const keep = new EventBuilder(30001, "keep")
        .tags([["d", "y"]])
        .createdAt(1)
        .signWithKeys(alice());
      await store.putMany([target, keep]);

      const targets: Array<{ address: string }> = [];
      for (let i = 0; i < 599; i++) {
        targets.push({ address: `30001:${(i + 1).toString(16).padStart(64, "0")}:z` });
      }
      targets.push({ address: `30001:${alice().publicKey}:x` });
      const del = EventBuilder.deletion(targets, "").createdAt(5).signWithKeys(alice());
      await expect(store.put(del)).resolves.toBe("deleted");
      await expect(store.get(target.id)).resolves.toBeUndefined();
      const keepRow = await store.get(keep.id);
      expect(keepRow?.content).toBe("keep");
    } finally {
      driver.close();
    }
  });

  test("issues driver statements sequentially", async () => {
    const raw = await SqliteTestDriver.open();
    const driver = serializedDriver(raw);
    const store = await SqliteEventStore.open(driver);
    try {
      const pending = note(alice(), "pending", 2);
      const target = new EventBuilder(30001, "v")
        .tags([["d", "x"]])
        .createdAt(1)
        .signWithKeys(alice());
      await store.putMany([note(alice(), "a", 1), target]);
      // A deletion over a missing id and a coordinate exercises the tombstone
      // read-then-write paths plus the removeIds delete loop.
      const del = EventBuilder.deletion(
        [pending.id, { address: `30001:${alice().publicKey}:x` }],
        "",
      )
        .createdAt(5)
        .signWithKeys(alice());
      await expect(store.put(del)).resolves.toBe("deleted");
      await store.remove([target.id, "00".repeat(32)]);
      await expect(store.query([{ kinds: [1] }, { kinds: [30001] }])).resolves.toBeInstanceOf(
        Array,
      );
      await expect(store.count([{ kinds: [1] }, { kinds: [30001] }])).resolves.toBe(1);
      expect(driver.overlapped()).toBe(false);
    } finally {
      raw.close();
    }
  });

  test("multi-char #tag filters fall back to a matchFilter pass", async () => {
    const { driver, store } = await openStore();
    try {
      const tagged = note(alice(), "tagged", 1, [["client", "test-app"]]);
      const plain = note(alice(), "plain", 2);
      await store.putMany([tagged, plain]);
      const tagRows = await store.query([{ "#client": ["test-app"] }]);
      expect(tagRows.map((e) => e.id)).toStrictEqual([tagged.id]);
      await expect(store.count([{ "#client": ["test-app"] }])).resolves.toBe(1);
    } finally {
      driver.close();
    }
  });
});

describe("SqliteEventStore tag cleanup", () => {
  const tagCount = async (driver: SqliteTestDriver, id: string): Promise<number> => {
    const rows = await driver.all<{ n: number }>(
      `SELECT COUNT(*) AS n FROM tags WHERE event_id = ?`,
      [id],
    );
    return rows.at(0)?.n ?? -1;
  };

  test("replacement, remove, and kind-5 deletion drop tag rows with foreign_keys off", async () => {
    const { driver, store } = await openStore();
    try {
      // Simulate expo-sqlite's exclusive-transaction connection: foreign_keys is off there,
      // so ON DELETE CASCADE never fires.
      await driver.exec("PRAGMA foreign_keys = OFF");

      const v1 = new EventBuilder(0, "v1")
        .tags([["p", bob().publicKey]])
        .createdAt(1)
        .signWithKeys(alice());
      const v2 = new EventBuilder(0, "v2")
        .tags([["p", bob().publicKey]])
        .createdAt(2)
        .signWithKeys(alice());
      await store.putMany([v1, v2]);
      await expect(tagCount(driver, v1.id)).resolves.toBe(0);
      await expect(tagCount(driver, v2.id)).resolves.toBe(1);

      const removed = note(alice(), "gone", 3, [["e", v2.id]]);
      await store.put(removed);
      await store.remove([removed.id]);
      await expect(tagCount(driver, removed.id)).resolves.toBe(0);

      const target = note(alice(), "del me", 4, [["p", "aabbcc"]]);
      await store.put(target);
      const del = EventBuilder.deletion([{ id: target.id, kind: 1 }], "")
        .createdAt(5)
        .signWithKeys(alice());
      await expect(store.put(del)).resolves.toBe("deleted");
      await expect(tagCount(driver, target.id)).resolves.toBe(0);
    } finally {
      driver.close();
    }
  });
});
