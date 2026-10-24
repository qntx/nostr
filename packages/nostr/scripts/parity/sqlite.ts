// Cross-language SQLite round trip (plan §4.3): `write <dir>` writes a
// deterministic fixture set plus its query results; `read <dir>` opens the
// database nk-store wrote and asserts the same results.
//
//   bun packages/nostr/scripts/parity/sqlite.ts write <dir>   # → events.json, ts.db, ts-results.json
//   NK_SQLITE_DIR=<dir> cargo test -p nk-store --features sqlite --test it -- --ignored sqlite_interop
//   bun packages/nostr/scripts/parity/sqlite.ts read <dir>    # opens rust.db, asserts ts-results.json

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { EventBuilder, Keys, SqliteEventStore } from "../../src/index.ts";
import type { Event, Filter, SqlDriver, SqlValue } from "../../src/index.ts";

type RawDb = {
  exec: (sql: string) => void;
  prepare: (sql: string) => {
    run: (...params: SqlValue[]) => { changes: number | bigint };
    all: (...params: SqlValue[]) => unknown[];
  };
  close: () => void;
};

/**
 * Bun:sqlite is synchronous; each statement awaits a resolved promise to keep the driver surface
 * async without a real round-trip.
 */
const wrap = (inner: RawDb): SqlDriver => ({
  exec: async (sql) => {
    await Promise.resolve();
    inner.exec(sql);
  },
  run: async (sql, params = []) => {
    await Promise.resolve();
    return { changes: Number(inner.prepare(sql).run(...params).changes) };
  },
  all: async <Row>(sql: string, params: ReadonlyArray<SqlValue> = []) => {
    await Promise.resolve();
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- bun:sqlite returns untyped rows
    return inner.prepare(sql).all(...params) as Row[];
  },
  transaction: async (fn) => {
    await Promise.resolve();
    inner.exec("BEGIN IMMEDIATE");
    try {
      const result = await fn(wrap(inner));
      inner.exec("COMMIT");
      return result;
    } catch (error) {
      inner.exec("ROLLBACK");
      throw error instanceof Error ? error : new Error(String(error));
    }
  },
});

/** `bun:sqlite` `Database` over a file path, wrapped as a `SqlDriver`. */
async function fileDriver(path: string): Promise<SqlDriver & { close: () => void }> {
  const specifier = "bun:sqlite";
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- bun:sqlite has no importable types; this is the RawDb contract
  const mod = (await import(specifier)) as { Database: new (path: string) => RawDb };
  const db = new mod.Database(path);
  return { ...wrap(db), close: () => db.close() };
}

const ALICE_SK = "0000000000000000000000000000000000000000000000000000000000000101";
const BOB_SK = "0000000000000000000000000000000000000000000000000000000000000102";
const alice = () => Keys.fromSecretKey(ALICE_SK);
const bob = () => Keys.fromSecretKey(BOB_SK);

const note = (keys: Keys, content: string, createdAt: number, tags: string[][] = []): Event =>
  new EventBuilder(1, content).tags(tags).createdAt(createdAt).signWithKeys(keys);

/** The deterministic fixture set, in put order. */
function fixtures(): Event[] {
  const regular = note(alice(), "hello", 1);
  const target = note(bob(), "target", 2);
  const tagged = note(alice(), "tagged", 3, [
    ["e", target.id],
    ["p", bob().publicKey],
  ]);
  const replaceableOld = new EventBuilder(0, "old").createdAt(4).signWithKeys(alice());
  const replaceableNew = new EventBuilder(0, "new").createdAt(5).signWithKeys(alice());
  const addressable = new EventBuilder(30001, "v1")
    .tags([["d", "interop"]])
    .createdAt(6)
    .signWithKeys(alice());
  const delE = EventBuilder.deletion([target.id], "").createdAt(7).signWithKeys(bob());
  const delA = EventBuilder.deletion([{ address: `30001:${alice().publicKey}:interop` }], "")
    .createdAt(8)
    .signWithKeys(alice());
  const covered = new EventBuilder(30001, "covered")
    .tags([["d", "interop"]])
    .createdAt(9)
    .signWithKeys(alice());
  return [
    regular,
    target,
    tagged,
    replaceableOld,
    replaceableNew,
    addressable,
    delE,
    delA,
    covered,
  ];
}

/** The fixed result set both languages must produce identically. */
function resultFilters(): Array<{ name: string; filter: Filter }> {
  return [
    { name: "all kind 1", filter: { kinds: [1] } },
    { name: "alice kind 1", filter: { kinds: [1], authors: [alice().publicKey] } },
    { name: "e-tag", filter: { "#e": [note(bob(), "target", 2).id] } },
    { name: "since", filter: { kinds: [1], since: 3 } },
    { name: "limit", filter: { kinds: [1], limit: 1 } },
  ];
}

async function collect(store: SqliteEventStore): Promise<unknown> {
  const queries: Record<string, string[]> = {};
  const counts: Record<string, number> = {};
  for (const { name, filter } of resultFilters()) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- results are collected sequentially like sqlite.ts
    const rows = await store.query([filter]);
    queries[name] = rows.map((event) => event.id);
    // oxlint-disable-next-line eslint/no-await-in-loop -- results are collected sequentially like sqlite.ts
    counts[name] = await store.count([filter]);
  }
  const items = await store.negentropyItems({ kinds: [1] });
  const negentropy = items.map((item) => ({
    id: item.id,
    created_at: item.created_at,
  }));
  return { queries, counts, negentropy };
}

async function write(dir: string): Promise<void> {
  mkdirSync(dir, { recursive: true });
  for (const suffix of ["ts.db", "ts.db-wal", "ts.db-shm"]) {
    rmSync(join(dir, suffix), { force: true });
  }
  const driver = await fileDriver(join(dir, "ts.db"));
  const store = await SqliteEventStore.open(driver);
  const events = fixtures();
  await store.putMany(events);
  writeFileSync(join(dir, "events.json"), JSON.stringify(events));
  writeFileSync(join(dir, "ts-results.json"), JSON.stringify(await collect(store)));
  driver.close();
}

async function read(dir: string): Promise<void> {
  const driver = await fileDriver(join(dir, "rust.db"));
  const store = await SqliteEventStore.open(driver);
  const expected = JSON.parse(readFileSync(join(dir, "ts-results.json"), "utf8")) as unknown;
  const actual = await collect(store);
  driver.close();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `sqlite interop mismatch\nexpected: ${JSON.stringify(expected)}\nactual:   ${JSON.stringify(actual)}`,
    );
  }
  console.log(`sqlite interop: rust.db matches ts-results.json`);
}

const [command, dir] = process.argv.slice(2);
if (dir === undefined || (command !== "write" && command !== "read")) {
  console.error("usage: sqlite.ts write <dir> | sqlite.ts read <dir>");
  process.exitCode = 1;
} else if (command === "write") {
  await write(dir);
} else {
  await read(dir);
}
