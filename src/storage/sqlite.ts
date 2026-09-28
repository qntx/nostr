// oxlint-disable no-await-in-loop -- SqlDriver statements are issued sequentially; drivers are not required to support overlapping statements on one connection
import { compareEventsDesc, itemCompare, sortEvents } from "../core/event.ts";
import type { Event } from "../core/event.ts";
import { matchFilter } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import { Kind } from "../core/kind.ts";
import { eventAddress, formatEventAddress, parseEventAddress } from "../core/tag.ts";
import { DeletionState } from "./deletion.ts";
import type { DeletionPlan } from "./deletion.ts";
import { toStorageError } from "./error.ts";
import { decidePut } from "./put.ts";
import type { PutDecision, PutLookup } from "./put.ts";
import type { EventStore, NegentropyItem, OutboxBound, PutResult } from "./types.ts";

/** Value bindable to a SQLite statement parameter. */
// oxlint-disable-next-line typescript/no-restricted-types -- SQL NULL is a first-class bind value
export type SqlValue = string | number | null | Uint8Array;

/**
 * Minimal async SQLite driver surface.
 *
 * `transaction` must serialize `fn` exclusively — no interleaved statements from other callers may
 * run while the callback transaction is active. It commits when `fn` resolves and rolls back when
 * `fn` rejects.
 *
 * The store always issues statements sequentially — a driver never sees a second `exec`/`run`/`all`
 * start before the previous one settles, inside or outside a transaction — so drivers need not
 * support overlapping statements on one connection.
 *
 * `expo-sqlite` maps onto this interface without changes to query code. Note that
 * `withExclusiveTransactionAsync` resolves `void` and statements inside the exclusive transaction
 * must run on the `txn` connection passed to its callback, not on `db` — the result is captured
 * out-of-band:
 *
 * ```ts
 * const toDriver = (db: SQLiteDatabase): SqlDriver => ({
 *   exec: (sql) => db.execAsync(sql),
 *   run: async (sql, params = []) => ({
 *     changes: (await db.runAsync(sql, [...params])).changes,
 *   }),
 *   all: (sql, params = []) => db.getAllAsync(sql, [...params]),
 *   transaction: async (fn) => {
 *     let result!: Awaited<ReturnType<typeof fn>>;
 *     await db.withExclusiveTransactionAsync(async (txn) => {
 *       result = await fn(toDriver(txn));
 *     });
 *     return result;
 *   },
 * });
 * ```
 */
export type SqlDriver = {
  /** Execute SQL without parameters (DDL, PRAGMA, multi-statement batches). */
  exec: (sql: string) => Promise<void>;
  /** Run a statement; resolves with the number of changed rows. */
  run: (sql: string, params?: ReadonlyArray<SqlValue>) => Promise<{ changes: number }>;
  /** Run a query; resolves with all result rows. */
  all: <Row>(sql: string, params?: ReadonlyArray<SqlValue>) => Promise<Row[]>;
  /** Run `fn` inside an exclusive transaction; commit on resolve, roll back on reject. */
  transaction: <T>(fn: (tx: SqlDriver) => Promise<T>) => Promise<T>;
};

/** Bound values per `IN (...)` list; stays below every host's variable limit. */
const IN_CHUNK = 500;
const SCHEMA_VERSION = 1;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  kind INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  sig TEXT NOT NULL,
  address TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS events_address
  ON events(address) WHERE address IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_kind_created ON events(kind, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_pubkey_kind_created
  ON events(pubkey, kind, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_pubkey_created ON events(pubkey, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_created ON events(created_at DESC, id);
CREATE TABLE IF NOT EXISTS tags (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tags_name_value_created
  ON tags(name, value, created_at DESC);
CREATE TABLE IF NOT EXISTS tombstones (
  kind TEXT NOT NULL CHECK(kind IN ('id', 'pending', 'coord')),
  key TEXT NOT NULL,
  pubkey TEXT,
  until INTEGER,
  PRIMARY KEY(kind, key)
);
CREATE TABLE IF NOT EXISTS outbox_bounds (
  pubkey TEXT NOT NULL,
  kind INTEGER NOT NULL,
  oldest INTEGER NOT NULL,
  newest INTEGER NOT NULL,
  PRIMARY KEY(pubkey, kind)
);
`;

type EventRow = {
  id: string;
  pubkey: string;
  kind: number;
  created_at: number;
  content: string;
  tags: string;
  sig: string;
};

type TombstoneKind = "id" | "pending" | "coord";

type TombstoneRow = {
  kind: TombstoneKind;
  key: string;
  // oxlint-disable-next-line typescript/no-restricted-types -- nullable SQL column
  pubkey: string | null;
  // oxlint-disable-next-line typescript/no-restricted-types -- nullable SQL column
  until: number | null;
};

function rowToEvent(row: EventRow): Event {
  // Key order mirrors finalizeEvent's canonical construction so a round-trip
  // through the store JSON-equals the originally signed object.
  return {
    kind: row.kind,
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the tags column is written by #insertEvent as JSON.stringify(event.tags)
    tags: JSON.parse(row.tags) as string[][],
    content: row.content,
    created_at: row.created_at,
    pubkey: row.pubkey,
    id: row.id,
    sig: row.sig,
  };
}

function chunkValues<T>(values: ReadonlyArray<T>): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < values.length; i += IN_CHUNK) {
    chunks.push(values.slice(i, i + IN_CHUNK));
  }
  return chunks;
}

function inClause(column: string, count: number): string {
  return `${column} IN (${Array.from({ length: count }, () => "?").join(",")})`;
}

/** One query variant of a filter: WHERE terms and bound params. */
type FilterPlan = {
  wheres: string[];
  params: SqlValue[];
};

/**
 * Compile one NIP-01 filter into query variants. `IN` lists are chunked so a variant never binds
 * more than {@link IN_CHUNK} values per list; variants are the cartesian product of chunks across
 * constrained fields. `deferred` means a `#<multi-char>` tag term cannot use the tags index (only
 * single-letter tag names are indexed) and must be checked with `matchFilter` before `limit`.
 * Returns `undefined` when an empty list field makes the filter match nothing.
 */
function compileFilter(filter: Filter): { plans: FilterPlan[]; deferred: boolean } | undefined {
  const variants: FilterPlan[][] = [];
  const pushIn = (values: ReadonlyArray<SqlValue>, clause: (n: number) => string) => {
    variants.push(
      chunkValues(values).map((chunk) => ({
        wheres: [clause(chunk.length)],
        params: [...chunk],
      })),
    );
  };

  if (filter.ids) {
    if (filter.ids.length === 0) {
      return undefined;
    }
    pushIn(
      filter.ids.map((id) => id.toLowerCase()),
      (n) => inClause("id", n),
    );
  }
  if (filter.authors) {
    if (filter.authors.length === 0) {
      return undefined;
    }
    pushIn(
      filter.authors.map((pk) => pk.toLowerCase()),
      (n) => inClause("pubkey", n),
    );
  }
  if (filter.kinds) {
    if (filter.kinds.length === 0) {
      return undefined;
    }
    pushIn(filter.kinds, (n) => inClause("kind", n));
  }
  if (filter.since !== undefined) {
    variants.push([{ wheres: ["created_at >= ?"], params: [filter.since] }]);
  }
  if (filter.until !== undefined) {
    variants.push([{ wheres: ["created_at <= ?"], params: [filter.until] }]);
  }

  let deferred = false;
  for (const key of Object.keys(filter)) {
    if (!key.startsWith("#")) {
      continue;
    }
    const name = key.slice(1);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- startsWith("#") above guarantees the template key
    const values = filter[key as `#${string}`];
    if (!values) {
      continue;
    }
    if (name.length !== 1) {
      deferred = true;
      continue;
    }
    if (values.length === 0) {
      return undefined;
    }
    const normalized = name === "e" || name === "p" ? values.map((v) => v.toLowerCase()) : values;
    variants.push(
      chunkValues(normalized).map((chunk) => ({
        wheres: [
          `EXISTS (SELECT 1 FROM tags t WHERE t.event_id = events.id ` +
            `AND t.name = ? AND ${inClause("t.value", chunk.length)})`,
        ],
        params: [name, ...chunk],
      })),
    );
  }

  const plans: FilterPlan[] = [{ wheres: [], params: [] }];
  for (const field of variants) {
    const next: FilterPlan[] = [];
    for (const plan of plans) {
      for (const variant of field) {
        next.push({
          wheres: [...plan.wheres, ...variant.wheres],
          params: [...plan.params, ...variant.params],
        });
      }
    }
    plans.length = 0;
    plans.push(...next);
  }
  return { plans, deferred };
}

/**
 * SQLite-backed {@link EventStore} for React Native (`expo-sqlite`, `op-sqlite`) and desktop
 * runtimes. Same semantics as {@link MemoryEventStore} and {@link IndexedDbEventStore}: identical
 * `decidePut` insertion policy, NIP-09 tombstones, and filter handling, with the database — not
 * in-memory caches — as the source of truth.
 *
 * Construct via {@link SqliteEventStore.open}; writes are serialized and run inside an exclusive
 * driver transaction.
 */
export class SqliteEventStore implements EventStore {
  readonly #driver: SqlDriver;
  #writeTail: Promise<void> = Promise.resolve();

  private constructor(driver: SqlDriver) {
    this.#driver = driver;
  }

  /** Create the schema on first use and return a ready store. */
  static async open(driver: SqlDriver): Promise<SqliteEventStore> {
    const store = new SqliteEventStore(driver);
    await store.#migrate();
    return store;
  }

  async #migrate(): Promise<void> {
    try {
      await this.#driver.exec("PRAGMA foreign_keys = ON");
      const rows = await this.#driver.all<{ user_version: number }>("PRAGMA user_version");
      const version = rows[0]?.user_version ?? 0;
      if (version === 0) {
        await this.#driver.exec(SCHEMA_SQL);
        await this.#driver.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
      } else if (version !== SCHEMA_VERSION) {
        throw toStorageError(new Error(`unsupported sqlite event store schema version ${version}`));
      }
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async #enqueueWrite<T>(op: () => Promise<T>): Promise<T> {
    const tail = this.#writeTail;
    const result = (async (): Promise<T> => {
      await tail;
      return op();
    })();
    this.#writeTail = (async (): Promise<void> => {
      try {
        await result;
      } catch {
        // a failed write must not wedge later writes
      }
    })();
    return result;
  }

  async put(event: Event): Promise<PutResult> {
    const results = await this.putMany([event]);
    const result = results.at(0);
    if (result === undefined) {
      throw toStorageError(new Error("putMany returned no result"));
    }
    return result;
  }

  async putMany(events: ReadonlyArray<Event>): Promise<PutResult[]> {
    if (events.length === 0) {
      return [];
    }
    return this.#enqueueWrite(async () => {
      try {
        return await this.#driver.transaction(async (tx) => this.#putAllInTx(tx, events));
      } catch (error) {
        throw toStorageError(error);
      }
    });
  }

  async #putAllInTx(tx: SqlDriver, batch: ReadonlyArray<Event>): Promise<PutResult[]> {
    const results: PutResult[] = [];
    for (const event of batch) {
      const lookup = await this.#buildLookup(tx, event);
      const decision = decidePut(event, lookup);
      await this.#applyDecision(tx, decision);
      results.push(decision.result);
    }
    return results;
  }

  async #buildLookup(tx: SqlDriver, event: Event): Promise<PutLookup> {
    const byId = new Map<string, Event>();
    const idList = [event.id];
    if (event.kind === Kind.EventDeletion) {
      for (const tag of event.tags) {
        if (tag[0] === "e" && tag[1] !== undefined && tag[1] !== "") {
          idList.push(tag[1].toLowerCase());
        }
      }
    }
    for (const row of await this.#eventRowsByIds(tx, idList)) {
      byId.set(row.id, row);
    }

    const byAddress = new Map<string, { id: string; created_at: number }>();
    const addressList: string[] = [];
    const ownAddress = eventAddress(event);
    if (ownAddress !== undefined) {
      addressList.push(ownAddress);
    }
    if (event.kind === Kind.EventDeletion) {
      for (const tag of event.tags) {
        if (tag[0] !== "a" || tag[1] === undefined || tag[1] === "") {
          continue;
        }
        const coord = parseEventAddress(tag[1]);
        if (coord === undefined) {
          continue;
        }
        const key = formatEventAddress(coord.kind, coord.pubkey, coord.identifier);
        if (!addressList.includes(key)) {
          addressList.push(key);
        }
      }
    }
    const addressRows: Array<{ address: string; id: string; created_at: number }> = [];
    for (const chunk of chunkValues(addressList)) {
      addressRows.push(
        ...(await tx.all<{ address: string; id: string; created_at: number }>(
          `SELECT address, id, created_at FROM events
           WHERE ${inClause("address", chunk.length)}`,
          chunk,
        )),
      );
    }
    for (const row of addressRows.flat()) {
      byAddress.set(row.address, { id: row.id, created_at: row.created_at });
    }

    const deletion = new DeletionState();
    const tombstoneRows = await tx.all<TombstoneRow>(
      ownAddress === undefined
        ? `SELECT kind, key, pubkey, until FROM tombstones
           WHERE kind IN ('id', 'pending') AND key = ?`
        : `SELECT kind, key, pubkey, until FROM tombstones
           WHERE (kind IN ('id', 'pending') AND key = ?)
              OR (kind = 'coord' AND key = ?)`,
      ownAddress === undefined ? [event.id] : [event.id, ownAddress],
    );
    for (const row of tombstoneRows) {
      if (row.kind === "id") {
        deletion.ids.add(row.key);
      } else if (row.kind === "pending" && row.pubkey !== null) {
        deletion.pending.set(row.key, row.pubkey);
      } else if (row.kind === "coord" && row.until !== null) {
        deletion.coordinates.set(row.key, row.until);
      }
    }

    return {
      deletion,
      getById: (id) => byId.get(id),
      getReplaceable: (address) => byAddress.get(address),
    };
  }

  async #eventRowsByIds(tx: SqlDriver, ids: ReadonlyArray<string>): Promise<Event[]> {
    const events: Event[] = [];
    for (const chunk of chunkValues(ids)) {
      const rows = await tx.all<EventRow>(
        `SELECT id, pubkey, kind, created_at, content, tags, sig FROM events
         WHERE ${inClause("id", chunk.length)}`,
        chunk,
      );
      for (const row of rows) {
        events.push(rowToEvent(row));
      }
    }
    return events;
  }

  async #applyDecision(tx: SqlDriver, d: PutDecision): Promise<void> {
    switch (d.action) {
      case "skip":
        return;
      case "tombstone":
        await this.#putTombstone(tx, "id", d.event.id);
        await this.#deleteTombstone(tx, "pending", d.event.id);
        return;
      case "delete":
        await this.#persistPlan(tx, d.event.id, d.plan, d.coordIds);
        for (const id of [...d.plan.removeIds, ...d.coordIds]) {
          await this.#deleteEvent(tx, id);
        }
        await this.#insertEvent(tx, d.event);
        return;
      case "insert":
        if (d.replaceId !== undefined) {
          await this.#deleteEvent(tx, d.replaceId);
        }
        await this.#insertEvent(tx, d.event);
    }
  }

  /** Persist a deletion plan's tombstones, mirroring `DeletionState.absorb`. */
  async #persistPlan(
    tx: SqlDriver,
    deletionId: string,
    plan: DeletionPlan,
    coordIds: ReadonlyArray<string>,
  ): Promise<void> {
    await this.#deleteTombstone(tx, "pending", deletionId);
    for (const id of [...plan.removeIds, ...coordIds]) {
      await this.#putTombstone(tx, "id", id);
      await this.#deleteTombstone(tx, "pending", id);
    }
    for (const p of plan.pendingIds) {
      const covered = await tx.all<{ found: number }>(
        `SELECT 1 AS found FROM tombstones WHERE kind = 'id' AND key = ?`,
        [p.id],
      );
      if (covered.length === 0) {
        await tx.run(
          `INSERT OR REPLACE INTO tombstones (kind, key, pubkey) VALUES ('pending', ?, ?)`,
          [p.id, p.pubkey],
        );
      }
    }
    for (const c of plan.coordinates) {
      await tx.run(
        `INSERT INTO tombstones (kind, key, until) VALUES ('coord', ?, ?)
         ON CONFLICT(kind, key)
         DO UPDATE SET until = MAX(tombstones.until, excluded.until)`,
        [c.key, c.until],
      );
    }
  }

  async #putTombstone(tx: SqlDriver, kind: TombstoneKind, key: string): Promise<void> {
    await tx.run(`INSERT OR REPLACE INTO tombstones (kind, key) VALUES (?, ?)`, [kind, key]);
  }

  async #deleteTombstone(tx: SqlDriver, kind: TombstoneKind, key: string): Promise<void> {
    await tx.run(`DELETE FROM tombstones WHERE kind = ? AND key = ?`, [kind, key]);
  }

  async #insertEvent(tx: SqlDriver, event: Event): Promise<void> {
    await tx.run(
      `INSERT INTO events (id, pubkey, kind, created_at, content, tags, sig, address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        event.id,
        event.pubkey,
        event.kind,
        event.created_at,
        event.content,
        JSON.stringify(event.tags),
        event.sig,
        eventAddress(event) ?? null,
      ],
    );
    for (const tag of event.tags) {
      if (tag[0] === undefined || tag[1] === undefined || tag[0].length !== 1) {
        continue;
      }
      await tx.run(`INSERT INTO tags (event_id, name, value, created_at) VALUES (?, ?, ?, ?)`, [
        event.id,
        tag[0],
        tag[0] === "e" || tag[0] === "p" ? tag[1].toLowerCase() : tag[1],
        event.created_at,
      ]);
    }
  }

  async #deleteEvent(tx: SqlDriver, id: string): Promise<number> {
    const result = await tx.run(`DELETE FROM events WHERE id = ?`, [id]);
    return result.changes;
  }

  async get(id: string): Promise<Event | undefined> {
    try {
      const rows = await this.#driver.all<EventRow>(
        `SELECT id, pubkey, kind, created_at, content, tags, sig FROM events
         WHERE id = ?`,
        [id.toLowerCase()],
      );
      const row = rows.at(0);
      return row === undefined ? undefined : rowToEvent(row);
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async query(filters: Filter[]): Promise<Event[]> {
    try {
      const perFilter: Event[][] = [];
      for (const filter of filters) {
        perFilter.push(await this.#filterRows(filter, "*"));
      }
      const seen = new Set<string>();
      const events: Event[] = [];
      for (const rows of perFilter) {
        for (const event of rows) {
          if (seen.has(event.id)) {
            continue;
          }
          seen.add(event.id);
          events.push(event);
        }
      }
      return sortEvents(events);
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async count(filters: Filter[]): Promise<number> {
    try {
      const perFilter: NegentropyItem[][] = [];
      for (const filter of filters) {
        perFilter.push(await this.#filterRows(filter, "id, created_at"));
      }
      const seen = new Set<string>();
      for (const rows of perFilter) {
        for (const row of rows) {
          seen.add(row.id);
        }
      }
      return seen.size;
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async negentropyItems(filter: Filter): Promise<NegentropyItem[]> {
    try {
      const items = await this.#filterRows(filter, "id, created_at");
      return [...items].sort(itemCompare);
    } catch (error) {
      throw toStorageError(error);
    }
  }

  /**
   * Rows matching one filter, deduped, newest-first, with `limit` applied. `select` is a trusted
   * column list for the projection. A filter with a non-indexed (multi-char) `#` tag term falls
   * back to a `matchFilter` pass and cannot push `limit` down.
   */
  async #filterRows(filter: Filter, select: "*"): Promise<Event[]>;
  async #filterRows(filter: Filter, select: "id, created_at"): Promise<NegentropyItem[]>;
  async #filterRows(
    filter: Filter,
    select: "*" | "id, created_at",
  ): Promise<Event[] | NegentropyItem[]> {
    if (filter.limit === 0) {
      return [];
    }
    const compiled = compileFilter(filter);
    if (compiled === undefined) {
      return [];
    }
    const { plans, deferred } = compiled;

    if (deferred) {
      // A multi-char #tag term bypasses the tags index — matchFilter decides and
      // `limit` cannot be pushed down.
      const merged = await this.#planRows<EventRow>(plans, "*", undefined);
      const matched = merged.map(rowToEvent).filter((event) => matchFilter(filter, event));
      const limited = filter.limit === undefined ? matched : matched.slice(0, filter.limit);
      return select === "*"
        ? limited
        : limited.map((e) => ({ id: e.id, created_at: e.created_at }));
    }

    if (select === "*") {
      const merged = await this.#planRows<EventRow>(plans, "*", filter.limit);
      return merged.map(rowToEvent);
    }
    return this.#planRows<NegentropyItem>(plans, "id, created_at", filter.limit);
  }

  /** Rows for the compiled plans of one filter, deduped newest-first, `limit` applied. */
  async #planRows<Row extends { id: string; created_at: number }>(
    plans: ReadonlyArray<FilterPlan>,
    select: string,
    limit: number | undefined,
  ): Promise<Row[]> {
    const tail = ` ORDER BY created_at DESC, id ASC${limit === undefined ? "" : " LIMIT ?"}`;
    const perPlan: Row[][] = [];
    for (const plan of plans) {
      const where = plan.wheres.length > 0 ? ` WHERE ${plan.wheres.join(" AND ")}` : "";
      const params = limit === undefined ? plan.params : [...plan.params, limit];
      perPlan.push(
        await this.#driver.all<Row>(`SELECT ${select} FROM events${where}${tail}`, params),
      );
    }
    const sorted = perPlan.flat().sort(compareEventsDesc);
    const seen = new Set<string>();
    const merged: Row[] = [];
    for (const row of sorted) {
      if (seen.has(row.id)) {
        continue;
      }
      seen.add(row.id);
      merged.push(row);
    }
    return limit === undefined ? merged : merged.slice(0, limit);
  }

  async getOutboxBound(pubkey: string, kind: number): Promise<OutboxBound | undefined> {
    const pk = pubkey.toLowerCase();
    try {
      const rows = await this.#driver.all<{ oldest: number; newest: number }>(
        `SELECT oldest, newest FROM outbox_bounds
         WHERE pubkey = ? AND kind = ?`,
        [pk, kind],
      );
      const row = rows.at(0);
      if (row !== undefined) {
        return { oldest: row.oldest, newest: row.newest };
      }
      const derived = await this.#driver.all<{
        // oxlint-disable-next-line typescript/no-restricted-types -- MIN() of an empty set is SQL NULL
        oldest: number | null;
        // oxlint-disable-next-line typescript/no-restricted-types -- MAX() of an empty set is SQL NULL
        newest: number | null;
      }>(
        `SELECT MIN(created_at) AS oldest, MAX(created_at) AS newest
         FROM events WHERE pubkey = ? AND kind = ?`,
        [pk, kind],
      );
      const d = derived.at(0);
      if (d === undefined || d.oldest === null || d.newest === null) {
        return undefined;
      }
      return { oldest: d.oldest, newest: d.newest };
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async setOutboxBound(pubkey: string, kind: number, bound: OutboxBound): Promise<void> {
    const pk = pubkey.toLowerCase();
    await this.#enqueueWrite(async () => {
      try {
        await this.#driver.transaction(async (tx) => {
          await tx.run(
            `INSERT OR REPLACE INTO outbox_bounds (pubkey, kind, oldest, newest)
             VALUES (?, ?, ?, ?)`,
            [pk, kind, bound.oldest, bound.newest],
          );
        });
      } catch (error) {
        throw toStorageError(error);
      }
    });
  }

  async remove(ids: string[]): Promise<number> {
    const lowered = ids.map((id) => id.toLowerCase());
    return this.#enqueueWrite(async () => {
      try {
        return await this.#driver.transaction(async (tx) => {
          let removed = 0;
          for (const id of lowered) {
            removed += await this.#deleteEvent(tx, id);
            await this.#putTombstone(tx, "id", id);
            await this.#deleteTombstone(tx, "pending", id);
          }
          return removed;
        });
      } catch (error) {
        throw toStorageError(error);
      }
    });
  }

  async clear(): Promise<void> {
    await this.#enqueueWrite(async () => {
      try {
        await this.#driver.transaction(async (tx) => {
          await tx.run("DELETE FROM tags");
          await tx.run("DELETE FROM events");
          await tx.run("DELETE FROM tombstones");
          await tx.run("DELETE FROM outbox_bounds");
        });
      } catch (error) {
        throw toStorageError(error);
      }
    });
  }
}
