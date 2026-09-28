/**
 * Minimal in-memory IndexedDB factory for unit tests (no browser). Installs on
 * `globalThis.indexedDB` / `IDBKeyRange` and returns an uninstall handle.
 */

// oxlint-disable-next-line typescript/no-restricted-types -- mirrors IndexedDB, where request.error and handlers are null
type Nullable<T> = T | null;

export type IdbMock = {
  uninstall: () => void;
  eventsGetAllCount: () => number;
  cursorVisitCount: () => number;
  readwriteTransactions: () => string[][];
  resetStats: () => void;
  /** Fail the next Nth `get` after this call (1-based). Restores tx snapshot on abort. */
  failGetOnCall: (n: number, error?: Nullable<Error>) => void;
  /** Fail the next `indexedDB.open` with this `req.error` (null exercises the fallback). */
  failOpen: (error: Nullable<Error>) => void;
  /** Fail the next `openCursor` with this `req.error` (null exercises the fallback). */
  failCursor: (error: Nullable<Error>) => void;
  /** Fail the next transaction complete with onabort/onerror (null exercises the fallback). */
  failNextTxComplete: (kind: "abort" | "error", error: Nullable<Error>) => void;
  /** Park the Nth `get` (1-based, after this call) until `release()`. */
  gateGetOnCall: (n: number) => { release: () => void };
};

type Row = Record<string, unknown>;
type StoreData = {
  keyPath: string;
  rows: Map<string, Row>;
  indexes: Map<string, string | string[]>;
};
type PersistedDb = {
  version: number;
  stores: Map<string, StoreData>;
};

export function installIdbMock(): IdbMock {
  const dbs = new Map<string, PersistedDb>();
  const openConns = new Map<string, Set<MockDb>>();
  const pendingOpens = new Map<string, Array<() => void>>();
  const stats = {
    eventsGetAll: 0,
    cursorVisits: 0,
    readwrite: [] as string[][],
    getCalls: 0,
    failGetOn: undefined as number | undefined,
    failGetError: undefined as Nullable<Error> | undefined,
    failOpenError: undefined as Nullable<Error> | undefined,
    failCursorError: undefined as Nullable<Error> | undefined,
    failTx: undefined as { kind: "abort" | "error"; error: Nullable<Error> } | undefined,
    gateOn: undefined as number | undefined,
    getGate: undefined as Promise<void> | undefined,
  };

  class MockKeyRange {
    readonly lower: unknown;
    readonly upper: unknown;
    readonly lowerOpen: boolean;
    readonly upperOpen: boolean;

    constructor(lower: unknown, upper: unknown, lowerOpen = false, upperOpen = false) {
      this.lower = lower;
      this.upper = upper;
      this.lowerOpen = lowerOpen;
      this.upperOpen = upperOpen;
    }
    static bound(
      lower: unknown,
      upper: unknown,
      lowerOpen = false,
      upperOpen = false,
    ): MockKeyRange {
      if (cmp(lower, upper) > 0) {
        throw new Error("DataError: lower bound is greater than upper bound");
      }
      return new MockKeyRange(lower, upper, lowerOpen, upperOpen);
    }
  }

  class MockRequest<T = unknown> {
    result!: T;
    error: Nullable<Error> = null;
    onsuccess: Nullable<(ev: unknown) => void> = null;
    onerror: Nullable<(ev: unknown) => void> = null;
    onupgradeneeded: Nullable<(ev: unknown) => void> = null;
    onblocked: Nullable<(ev: unknown) => void> = null;
    complete(value: T) {
      this.result = value;
      queueMicrotask(() => this.onsuccess?.({}));
    }
  }

  class MockTx {
    oncomplete: Nullable<(ev: unknown) => void> = null;
    onerror: Nullable<(ev: unknown) => void> = null;
    onabort: Nullable<(ev: unknown) => void> = null;
    error: Nullable<Error> = null;
    #pending = 0;
    #held = false;
    #completed = false;
    #scheduled = false;
    #aborted = false;
    readonly #backup = new Map<string, Map<string, Row>>();
    private readonly db: MockDb;
    private readonly names: string[] | "all";

    constructor(db: MockDb, names: string[] | "all") {
      this.db = db;
      this.names = names;
      const list = names === "all" ? db.storeNames() : names;
      for (const name of list) {
        const data = db.getStore(name);
        if (!data) {
          continue;
        }
        const copy = new Map<string, Row>();
        for (const [k, v] of data.rows) {
          copy.set(k, structuredClone(v));
        }
        this.#backup.set(name, copy);
      }
      this.#queue();
    }

    hold() {
      this.#held = true;
    }

    release() {
      this.#held = false;
      this.#queue();
    }

    get completed() {
      return this.#completed;
    }

    get aborted() {
      return this.#aborted;
    }

    abort() {
      if (this.#aborted) {
        return;
      }
      if (this.#completed) {
        throw new Error("InvalidStateError: transaction already finished");
      }
      this.#aborted = true;
      for (const [name, rows] of this.#backup) {
        const data = this.db.getStore(name);
        if (!data) {
          continue;
        }
        data.rows.clear();
        for (const [k, v] of rows) {
          data.rows.set(k, structuredClone(v));
        }
      }
      this.error = new Error("transaction aborted");
      this.#completed = true;
      this.onabort?.({});
    }

    begin() {
      this.#pending++;
    }

    end() {
      this.#pending--;
      this.#queue();
    }

    #queue() {
      if (this.#scheduled) {
        return;
      }
      this.#scheduled = true;
      // Real IDB commits at a task boundary; a microtask tick would complete
      // the tx before microtask-chained follow-up requests are issued.
      setTimeout(() => {
        this.#scheduled = false;
        if (this.#completed || this.#held || this.#pending > 0) {
          return;
        }
        if (stats.failTx) {
          const fail = stats.failTx;
          stats.failTx = undefined;
          for (const [name, rows] of this.#backup) {
            const data = this.db.getStore(name);
            if (!data) {
              continue;
            }
            data.rows.clear();
            for (const [k, v] of rows) {
              data.rows.set(k, structuredClone(v));
            }
          }
          this.error = fail.error;
          this.#completed = true;
          if (fail.kind === "abort") {
            this.#aborted = true;
            this.onabort?.({});
          } else {
            this.onerror?.({});
          }
          return;
        }
        this.#completed = true;
        this.oncomplete?.({});
      });
    }

    objectStore(name: string) {
      if (this.names !== "all" && !this.names.includes(name)) {
        throw new Error(`store ${name} not in transaction`);
      }
      const data = this.db.getStore(name);
      if (!data) {
        throw new Error(`store ${name} not found`);
      }
      return new MockStore(data, this, name);
    }
  }

  class MockIndex {
    private readonly data: StoreData;
    private readonly keyPath: string | string[];
    private readonly tx: MockTx;

    constructor(data: StoreData, keyPath: string | string[], tx: MockTx) {
      this.data = data;
      this.keyPath = keyPath;
      this.tx = tx;
    }

    openCursor(range?: MockKeyRange, direction: "next" | "prev" = "next") {
      return openCursor(
        this.data,
        (row) => getKeyPath(row, this.keyPath),
        range,
        direction,
        this.tx,
        stats,
      );
    }

    openKeyCursor(range?: MockKeyRange, direction: "next" | "prev" = "next") {
      return this.openCursor(range, direction);
    }
  }

  class MockStore {
    private readonly data: StoreData;
    private readonly tx: MockTx;
    private readonly name: string;

    constructor(data: StoreData, tx: MockTx, name: string) {
      this.data = data;
      this.tx = tx;
      this.name = name;
    }

    createIndex(name: string, keyPath: string | string[]) {
      this.data.indexes.set(name, keyPath);
      return this.index(name);
    }

    index(name: string) {
      const keyPath = this.data.indexes.get(name);
      if (keyPath === undefined) {
        throw new Error(`index ${name} not found`);
      }
      return new MockIndex(this.data, keyPath, this.tx);
    }

    put(value: unknown) {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- test rows are caller-shaped
      const row = structuredClone(value) as Row;
      const key = row[this.data.keyPath];
      if (typeof key !== "string") {
        throw new TypeError("IndexedDB put missing keyPath value");
      }
      this.data.rows.set(key, row);
    }

    get(id: string) {
      const req = new MockRequest<Row | undefined>();
      this.tx.begin();
      stats.getCalls += 1;
      const fail = stats.failGetOn !== undefined && stats.getCalls === stats.failGetOn;
      const gate = stats.gateOn === stats.getCalls ? stats.getGate : undefined;
      const finish = () => {
        if (this.tx.aborted || this.tx.completed) {
          this.tx.end();
          return;
        }
        if (fail) {
          req.error =
            stats.failGetError === undefined
              ? new Error("IndexedDB request failed")
              : stats.failGetError;
          req.onerror?.({});
          this.tx.abort();
          this.tx.end();
          return;
        }
        const row = this.data.rows.get(id);
        req.result = row ? structuredClone(row) : undefined;
        req.onsuccess?.({});
        this.tx.end();
      };
      if (gate === undefined) {
        queueMicrotask(finish);
      } else {
        // oxlint-disable-next-line promise/prefer-await-to-then -- fires a release callback inside a synchronous scheduler
        void gate.then(() => queueMicrotask(finish));
      }
      return req;
    }

    delete(id: string) {
      this.data.rows.delete(id);
    }

    clear() {
      this.data.rows.clear();
    }

    getAll() {
      if (this.name === "events") {
        stats.eventsGetAll += 1;
      }
      const req = new MockRequest<Row[]>();
      this.tx.begin();
      queueMicrotask(() => {
        req.result = [...this.data.rows.values()].map((r) => structuredClone(r));
        req.onsuccess?.({});
        this.tx.end();
      });
      return req;
    }

    openCursor(range?: MockKeyRange, direction: "next" | "prev" = "next") {
      return openCursor(
        this.data,
        (row) => row[this.data.keyPath],
        range,
        direction,
        this.tx,
        stats,
      );
    }
  }

  class MockDb {
    objectStoreNames = {
      contains: (name: string) => this.rec.stores.has(name),
    };
    onversionchange: Nullable<(ev: unknown) => void> = null;

    private readonly rec: PersistedDb;
    private readonly dbName: string;
    #closed = false;

    constructor(rec: PersistedDb, dbName: string) {
      this.rec = rec;
      this.dbName = dbName;
    }

    get closed() {
      return this.#closed;
    }

    getStore(name: string) {
      return this.rec.stores.get(name);
    }

    storeNames() {
      return [...this.rec.stores.keys()];
    }

    createObjectStore(name: string, options?: { keyPath?: string }) {
      if (this.rec.stores.has(name)) {
        throw new Error(`store ${name} already exists`);
      }
      const data: StoreData = {
        keyPath: options?.keyPath ?? "id",
        rows: new Map(),
        indexes: new Map(),
      };
      this.rec.stores.set(name, data);
      return new MockStore(data, new MockTx(this, "all"), name);
    }

    transaction(storeNames: string | string[], mode: "readonly" | "readwrite" = "readonly") {
      if (this.#closed) {
        throw new Error("InvalidStateError: connection is closed");
      }
      const names = Array.isArray(storeNames) ? storeNames : [storeNames];
      if (mode === "readwrite") {
        stats.readwrite.push([...names]);
      }
      return new MockTx(this, names);
    }

    close() {
      if (this.#closed) {
        return;
      }
      this.#closed = true;
      openConns.get(this.dbName)?.delete(this);
      const pending = pendingOpens.get(this.dbName);
      if (pending !== undefined && pending.length > 0) {
        pendingOpens.delete(this.dbName);
        for (const attempt of pending) {
          attempt();
        }
      }
    }
  }

  const indexedDB = {
    open(name: string, version = 1) {
      const req = new MockRequest<MockDb>();
      if (stats.failOpenError !== undefined) {
        const err = stats.failOpenError;
        stats.failOpenError = undefined;
        queueMicrotask(() => {
          req.error = err;
          req.onerror?.({});
        });
        return req;
      }
      let rec = dbs.get(name);
      if (!rec) {
        rec = { version: 0, stores: new Map() };
        dbs.set(name, rec);
      }
      const persisted = rec;
      const db = new MockDb(persisted, name);
      req.result = db;
      const registerConn = () => {
        let conns = openConns.get(name);
        if (conns === undefined) {
          conns = new Set();
          openConns.set(name, conns);
        }
        conns.add(db);
      };
      const finish = () => {
        const oldVersion = persisted.version;
        if (oldVersion < version) {
          const tx = new MockTx(db, "all");
          tx.hold();
          req.onupgradeneeded?.({
            oldVersion,
            newVersion: version,
            target: { result: db, transaction: tx },
          });
          persisted.version = version;
          const done = () => {
            registerConn();
            req.complete(db);
          };
          if (tx.completed) {
            done();
          } else {
            const prev = tx.oncomplete;
            tx.oncomplete = (e) => {
              prev?.(e);
              done();
            };
            tx.release();
          }
        } else {
          registerConn();
          req.complete(db);
        }
      };
      const attempt = () => {
        queueMicrotask(() => {
          const conns = openConns.get(name);
          if (conns !== undefined && conns.size > 0) {
            let pending = pendingOpens.get(name);
            if (pending === undefined) {
              pending = [];
              pendingOpens.set(name, pending);
            }
            pending.push(attempt);
            return;
          }
          finish();
        });
      };
      queueMicrotask(() => {
        const blockers = openConns.get(name);
        if (version > persisted.version && blockers !== undefined && blockers.size > 0) {
          for (const conn of blockers) {
            conn.onversionchange?.({
              oldVersion: persisted.version,
              newVersion: version,
            });
          }
          const remaining = openConns.get(name);
          if (remaining !== undefined && remaining.size > 0) {
            req.onblocked?.({});
            let pending = pendingOpens.get(name);
            if (pending === undefined) {
              pending = [];
              pendingOpens.set(name, pending);
            }
            pending.push(attempt);
            return;
          }
        }
        finish();
      });
      return req;
    },
  };

  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- installs the mock over the host global
  (globalThis as { indexedDB?: unknown }).indexedDB = indexedDB;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- installs the mock over the host global
  (globalThis as { IDBKeyRange?: unknown }).IDBKeyRange = MockKeyRange;

  return {
    uninstall() {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- uninstalls the mock from the host global
      delete (globalThis as { indexedDB?: unknown }).indexedDB;
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- uninstalls the mock from the host global
      delete (globalThis as { IDBKeyRange?: unknown }).IDBKeyRange;
      dbs.clear();
      openConns.clear();
      pendingOpens.clear();
    },
    eventsGetAllCount: () => stats.eventsGetAll,
    cursorVisitCount: () => stats.cursorVisits,
    readwriteTransactions: () => stats.readwrite,
    resetStats() {
      stats.eventsGetAll = 0;
      stats.cursorVisits = 0;
      stats.readwrite = [];
      stats.getCalls = 0;
      stats.failGetOn = undefined;
      stats.failGetError = undefined;
      stats.failOpenError = undefined;
      stats.failCursorError = undefined;
      stats.failTx = undefined;
      stats.gateOn = undefined;
      stats.getGate = undefined;
    },
    failGetOnCall(n: number, error?: Nullable<Error>) {
      stats.getCalls = 0;
      stats.failGetOn = n;
      stats.failGetError = error === undefined ? new Error("IndexedDB request failed") : error;
    },
    failOpen(error: Nullable<Error>) {
      stats.failOpenError = error;
    },
    failCursor(error: Nullable<Error>) {
      stats.failCursorError = error;
    },
    failNextTxComplete(kind: "abort" | "error", error: Nullable<Error>) {
      stats.failTx = { kind, error };
    },
    gateGetOnCall(n: number) {
      stats.getCalls = 0;
      let releaseGate!: () => void;
      stats.getGate = new Promise<void>((resolve) => {
        releaseGate = resolve;
      });
      stats.gateOn = n;
      return {
        release() {
          stats.gateOn = undefined;
          stats.getGate = undefined;
          releaseGate();
        },
      };
    },
  };
}

export async function seedIdbV1(
  dbName: string,
  events: Array<Record<string, unknown>>,
): Promise<void> {
  const host =
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the installed mock IS this shape
    globalThis as unknown as {
      indexedDB: { open: (name: string, version?: number) => MockOpenReq };
    };
  const factory = host.indexedDB;
  return new Promise((resolve, reject) => {
    const req = factory.open(dbName, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("events")) {
        db.createObjectStore("events", { keyPath: "id" });
      }
    };
    // oxlint-disable-next-line unicorn/prefer-add-event-listener -- the mock request mirrors IDB on* handlers
    req.onerror = () => reject(req.error ?? new Error("seed v1 open failed"));
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("events", "readwrite");
      const store = tx.objectStore("events");
      for (const event of events) {
        store.put(event);
      }
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      // oxlint-disable-next-line unicorn/prefer-add-event-listener -- the mock request mirrors IDB on* handlers
      tx.onerror = () => reject(tx.error ?? new Error("seed v1 put failed"));
    };
  });
}

export async function seedIdbV2(
  dbName: string,
  data: {
    events: Array<Record<string, unknown>>;
    addresses: Array<Record<string, unknown>>;
    tagRefs: Array<Record<string, unknown>>;
  },
): Promise<void> {
  const host =
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the installed mock IS this shape
    globalThis as unknown as {
      indexedDB: { open: (name: string, version?: number) => MockOpenReq };
    };
  const factory = host.indexedDB;
  return new Promise((resolve, reject) => {
    const req = factory.open(dbName, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      const events = db.createObjectStore("events", { keyPath: "id" });
      events.createIndex("created_at", "created_at");
      events.createIndex("kind_created_at", ["kind", "created_at"]);
      events.createIndex("pubkey_created_at", ["pubkey", "created_at"]);
      events.createIndex("kind_pubkey_created_at", ["kind", "pubkey", "created_at"]);
      db.createObjectStore("tag_refs", { keyPath: "key" }).createIndex("name_value_created", [
        "name",
        "value",
        "created_at",
      ]);
      db.createObjectStore("addresses", { keyPath: "address" });
      db.createObjectStore("tombstones", { keyPath: "key" });
    };
    // oxlint-disable-next-line unicorn/prefer-add-event-listener -- the mock request mirrors IDB on* handlers
    req.onerror = () => reject(req.error ?? new Error("seed v2 open failed"));
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction(["events", "addresses", "tag_refs"], "readwrite");
      const eventsStore = tx.objectStore("events");
      for (const event of data.events) {
        eventsStore.put(event);
      }
      const addressesStore = tx.objectStore("addresses");
      for (const row of data.addresses) {
        addressesStore.put(row);
      }
      const tagStore = tx.objectStore("tag_refs");
      for (const row of data.tagRefs) {
        tagStore.put(row);
      }
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      // oxlint-disable-next-line unicorn/prefer-add-event-listener -- the mock request mirrors IDB on* handlers
      tx.onerror = () => reject(tx.error ?? new Error("seed v2 put failed"));
    };
  });
}

export async function seedIdbV3(dbName: string): Promise<void> {
  const host =
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the installed mock IS this shape
    globalThis as unknown as {
      indexedDB: { open: (name: string, version?: number) => MockOpenReq };
    };
  const factory = host.indexedDB;
  return new Promise((resolve, reject) => {
    const req = factory.open(dbName, 3);
    req.onupgradeneeded = () => {
      const db = req.result;
      const events = db.createObjectStore("events", { keyPath: "id" });
      events.createIndex("created_at", "created_at");
      events.createIndex("kind_created_at", ["kind", "created_at"]);
      events.createIndex("pubkey_created_at", ["pubkey", "created_at"]);
      events.createIndex("kind_pubkey_created_at", ["kind", "pubkey", "created_at"]);
      db.createObjectStore("tag_refs", { keyPath: "key" }).createIndex("name_value_created", [
        "name",
        "value",
        "created_at",
      ]);
      db.createObjectStore("addresses", { keyPath: "address" });
      db.createObjectStore("tombstones", { keyPath: "key" });
    };
    // oxlint-disable-next-line unicorn/prefer-add-event-listener -- the mock request mirrors IDB on* handlers
    req.onerror = () => reject(req.error ?? new Error("seed v3 open failed"));
    req.onsuccess = () => {
      req.result.close();
      resolve();
    };
  });
}

type MockOpenReq = {
  result: {
    objectStoreNames: { contains: (name: string) => boolean };
    createObjectStore: (
      name: string,
      options?: { keyPath?: string },
    ) => { createIndex: (name: string, keyPath: string | string[]) => unknown };
    transaction: (
      storeNames: string | string[],
      mode?: "readonly" | "readwrite",
    ) => {
      objectStore: (name: string) => { put: (value: unknown) => unknown };
      oncomplete: ((ev: unknown) => void) | undefined;
      onerror: ((ev: unknown) => void) | undefined;
      error: Error | undefined;
    };
    close: () => void;
  };
  error: Error;
  onupgradeneeded: (ev: unknown) => void;
  onsuccess: (ev: unknown) => void;
  onerror: (ev: unknown) => void;
};

function getKeyPath(row: Row, keyPath: string | string[]): unknown {
  if (typeof keyPath === "string") {
    return row[keyPath];
  }
  return keyPath.map((k) => row[k]);
}

function keyRangeIncludes(
  range: { lower: unknown; upper: unknown; lowerOpen: boolean; upperOpen: boolean },
  key: unknown,
): boolean {
  const lo = cmp(key, range.lower);
  const hi = cmp(key, range.upper);
  if (range.lowerOpen ? lo <= 0 : lo < 0) {
    return false;
  }
  if (range.upperOpen ? hi >= 0 : hi > 0) {
    return false;
  }
  return true;
}

function openCursor(
  data: StoreData,
  keyOf: (row: Row) => unknown,
  range: { lower: unknown; upper: unknown; lowerOpen: boolean; upperOpen: boolean } | undefined,
  direction: "next" | "prev",
  tx: { begin: () => void; end: () => void; readonly completed: boolean },
  stats: { cursorVisits: number; failCursorError: Nullable<Error> | undefined },
) {
  const req = {
    result: undefined as
      | { key: unknown; primaryKey: unknown; value: Row; continue: () => void }
      | undefined,
    error: null as Nullable<Error>,
    onsuccess: null as Nullable<(ev: unknown) => void>,
    onerror: null as Nullable<(ev: unknown) => void>,
  };
  if (stats.failCursorError !== undefined) {
    req.error = stats.failCursorError;
    stats.failCursorError = undefined;
    tx.begin();
    queueMicrotask(() => {
      req.onerror?.({});
      tx.end();
    });
    return req;
  }
  const entries: Array<{ key: unknown; primaryKey: unknown; value: Row }> = [];
  for (const row of data.rows.values()) {
    const key = keyOf(row);
    if (key === undefined) {
      continue;
    }
    if (range && !keyRangeIncludes(range, key)) {
      continue;
    }
    entries.push({ key, primaryKey: row[data.keyPath], value: row });
  }
  entries.sort((a, b) => {
    const c = cmp(a.key, b.key);
    if (c !== 0) {
      return c;
    }
    return cmp(a.primaryKey, b.primaryKey);
  });
  if (direction === "prev") {
    entries.reverse();
  }

  let pos = 0;
  const emit = () => {
    if (pos >= entries.length) {
      req.result = undefined;
      req.onsuccess?.({});
      tx.end();
      return;
    }
    stats.cursorVisits += 1;
    const entry = entries[pos];
    if (entry === undefined) {
      return;
    }
    req.result = {
      key: entry.key,
      primaryKey: entry.primaryKey,
      value: structuredClone(entry.value),
      continue() {
        if (tx.completed) {
          throw new Error("InvalidStateError: The transaction has finished.");
        }
        pos += 1;
        tx.begin();
        queueMicrotask(emit);
      },
    };
    req.onsuccess?.({});
    tx.end();
  };
  tx.begin();
  queueMicrotask(emit);
  return req;
}

function cmp(a: unknown, b: unknown): number {
  if (a === b) {
    return 0;
  }
  const ra = typeRank(a);
  const rb = typeRank(b);
  if (ra !== rb) {
    return ra - rb;
  }
  if (typeof a === "number" && typeof b === "number") {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (typeof a === "string" && typeof b === "string") {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
      const c = cmp(a[i], b[i]);
      if (c !== 0) {
        return c;
      }
    }
    return a.length - b.length;
  }
  return 0;
}

function typeRank(value: unknown): number {
  if (typeof value === "number") {
    return 1;
  }
  if (typeof value === "string") {
    return 2;
  }
  if (Array.isArray(value)) {
    return 3;
  }
  return 0;
}
