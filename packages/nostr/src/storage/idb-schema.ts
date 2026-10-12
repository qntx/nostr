// oxlint-disable unicorn/prefer-add-event-listener -- the *Like driver interfaces model only the `on*` handler surface
import { StorageError } from "./error.ts";
import { ADDRESSES, EVENTS, OUTBOX_BOUNDS, TAG_REFS, TOMBSTONES } from "./idb-types.ts";
import type { IDBDatabaseLike, IDBFactoryLike } from "./idb-types.ts";

export const IDB_VERSION = 5;

const ALL_STORES = [EVENTS, TAG_REFS, ADDRESSES, TOMBSTONES, OUTBOX_BOUNDS];

function createSchema(db: IDBDatabaseLike): void {
  const events = db.createObjectStore(EVENTS, { keyPath: "id" });
  events.createIndex("created_at", "created_at");
  events.createIndex("kind_created_at", ["kind", "created_at"]);
  events.createIndex("pubkey_created_at", ["pubkey", "created_at"]);
  events.createIndex("kind_pubkey_created_at", ["kind", "pubkey", "created_at"]);
  db.createObjectStore(TAG_REFS, { keyPath: "key" }).createIndex("name_value_created", [
    "name",
    "value",
    "created_at",
  ]);
  db.createObjectStore(ADDRESSES, { keyPath: "address" });
  db.createObjectStore(TOMBSTONES, { keyPath: "key" });
  db.createObjectStore(OUTBOX_BOUNDS, { keyPath: "key" });
}

export async function openDb(dbName: string): Promise<IDBDatabaseLike> {
  return new Promise((resolve, reject) => {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- reads the platform global, which has no ambient types here
    const factory = (globalThis as unknown as { indexedDB: IDBFactoryLike }).indexedDB;
    const req = factory.open(dbName, IDB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      if (ev.oldVersion !== 0) {
        // The stores are caches of relay data: a non-current schema is dropped
        // and recreated rather than migrated.
        for (const name of ALL_STORES) {
          if (db.objectStoreNames.contains(name)) {
            db.deleteObjectStore(name);
          }
        }
      }
      createSchema(db);
    };
    let settled = false;
    req.onsuccess = () => {
      const db = req.result;
      if (settled) {
        // The blocked rejection already fired; do not leak this late connection.
        db.close();
        return;
      }
      settled = true;
      // Yield to any newer-version open instead of blocking it forever.
      db.onversionchange = () => db.close();
      resolve(db);
    };
    req.onerror = () => {
      settled = true;
      reject(req.error ?? new StorageError("IndexedDB open failed"));
    };
    req.onblocked = () => {
      settled = true;
      reject(new StorageError("IndexedDB open blocked by another connection"));
    };
  });
}
