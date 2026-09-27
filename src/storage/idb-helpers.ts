// oxlint-disable unicorn/prefer-add-event-listener -- the *Like driver interfaces model only the `on*` handler surface
import type { Event } from "../core/event.ts";
import { isRecord } from "../core/util.ts";
import type { DeletionPlan, DeletionState } from "./deletion.ts";
import { StorageError } from "./error.ts";
import { ADDRESSES, EVENTS, TAG_REFS, TOMBSTONES } from "./idb-types.ts";
import type {
  AddressRow,
  IDBCursorDirectionLike,
  IDBCursorLike,
  IDBKeyRangeLike,
  IDBObjectStoreLike,
  IDBRequestLike,
  IDBTransactionLike,
  TagRef,
  Tombstone,
} from "./idb-types.ts";
import type { PutDecision } from "./put.ts";
import type { PutResult } from "./types.ts";

export async function reqOf<T>(req: IDBRequestLike): Promise<T> {
  return new Promise((resolve, reject) => {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- request results are trusted as T at each call site
    req.onsuccess = () => resolve(req.result as T);
    req.onerror = () => reject(req.error ?? new StorageError("IndexedDB request failed"));
  });
}

export async function txDone(tx: IDBTransactionLike): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new StorageError("IndexedDB transaction failed"));
  });
}

export async function walkCursor(
  source: {
    openCursor: (range?: IDBKeyRangeLike, direction?: IDBCursorDirectionLike) => IDBRequestLike;
  },
  range: IDBKeyRangeLike | undefined,
  direction: IDBCursorDirectionLike,
  visit: (cursor: IDBCursorLike) => boolean,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = source.openCursor(range, direction);
    req.onerror = () => reject(req.error ?? new StorageError("IndexedDB cursor failed"));
    req.onsuccess = () => {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- openCursor resolves with a cursor or null
      const cursor = (req.result ?? undefined) as IDBCursorLike | undefined;
      if (cursor === undefined) {
        resolve();
        return;
      }
      if (visit(cursor)) {
        resolve();
        return;
      }
      cursor.continue();
    };
  });
}

export function tagRefKey(name: string, value: string, id: string): string {
  return `${name}:${value.toLowerCase()}:${id}`;
}

export function writeTagRefs(store: IDBObjectStoreLike, event: Event): void {
  for (const tag of event.tags) {
    if ((tag[0] !== "e" && tag[0] !== "p") || tag[1] === undefined) {
      continue;
    }
    const value = tag[1].toLowerCase();
    const { id } = event;
    store.put({
      key: tagRefKey(tag[0], value, id),
      name: tag[0],
      value,
      id,
      created_at: event.created_at,
    } satisfies TagRef);
  }
}

export function deleteStoredEvent(
  tx: IDBTransactionLike,
  event: Event,
  addressRow?: AddressRow,
): void {
  const tagRefs = tx.objectStore(TAG_REFS);
  for (const tag of event.tags) {
    if ((tag[0] === "e" || tag[0] === "p") && tag[1] !== undefined) {
      tagRefs.delete(tagRefKey(tag[0], tag[1], event.id));
    }
  }
  if (addressRow?.id === event.id) {
    tx.objectStore(ADDRESSES).delete(addressRow.address);
  }
  tx.objectStore(EVENTS).delete(event.id);
}

export function persistPlanTombstones(
  store: IDBObjectStoreLike,
  plan: DeletionPlan,
  coordIds: ReadonlyArray<string>,
  deletion: DeletionState,
): void {
  for (const id of plan.removeIds) {
    store.put({ key: `id:${id}`, type: "id" } satisfies Tombstone);
    store.delete(`pending:${id}`);
  }
  for (const id of coordIds) {
    store.put({ key: `id:${id}`, type: "id" } satisfies Tombstone);
    store.delete(`pending:${id}`);
  }
  for (const p of plan.pendingIds) {
    if (deletion.ids.has(p.id)) {
      continue;
    }
    store.put({
      key: `pending:${p.id}`,
      type: "pending",
      pubkey: p.pubkey,
    } satisfies Tombstone);
  }
  for (const c of plan.coordinates) {
    const prev = deletion.coordinates.get(c.key) ?? Number.NEGATIVE_INFINITY;
    store.put({
      key: `coord:${c.key}`,
      type: "coord",
      until: Math.max(prev, c.until),
    } satisfies Tombstone);
  }
}

export function tombstonesToPlan(rows: unknown[]): DeletionPlan {
  const plan: DeletionPlan = { removeIds: [], pendingIds: [], coordinates: [] };
  for (const row of rows) {
    if (!isRecord(row)) {
      continue;
    }
    const r = row;
    if (r["type"] === "id" && typeof r["key"] === "string" && r["key"].startsWith("id:")) {
      plan.removeIds.push(r["key"].slice(3));
      continue;
    }
    if (
      r["type"] === "pending" &&
      typeof r["key"] === "string" &&
      r["key"].startsWith("pending:") &&
      typeof r["pubkey"] === "string"
    ) {
      plan.pendingIds.push({ id: r["key"].slice(8), pubkey: r["pubkey"] });
      continue;
    }
    if (
      r["type"] === "coord" &&
      typeof r["key"] === "string" &&
      r["key"].startsWith("coord:") &&
      typeof r["until"] === "number"
    ) {
      plan.coordinates.push({ key: r["key"].slice(6), until: r["until"] });
    }
  }
  return plan;
}

export function applyPutIndexedDb(
  tx: IDBTransactionLike,
  s: {
    deletion: DeletionState;
    replaceable: Map<string, string>;
  },
  d: PutDecision,
): PutResult {
  const events = tx.objectStore(EVENTS);
  const tagRefs = tx.objectStore(TAG_REFS);
  const addresses = tx.objectStore(ADDRESSES);
  const tombstones = tx.objectStore(TOMBSTONES);
  if (d.action === "skip") {
    return d.result;
  }
  if (d.action === "tombstone") {
    tombstones.put({ key: `id:${d.event.id}`, type: "id" } satisfies Tombstone);
    tombstones.delete(`pending:${d.event.id}`);
    s.deletion.ids.add(d.event.id);
    s.deletion.pending.delete(d.event.id);
    return "duplicate";
  }
  if (d.action === "delete") {
    s.deletion.pending.delete(d.event.id);
    persistPlanTombstones(tombstones, d.plan, d.coordIds, s.deletion);
    s.deletion.absorb(d.plan);
    for (const id of d.coordIds) {
      s.deletion.ids.add(id);
    }
    events.put(d.event);
    writeTagRefs(tagRefs, d.event);
    return "deleted";
  }
  events.put(d.event);
  writeTagRefs(tagRefs, d.event);
  if (d.address !== undefined) {
    addresses.put({
      address: d.address,
      id: d.event.id,
      created_at: d.event.created_at,
    });
    s.replaceable.set(d.address, d.event.id);
  }
  return d.result;
}
