// oxlint-disable unicorn/prefer-add-event-listener -- the *Like driver interfaces model only the `on*` handler surface
import type { Event } from "../core/event.ts";
import { compareEventsDesc, sortEvents } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { StorageError } from "./error.ts";
import { reqOf } from "./idb-helpers.ts";
import { EVENTS, TAG_REFS } from "./idb-types.ts";
import type {
  IDBCursorDirectionLike,
  IDBCursorLike,
  IDBIndexLike,
  IDBKeyRangeLike,
  IDBObjectStoreLike,
  IDBRequestLike,
  IDBTransactionLike,
  TagRef,
} from "./idb-types.ts";

export function prefixRange(
  prefix: ReadonlyArray<string | number>,
  since?: number,
  until?: number,
): IDBKeyRangeLike {
  return idbKeyRange().bound(
    [...prefix, since ?? 0],
    [...prefix, until ?? Number.MAX_SAFE_INTEGER],
  );
}

function createdAtRange(since?: number, until?: number): IDBKeyRangeLike {
  return idbKeyRange().bound(since ?? 0, until ?? Number.MAX_SAFE_INTEGER);
}

function idbKeyRange(): {
  bound: (
    lower: unknown,
    upper: unknown,
    lowerOpen?: boolean,
    upperOpen?: boolean,
  ) => IDBKeyRangeLike;
} {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- globalThis lookup of the platform IDBKeyRange
  return (globalThis as unknown as { IDBKeyRange: ReturnType<typeof idbKeyRange> }).IDBKeyRange;
}

export function epTagPrefixes(filter: Filter): Array<{ name: "e" | "p"; value: string }> {
  const out: Array<{ name: "e" | "p"; value: string }> = [];
  for (const name of ["e", "p"] as const) {
    const values = filter[`#${name}`];
    if (values === undefined) {
      continue;
    }
    for (const value of values) {
      out.push({ name, value: value.toLowerCase() });
    }
  }
  return out;
}

type MergeOpener = {
  open: () => IDBRequestLike;
  read: (
    cursor: IDBCursorLike,
    ok: (event: Event | undefined) => void,
    err: (error: Error) => void,
  ) => void;
};

function eventCursor(
  source: {
    openCursor: (range?: IDBKeyRangeLike, direction?: IDBCursorDirectionLike) => IDBRequestLike;
  },
  range: IDBKeyRangeLike,
): MergeOpener {
  return {
    open: () => source.openCursor(range, "prev"),
    read: (cursor, ok) => {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- index cursor values are stored Event rows
      ok(cursor.value as Event);
    },
  };
}

function tagCursor(
  index: IDBIndexLike,
  events: IDBObjectStoreLike,
  range: IDBKeyRangeLike,
): MergeOpener {
  return {
    open: () => index.openCursor(range, "prev"),
    read: (cursor, ok, err) => {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- tag_refs cursor values are TagRef rows written by writeTagRefs
      const row = cursor.value as TagRef;
      const req = events.get(row.id);
      req.onerror = () => err(req.error ?? new StorageError("IndexedDB get failed"));
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- get resolves with a stored Event row or undefined
      req.onsuccess = () => ok(req.result as Event | undefined);
    },
  };
}

export async function scanIds(
  tx: IDBTransactionLike,
  filter: Filter,
  accept: (event: Event) => boolean,
  take: (event: Event) => boolean,
): Promise<void> {
  const ids = filter.ids ?? [];
  const events = tx.objectStore(EVENTS);
  const reqs = ids.map((id) => events.get(id.toLowerCase()));
  const rows = await Promise.all(reqs.map(async (req) => reqOf<Event | undefined>(req)));
  const matched: Event[] = [];
  const seen = new Set<string>();
  for (const event of rows) {
    if (event === undefined || seen.has(event.id) || !accept(event)) {
      continue;
    }
    seen.add(event.id);
    matched.push(event);
  }
  sortEvents(matched);
  const out = filter.limit === undefined ? matched : matched.slice(0, filter.limit);
  for (const event of out) {
    if (take(event)) {
      break;
    }
  }
}

/** IDB auto-commits when onsuccess returns with no outstanding requests. */
export async function kWayMerge(
  openers: ReadonlyArray<MergeOpener>,
  accept: (event: Event) => boolean,
  take: (event: Event) => boolean,
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (openers.length === 0) {
      resolve();
      return;
    }

    type Slot = { cursor: IDBCursorLike | undefined; head: Event | undefined };
    const slots: Slot[] = openers.map(() => ({ cursor: undefined, head: undefined }));
    const seen = new Set<string>();
    let inflight = 0;
    let phase: "merge" | "drain" | "done" = "merge";
    let drainT = 0;
    let drainBuf: Event[] = [];

    const finish = () => {
      if (phase === "done") {
        return;
      }
      phase = "done";
      resolve();
    };
    const fail = (error: Error) => {
      if (phase === "done") {
        return;
      }
      phase = "done";
      reject(error);
    };

    const stepCursor = (i: number) => {
      const { cursor } = slots.at(i) ?? { cursor: undefined };
      if (cursor === undefined) {
        return;
      }
      inflight++;
      cursor.continue();
    };

    const emitDrain = () => {
      sortEvents(drainBuf);
      for (const event of drainBuf) {
        if (seen.has(event.id) || !accept(event)) {
          continue;
        }
        seen.add(event.id);
        if (take(event)) {
          finish();
          return;
        }
      }
      drainBuf = [];
      phase = "merge";
      pump();
    };

    const pump = () => {
      if (phase === "done" || inflight > 0) {
        return;
      }
      if (phase === "drain") {
        emitDrain();
        return;
      }
      let best: Event | undefined;
      for (const slot of slots) {
        const event = slot.head;
        if (event === undefined) {
          continue;
        }
        if (best === undefined || compareEventsDesc(event, best) < 0) {
          best = event;
        }
      }
      if (best === undefined) {
        finish();
        return;
      }
      phase = "drain";
      drainT = best.created_at;
      drainBuf = [];
      for (const [i, slot] of slots.entries()) {
        const event = slot.head;
        if (event === undefined || event.created_at !== drainT) {
          continue;
        }
        drainBuf.push(event);
        slot.head = undefined;
        stepCursor(i);
      }
      if (inflight === 0) {
        pump();
      }
    };

    const onEvent = (i: number, event: Event | undefined) => {
      if (phase === "done") {
        return;
      }
      const slot = slots.at(i);
      if (slot === undefined) {
        return;
      }
      const { cursor } = slot;
      if (event === undefined) {
        if (cursor === undefined) {
          pump();
        } else {
          inflight++;
          cursor.continue();
        }
        return;
      }
      if (phase === "drain") {
        if (event.created_at === drainT) {
          drainBuf.push(event);
          if (cursor === undefined) {
            pump();
          } else {
            inflight++;
            cursor.continue();
          }
          return;
        }
        slot.head = event;
        pump();
        return;
      }
      slot.head = event;
      pump();
    };

    const openSlot = (i: number, opener: MergeOpener): void => {
      const req = opener.open();
      req.onerror = () => fail(req.error ?? new StorageError("IndexedDB cursor failed"));
      inflight++;
      req.onsuccess = () => {
        inflight--;
        if (phase === "done") {
          return;
        }
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- openCursor resolves with a cursor or null
        const cursor = (req.result ?? undefined) as IDBCursorLike | undefined;
        const slot = slots.at(i);
        if (slot === undefined) {
          return;
        }
        if (cursor === undefined) {
          slot.cursor = undefined;
          slot.head = undefined;
          pump();
          return;
        }
        slot.cursor = cursor;
        inflight++;
        opener.read(
          cursor,
          (event) => {
            inflight--;
            onEvent(i, event);
          },
          (error) => {
            inflight--;
            fail(error);
          },
        );
      };
    };
    for (const [i, opener] of openers.entries()) {
      openSlot(i, opener);
    }
  });
}

/**
 * Cap on cursors opened per filter: beyond it a k-way merge degenerates into one request per match
 * candidate. Past the cap the planner opens fewer, wider cursors and lets `accept` (matchFilter)
 * enforce the remaining terms, so results and per-filter limits are unchanged.
 */
export const MAX_MERGE_CURSORS = 64;

export async function scanFilter(
  tx: IDBTransactionLike,
  filter: Filter,
  accept: (event: Event) => boolean,
  take: (event: Event) => boolean,
): Promise<void> {
  if (filter.limit === 0) {
    return;
  }
  if (filter.since !== undefined && filter.until !== undefined && filter.since > filter.until) {
    return;
  }

  if (filter.ids) {
    return scanIds(tx, filter, accept, take);
  }

  const events = tx.objectStore(EVENTS);
  const fullScan: MergeOpener = eventCursor(
    events.index("created_at"),
    createdAtRange(filter.since, filter.until),
  );
  const openers: MergeOpener[] = [];
  if (filter.authors && filter.kinds) {
    if (filter.authors.length * filter.kinds.length > MAX_MERGE_CURSORS) {
      // One cursor per kind keeps the bound tight when the kind list is
      // small; otherwise a single created_at scan still fits under the cap.
      if (filter.kinds.length <= MAX_MERGE_CURSORS) {
        const index = events.index("kind_created_at");
        for (const kind of filter.kinds) {
          openers.push(eventCursor(index, prefixRange([kind], filter.since, filter.until)));
        }
      } else {
        openers.push(fullScan);
      }
    } else {
      const index = events.index("kind_pubkey_created_at");
      for (const kind of filter.kinds) {
        for (const pk of filter.authors) {
          openers.push(
            eventCursor(index, prefixRange([kind, pk.toLowerCase()], filter.since, filter.until)),
          );
        }
      }
    }
  } else if (filter.authors) {
    if (filter.authors.length > MAX_MERGE_CURSORS) {
      openers.push(fullScan);
    } else {
      const index = events.index("pubkey_created_at");
      for (const pk of filter.authors) {
        openers.push(
          eventCursor(index, prefixRange([pk.toLowerCase()], filter.since, filter.until)),
        );
      }
    }
  } else if (filter.kinds) {
    if (filter.kinds.length > MAX_MERGE_CURSORS) {
      openers.push(fullScan);
    } else {
      const index = events.index("kind_created_at");
      for (const kind of filter.kinds) {
        openers.push(eventCursor(index, prefixRange([kind], filter.since, filter.until)));
      }
    }
  } else {
    const tags = epTagPrefixes(filter);
    if (tags.length > MAX_MERGE_CURSORS) {
      openers.push(fullScan);
    } else if (tags.length > 0) {
      const index = tx.objectStore(TAG_REFS).index("name_value_created");
      for (const tag of tags) {
        openers.push(
          tagCursor(index, events, prefixRange([tag.name, tag.value], filter.since, filter.until)),
        );
      }
    } else {
      openers.push(fullScan);
    }
  }
  return kWayMerge(openers, accept, take);
}
