import { trimOldest } from "../core/collections.ts";
import type { Event } from "../core/event.ts";
import { compareEventsDesc, itemCompare, sortEvents } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { filterTagConditions, matchFilter } from "../core/filter.ts";
import { eventAddress, formatEventAddress, parseEventAddressInput } from "../core/tag.ts";
import { DeletionState } from "./deletion.ts";
import { applyPutMemory, decidePut, outboxBoundKey } from "./put.ts";
import type { PutLookup } from "./put.ts";
import { SortedEvents } from "./sorted-events.ts";
import type { EventCursor } from "./sorted-events.ts";
import type { NegentropyItem, OutboxBound, PutResult } from "./types.ts";

/**
 * NIP-01 only defines single-letter tag conditions; `#e`/`#p` hold hex ids (filter side
 * lowercased).
 */
const SINGLE_ASCII_LETTER = /^[a-zA-Z]$/;

export type MemoryIndexOptions = {
  /**
   * FIFO cap applied independently to each deletion-state collection: tombstoned event ids, pending
   * e-tag ids, and coordinate tombstones. Default unbounded. Trade-off: once an entry is trimmed, a
   * re-arriving old deleted event or replaceable version can be accepted again.
   */
  maxTombstones?: number | undefined;
  /**
   * FIFO cap on replaceable/addressable winner watermarks recorded by {@link evict}. A watermark
   * keeps only `{ id, created_at }` per address so stale versions stay rejected after the winner's
   * body is evicted, and a re-put of the watermarked id re-inserts it. Default 0 (no watermark
   * retention); callers that evict should pass a bound. Once a watermark is trimmed, an older
   * evicted version can be accepted again — the same trade-off as deletion tombstones.
   */
  maxWatermarks?: number | undefined;
  /** Fires after every physical index insert (accept, replace, deletion event). */
  onInsert?: ((event: Event) => void) | undefined;
  /** Fires after every physical index remove (replace, delete, evict, remove, clear). */
  onRemove?: ((event: Event) => void) | undefined;
};

/**
 * Synchronous in-memory event index with NIP-01 replaceable / addressable / ephemeral handling and
 * NIP-09 deletion (kind 5) application. Shared by {@link MemoryEventStore} (async facade) and
 * `ReactiveEventStore`.
 */
export class MemoryIndex {
  readonly #byId = new Map<string, Event>();
  readonly #all = new SortedEvents();
  readonly #byPubkey = new Map<string, SortedEvents>();
  readonly #byKind = new Map<number, SortedEvents>();
  readonly #byKindPubkey = new Map<string, SortedEvents>(); // `${kind}:${pubkey}` bucket
  readonly #byTag = new Map<string, SortedEvents>(); // `${name}:${value}` for single-letter tag names (event-side verbatim)
  readonly #replaceable = new Map<string, string>(); // address -> event id
  // address -> last evicted winner; insertion order is the FIFO trim order
  readonly #watermarks = new Map<string, { id: string; created_at: number }>();
  // winner id -> address reverse index for O(1) watermark drops on deletion
  readonly #watermarkIds = new Map<string, string>();
  readonly #deletion = new DeletionState();
  readonly #outboxBounds = new Map<string, OutboxBound>();
  readonly #maxTombstones: number | undefined;
  readonly #maxWatermarks: number;
  readonly #onInsert: ((event: Event) => void) | undefined;
  readonly #onRemove: ((event: Event) => void) | undefined;

  constructor(opts?: MemoryIndexOptions) {
    this.#maxTombstones = opts?.maxTombstones;
    this.#maxWatermarks = opts?.maxWatermarks ?? 0;
    this.#onInsert = opts?.onInsert;
    this.#onRemove = opts?.onRemove;
  }

  put(raw: Event): PutResult {
    const lookup: PutLookup = {
      deletion: this.#deletion,
      getById: (id) => this.#byId.get(id),
      getReplaceable: (addr) => {
        const id = this.#replaceable.get(addr);
        const ev = id === undefined ? undefined : this.#byId.get(id);
        if (ev) {
          return { id: ev.id, created_at: ev.created_at };
        }
        const watermark = this.#watermarks.get(addr);
        return watermark === undefined ? undefined : { ...watermark, evicted: true };
      },
    };
    const decision = decidePut(raw, lookup);
    if (decision.action === "delete") {
      // Pending e-tag targets and coordinate tombstones never reach
      // indexRemove — drop their watermarks here.
      for (const p of decision.plan.pendingIds) {
        this.#dropWatermarkId(p.id);
      }
      for (const c of decision.plan.coordinates) {
        this.#dropWatermark(c.key);
      }
    }
    const result = applyPutMemory(
      {
        deletion: this.#deletion,
        indexInsert: (e) => this.#indexInsert(e),
        indexRemove: (id) => this.#indexRemove(id),
      },
      decision,
    );
    this.#trimTombstones();
    return result;
  }

  /** Sequential `put` in input order. */
  putMany(events: ReadonlyArray<Event>): PutResult[] {
    const results: PutResult[] = [];
    for (const event of events) {
      results.push(this.put(event));
    }
    return results;
  }

  get(id: string): Event | undefined {
    const key = id.toLowerCase();
    if (this.#deletion.ids.has(key)) {
      return undefined;
    }
    return this.#byId.get(key);
  }

  /** Current event at a `kind:pubkey:d` coordinate (replaceable or addressable). */
  getByAddress(address: string): Event | undefined {
    const coord = parseEventAddressInput(address);
    if (!coord) {
      return undefined;
    }
    const id = this.#replaceable.get(
      formatEventAddress(coord.kind, coord.pubkey, coord.identifier),
    );
    if (id === undefined) {
      return undefined;
    }
    if (this.#deletion.ids.has(id)) {
      return undefined;
    }
    return this.#byId.get(id);
  }

  query(filters: ReadonlyArray<Filter>): Event[] {
    const seen = new Set<string>();
    const events: Event[] = [];
    for (const filter of filters) {
      for (const event of this.#matchedEvents(filter)) {
        if (seen.has(event.id)) {
          continue;
        }
        seen.add(event.id);
        events.push(event);
      }
    }
    sortEvents(events);
    return events;
  }

  count(filters: ReadonlyArray<Filter>): number {
    const seen = new Set<string>();
    for (const filter of filters) {
      for (const event of this.#matchedEvents(filter)) {
        seen.add(event.id);
      }
    }
    return seen.size;
  }

  negentropyItems(filter: Filter): NegentropyItem[] {
    if (filter.limit === 0) {
      return [];
    }
    const items: NegentropyItem[] = [];
    const { limit } = filter;
    if (filter.ids) {
      const seen = new Set<string>();
      for (const raw of filter.ids) {
        const event = this.#byId.get(raw.toLowerCase());
        if (!event || seen.has(event.id)) {
          continue;
        }
        seen.add(event.id);
        if (this.#deletion.covers(event) || !matchFilter(filter, event)) {
          continue;
        }
        items.push({ id: event.id, created_at: event.created_at });
      }
    } else {
      const cursor = this.#candidates(filter);
      while (cursor.value !== undefined) {
        const event = cursor.value;
        cursor.next();
        if (this.#deletion.covers(event) || !matchFilter(filter, event)) {
          continue;
        }
        items.push({ id: event.id, created_at: event.created_at });
        if (limit !== undefined && items.length >= limit) {
          break;
        }
      }
    }
    if (filter.limit !== undefined) {
      // The ids path collected matches in filter order; cursor results are already canonical.
      if (filter.ids) {
        items.sort(compareEventsDesc);
      }
      if (items.length > filter.limit) {
        items.length = filter.limit;
      }
    }
    items.sort(itemCompare);
    return items;
  }

  /** Remove by id and tombstone (like a local NIP-09). Returns removed count. */
  remove(ids: ReadonlyArray<string>): number {
    let n = 0;
    for (const raw of ids) {
      const id = raw.toLowerCase();
      if (this.#indexRemove(id)) {
        n += 1;
      }
      this.#deletion.ids.add(id);
      this.#deletion.pending.delete(id);
    }
    this.#trimTombstones();
    return n;
  }

  /**
   * Remove by id without writing a tombstone (LRU eviction). When the evicted event is the current
   * winner of a replaceable/addressable address, a `{ id, created_at }` watermark is recorded so
   * stale versions stay rejected while the body is gone; the watermarks are FIFO-bounded by
   * `maxWatermarks`.
   */
  evict(ids: ReadonlyArray<string>): number {
    let n = 0;
    for (const raw of ids) {
      const id = raw.toLowerCase();
      const event = this.#byId.get(id);
      if (event === undefined) {
        continue;
      }
      const addr = eventAddress(event);
      const winner = addr !== undefined && this.#replaceable.get(addr) === id;
      if (this.#indexRemove(id)) {
        n += 1;
      }
      if (winner) {
        this.#setWatermark(addr, { id, created_at: event.created_at });
      }
    }
    return n;
  }

  /**
   * True when the id is tombstoned, or the coordinate has a deletion marker that still covers the
   * current event at that address: a replacement published after the marker's `until` clears the
   * deletion. Coordinates are matched on the canonical lowercase pubkey.
   */
  isDeleted(idOrAddress: string): boolean {
    if (this.#deletion.ids.has(idOrAddress.toLowerCase())) {
      return true;
    }
    const coord = parseEventAddressInput(idOrAddress);
    if (!coord) {
      return false;
    }
    const address = formatEventAddress(coord.kind, coord.pubkey, coord.identifier);
    const until = this.#deletion.coordinates.get(address);
    if (until === undefined) {
      return false;
    }
    const id = this.#replaceable.get(address);
    if (id === undefined) {
      return true;
    }
    const event = this.#byId.get(id);
    return event === undefined || event.created_at <= until;
  }

  getOutboxBound(pubkey: string, kind: number): OutboxBound | undefined {
    const persisted = this.#outboxBounds.get(outboxBoundKey(pubkey, kind));
    if (persisted) {
      return { oldest: persisted.oldest, newest: persisted.newest };
    }
    return this.#deriveOutboxBound(pubkey, kind);
  }

  setOutboxBound(pubkey: string, kind: number, bound: OutboxBound): void {
    this.#outboxBounds.set(outboxBoundKey(pubkey, kind), {
      oldest: bound.oldest,
      newest: bound.newest,
    });
  }

  clear(): void {
    if (this.#onRemove) {
      for (const event of this.#byId.values()) {
        this.#onRemove(event);
      }
    }
    this.#byId.clear();
    this.#all.clear();
    this.#byPubkey.clear();
    this.#byKind.clear();
    this.#byKindPubkey.clear();
    this.#byTag.clear();
    this.#replaceable.clear();
    this.#watermarks.clear();
    this.#watermarkIds.clear();
    this.#deletion.clear();
    this.#outboxBounds.clear();
  }

  get size(): number {
    return this.#byId.size;
  }

  #indexInsert(event: Event): void {
    this.#byId.set(event.id, event);
    const { pubkey } = event;
    this.#all.insert(event);
    insertBucket(this.#byPubkey, pubkey, event);
    insertBucket(this.#byKind, event.kind, event);
    insertBucket(this.#byKindPubkey, `${event.kind}:${pubkey}`, event);
    for (const key of tagKeys(event)) {
      insertBucket(this.#byTag, key, event);
    }
    const addr = eventAddress(event);
    if (addr !== undefined) {
      this.#replaceable.set(addr, event.id);
      this.#dropWatermark(addr);
    }
    this.#onInsert?.(event);
  }

  #indexRemove(id: string): boolean {
    // A removed/deleted id must not keep a stale watermark alive; eviction
    // re-records its winner watermark right after this call.
    this.#dropWatermarkId(id);
    const event = this.#byId.get(id);
    if (!event) {
      return false;
    }
    this.#byId.delete(id);
    const { pubkey } = event;
    this.#all.remove(event);
    removeBucket(this.#byPubkey, pubkey, event);
    removeBucket(this.#byKind, event.kind, event);
    removeBucket(this.#byKindPubkey, `${event.kind}:${pubkey}`, event);
    for (const key of tagKeys(event)) {
      removeBucket(this.#byTag, key, event);
    }
    const addr = eventAddress(event);
    if (addr !== undefined && this.#replaceable.get(addr) === id) {
      this.#replaceable.delete(addr);
    }
    this.#onRemove?.(event);
    return true;
  }

  #matchedEvents(filter: Filter): Event[] {
    if (filter.limit === 0) {
      return [];
    }
    const { limit } = filter;
    const matched: Event[] = [];
    if (filter.ids) {
      const seen = new Set<string>();
      for (const raw of filter.ids) {
        const event = this.#byId.get(raw.toLowerCase());
        if (!event || seen.has(event.id)) {
          continue;
        }
        seen.add(event.id);
        if (this.#deletion.covers(event) || !matchFilter(filter, event)) {
          continue;
        }
        matched.push(event);
      }
      sortEvents(matched);
      return limit === undefined ? matched : matched.slice(0, limit);
    }
    const cursor = this.#candidates(filter);
    while (cursor.value !== undefined) {
      const event = cursor.value;
      cursor.next();
      if (this.#deletion.covers(event) || !matchFilter(filter, event)) {
        continue;
      }
      matched.push(event);
      if (limit !== undefined && matched.length >= limit) {
        break;
      }
    }
    return matched;
  }

  /**
   * Smallest-total bucket set for the filter's usable indexes: `authors`×`kinds` (both present),
   * `authors`, `kinds`, each single-letter `#x` condition (a bucket per value; `#e`/`#p` filter
   * values lowercased like `matchFilter`, others verbatim), or `all` as the fallback.
   */
  #plan(filter: Filter): SortedEvents[] {
    const { authors, kinds } = filter;
    const tagConds = filterTagConditions(filter);

    let best: SortedEvents[] | undefined;
    let bestTotal = Number.POSITIVE_INFINITY;
    const consider = (buckets: Array<SortedEvents | undefined>): void => {
      let total = 0;
      const present: SortedEvents[] = [];
      for (const bucket of buckets) {
        if (bucket !== undefined) {
          present.push(bucket);
          total += bucket.size;
        }
      }
      if (total < bestTotal) {
        bestTotal = total;
        best = present;
      }
    };

    if (authors !== undefined && kinds !== undefined) {
      const buckets: Array<SortedEvents | undefined> = [];
      for (const pk of authors) {
        const pubkey = pk.toLowerCase();
        for (const kind of kinds) {
          buckets.push(this.#byKindPubkey.get(`${kind}:${pubkey}`));
        }
      }
      consider(buckets);
    }
    if (authors !== undefined) {
      consider(authors.map((pk) => this.#byPubkey.get(pk.toLowerCase())));
    }
    if (kinds !== undefined) {
      consider(kinds.map((kind) => this.#byKind.get(kind)));
    }
    for (const { name, values } of tagConds) {
      consider(values.map((v) => this.#byTag.get(`${name}:${v}`)));
    }
    if (best === undefined || bestTotal > this.#all.size) {
      return [this.#all];
    }
    return best;
  }

  /** Canonical-order candidates from the planned buckets, each clipped to `since`/`until`. */
  #candidates(filter: Filter): CandidateCursor {
    const buckets = this.#plan(filter);
    const cursors: EventCursor[] = [];
    for (const bucket of buckets) {
      const cursor = bucket.cursor(filter.since, filter.until);
      if (cursor.value !== undefined) {
        cursors.push(cursor);
      }
    }
    if (cursors.length === 0) {
      return EMPTY_CURSOR;
    }
    if (cursors.length === 1) {
      return cursors[0] ?? EMPTY_CURSOR;
    }
    return new CursorHeap(cursors);
  }

  #deriveOutboxBound(pubkey: string, kind: number): OutboxBound | undefined {
    const bucket = this.#byKindPubkey.get(`${kind}:${pubkey.toLowerCase()}`);
    if (bucket === undefined) {
      return undefined;
    }
    // Canonical order: first non-deleted event is the newest, last the oldest.
    let oldest: number | undefined;
    let newest: number | undefined;
    const cursor = bucket.cursor();
    while (cursor.value !== undefined) {
      const event = cursor.value;
      cursor.next();
      if (this.#deletion.covers(event)) {
        continue;
      }
      newest ??= event.created_at;
      oldest = event.created_at;
    }
    if (oldest === undefined || newest === undefined) {
      return undefined;
    }
    return { oldest, newest };
  }

  #setWatermark(addr: string, watermark: { id: string; created_at: number }): void {
    if (this.#maxWatermarks === 0) {
      return;
    }
    this.#dropWatermark(addr);
    this.#watermarks.set(addr, watermark);
    this.#watermarkIds.set(watermark.id, addr);
    trimOldest(this.#watermarks, this.#maxWatermarks, (a) => this.#dropWatermark(a));
  }

  #dropWatermark(addr: string): void {
    const watermark = this.#watermarks.get(addr);
    if (watermark === undefined) {
      return;
    }
    this.#watermarks.delete(addr);
    this.#watermarkIds.delete(watermark.id);
  }

  #dropWatermarkId(id: string): void {
    const addr = this.#watermarkIds.get(id);
    if (addr === undefined) {
      return;
    }
    this.#watermarkIds.delete(id);
    this.#watermarks.delete(addr);
  }

  #trimTombstones(): void {
    const cap = this.#maxTombstones;
    if (cap === undefined) {
      return;
    }
    trimOldest(this.#deletion.ids, cap, (id) => {
      this.#deletion.pending.delete(id);
    });
    trimOldest(this.#deletion.pending, cap);
    trimOldest(this.#deletion.coordinates, cap);
  }
}

type CandidateCursor = {
  readonly value: Event | undefined;
  next: () => void;
};

const EMPTY_CURSOR: CandidateCursor = {
  value: undefined,
  next: () => undefined,
};

/**
 * Binary-heap k-way merge of sorted cursors. `next()` advances every cursor sitting on the emitted
 * event, which dedupes an event present in several buckets (multi-value `#x` filters); copies
 * compare equal so they always surface adjacent. Entries pair each cursor with its head event so
 * heap comparisons never read `undefined`.
 */
class CursorHeap implements CandidateCursor {
  #heap: Array<{ cursor: EventCursor; event: Event }>;

  constructor(cursors: EventCursor[]) {
    const heap: Array<{ cursor: EventCursor; event: Event }> = [];
    for (const cursor of cursors) {
      const event = cursor.value;
      if (event !== undefined) {
        heap.push({ cursor, event });
      }
    }
    this.#heap = heap;
    for (let i = Math.floor(heap.length / 2) - 1; i >= 0; i--) {
      this.#siftDown(i);
    }
  }

  get value(): Event | undefined {
    return this.#heap[0]?.event;
  }

  next(): void {
    const emitted = this.#heap[0]?.event;
    if (emitted === undefined) {
      return;
    }
    while (this.#heap[0]?.event === emitted) {
      const [root] = this.#heap;
      if (root === undefined) {
        return;
      }
      root.cursor.next();
      const nextEvent = root.cursor.value;
      if (nextEvent === undefined) {
        const last = this.#heap.pop();
        if (this.#heap.length > 0 && last !== undefined) {
          this.#heap[0] = last;
          this.#siftDown(0);
        }
      } else {
        root.event = nextEvent;
        this.#siftDown(0);
      }
    }
  }

  #less(a: number, b: number): boolean {
    const x = this.#heap[a];
    const y = this.#heap[b];
    return x !== undefined && y !== undefined && compareEventsDesc(x.event, y.event) < 0;
  }

  #siftDown(start: number): void {
    const heap = this.#heap;
    let i = start;
    for (;;) {
      let min = i;
      if (this.#less(2 * i + 1, min)) {
        min = 2 * i + 1;
      }
      if (this.#less(2 * i + 2, min)) {
        min = 2 * i + 2;
      }
      if (min === i) {
        return;
      }
      const tmp = heap[i];
      const swap = heap[min];
      if (tmp === undefined || swap === undefined) {
        return;
      }
      heap[i] = swap;
      heap[min] = tmp;
      i = min;
    }
  }
}

/** Distinct `${name}:${value}` bucket keys for every ASCII single-letter tag name on the event. */
function tagKeys(event: Event): string[] {
  const keys = new Set<string>();
  for (const tag of event.tags) {
    const [name, value] = tag;
    if (name === undefined || value === undefined || !SINGLE_ASCII_LETTER.test(name)) {
      continue;
    }
    keys.add(`${name}:${value}`);
  }
  return [...keys];
}

function insertBucket<K>(map: Map<K, SortedEvents>, key: K, event: Event): void {
  let bucket = map.get(key);
  if (bucket === undefined) {
    bucket = new SortedEvents();
    map.set(key, bucket);
  }
  bucket.insert(event);
}

function removeBucket<K>(map: Map<K, SortedEvents>, key: K, event: Event): void {
  const bucket = map.get(key);
  if (bucket === undefined || !bucket.remove(event)) {
    return;
  }
  if (bucket.size === 0) {
    map.delete(key);
  }
}
