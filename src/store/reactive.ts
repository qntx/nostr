import { itemCompare } from "../core/event.ts";
import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { filterFingerprint, matchFilters } from "../core/filter.ts";
import { invokeSafely } from "../core/report.ts";
import { formatEventAddress, eventAddress } from "../core/tag.ts";
import { normalizeURL } from "../core/util.ts";
import { MemoryIndex } from "../storage/memory-index.ts";
import type { PutResult } from "../storage/types.ts";

/** A reactive snapshot source compatible with `useSyncExternalStore`. */
export type Watch<T> = {
  subscribe: (onChange: () => void) => () => void;
  getSnapshot: () => T;
};

/** Capacity options for {@link ReactiveEventStore}. */
export type ReactiveEventStoreOptions = {
  /** Max stored events before LRU eviction. Default 50_000. */
  maxEvents?: number;
  /** Max ids tracked by `seenOn`. Default 20_000. */
  maxSeenOnEntries?: number;
  /** FIFO cap on tombstoned deletion ids. Default 100_000. */
  maxTombstones?: number;
};

const SEEN_ON_PER_ID = 16;

/** Category of a {@link Watch} subscription. */
type WatchKind = "event" | "replaceable" | "query";

/** Structural handle the store needs for invalidation; implemented by WatchImpl. */
type WatchHandle = {
  readonly kind: WatchKind;
  readonly key: string;
  readonly filters: ReadonlyArray<Filter> | undefined;
  readonly subscribed: boolean;
  readonly pinnedIds: ReadonlyArray<string>;
  _markDirty: () => void;
  _notify: () => void;
};

class WatchImpl<T> implements Watch<T>, WatchHandle {
  readonly store: ReactiveEventStore;
  readonly kind: WatchKind;
  readonly key: string;
  readonly filters: ReadonlyArray<Filter> | undefined;
  readonly compute: () => T;
  readonly equal: (a: T, b: T) => boolean;
  readonly snapshotIds: (snapshot: T) => ReadonlyArray<string>;
  readonly #subscribers = new Set<() => void>();
  #snapshot: T;
  #version = -1;
  #dirty = false;
  #pendingRemove = false;

  constructor(
    store: ReactiveEventStore,
    kind: WatchKind,
    key: string,
    compute: () => T,
    equal: (a: T, b: T) => boolean,
    snapshotIds: (snapshot: T) => ReadonlyArray<string>,
    filters?: ReadonlyArray<Filter>,
  ) {
    this.store = store;
    this.kind = kind;
    this.key = key;
    this.filters = filters;
    this.compute = compute;
    this.equal = equal;
    this.snapshotIds = snapshotIds;
    this.#snapshot = compute();
    this.#version = store._version;
  }

  get subscribed(): boolean {
    return this.#subscribers.size > 0;
  }

  get pinnedIds(): ReadonlyArray<string> {
    return this.snapshotIds(this.#snapshot);
  }

  subscribe(onChange: () => void): () => void {
    const wasUnsubscribed = this.#subscribers.size === 0;
    this.#subscribers.add(onChange);
    this.#pendingRemove = false;
    // Writes that landed while unregistered must not be lost.
    if (wasUnsubscribed && this.#version !== this.store._version) {
      this.#dirty = true;
    }
    this.store._register(this);
    return () => {
      this.#subscribers.delete(onChange);
      if (this.#subscribers.size > 0 || this.#pendingRemove) {
        return;
      }
      this.#pendingRemove = true;
      queueMicrotask(() => {
        if (this.#pendingRemove) {
          this.store._unregister(this);
        }
      });
    };
  }

  getSnapshot(): T {
    if (this.subscribed ? this.#dirty : this.#version !== this.store._version) {
      const next = this.compute();
      if (!this.equal(next, this.#snapshot)) {
        this.#snapshot = next;
      }
      this.#version = this.store._version;
      this.#dirty = false;
    }
    return this.#snapshot;
  }

  _markDirty(): void {
    this.#dirty = true;
  }

  _notify(): void {
    // Do not sync #version here: subscribers will call getSnapshot, which
    // recomputes against the bumped store version and keeps the reference
    // when the result is element-wise identical. A throwing subscriber is
    // reported and never aborts the remaining notifications.
    for (const onChange of this.#subscribers) {
      invokeSafely(onChange);
    }
  }
}

const EVENT_IDS = (e: Event | undefined): ReadonlyArray<string> => (e ? [e.id] : []);
const LIST_IDS = (events: ReadonlyArray<Event>): ReadonlyArray<string> => events.map((e) => e.id);

function sameRef(a: Event | undefined, b: Event | undefined): boolean {
  return a === b;
}

function sameList(a: ReadonlyArray<Event>, b: ReadonlyArray<Event>): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Synchronous reactive in-memory event store backed by {@link MemoryIndex}. The single read source
 * for Nostr events on the UI side: `Watch` snapshots keep referential stability for
 * `useSyncExternalStore` and are invalidated on matching writes, deletions and tombstones. Writes
 * batch notifications into one microtask flush.
 */
export class ReactiveEventStore {
  readonly #index: MemoryIndex;
  readonly #maxEvents: number;
  readonly #maxSeenOnEntries: number;

  _version = 0;

  // id -> recency-ordered access order (delete+add moves to the newest end)
  readonly #recency = new Set<string>();
  // id -> relay urls (≤ SEEN_ON_PER_ID); Map insertion order for eviction
  readonly #seenOn = new Map<string, string[]>();

  readonly #idWatches = new Map<string, Set<WatchHandle>>();
  readonly #addressWatches = new Map<string, Set<WatchHandle>>();
  readonly #queryCache = new Map<string, WatchImpl<ReadonlyArray<Event>>>();
  readonly #queryRegistry = new Set<WatchHandle>();

  readonly #dirty = new Set<WatchHandle>();
  #flushScheduled = false;
  readonly #insertListeners = new Set<(event: Event) => void>();

  constructor(opts?: ReactiveEventStoreOptions) {
    this.#maxEvents = opts?.maxEvents ?? 50_000;
    this.#maxSeenOnEntries = opts?.maxSeenOnEntries ?? 20_000;
    this.#index = new MemoryIndex({
      maxTombstones: opts?.maxTombstones ?? 100_000,
      // Keep evicted replaceable winners rejectable while their body is gone.
      maxWatermarks: this.#maxEvents,
      onInsert: (event) => this.#onInsert(event),
      onRemove: (event) => this.#onRemove(event),
    });
  }

  add(event: Event, relayUrl?: string): PutResult {
    const result = this.#index.put(event);
    // Stored events are canonical; seenOn keys are their lowercase ids.
    const { id } = event;
    if (
      relayUrl !== undefined &&
      result !== "ephemeral" &&
      result !== "rejected" &&
      result !== "invalid"
    ) {
      this.#recordSeen(id, relayUrl);
    }
    // The just-inserted event must survive its own eviction pass even when
    // every older entry is pinned by a subscribed watch snapshot.
    this.#evictIfNeeded(id);
    return result;
  }

  addMany(events: ReadonlyArray<Event>, relayUrl?: string): PutResult[] {
    const results: PutResult[] = [];
    for (const event of events) {
      results.push(this.add(event, relayUrl));
    }
    return results;
  }

  /** Record a relay sighting for an id already in the index. No notification. */
  markSeen(id: string, relayUrl: string): boolean {
    const key = id.toLowerCase();
    if (this.#index.get(key) === undefined) {
      return false;
    }
    this.#recordSeen(key, relayUrl);
    return true;
  }

  /** Bulk load (initial hydration): no seenOn, one batched notification. */
  hydrate(events: ReadonlyArray<Event>): void {
    // Insert oldest-first so recency ends with the newest entries hottest.
    const sorted = [...events].sort(itemCompare);
    for (const event of sorted) {
      this.#index.put(event);
    }
    this.#evictIfNeeded();
  }

  remove(ids: ReadonlyArray<string>): number {
    return this.#index.remove(ids);
  }

  clear(): void {
    this.#index.clear();
    this.#seenOn.clear();
    this.#recency.clear();
    this._version += 1;
    this.#invalidateAll();
  }

  get(id: string): Event | undefined {
    const event = this.#index.get(id);
    if (event) {
      this.#touch(event.id);
    }
    return event;
  }

  getReplaceable(kind: number, pubkey: string, d?: string): Event | undefined {
    return this.getByAddress(formatEventAddress(kind, pubkey, d ?? ""));
  }

  getByAddress(address: string): Event | undefined {
    const event = this.#index.getByAddress(address);
    if (event) {
      this.#touch(event.id);
    }
    return event;
  }

  query(filters: ReadonlyArray<Filter>): ReadonlyArray<Event> {
    const events = this.#index.query(filters);
    // Results come back newest-first; touch oldest→newest so the newest
    // entries end up hottest in the recency order.
    for (const event of [...events].reverse()) {
      this.#touch(event.id);
    }
    return events;
  }

  isDeleted(idOrAddress: string): boolean {
    return this.#index.isDeleted(idOrAddress);
  }

  seenOn(id: string): ReadonlyArray<string> {
    return this.#seenOn.get(id.toLowerCase()) ?? [];
  }

  get size(): number {
    return this.#index.size;
  }

  watchEvent(id: string): Watch<Event | undefined> {
    const key = id.toLowerCase();
    return new WatchImpl(this, "event", key, () => this.get(key), sameRef, EVENT_IDS);
  }

  watchReplaceable(kind: number, pubkey: string, d?: string): Watch<Event | undefined> {
    const address = formatEventAddress(kind, pubkey, d ?? "");
    return new WatchImpl(
      this,
      "replaceable",
      address,
      () => this.getByAddress(address),
      sameRef,
      EVENT_IDS,
    );
  }

  watchQuery(filters: ReadonlyArray<Filter>): Watch<ReadonlyArray<Event>> {
    const key = filterFingerprint(filters);
    let watch = this.#queryCache.get(key);
    if (!watch) {
      const list = [...filters];
      watch = new WatchImpl(this, "query", key, () => this.query(list), sameList, LIST_IDS, list);
      this.#queryCache.set(key, watch);
    }
    return watch;
  }

  /** Synchronous listener for every physical index insert (after update). */
  onInsert(listener: (event: Event) => void): () => void {
    this.#insertListeners.add(listener);
    return () => {
      this.#insertListeners.delete(listener);
    };
  }

  _register(watch: WatchHandle): void {
    switch (watch.kind) {
      case "event":
        addWatch(this.#idWatches, watch.key, watch);
        return;
      case "replaceable":
        addWatch(this.#addressWatches, watch.key, watch);
        return;
      case "query":
        this.#queryRegistry.add(watch);
    }
  }

  _unregister(watch: WatchHandle): void {
    if (watch.subscribed) {
      return;
    }
    switch (watch.kind) {
      case "event":
        removeWatch(this.#idWatches, watch.key, watch);
        return;
      case "replaceable":
        removeWatch(this.#addressWatches, watch.key, watch);
        return;
      case "query":
        this.#queryRegistry.delete(watch);
        if (this.#queryCache.get(watch.key) === watch) {
          this.#queryCache.delete(watch.key);
        }
    }
  }

  #touch(id: string): void {
    if (this.#recency.delete(id)) {
      this.#recency.add(id);
    } else {
      this.#recency.add(id);
    }
  }

  #recordSeen(id: string, relayUrl: string): void {
    const url = normalizeURL(relayUrl);
    let urls = this.#seenOn.get(id);
    if (!urls) {
      urls = [];
      this.#seenOn.set(id, urls);
    }
    if (!urls.includes(url) && urls.length < SEEN_ON_PER_ID) {
      urls.push(url);
    }
    while (this.#seenOn.size > this.#maxSeenOnEntries) {
      const oldest = this.#seenOn.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.#seenOn.delete(oldest);
    }
  }

  #onInsert(event: Event): void {
    this._version += 1;
    this.#touch(event.id);
    this.#invalidateByEvent(event);
    for (const listener of this.#insertListeners) {
      invokeSafely(() => listener(event));
    }
  }

  #onRemove(event: Event): void {
    this._version += 1;
    this.#recency.delete(event.id);
    this.#invalidateByEvent(event);
  }

  #invalidateByEvent(event: Event): void {
    const byId = this.#idWatches.get(event.id);
    if (byId) {
      for (const watch of byId) {
        this.#markDirty(watch);
      }
    }
    const address = eventAddress(event);
    if (address !== undefined) {
      const byAddress = this.#addressWatches.get(address);
      if (byAddress) {
        for (const watch of byAddress) {
          this.#markDirty(watch);
        }
      }
    }
    for (const watch of this.#queryRegistry) {
      if (watch.filters !== undefined && matchFilters(watch.filters, event)) {
        this.#markDirty(watch);
      }
    }
  }

  #invalidateAll(): void {
    for (const watches of this.#idWatches.values()) {
      for (const watch of watches) {
        this.#markDirty(watch);
      }
    }
    for (const watches of this.#addressWatches.values()) {
      for (const watch of watches) {
        this.#markDirty(watch);
      }
    }
    for (const watch of this.#queryRegistry) {
      this.#markDirty(watch);
    }
    this.#scheduleFlush();
  }

  #markDirty(watch: WatchHandle): void {
    watch._markDirty();
    this.#dirty.add(watch);
    this.#scheduleFlush();
  }

  #scheduleFlush(): void {
    if (this.#flushScheduled) {
      return;
    }
    this.#flushScheduled = true;
    queueMicrotask(() => {
      // Keep the flag set while flushing: writes re-entered from a
      // subscriber land in #dirty and are notified in the same pass.
      while (this.#dirty.size > 0) {
        const batch = [...this.#dirty];
        this.#dirty.clear();
        for (const watch of batch) {
          watch._notify();
        }
      }
      this.#flushScheduled = false;
    });
  }

  #pinnedIds(): Set<string> {
    const pinned = new Set<string>();
    const collect = (watch: WatchHandle): void => {
      for (const id of watch.pinnedIds) {
        pinned.add(id);
      }
    };
    for (const watches of this.#idWatches.values()) {
      for (const watch of watches) {
        collect(watch);
      }
    }
    for (const watches of this.#addressWatches.values()) {
      for (const watch of watches) {
        collect(watch);
      }
    }
    for (const watch of this.#queryRegistry) {
      collect(watch);
    }
    return pinned;
  }

  #evictIfNeeded(protectedId?: string): void {
    if (this.#index.size <= this.#maxEvents) {
      return;
    }
    const pinned = this.#pinnedIds();
    const evicting: string[] = [];
    for (const id of this.#recency) {
      if (this.#index.size - evicting.length <= this.#maxEvents) {
        break;
      }
      if (pinned.has(id) || id === protectedId) {
        continue;
      }
      const event = this.#index.get(id);
      if (event === undefined) {
        continue;
      }
      // Replaceable/addressable winners evict like any other event; the index
      // records a watermark so stale versions stay rejected afterwards.
      evicting.push(id);
    }
    this.#index.evict(evicting);
    for (const id of evicting) {
      this.#recency.delete(id);
    }
  }
}

function addWatch(map: Map<string, Set<WatchHandle>>, key: string, watch: WatchHandle): void {
  let set = map.get(key);
  if (!set) {
    set = new Set();
    map.set(key, set);
  }
  set.add(watch);
}

function removeWatch(map: Map<string, Set<WatchHandle>>, key: string, watch: WatchHandle): void {
  const set = map.get(key);
  if (!set) {
    return;
  }
  set.delete(watch);
  if (set.size === 0) {
    map.delete(key);
  }
}
