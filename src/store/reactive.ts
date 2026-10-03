import { addToSetMap, removeFromSetMap, trimOldest } from "../core/collections.ts";
import { itemCompare } from "../core/event.ts";
import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { filterFingerprint, matchFilters } from "../core/filter.ts";
import { Kind } from "../core/kind.ts";
import { invokeSafely } from "../core/report.ts";
import { formatEventAddress, eventAddress, parseEventAddress } from "../core/tag.ts";
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
  maxEvents?: number | undefined;
  /** Max ids tracked by `seenOn`. Default 20_000. */
  maxSeenOnEntries?: number | undefined;
  /** FIFO cap on tombstoned deletion ids. Default 100_000. */
  maxTombstones?: number | undefined;
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
  markDirty: () => void;
  notify: () => void;
};

/** Store internals exposed to a {@link WatchImpl}: version clock and registry/pin bookkeeping. */
type WatchHost = {
  version: () => number;
  register: (watch: WatchHandle) => void;
  unregister: (watch: WatchHandle) => void;
  /** Refresh pinned ids after a registered watch's snapshot changed. No-op when unregistered. */
  repin: (watch: WatchHandle) => void;
};

class WatchImpl<T> implements Watch<T>, WatchHandle {
  readonly host: WatchHost;
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
    host: WatchHost,
    kind: WatchKind,
    key: string,
    compute: () => T,
    equal: (a: T, b: T) => boolean,
    snapshotIds: (snapshot: T) => ReadonlyArray<string>,
    filters?: ReadonlyArray<Filter>,
  ) {
    this.host = host;
    this.kind = kind;
    this.key = key;
    this.filters = filters;
    this.compute = compute;
    this.equal = equal;
    this.snapshotIds = snapshotIds;
    this.#snapshot = compute();
    this.#version = host.version();
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
    if (wasUnsubscribed && this.#version !== this.host.version()) {
      this.#dirty = true;
    }
    this.host.register(this);
    return () => {
      this.#subscribers.delete(onChange);
      if (this.#subscribers.size > 0 || this.#pendingRemove) {
        return;
      }
      this.#pendingRemove = true;
      queueMicrotask(() => {
        if (this.#pendingRemove) {
          this.host.unregister(this);
        }
      });
    };
  }

  getSnapshot(): T {
    if (this.subscribed ? this.#dirty : this.#version !== this.host.version()) {
      const next = this.compute();
      if (!this.equal(next, this.#snapshot)) {
        this.#snapshot = next;
        this.host.repin(this);
      }
      this.#version = this.host.version();
      this.#dirty = false;
    }
    return this.#snapshot;
  }

  markDirty(): void {
    this.#dirty = true;
  }

  notify(): void {
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

  #version = 0;

  // id -> recency-ordered access order (delete+add moves to the newest end)
  readonly #recency = new Set<string>();
  // id -> relay urls (≤ SEEN_ON_PER_ID); Map insertion order for eviction
  readonly #seenOn = new Map<string, string[]>();

  readonly #idWatches = new Map<string, Set<WatchHandle>>();
  readonly #addressWatches = new Map<string, Set<WatchHandle>>();
  readonly #eventCache = new Map<string, WatchImpl<Event | undefined>>();
  readonly #addressCache = new Map<string, WatchImpl<Event | undefined>>();
  readonly #queryCache = new Map<string, WatchImpl<ReadonlyArray<Event>>>();
  readonly #queryRegistry = new Set<WatchHandle>();

  // Event-id → pin refcount across registered watch snapshots; eviction skips pinned ids.
  readonly #pinned = new Map<string, number>();
  // Registered watch → ids it currently pins (repin/unpin need the old set).
  readonly #watchPins = new Map<WatchHandle, ReadonlyArray<string>>();

  readonly #dirty = new Set<WatchHandle>();
  #flushScheduled = false;
  readonly #insertListeners = new Set<(event: Event) => void>();
  readonly #removeListeners = new Set<(event: Event) => void>();

  readonly #watchHost: WatchHost = {
    version: () => this.#version,
    register: (watch) => {
      this.#registerWatch(watch);
      if (!this.#watchPins.has(watch)) {
        const ids = watch.pinnedIds;
        this.#watchPins.set(watch, ids);
        this.#pin(ids);
      }
    },
    unregister: (watch) => {
      if (watch.subscribed) {
        return;
      }
      this.#unregisterWatch(watch);
      const ids = this.#watchPins.get(watch);
      if (ids !== undefined) {
        this.#watchPins.delete(watch);
        this.#unpin(ids);
      }
    },
    repin: (watch) => {
      const old = this.#watchPins.get(watch);
      if (old === undefined) {
        return;
      }
      const next = watch.pinnedIds;
      this.#unpin(old);
      this.#pin(next);
      this.#watchPins.set(watch, next);
    },
  };

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
    this.#version += 1;
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
    let watch = this.#eventCache.get(key);
    if (!watch) {
      watch = new WatchImpl(this.#watchHost, "event", key, () => this.get(key), sameRef, EVENT_IDS);
      this.#eventCache.set(key, watch);
    }
    return watch;
  }

  watchReplaceable(kind: number, pubkey: string, d?: string): Watch<Event | undefined> {
    const address = formatEventAddress(kind, pubkey, d ?? "");
    let watch = this.#addressCache.get(address);
    if (!watch) {
      watch = new WatchImpl(
        this.#watchHost,
        "replaceable",
        address,
        () => this.getByAddress(address),
        sameRef,
        EVENT_IDS,
      );
      this.#addressCache.set(address, watch);
    }
    return watch;
  }

  watchQuery(filters: ReadonlyArray<Filter>): Watch<ReadonlyArray<Event>> {
    const key = filterFingerprint(filters);
    let watch = this.#queryCache.get(key);
    if (!watch) {
      const list = [...filters];
      watch = new WatchImpl(
        this.#watchHost,
        "query",
        key,
        () => this.query(list),
        sameList,
        LIST_IDS,
        list,
      );
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

  /** Synchronous listener for every physical index remove (after watch invalidation). */
  onRemove(listener: (event: Event) => void): () => void {
    this.#removeListeners.add(listener);
    return () => {
      this.#removeListeners.delete(listener);
    };
  }

  #registerWatch(watch: WatchHandle): void {
    switch (watch.kind) {
      case "event":
        addToSetMap(this.#idWatches, watch.key, watch);
        return;
      case "replaceable":
        addToSetMap(this.#addressWatches, watch.key, watch);
        return;
      case "query":
        this.#queryRegistry.add(watch);
    }
  }

  #unregisterWatch(watch: WatchHandle): void {
    switch (watch.kind) {
      case "event":
        removeFromSetMap(this.#idWatches, watch.key, watch);
        if (this.#eventCache.get(watch.key) === watch) {
          this.#eventCache.delete(watch.key);
        }
        return;
      case "replaceable":
        removeFromSetMap(this.#addressWatches, watch.key, watch);
        if (this.#addressCache.get(watch.key) === watch) {
          this.#addressCache.delete(watch.key);
        }
        return;
      case "query":
        this.#queryRegistry.delete(watch);
        if (this.#queryCache.get(watch.key) === watch) {
          this.#queryCache.delete(watch.key);
        }
    }
  }

  #touch(id: string): void {
    this.#recency.delete(id);
    this.#recency.add(id);
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
    trimOldest(this.#seenOn, this.#maxSeenOnEntries);
  }

  #onInsert(event: Event): void {
    this.#version += 1;
    this.#touch(event.id);
    this.#invalidateByEvent(event);
    for (const listener of this.#insertListeners) {
      invokeSafely(() => listener(event));
    }
  }

  #onRemove(event: Event): void {
    this.#version += 1;
    this.#recency.delete(event.id);
    this.#invalidateByEvent(event);
    for (const listener of this.#removeListeners) {
      invokeSafely(() => listener(event));
    }
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
    // A kind-5 deletion marks its targets tombstoned even when they are not in
    // the index, so nothing else invalidates a watch keyed on the target.
    if (event.kind === Kind.EventDeletion) {
      for (const tag of event.tags) {
        if (tag[0] === "e" && tag[1] !== undefined) {
          const watches = this.#idWatches.get(tag[1].toLowerCase());
          if (watches) {
            for (const watch of watches) {
              this.#markDirty(watch);
            }
          }
        } else if (tag[0] === "a" && tag[1] !== undefined) {
          const coord = parseEventAddress(tag[1]);
          if (coord === undefined) {
            continue;
          }
          const watches = this.#addressWatches.get(
            formatEventAddress(coord.kind, coord.pubkey, coord.identifier),
          );
          if (watches) {
            for (const watch of watches) {
              this.#markDirty(watch);
            }
          }
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
    watch.markDirty();
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
          watch.notify();
        }
      }
      this.#flushScheduled = false;
    });
  }

  #pin(ids: ReadonlyArray<string>): void {
    for (const id of ids) {
      this.#pinned.set(id, (this.#pinned.get(id) ?? 0) + 1);
    }
  }

  #unpin(ids: ReadonlyArray<string>): void {
    for (const id of ids) {
      const count = (this.#pinned.get(id) ?? 0) - 1;
      if (count <= 0) {
        this.#pinned.delete(id);
      } else {
        this.#pinned.set(id, count);
      }
    }
  }

  #evictIfNeeded(protectedId?: string): void {
    if (this.#index.size <= this.#maxEvents) {
      return;
    }
    const evicting: string[] = [];
    for (const id of this.#recency) {
      if (this.#index.size - evicting.length <= this.#maxEvents) {
        break;
      }
      if (this.#pinned.has(id) || id === protectedId) {
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
