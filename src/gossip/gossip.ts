import { touchKey, trimOldest } from "../core/collections.ts";
import type { Event } from "../core/event.ts";
import { isReplaceableWinner } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { Kind } from "../core/kind.ts";
import { normalizeRelayUrls, normalizeURL, nowSeconds } from "../core/util.ts";
import { parseDmRelayList } from "../nips/nip17.ts";
import { parseRelayList } from "../nips/nip65.ts";
import type { RelayListItem } from "../nips/nip65.ts";

/** Relay routing state for one pubkey: NIP-65 outbox/inbox plus NIP-17 DM relays. */
export type PubkeyRoutes = {
  /** Relays the user writes to (outbox). NIP-65. */
  readonly write: ReadonlyArray<string>;
  /** Relays the user reads from (inbox). NIP-65. */
  readonly read: ReadonlyArray<string>;
  /** Relays for NIP-17 gift-wrap delivery. Kind 10050. */
  readonly dm: ReadonlyArray<string>;
  /** `created_at` of the last accepted kind:10002 list. */
  readonly updatedAt: number;
  /** `created_at` of the last accepted kind:10050 list. */
  readonly dmUpdatedAt: number;
  /** Event id of the last accepted kind:10002 (NIP-01 equal-timestamp tie-break). */
  readonly relayListId?: string | undefined;
  /** Event id of the last accepted kind:10050. */
  readonly dmListId?: string | undefined;
};

/** A filter split by gossip routes: per-relay narrowed filters plus the unrouted remainder. */
export type RoutedFilter = {
  /** Url → already-narrowed filter. Empty when nothing routed. */
  perRelay: Map<string, Filter>;
  /**
   * Unrouted work for the caller:
   *
   * - No authors and no #p: original filter ("generic")
   * - Authors/#p all unrouted: original filter ("orphan")
   * - Mixed: narrowed leftover ("fallback")
   * - All routed: undefined
   */
  remainder?: Filter;
};

export type GossipOptions = {
  /** Max relays to keep per direction when ranking. Default 4. */
  maxRelaysPerPubkey?: number | undefined;
  /**
   * Max pubkeys with tracked routes; the map is LRU — writes and lookups refresh recency, and
   * inserting beyond the cap drops the oldest entry. Default 10_000.
   */
  maxPubkeys?: number | undefined;
};

function emptyRoutes(): PubkeyRoutes {
  return {
    write: [],
    read: [],
    dm: [],
    updatedAt: 0,
    dmUpdatedAt: 0,
  };
}

/**
 * Routing table for NIP-65 (10002) and NIP-17 DM relays (10050). Ingest replaceable list events,
 * then route filters into per-relay REQs.
 */
export class Gossip {
  readonly #routes = new Map<string, PubkeyRoutes>();
  readonly #maxRelays: number;
  readonly #maxPubkeys: number;

  constructor(opts: GossipOptions = {}) {
    this.#maxRelays = opts.maxRelaysPerPubkey ?? 4;
    this.#maxPubkeys = opts.maxPubkeys ?? 10_000;
  }

  /**
   * Ingest a routing list event.
   *
   * - Kind:10002 → write/read (NIP-65)
   * - Kind:10050 → dm (NIP-17)
   *
   * Returns true if routes for that list type were updated.
   */
  ingest(event: Event): boolean {
    if (event.kind === Kind.RelayList) {
      let items: RelayListItem[];
      try {
        items = parseRelayList(event);
      } catch {
        return false;
      }
      return this.setRoutes(event.pubkey, items, event.created_at, event.id);
    }
    if (event.kind === Kind.DirectMessageRelaysList) {
      let relays: string[];
      try {
        relays = parseDmRelayList(event);
      } catch {
        return false;
      }
      return this.setDmRoutes(event.pubkey, relays, event.created_at, event.id);
    }
    return false;
  }

  setRoutes(
    pubkey: string,
    items: ReadonlyArray<RelayListItem>,
    updatedAt: number = nowSeconds(),
    eventId?: string,
  ): boolean {
    const pk = pubkey.toLowerCase();
    const prev = this.#lookup(pk) ?? emptyRoutes();
    if (prev.updatedAt > updatedAt) {
      return false;
    }
    if (
      eventId !== undefined &&
      prev.relayListId !== undefined &&
      prev.updatedAt === updatedAt &&
      !isReplaceableWinner(
        { created_at: updatedAt, id: eventId },
        { created_at: prev.updatedAt, id: prev.relayListId },
      )
    ) {
      return false;
    }

    const write: string[] = [];
    const read: string[] = [];
    for (const item of items) {
      let url: string;
      try {
        url = normalizeURL(item.url);
      } catch {
        continue;
      }
      if (item.marker !== "read" && !write.includes(url)) {
        write.push(url);
      }
      if (item.marker !== "write" && !read.includes(url)) {
        read.push(url);
      }
    }

    this.#put(pk, {
      write: write.slice(0, this.#maxRelays),
      read: read.slice(0, this.#maxRelays),
      dm: prev.dm,
      updatedAt,
      dmUpdatedAt: prev.dmUpdatedAt,
      relayListId: eventId ?? prev.relayListId,
      dmListId: prev.dmListId,
    });
    return true;
  }

  setDmRoutes(
    pubkey: string,
    relays: ReadonlyArray<string>,
    updatedAt: number = nowSeconds(),
    eventId?: string,
  ): boolean {
    const pk = pubkey.toLowerCase();
    const prev = this.#lookup(pk) ?? emptyRoutes();
    if (prev.dmUpdatedAt > updatedAt) {
      return false;
    }
    if (
      eventId !== undefined &&
      prev.dmListId !== undefined &&
      prev.dmUpdatedAt === updatedAt &&
      !isReplaceableWinner(
        { created_at: updatedAt, id: eventId },
        { created_at: prev.dmUpdatedAt, id: prev.dmListId },
      )
    ) {
      return false;
    }

    const dm = normalizeRelayUrls(relays);

    this.#put(pk, {
      write: prev.write,
      read: prev.read,
      dm: dm.slice(0, this.#maxRelays),
      updatedAt: prev.updatedAt,
      dmUpdatedAt: updatedAt,
      relayListId: prev.relayListId,
      dmListId: eventId ?? prev.dmListId,
    });
    return true;
  }

  getRoutes(pubkey: string): Readonly<PubkeyRoutes> | undefined {
    return this.#lookup(pubkey.toLowerCase());
  }

  outboxRelays(pubkey: string): ReadonlyArray<string> {
    return this.#lookup(pubkey.toLowerCase())?.write ?? [];
  }

  inboxRelays(pubkey: string): ReadonlyArray<string> {
    return this.#lookup(pubkey.toLowerCase())?.read ?? [];
  }

  /** NIP-17 kind:10050 delivery relays for gift-wraps. */
  dmRelays(pubkey: string): ReadonlyArray<string> {
    return this.#lookup(pubkey.toLowerCase())?.dm ?? [];
  }

  clear(pubkey?: string): void {
    if (pubkey !== undefined && pubkey !== "") {
      this.#routes.delete(pubkey.toLowerCase());
    } else {
      this.#routes.clear();
    }
  }

  get size(): number {
    return this.#routes.size;
  }

  /**
   * Route a user-facing filter into per-relay sub-filters plus leftover.
   *
   * - Authors → outbox relays, filter narrowed per relay's authors
   * - #p only → inbox relays of those pubkeys
   * - Neither / all unrouted → remainder is the original filter
   * - Mixed → remainder is the narrowed leftover; all routed → no remainder
   */
  route(filter: Filter): RoutedFilter {
    const authors = filter.authors?.map((a) => a.toLowerCase());
    const pTags = filter["#p"]?.map((p) => p.toLowerCase());

    if ((!authors || authors.length === 0) && (!pTags || pTags.length === 0)) {
      return { perRelay: new Map(), remainder: filter };
    }

    if (authors && authors.length > 0 && (!pTags || pTags.length === 0)) {
      return this.#breakAuthors(filter, authors, "write");
    }

    if (pTags && pTags.length > 0 && (!authors || authors.length === 0)) {
      const { authors: _authors, ...base } = filter;
      return this.#breakAuthors(base, pTags, "read", (b, pubkeys) => ({ ...b, "#p": pubkeys }));
    }

    // both authors and #p: send full filter to union of routes
    const unionKeys = new Set([...(authors ?? []), ...(pTags ?? [])]);
    const relays = new Set<string>();
    let anyUnrouted = false;
    for (const pk of unionKeys) {
      const r = this.#lookup(pk);
      const urls = r ? [...r.write, ...r.read] : [];
      if (urls.length === 0) {
        anyUnrouted = true;
        continue;
      }
      for (const u of urls) {
        relays.add(u);
      }
    }
    if (relays.size === 0) {
      return { perRelay: new Map(), remainder: filter };
    }
    const map = new Map<string, Filter>();
    for (const url of relays) {
      map.set(url, { ...filter });
    }
    return anyUnrouted ? { perRelay: map, remainder: filter } : { perRelay: map };
  }

  #breakAuthors(
    filter: Filter,
    pubkeys: string[],
    direction: "read" | "write",
    narrow: (base: Filter, pubkeys: string[]) => Filter = (base, pks) => ({
      ...base,
      authors: pks,
    }),
  ): RoutedFilter {
    const perRelay = new Map<string, string[]>();
    const unrouted: string[] = [];
    let anyRoute = false;

    for (const pk of pubkeys) {
      const routes = this.#lookup(pk);
      const urls = direction === "write" ? routes?.write : routes?.read;
      if (!urls || urls.length === 0) {
        unrouted.push(pk);
        continue;
      }
      anyRoute = true;
      for (const url of urls) {
        const list = perRelay.get(url) ?? [];
        list.push(pk);
        perRelay.set(url, list);
      }
    }

    if (!anyRoute) {
      return { perRelay: new Map(), remainder: filter };
    }

    const map = new Map<string, Filter>();
    for (const [url, pks] of perRelay) {
      map.set(url, narrow(filter, pks));
    }
    return unrouted.length > 0
      ? { perRelay: map, remainder: narrow(filter, unrouted) }
      : { perRelay: map };
  }

  /** Read that refreshes LRU recency. */
  #lookup(pk: string): PubkeyRoutes | undefined {
    const routes = this.#routes.get(pk);
    if (routes !== undefined) {
      touchKey(this.#routes, pk, routes);
    }
    return routes;
  }

  /** Write at the newest LRU end, then trim the oldest beyond the cap. */
  #put(pk: string, routes: PubkeyRoutes): void {
    touchKey(this.#routes, pk, routes);
    trimOldest(this.#routes, this.#maxPubkeys);
  }
}
