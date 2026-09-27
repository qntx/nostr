import type { Event } from "./event.ts";
import { isAddressableKind, isReplaceableKind } from "./kind.ts";

/** NIP-01 filter object (immutable-friendly; callers may still pass plain objects). */
export type Filter = {
  readonly ids?: ReadonlyArray<string> | undefined;
  readonly kinds?: ReadonlyArray<number> | undefined;
  readonly authors?: ReadonlyArray<string> | undefined;
  readonly since?: number | undefined;
  readonly until?: number | undefined;
  readonly limit?: number | undefined;
  /** NIP-50 full-text search. Relays interpret this. Local `matchFilter` / `query` ignore it. */
  readonly search?: string | undefined;
  readonly [key: `#${string}`]: ReadonlyArray<string> | undefined;
};

/** Local NIP-01 match. `search` is ignored; relays interpret NIP-50. */
export function matchFilter(filter: Filter, event: Event): boolean {
  if (filter.ids && !filter.ids.some((id) => id.toLowerCase() === event.id)) {
    return false;
  }
  if (filter.kinds && !filter.kinds.includes(event.kind)) {
    return false;
  }
  if (filter.authors && !filter.authors.some((pk) => pk.toLowerCase() === event.pubkey)) {
    return false;
  }

  for (const key of Object.keys(filter)) {
    if (!key.startsWith("#")) {
      continue;
    }
    const tagName = key.slice(1);
    const values = filter[`#${tagName}`];
    if (!values) {
      continue;
    }
    const hexTag = tagName === "e" || tagName === "p";
    const hit = event.tags.some((tag) => {
      const [tagKey, tagValue] = tag;
      if (tagKey !== tagName || tagValue === undefined) {
        return false;
      }
      if (hexTag) {
        return values.some((v) => v.toLowerCase() === tagValue.toLowerCase());
      }
      return values.includes(tagValue);
    });
    if (!hit) {
      return false;
    }
  }

  if (filter.since !== undefined && event.created_at < filter.since) {
    return false;
  }
  if (filter.until !== undefined && event.created_at > filter.until) {
    return false;
  }

  return true;
}

/** True when the event matches any of the filters (NIP-01 OR semantics). */
export function matchFilters(filters: ReadonlyArray<Filter>, event: Event): boolean {
  for (const filter of filters) {
    if (matchFilter(filter, event)) {
      return true;
    }
  }
  return false;
}

/** Merge filters by unioning list fields; returns a new plain object. */
export function mergeFilters(...filters: Filter[]): Filter {
  const result: Record<string, unknown> = {};
  const mergeList = (property: string, values: ReadonlyArray<unknown> | undefined): void => {
    if (values === undefined) {
      return;
    }
    const existing = result[property];
    const list: unknown[] = Array.isArray(existing) ? [...(existing as unknown[])] : [];
    for (const value of values) {
      if (!list.includes(value)) {
        list.push(value);
      }
    }
    result[property] = list;
  };
  const mergeMax = (property: "limit" | "until", value: number | undefined): void => {
    if (value === undefined) {
      return;
    }
    const prev = result[property];
    if (typeof prev !== "number" || value > prev) {
      result[property] = value;
    }
  };
  for (const filter of filters) {
    mergeList("ids", filter.ids);
    mergeList("authors", filter.authors);
    mergeList("kinds", filter.kinds);
    for (const key of Object.keys(filter)) {
      if (!key.startsWith("#")) {
        continue;
      }
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- startsWith("#") above guarantees the template key
      mergeList(key, filter[key as `#${string}`]);
    }
    mergeMax("limit", filter.limit);
    mergeMax("until", filter.until);
    if (filter.since !== undefined) {
      const prev = result["since"];
      if (typeof prev !== "number" || filter.since < prev) {
        result["since"] = filter.since;
      }
    }
    if (filter.search !== undefined) {
      result["search"] = filter.search;
    }
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- built key by key above; the record is filter-shaped by construction
  return result as Filter;
}

/**
 * Intrinsic upper bound implied by the filter alone. Returns a positive integer, or `Infinity` when
 * unbounded.
 */
export function getFilterLimit(filter: Filter): number {
  if (filter.ids && filter.ids.length === 0) {
    return 0;
  }
  if (filter.kinds && filter.kinds.length === 0) {
    return 0;
  }
  if (filter.authors && filter.authors.length === 0) {
    return 0;
  }

  let limit = Number.POSITIVE_INFINITY;
  if (filter.ids) {
    limit = Math.min(limit, filter.ids.length);
  }
  if (filter.limit !== undefined) {
    limit = Math.min(limit, filter.limit);
  }

  if (filter.kinds && filter.authors) {
    const allReplaceable = filter.kinds.every((k) => isReplaceableKind(k) || isAddressableKind(k));
    if (allReplaceable) {
      const dTags = filter["#d"];
      const perAuthor = dTags && dTags.length > 0 ? dTags.length : 1;
      limit = Math.min(limit, filter.authors.length * filter.kinds.length * perAuthor);
    }
  }

  return limit;
}

const HEX_LIST_KEYS = new Set(["ids", "authors", "#e", "#p"]);

/** Lowercase hex lists and sort every array. Omits undefined so `[]` stays distinct from missing. */
export function canonicalizeFilter(filter: Filter): Filter {
  const raw = filter as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(raw).toSorted()) {
    const value = raw[key];
    // omit undefined so a missing key is not `[]` / null
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      if (HEX_LIST_KEYS.has(key)) {
        out[key] = value.map((v) => String(v).toLowerCase()).toSorted();
      } else if (key === "kinds") {
        out[key] = value.map(Number).toSorted((a, b) => a - b);
      } else {
        out[key] = value.map(String).toSorted();
      }
    } else {
      out[key] = value;
    }
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- built key by key above; the record is filter-shaped by construction
  return out as Filter;
}

/** Apply {@link canonicalizeFilter} to each filter. */
export function canonicalizeFilters(filters: ReadonlyArray<Filter>): Filter[] {
  return filters.map(canonicalizeFilter);
}

/**
 * Canonical identity for live REQ coalescing. Relays treat a missing list key as unconstrained and
 * `[]` as match-nothing.
 */
export function filterFingerprint(filters: ReadonlyArray<Filter>): string {
  const parts = filters.map((filter) => JSON.stringify(canonicalizeFilter(filter)));
  parts.sort();
  return `[${parts.join(",")}]`;
}
