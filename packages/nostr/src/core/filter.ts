import type { Event } from "./event.ts";
import { isAddressableKind, isReplaceableKind } from "./kind.ts";

/**
 * NIP-01 filter object (immutable-friendly; callers may still pass plain objects). Filters are
 * treated as immutable once used: `matchFilter` and the event stores cache a compiled form keyed on
 * the object, so mutating a filter after it has been matched yields stale results.
 */
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

/** NIP-01 only defines single-letter tag conditions. */
const SINGLE_LETTER_TAG = /^#[a-zA-Z]$/;

type CompiledTagCondition = {
  readonly name: string;
  readonly values: ReadonlySet<string>;
};

/** `matchFilter` condition form: `Set` lookups instead of per-element scans and `toLowerCase`. */
type CompiledFilter = {
  readonly ids: ReadonlySet<string> | undefined;
  readonly kinds: ReadonlySet<number> | undefined;
  readonly authors: ReadonlySet<string> | undefined;
  readonly tags: ReadonlyArray<CompiledTagCondition>;
  readonly since: number | undefined;
  readonly until: number | undefined;
};

const compiledFilters = new WeakMap<Filter, CompiledFilter>();

/**
 * Single-letter `#x` conditions shared by `matchFilter` and the event stores: `#e`/`#p` values are
 * lowercased (they hold hex ids, same as `encodeClientMessage`), other tag values stay verbatim —
 * relays match tag values literally. Multi-letter `#` keys are outside NIP-01. Internal to the
 * package; not exported from the index.
 */
export function filterTagConditions(
  filter: Filter,
): Array<{ name: string; values: ReadonlyArray<string> }> {
  const conditions: Array<{ name: string; values: ReadonlyArray<string> }> = [];
  for (const key of Object.keys(filter)) {
    if (!SINGLE_LETTER_TAG.test(key)) {
      continue;
    }
    const name = key.slice(1);
    const values = filter[`#${name}`];
    if (values === undefined) {
      continue;
    }
    conditions.push({
      name,
      values: name === "e" || name === "p" ? values.map((v) => v.toLowerCase()) : values,
    });
  }
  return conditions;
}

function compileFilter(filter: Filter): CompiledFilter {
  return {
    ids: filter.ids ? new Set(filter.ids.map((id) => id.toLowerCase())) : undefined,
    kinds: filter.kinds ? new Set(filter.kinds) : undefined,
    authors: filter.authors ? new Set(filter.authors.map((pk) => pk.toLowerCase())) : undefined,
    tags: filterTagConditions(filter).map(({ name, values }) => ({
      name,
      values: new Set(values),
    })),
    since: filter.since,
    until: filter.until,
  };
}

/** Local NIP-01 match. `search` is ignored; relays interpret NIP-50. */
export function matchFilter(filter: Filter, event: Event): boolean {
  let compiled = compiledFilters.get(filter);
  if (compiled === undefined) {
    compiled = compileFilter(filter);
    compiledFilters.set(filter, compiled);
  }
  if (compiled.ids !== undefined && !compiled.ids.has(event.id)) {
    return false;
  }
  if (compiled.kinds !== undefined && !compiled.kinds.has(event.kind)) {
    return false;
  }
  if (compiled.authors !== undefined && !compiled.authors.has(event.pubkey)) {
    return false;
  }

  for (const { name, values } of compiled.tags) {
    const hit = event.tags.some((tag) => {
      const [tagKey, tagValue] = tag;
      return tagKey === name && tagValue !== undefined && values.has(tagValue);
    });
    if (!hit) {
      return false;
    }
  }

  if (compiled.since !== undefined && event.created_at < compiled.since) {
    return false;
  }
  if (compiled.until !== undefined && event.created_at > compiled.until) {
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
    limit = Math.min(limit, new Set(filter.ids.map((id) => id.toLowerCase())).size);
  }
  if (filter.limit !== undefined) {
    limit = Math.min(limit, filter.limit);
  }

  if (filter.kinds && filter.authors) {
    const kinds = new Set(filter.kinds);
    const allReplaceable = [...kinds].every((k) => isReplaceableKind(k) || isAddressableKind(k));
    if (allReplaceable) {
      const dTags = filter["#d"];
      const perAuthor = dTags && dTags.length > 0 ? new Set(dTags).size : 1;
      const authors = new Set(filter.authors.map((pk) => pk.toLowerCase())).size;
      limit = Math.min(limit, authors * kinds.size * perAuthor);
    }
  }

  return limit;
}

const HEX_LIST_KEYS = new Set(["ids", "authors", "#e", "#p"]);

/** NIP-01 known fields; everything else (incl. multi-letter `#` keys) is dropped. */
const KNOWN_FILTER_KEYS = new Set(["ids", "authors", "kinds", "since", "until", "limit", "search"]);

/**
 * Lowercase hex lists, sort and dedupe every array, and keep only the NIP-01 known fields plus
 * single-letter `#` keys — unknown keys and multi-letter `#` keys are dropped. Omits undefined so
 * `[]` stays distinct from missing.
 */
export function canonicalizeFilter(filter: Filter): Filter {
  const raw = filter as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(raw).sort()) {
    if (key.startsWith("#")) {
      if (!SINGLE_LETTER_TAG.test(key)) {
        continue;
      }
    } else if (!KNOWN_FILTER_KEYS.has(key)) {
      continue;
    }
    const value = raw[key];
    // omit undefined so a missing key is not `[]` / null
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      if (HEX_LIST_KEYS.has(key)) {
        out[key] = [...new Set(value.map((v) => String(v).toLowerCase()))].sort();
      } else if (key === "kinds") {
        out[key] = [...new Set(value.map(Number))].sort((a, b) => a - b);
      } else {
        out[key] = [...new Set(value.map(String))].sort();
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
