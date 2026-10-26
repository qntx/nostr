import { FilterError } from "./error.ts";
import type { Event } from "./event.ts";
import { isAddressableKind, isReplaceableKind } from "./kind.ts";
import { isHex32 } from "./util.ts";

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
  const canonical = canonicalizeFilter(filter);
  const conditions: Array<{ name: string; values: ReadonlyArray<string> }> = [];
  for (const key of Object.keys(canonical)) {
    if (!SINGLE_LETTER_TAG.test(key)) {
      continue;
    }
    const name = key.slice(1);
    const values = canonical[`#${name}`];
    if (values === undefined) {
      continue;
    }
    conditions.push({ name, values });
  }
  return conditions;
}

function compileFilter(filter: Filter): CompiledFilter {
  const canonical = canonicalizeFilter(filter);
  return {
    ids: canonical.ids ? new Set(canonical.ids) : undefined,
    kinds: canonical.kinds ? new Set(canonical.kinds) : undefined,
    authors: canonical.authors ? new Set(canonical.authors) : undefined,
    tags: filterTagConditions(canonical).map(({ name, values }) => ({
      name,
      values: new Set(values),
    })),
    since: canonical.since,
    until: canonical.until,
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
  const f = canonicalizeFilter(filter);
  let limit = Number.POSITIVE_INFINITY;
  if (f.ids) {
    limit = Math.min(limit, new Set(f.ids).size);
  }
  if (f.limit !== undefined) {
    limit = Math.min(limit, f.limit);
  }

  if (f.kinds && f.authors) {
    const kinds = new Set(f.kinds);
    const allReplaceable = [...kinds].every((k) => isReplaceableKind(k) || isAddressableKind(k));
    if (allReplaceable) {
      const dTags = f["#d"];
      const perAuthor = dTags === undefined ? 1 : new Set(dTags).size;
      limit = Math.min(limit, f.authors.length * kinds.size * perAuthor);
    }
  }

  return limit;
}

const HEX_LIST_KEYS = new Set(["ids", "authors", "#e", "#p"]);

/** NIP-01 known fields; everything else (incl. multi-letter `#` keys) is dropped. */
const KNOWN_FILTER_KEYS = new Set(["ids", "authors", "kinds", "since", "until", "limit", "search"]);

/**
 * The caller-input normalizer shared by `matchFilter`, the stores, `encodeClientMessage`,
 * `canonicalizeFilter` and `filterFingerprint`: known fields kept, hex lists lowercased, every list
 * sorted and deduplicated — then validated. Throws {@link FilterError} when any list is empty or
 * when an `ids`/`authors`/`#e`/`#p` value is not 64-hex (the caller-input hex profile: any case in,
 * lowercase out).
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
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) {
        throw new FilterError(`filter ${key} must not be empty`);
      }
      if (HEX_LIST_KEYS.has(key)) {
        const list = [...new Set(value.map((v) => String(v).toLowerCase()))].sort();
        if (!list.every((v) => isHex32(v))) {
          throw new FilterError(`filter ${key} values must be 64-char hex`);
        }
        out[key] = list;
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
 * Canonical identity for live REQ coalescing. Filters carry no empty list fields —
 * `canonicalizeFilter` rejects them.
 */
export function filterFingerprint(filters: ReadonlyArray<Filter>): string {
  const parts = filters.map((filter) => JSON.stringify(canonicalizeFilter(filter)));
  parts.sort();
  return `[${parts.join(",")}]`;
}
