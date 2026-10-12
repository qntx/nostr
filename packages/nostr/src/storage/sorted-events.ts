import type { Event } from "../core/event.ts";

/**
 * Chunk bounds: a chunk splice moves at most `CHUNK_MAX` element refs and a chunk merge at
 * `CHUNK_MIN` keeps chunk count proportional to `size` under removals.
 */
const CHUNK_MAX = 1024;
const CHUNK_MIN = 128;

/** Reverse of `compareEventsDesc`: `created_at` asc, `id` desc — the physical chunk order. */
function compareAsc(
  a: { id: string; created_at: number },
  b: { id: string; created_at: number },
): number {
  if (a.created_at !== b.created_at) {
    return a.created_at - b.created_at;
  }
  if (a.id < b.id) {
    return 1;
  }
  if (a.id > b.id) {
    return -1;
  }
  return 0;
}

function mid(lo: number, hi: number): number {
  return lo + Math.floor((hi - lo) / 2);
}

/** A read cursor over a `SortedEvents` range in canonical order; `value` is the current event. */
export class EventCursor {
  readonly #chunks: Event[][];
  #chunk: number;
  #index: number;
  readonly #endChunk: number;
  readonly #endIndex: number;

  constructor(chunks: Event[][], chunk: number, index: number, endChunk: number, endIndex: number) {
    this.#chunks = chunks;
    this.#chunk = chunk;
    this.#index = index;
    this.#endChunk = endChunk;
    this.#endIndex = endIndex;
  }

  get value(): Event | undefined {
    const chunk = this.#chunk;
    const index = this.#index;
    if (chunk < this.#endChunk || (chunk === this.#endChunk && index <= this.#endIndex)) {
      return undefined;
    }
    return this.#chunks[chunk]?.[index];
  }

  next(): void {
    this.#index -= 1;
    if (this.#index < 0) {
      this.#chunk -= 1;
      this.#index = (this.#chunks[this.#chunk]?.length ?? 1) - 1;
    }
  }
}

/**
 * Event refs sorted in canonical order (`compareEventsDesc`: `created_at` desc, `id` asc) stored as
 * chunks of ≤ `CHUNK_MAX` elements in ascending physical order so insertion and removal
 * binary-search a chunk and then move a bounded number of refs — appending newer events (live
 * ingest, ascending fills) pushes at the end, and appending older ones (relay backfill) moves at
 * most one chunk's worth of refs. Internal to the memory index; not exported.
 */
export class SortedEvents {
  #chunks: Event[][] = [];
  #size = 0;

  get size(): number {
    return this.#size;
  }

  clear(): void {
    this.#chunks = [];
    this.#size = 0;
  }

  /** Index of the chunk `event` belongs to: the last one whose first element is not newer. */
  #chunkOf(event: Event): number {
    const chunks = this.#chunks;
    let lo = 0;
    let hi = chunks.length;
    while (lo < hi) {
      const m = mid(lo, hi);
      const first = chunks[m]?.[0];
      if (first !== undefined && compareAsc(first, event) <= 0) {
        lo = m + 1;
      } else {
        hi = m;
      }
    }
    return lo - 1;
  }

  insert(event: Event): void {
    const chunks = this.#chunks;
    if (chunks.length === 0) {
      chunks.push([event]);
      this.#size = 1;
      return;
    }
    const chunkIndex = Math.max(this.#chunkOf(event), 0);
    const chunk = chunks[chunkIndex];
    if (chunk === undefined) {
      return;
    }
    // Upper bound inside the chunk: insert after all elements that sort before `event`.
    let a = 0;
    let b = chunk.length;
    while (a < b) {
      const m = mid(a, b);
      const element = chunk[m];
      if (element !== undefined && compareAsc(element, event) <= 0) {
        a = m + 1;
      } else {
        b = m;
      }
    }
    chunk.splice(a, 0, event);
    this.#size += 1;
    if (chunk.length > CHUNK_MAX) {
      const half = chunk.splice(Math.floor(CHUNK_MAX / 2));
      chunks.splice(chunkIndex + 1, 0, half);
    }
  }

  remove(event: Event): boolean {
    const chunks = this.#chunks;
    const chunkIndex = this.#chunkOf(event);
    if (chunkIndex < 0) {
      return false;
    }
    const chunk = chunks[chunkIndex];
    if (chunk === undefined) {
      return false;
    }
    let a = 0;
    let b = chunk.length;
    while (a < b) {
      const m = mid(a, b);
      const element = chunk[m];
      if (element !== undefined && compareAsc(element, event) < 0) {
        a = m + 1;
      } else {
        b = m;
      }
    }
    const found = chunk[a];
    if (found === undefined || compareAsc(found, event) !== 0) {
      return false;
    }
    chunk.splice(a, 1);
    this.#size -= 1;
    if (chunk.length === 0) {
      chunks.splice(chunkIndex, 1);
    } else if (chunk.length < CHUNK_MIN) {
      // Absorb a thin chunk into a neighbor when it fits; a small chunk left between
      // fuller ones is still sorted and correct.
      const next = chunks[chunkIndex + 1];
      const prev = chunks[chunkIndex - 1];
      if (next !== undefined && chunk.length + next.length <= CHUNK_MAX) {
        chunk.push(...next);
        chunks.splice(chunkIndex + 1, 1);
      } else if (prev !== undefined && prev.length + chunk.length <= CHUNK_MAX) {
        prev.push(...chunk);
        chunks.splice(chunkIndex, 1);
      }
    }
    return true;
  }

  /**
   * Cursor over the [since, until] `created_at` window in canonical (desc) order: iteration starts
   * at the newest element with `created_at <= until` and stops before the first with `created_at <
   * since`. Chunks and their elements are stored ascending; the cursor walks back.
   */
  cursor(since?: number, until?: number): EventCursor {
    const chunks = this.#chunks;
    // Start position: last element with created_at <= until.
    let chunk = chunks.length - 1;
    let index = -1;
    if (until === undefined) {
      index = (chunks[chunk]?.length ?? 1) - 1;
    } else {
      // Last chunk holding an element with created_at <= until.
      let lo = 0;
      let hi = chunks.length;
      while (lo < hi) {
        const m = mid(lo, hi);
        const first = chunks[m]?.[0];
        if (first !== undefined && first.created_at <= until) {
          lo = m + 1;
        } else {
          hi = m;
        }
      }
      chunk = lo - 1;
      if (chunk >= 0) {
        const bucket = chunks[chunk];
        let a = 0;
        let b = bucket?.length ?? 0;
        while (a < b) {
          const m = mid(a, b);
          const element = bucket?.[m];
          if (element !== undefined && element.created_at <= until) {
            a = m + 1;
          } else {
            b = m;
          }
        }
        index = a - 1;
      }
    }
    // End position: last element with created_at < since (walk stops once past it).
    let endChunk = -1;
    let endIndex = -1;
    if (since !== undefined) {
      // First chunk holding an element with created_at >= since; the position before the
      // first such element is the boundary.
      let lo = 0;
      let hi = chunks.length;
      while (lo < hi) {
        const m = mid(lo, hi);
        const bucket = chunks[m];
        const last = bucket?.at(-1);
        if (last !== undefined && last.created_at >= since) {
          hi = m;
        } else {
          lo = m + 1;
        }
      }
      if (lo === chunks.length) {
        // Everything is older than since: empty range.
        endChunk = Number.MAX_SAFE_INTEGER;
      } else {
        const bucket = chunks[lo];
        let a = 0;
        let b = bucket?.length ?? 0;
        while (a < b) {
          const m = mid(a, b);
          const element = bucket?.[m];
          if (element !== undefined && element.created_at >= since) {
            b = m;
          } else {
            a = m + 1;
          }
        }
        if (a === 0) {
          endChunk = lo - 1;
          endIndex = (chunks[endChunk]?.length ?? 1) - 1;
        } else {
          endChunk = lo;
          endIndex = a - 1;
        }
      }
    }
    return new EventCursor(chunks, chunk, index, endChunk, endIndex);
  }
}
