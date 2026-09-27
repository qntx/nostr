import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { MemoryIndex } from "./memory-index.ts";
import type { EventStore, NegentropyItem, OutboxBound, PutResult } from "./types.ts";

/** In-memory event store: async {@link EventStore} facade over the synchronous {@link MemoryIndex}. */
export class MemoryEventStore implements EventStore {
  readonly #index = new MemoryIndex();

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async put(raw: Event): Promise<PutResult> {
    return this.#index.put(raw);
  }

  /** Sequential `put` in input order. No transaction: a throw leaves earlier events applied. */
  async putMany(events: ReadonlyArray<Event>): Promise<PutResult[]> {
    const results: PutResult[] = [];
    for (const event of events) {
      // oxlint-disable-next-line no-await-in-loop -- putMany applies puts sequentially in input order
      results.push(await this.put(event));
    }
    return results;
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async get(id: string): Promise<Event | undefined> {
    return this.#index.get(id);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async query(filters: Filter[]): Promise<Event[]> {
    return this.#index.query(filters);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async count(filters: Filter[]): Promise<number> {
    return this.#index.count(filters);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async negentropyItems(filter: Filter): Promise<NegentropyItem[]> {
    return this.#index.negentropyItems(filter);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async remove(ids: string[]): Promise<number> {
    return this.#index.remove(ids);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async getOutboxBound(pubkey: string, kind: number): Promise<OutboxBound | undefined> {
    return this.#index.getOutboxBound(pubkey, kind);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async setOutboxBound(pubkey: string, kind: number, bound: OutboxBound): Promise<void> {
    this.#index.setOutboxBound(pubkey, kind, bound);
  }

  // oxlint-disable-next-line typescript/require-await -- EventStore is async; MemoryIndex is synchronous
  async clear(): Promise<void> {
    this.#index.clear();
  }

  get size(): number {
    return this.#index.size;
  }
}
