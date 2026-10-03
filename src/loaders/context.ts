import type { Event } from "../core/event.ts";
import { nowSeconds } from "../core/util.ts";
import type { Pool } from "../relay/pool.ts";
import { DEFAULT_REQUEST_TIMEOUT_MS } from "../relay/relay.ts";
import type { ReactiveEventStore } from "../store/reactive.ts";

export type LoaderContextOptions = {
  pool: Pool;
  /** Fallback / discovery relays when no per-user routing is known. */
  relays: ReadonlyArray<string>;
  /** The reactive index loaders read from and feed fetched events into. */
  index: ReactiveEventStore;
  /**
   * Inbound-event sink for fetched events. Defaults to `index.add`; Client supplies its single
   * ingest path so loader fetches get gossip meta and persistence like every other inbound event.
   */
  ingest?: ((event: Event, relayUrl: string) => void) | undefined;
  /** Max age (seconds) before a fetched replaceable is considered stale. Default 2 days. */
  staleAfterSec?: number | undefined;
  fetchTimeoutMs?: number | undefined;
};

/** Internal dependency bag for loaders — never a module-level singleton. */
export class LoaderContext {
  readonly pool: Pool;
  readonly index: ReactiveEventStore;
  readonly ingest: (event: Event, relayUrl: string) => void;
  readonly staleAfterSec: number;
  readonly fetchTimeoutMs: number;
  #relays: string[];

  constructor(opts: LoaderContextOptions) {
    this.pool = opts.pool;
    this.#relays = [...opts.relays];
    this.index = opts.index;
    this.ingest = opts.ingest ?? ((event, relayUrl) => this.index.add(event, relayUrl));
    this.staleAfterSec = opts.staleAfterSec ?? 60 * 60 * 24 * 2;
    this.fetchTimeoutMs = opts.fetchTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  /** Snapshot of discovery/fallback relays. */
  get relays(): ReadonlyArray<string> {
    return this.#relays;
  }

  addRelay(url: string): void {
    if (!this.#relays.includes(url)) {
      this.#relays.push(url);
    }
  }

  removeRelay(url: string): void {
    this.#relays = this.#relays.filter((r) => r !== url);
  }

  setRelays(urls: ReadonlyArray<string>): void {
    this.#relays = [...urls];
  }

  isFresh(fetchedAt: number, now: number = nowSeconds()): boolean {
    return now - fetchedAt < this.staleAfterSec;
  }
}
