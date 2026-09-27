import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { createSubscriptionId } from "../core/message.ts";
import { invokeSafely } from "../core/report.ts";
import { RelayClosedError } from "./error.ts";

export type SubscriptionHandlers = {
  onevent?: ((event: Event) => void) | undefined;
  oneose?: (() => void) | undefined;
  onclose?: ((reason: string) => void) | undefined;
  /** Skip verify + onevent when true. Evaluated after parse, before verify. */
  alreadyHaveEvent?: ((id: string) => boolean) | undefined;
  /**
   * Fired for every EVENT id this sub sees, including duplicates and alreadyHaveEvent hits, after
   * parse and before the verify skip.
   */
  receivedEvent?: ((id: string) => void) | undefined;
};

/** Options for {@link Relay.subscribe}: event handlers plus REQ behavior. */
export type SubscribeOptions = SubscriptionHandlers & {
  id?: string | undefined;
  /**
   * If set, fire `oneose` once after this many ms if EOSE has not arrived. Does not close the REQ.
   * `Relay.fetch` is the one-shot closer.
   */
  eoseTimeoutMs?: number | undefined;
  /**
   * One-shot REQ: do not join a live coalescing group, and close on EOSE. Default false (live).
   * `Relay.fetch` passes true.
   */
  closeOnEose?: boolean | undefined;
  signal?: AbortSignal | undefined;
};

export class Subscription {
  readonly id: string;
  readonly filters: Filter[];
  readonly handlers: SubscriptionHandlers;
  readonly closeOnEose: boolean;
  eosed = false;
  closed = false;
  /** True after one CLOSED `auth-required:` retry. */
  authRetried = false;
  /** Inclusive NIP-01 `since` watermark from verified EVENTs. */
  lastCreatedAt: number | undefined;
  /** Event ids at `lastCreatedAt` (same-second reconnect dedup). Not all seen ids. */
  readonly idsAtWatermark: Set<string> = new Set<string>();
  readonly #sendClose: (id: string) => void;
  readonly #abort: (() => void) | undefined;

  constructor(filters: Filter[], opts: SubscribeOptions, sendClose: (id: string) => void) {
    this.#sendClose = sendClose;
    this.id = createSubscriptionId(opts.id);
    this.filters = filters;
    this.closeOnEose = opts.closeOnEose === true;
    this.handlers = {
      onevent: opts.onevent,
      oneose: opts.oneose,
      onclose: opts.onclose,
      alreadyHaveEvent: opts.alreadyHaveEvent,
      receivedEvent: opts.receivedEvent,
    };

    if (opts.signal) {
      if (opts.signal.aborted) {
        this.close("aborted");
      } else {
        const onAbort = () => this.close("aborted");
        opts.signal.addEventListener("abort", onAbort, { once: true });
        this.#abort = () => opts.signal?.removeEventListener("abort", onAbort);
      }
    }
  }

  close(reason = "closed by client"): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.#abort?.();
    this.#sendClose(this.id);
    invokeSafely(() => this.handlers.onclose?.(reason));
  }

  /** Advance the reconnect watermark after a verified EVENT. */
  noteVerified(event: Event): void {
    if (this.lastCreatedAt === undefined || event.created_at > this.lastCreatedAt) {
      this.lastCreatedAt = event.created_at;
      this.idsAtWatermark.clear();
      this.idsAtWatermark.add(event.id);
      return;
    }
    if (event.created_at === this.lastCreatedAt) {
      this.idsAtWatermark.add(event.id);
    }
  }

  /**
   * Filters for re-REQ. Original `filters` stay unchanged. NIP-01 `since` is inclusive — never
   * `lastCreatedAt + 1`.
   */
  replayFilters(): Filter[] {
    const since = this.lastCreatedAt;
    if (since === undefined) {
      return this.filters;
    }
    return this.filters.map((f) => ({
      ...f,
      since: f.since === undefined ? since : Math.max(f.since, since),
    }));
  }
}

/** AsyncIterable wrapper over a subscription's events until EOSE or close. */
export function subscriptionToAsyncIterable(
  start: (handlers: SubscriptionHandlers) => { close: (reason?: string) => void },
  opts?: { signal?: AbortSignal | undefined; includeEose?: boolean | undefined },
): AsyncIterable<Event> & { close: (reason?: string) => void } {
  const queue: Event[] = [];
  let done = false;
  let error: Error | undefined;
  let wake: (() => void) | undefined;
  // `let` is required: onclose can fire synchronously while start() is still assigning closer.
  // oxlint-disable-next-line prefer-const
  let closer: { close: (reason?: string) => void } | undefined;
  // Set before every locally initiated close so onclose can distinguish it
  // from a remote/transport close without comparing reason strings.
  let localClose = false;

  const notify = () => {
    wake?.();
    wake = undefined;
  };

  const waitForWake = async (): Promise<void> =>
    new Promise<void>((resolve) => {
      wake = resolve;
    });

  const closeLocal = (reason: string): void => {
    localClose = true;
    closer?.close(reason);
    done = true;
    notify();
  };

  closer = start({
    onevent(event) {
      queue.push(event);
      notify();
    },
    oneose() {
      if (opts?.includeEose === false) {
        closeLocal("eose");
      }
    },
    onclose(reason) {
      // The Subscription's own abort listener fires before this wrapper's,
      // so a signal-driven close can surface here while localClose is still
      // false — it is still a local close, not a remote one.
      if (opts?.signal?.aborted === true) {
        localClose = true;
      }
      if (!localClose && reason) {
        error = new RelayClosedError(reason);
      }
      done = true;
      notify();
    },
  });

  if (opts?.signal) {
    if (opts.signal.aborted) {
      closeLocal("aborted");
    } else {
      opts.signal.addEventListener("abort", () => closeLocal("aborted"), { once: true });
    }
  }

  return {
    close(reason?: string) {
      closeLocal(reason ?? "closed by client");
    },
    [Symbol.asyncIterator]() {
      return {
        async next(): Promise<IteratorResult<Event>> {
          while (true) {
            const value = queue.shift();
            if (value !== undefined) {
              return { value, done: false };
            }
            if (error !== undefined) {
              throw error;
            }
            if (done) {
              return { value: undefined, done: true };
            }
            // oxlint-disable-next-line no-await-in-loop -- the async iterator waits for each EVENT serially
            await waitForWake();
          }
        },
        // oxlint-disable-next-line typescript/require-await -- AsyncIterator.return must be async-shaped though cleanup is synchronous
        async return(): Promise<IteratorResult<Event>> {
          closeLocal("iterator returned");
          return { value: undefined, done: true };
        },
      };
    },
  };
}
