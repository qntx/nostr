import { onAbort } from "../core/abort.ts";
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
   * If set, fire `oneose` once after this many ms if EOSE has not arrived. The synthesized EOSE
   * also closes a `closeOnEose` subscription — without it a one-shot REQ would hang until a real
   * EOSE that is then ignored.
   */
  eoseTimeoutMs?: number | undefined;
  /**
   * One-shot REQ: do not join a live coalescing group, and close on EOSE. Default false (live).
   * `Relay.fetch` passes true.
   */
  closeOnEose?: boolean | undefined;
  signal?: AbortSignal | undefined;
};

/** Uniform close handle returned by subscriptions, fan-ins, and feeds. */
export type Closer = { close: (reason?: string) => void };

/** Public subscription handle returned by {@link Relay.subscribe}. */
export type RelaySubscription = {
  readonly id: string;
  readonly closed: boolean;
  close: (reason?: string) => void;
};

/**
 * Internal REQ runtime: owns its lifecycle flags, watermark bookkeeping and handler dispatch.
 * `onLocalClose` is supplied by the registry — it sends CLOSE / detaches from a live group — and is
 * invoked by {@link close} only, never by {@link end}.
 */
export class Subscription {
  readonly id: string;
  readonly filters: ReadonlyArray<Filter>;
  readonly closeOnEose: boolean;
  readonly #handlers: SubscriptionHandlers;
  readonly #onLocalClose: (sub: Subscription) => void;
  #abortDispose: (() => void) | undefined;
  #eoseTimer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  #eosed = false;
  /** True after one CLOSED `auth-required:` retry. */
  #authRetried = false;
  /** Inclusive NIP-01 `since` watermark from verified EVENTs. */
  #lastCreatedAt: number | undefined;
  /** Event ids at `lastCreatedAt` (same-second reconnect dedup). Not all seen ids. */
  readonly #idsAtWatermark = new Set<string>();

  constructor(
    filters: ReadonlyArray<Filter>,
    opts: SubscribeOptions,
    onLocalClose: (sub: Subscription) => void,
  ) {
    this.#onLocalClose = onLocalClose;
    this.id = createSubscriptionId(opts.id);
    this.filters = filters;
    this.closeOnEose = opts.closeOnEose === true;
    this.#handlers = {
      onevent: opts.onevent,
      oneose: opts.oneose,
      onclose: opts.onclose,
      alreadyHaveEvent: opts.alreadyHaveEvent,
      receivedEvent: opts.receivedEvent,
    };
    if (opts.eoseTimeoutMs !== undefined) {
      this.#eoseTimer = setTimeout(() => {
        this.#eoseTimer = undefined;
        this.markEose();
      }, opts.eoseTimeoutMs);
    }
    if (opts.signal) {
      if (opts.signal.aborted) {
        this.close("aborted");
      } else {
        this.#abortDispose = onAbort(opts.signal, () => this.close("aborted"));
      }
    }
  }

  get closed(): boolean {
    return this.#closed;
  }

  get eosed(): boolean {
    return this.#eosed;
  }

  get lastCreatedAt(): number | undefined {
    return this.#lastCreatedAt;
  }

  get idsAtWatermark(): ReadonlySet<string> {
    return this.#idsAtWatermark;
  }

  /**
   * Local close: idempotent; clears the EOSE timer and abort listener, detaches via `onLocalClose`
   * (sends CLOSE / leaves the live group), then fires `onclose`.
   */
  close(reason = "closed by client"): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#teardown();
    this.#onLocalClose(this);
    invokeSafely(() => this.#handlers.onclose?.(reason));
  }

  /** Remote/transport termination: like {@link close} but `onLocalClose` is not called. */
  end(reason: string): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#teardown();
    invokeSafely(() => this.#handlers.onclose?.(reason));
  }

  #teardown(): void {
    if (this.#eoseTimer !== undefined) {
      clearTimeout(this.#eoseTimer);
      this.#eoseTimer = undefined;
    }
    this.#abortDispose?.();
    this.#abortDispose = undefined;
  }

  /** Mark EOSE: fires `oneose`, then closes when `closeOnEose`. No-op when closed or EOSE'd. */
  markEose(): void {
    if (this.#closed || this.#eosed) {
      return;
    }
    this.#eosed = true;
    if (this.#eoseTimer !== undefined) {
      clearTimeout(this.#eoseTimer);
      this.#eoseTimer = undefined;
    }
    invokeSafely(() => this.#handlers.oneose?.());
    if (this.closeOnEose) {
      this.close("eose");
    }
  }

  /** Clear `eosed` for a replayed REQ (AUTH retry / reconnect). */
  rearm(): void {
    this.#eosed = false;
  }

  /** First `auth-required:` retry wins; later calls report false without side effects. */
  beginAuthRetry(): boolean {
    if (this.#authRetried) {
      return false;
    }
    this.#authRetried = true;
    return true;
  }

  resetAuthRetry(): void {
    this.#authRetried = false;
  }

  /** `receivedEvent` for every EVENT id, before watermark/alreadyHaveEvent/verify. */
  notifyReceived(id: string): void {
    invokeSafely(() => this.#handlers.receivedEvent?.(id));
  }

  alreadyHas(id: string): boolean {
    let have = false;
    invokeSafely(() => {
      have = Boolean(this.#handlers.alreadyHaveEvent?.(id));
    });
    return have;
  }

  isAtWatermark(id: string): boolean {
    return this.#idsAtWatermark.has(id);
  }

  /** Verified event: advance the watermark, then fire `onevent`. */
  deliver(event: Event): void {
    this.noteVerified(event);
    invokeSafely(() => this.#handlers.onevent?.(event));
  }

  /** Advance the reconnect watermark after a verified EVENT. */
  noteVerified(event: Event): void {
    if (this.#lastCreatedAt === undefined || event.created_at > this.#lastCreatedAt) {
      this.#lastCreatedAt = event.created_at;
      this.#idsAtWatermark.clear();
      this.#idsAtWatermark.add(event.id);
      return;
    }
    if (event.created_at === this.#lastCreatedAt) {
      this.#idsAtWatermark.add(event.id);
    }
  }

  /**
   * Filters for re-REQ. Original `filters` stay unchanged. NIP-01 `since` is inclusive — never
   * `lastCreatedAt + 1`.
   */
  replayFilters(): Filter[] {
    const since = this.#lastCreatedAt;
    if (since === undefined) {
      return [...this.filters];
    }
    return this.filters.map((f) => ({
      ...f,
      since: f.since === undefined ? since : Math.max(f.since, since),
    }));
  }
}

/** AsyncIterable wrapper over a subscription's events until EOSE or close. */
export function subscriptionToAsyncIterable(
  start: (handlers: SubscriptionHandlers) => Closer,
  opts?: { signal?: AbortSignal | undefined; includeEose?: boolean | undefined },
): AsyncIterable<Event> & Closer {
  const queue: Event[] = [];
  let head = 0;
  let done = false;
  let error: Error | undefined;
  let wake: (() => void) | undefined;
  // `let` is required: onclose can fire synchronously while start() is still assigning closer.
  // oxlint-disable-next-line prefer-const
  let closer: Closer | undefined;
  // Set before every locally initiated close so onclose can distinguish it
  // from a remote/transport close without comparing reason strings.
  let localClose = false;
  let disposeAbort: (() => void) | undefined;

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
    disposeAbort?.();
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
      disposeAbort = onAbort(opts.signal, () => closeLocal("aborted"));
      // `start` may have ended the subscription synchronously before the
      // listener was registered.
      if (done) {
        disposeAbort();
      }
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
            const value = head < queue.length ? queue[head] : undefined;
            if (value !== undefined) {
              head += 1;
              if (head === queue.length) {
                queue.length = 0;
                head = 0;
              }
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
        async return(): Promise<IteratorResult<Event>> {
          closeLocal("iterator returned");
          return { value: undefined, done: true };
        },
      };
    },
  };
}
