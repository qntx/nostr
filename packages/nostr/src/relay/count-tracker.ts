/**
 * COUNT request correlation: one waiter per request id with a timeout, abort cleanup and a re-send
 * after AUTH.
 */
import { abortReason, onAbort } from "../core/abort.ts";
import type { Filter } from "../core/filter.ts";
import type { CountResult } from "../core/message.ts";

export type CountWaiter = {
  readonly id: string;
  resolve: (result: CountResult) => void;
  reject: (err: unknown) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  readonly filters: Filter[];
  /** True after one `auth-required:` retry. */
  authRetried: boolean;
  readonly timeoutMs: number;
  readonly timeoutError: () => Error;
};

export class CountTracker {
  readonly #entries = new Map<string, CountWaiter>();

  get size(): number {
    return this.#entries.size;
  }

  get(id: string): CountWaiter | undefined {
    return this.#entries.get(id);
  }

  /**
   * Register a waiter, wire the abort listener, arm its timeout and call `send`. A send throw
   * rejects (`sendError` when the throw is not an Error). resolve/reject unwind the timer, abort
   * listener and map entry.
   */
  async track(
    id: string,
    opts: {
      timeoutMs: number;
      timeoutError: () => Error;
      sendError: () => Error;
      filters: Filter[];
      signal?: AbortSignal | undefined;
      send: () => void;
    },
  ): Promise<CountResult> {
    return new Promise<CountResult>((resolve, reject) => {
      const waiter: CountWaiter = {
        id,
        resolve: (result) => {
          this.#finish(waiter);
          cleanup();
          resolve(result);
        },
        reject: (err) => {
          this.#finish(waiter);
          cleanup();
          // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards abort/signal reasons verbatim
          reject(err);
        },
        timer: undefined,
        filters: opts.filters,
        authRetried: false,
        timeoutMs: opts.timeoutMs,
        timeoutError: opts.timeoutError,
      };
      const cleanup = onAbort(opts.signal, () => {
        if (opts.signal !== undefined) {
          waiter.reject(abortReason(opts.signal));
        }
      });
      waiter.timer = setTimeout(() => {
        waiter.reject(opts.timeoutError());
      }, opts.timeoutMs);
      this.#entries.set(id, waiter);
      try {
        opts.send();
      } catch (error) {
        waiter.reject(error instanceof Error ? error : opts.sendError());
      }
    });
  }

  /** Stop a waiter's timeout without settling (AUTH retry window). */
  clearTimer(waiter: CountWaiter): void {
    if (waiter.timer !== undefined) {
      clearTimeout(waiter.timer);
      waiter.timer = undefined;
    }
  }

  /** Re-arm the timeout for a re-sent COUNT (after an AUTH retry). */
  restartTimer(id: string): void {
    const waiter = this.#entries.get(id);
    if (waiter === undefined) {
      return;
    }
    waiter.timer = setTimeout(() => {
      waiter.reject(waiter.timeoutError());
    }, waiter.timeoutMs);
  }

  /**
   * Re-send a COUNT after the relay demanded AUTH: pause the timeout through the AUTH window,
   * re-arm it and re-send on success, reject on failure.
   */
  async authRetry(
    waiter: CountWaiter,
    deps: {
      ensureAuthed: () => Promise<boolean>;
      isOpen: () => boolean;
      failError: () => Error;
      send: () => void;
    },
  ): Promise<void> {
    this.clearTimer(waiter);
    try {
      const ok = await deps.ensureAuthed();
      if (this.#entries.get(waiter.id) !== waiter) {
        return;
      }
      if (!ok || !deps.isOpen()) {
        waiter.reject(deps.failError());
        return;
      }
      this.restartTimer(waiter.id);
      deps.send();
    } catch (error) {
      if (this.#entries.get(waiter.id) === undefined) {
        return;
      }
      waiter.reject(error instanceof Error ? error : deps.failError());
    }
  }

  rejectAll(err: Error): void {
    for (const waiter of this.#entries.values()) {
      this.clearTimer(waiter);
      waiter.reject(err);
    }
    this.#entries.clear();
  }

  #finish(waiter: CountWaiter): void {
    this.clearTimer(waiter);
    this.#entries.delete(waiter.id);
  }
}
