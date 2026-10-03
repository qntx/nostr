/** OK correlation for EVENT and AUTH frames: one waiter per event id with a timeout. */
import type { Event } from "../core/event.ts";

/** A relay's NIP-01 OK reply to a published event. */
export type PublishResult = {
  readonly ok: boolean;
  readonly message: string;
};

export type OkWaiter = {
  readonly id: string;
  resolve: (result: PublishResult) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  /** Set for `publish` waiters; absent for AUTH waiters. Also marks joinable entries. */
  event: Event | undefined;
  /** True after one `auth-required:` retry. */
  authRetried: boolean;
  readonly timeoutMs: number;
  readonly timeoutError: () => Error;
  /** The owning publish()/auth() promise — joiners on the same event id settle with it. */
  readonly promise: Promise<PublishResult>;
};

export class OkTracker {
  readonly #entries = new Map<string, OkWaiter>();

  get size(): number {
    return this.#entries.size;
  }

  get(eventId: string): OkWaiter | undefined {
    return this.#entries.get(eventId);
  }

  /** Joiner's view: only publish waiters (carrying an `event`) are joinable. */
  inFlight(eventId: string): Promise<PublishResult> | undefined {
    const waiter = this.#entries.get(eventId);
    return waiter?.event === undefined ? undefined : waiter.promise;
  }

  /**
   * Register a waiter, arm its timeout and call `send`. A send throw removes the entry and rejects
   * (`sendError` when the throw is not an Error). The timer only rejects while this waiter still
   * owns the id.
   */
  async track(
    eventId: string,
    opts: {
      timeoutMs: number;
      timeoutError: () => Error;
      sendError: () => Error;
      event?: Event;
      send: () => void;
    },
  ): Promise<PublishResult> {
    const promise = new Promise<PublishResult>((resolve, reject) => {
      const waiter: OkWaiter = {
        id: eventId,
        resolve,
        reject,
        timer: setTimeout(() => {
          if (this.#entries.get(eventId) === waiter) {
            this.#entries.delete(eventId);
            reject(opts.timeoutError());
          }
        }, opts.timeoutMs),
        event: opts.event,
        authRetried: false,
        timeoutMs: opts.timeoutMs,
        timeoutError: opts.timeoutError,
        get promise() {
          return promise;
        },
      };
      this.#entries.set(eventId, waiter);
      try {
        opts.send();
      } catch (error) {
        this.#finish(waiter);
        reject(error instanceof Error ? error : opts.sendError());
      }
    });
    return promise;
  }

  /**
   * An OK reply arrived: `retry` is the caller's auth-required policy — a kept waiter is returned
   * unsettled for the retry path; otherwise the entry is settled and undefined is returned.
   */
  handleOk(
    eventId: string,
    ok: boolean,
    message: string,
    retry: (waiter: OkWaiter) => boolean,
  ): OkWaiter | undefined {
    const waiter = this.#entries.get(eventId);
    if (waiter === undefined) {
      return undefined;
    }
    if (!retry(waiter)) {
      this.settle(waiter, { ok, message });
      return undefined;
    }
    return waiter;
  }

  /** Settle a waiter: stop its timer, drop the entry it still owns, then resolve. */
  settle(waiter: OkWaiter, result: PublishResult): void {
    this.#finish(waiter);
    waiter.resolve(result);
  }

  /** Stop a waiter's timeout without settling (AUTH retry window). */
  clearTimer(waiter: OkWaiter): void {
    if (waiter.timer !== undefined) {
      clearTimeout(waiter.timer);
      waiter.timer = undefined;
    }
  }

  /** Re-arm the timeout for a re-sent frame (after an AUTH retry). */
  restartTimer(eventId: string): void {
    const waiter = this.#entries.get(eventId);
    if (waiter === undefined) {
      return;
    }
    waiter.timer = setTimeout(() => {
      if (this.#entries.get(eventId) === waiter) {
        this.#entries.delete(eventId);
        waiter.reject(waiter.timeoutError());
      }
    }, waiter.timeoutMs);
  }

  /**
   * Re-send a tracked EVENT after the relay demanded AUTH: pause the timeout through the AUTH
   * window, re-arm it and re-send on success, settle `{ok:false,message}` on failure. AUTH waiters
   * (no `event`) settle immediately.
   */
  async authRetry(
    waiter: OkWaiter,
    message: string,
    deps: {
      ensureAuthed: () => Promise<boolean>;
      isOpen: () => boolean;
      send: (event: Event) => void;
    },
  ): Promise<void> {
    this.clearTimer(waiter);
    const finish = (result: PublishResult) => {
      this.settle(waiter, result);
    };
    try {
      const { event } = waiter;
      if (event === undefined) {
        finish({ ok: false, message });
        return;
      }
      const ok = await deps.ensureAuthed();
      if (this.#entries.get(waiter.id) !== waiter) {
        return;
      }
      if (!ok || !deps.isOpen()) {
        finish({ ok: false, message });
        return;
      }
      this.restartTimer(waiter.id);
      deps.send(event);
    } catch {
      if (this.#entries.get(waiter.id) === undefined) {
        return;
      }
      finish({ ok: false, message });
    }
  }

  rejectAll(err: Error): void {
    for (const waiter of this.#entries.values()) {
      this.clearTimer(waiter);
      waiter.reject(err);
    }
    this.#entries.clear();
  }

  #finish(waiter: OkWaiter): void {
    this.clearTimer(waiter);
    if (this.#entries.get(waiter.id) === waiter) {
      this.#entries.delete(waiter.id);
    }
  }
}
