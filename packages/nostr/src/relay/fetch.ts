import { abortReason, onAbort, throwIfAborted } from "../core/abort.ts";
import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { subscriptionToAsyncIterable } from "./subscription.ts";
import type { Closer, RelaySubscription, SubscribeOptions } from "./subscription.ts";

/** How a one-shot {@link Relay.fetch} REQ ended. */
export type RelayFetchEnd =
  | {
      readonly type: "eose";
      /** NIP-67 EOSE completeness hints, only when the relay sent a well-formed array. */
      readonly hints?: ReadonlyArray<string> | undefined;
    }
  | {
      readonly type: "closed";
      readonly reason: string;
      /** The NIP-01 `<params>` of the CLOSED frame, only when the relay sent one. */
      readonly params?: string | undefined;
    }
  | { readonly type: "timeout" };

/** `Relay.fetch` result: collected events plus the REQ's end reason. */
export type RelayFetchResult = {
  readonly events: ReadonlyArray<Event>;
  readonly end: RelayFetchEnd;
};

export function streamFilters(
  subscribe: (filters: ReadonlyArray<Filter>, opts: SubscribeOptions) => RelaySubscription,
  filters: ReadonlyArray<Filter>,
  opts?: { signal?: AbortSignal | undefined; id?: string | undefined },
): AsyncIterable<Event> & Closer {
  return subscriptionToAsyncIterable(
    (handlers) => subscribe(filters, { ...handlers, id: opts?.id, signal: opts?.signal }),
    { signal: opts?.signal },
  );
}

export async function fetchFilters(
  subscribe: (filters: ReadonlyArray<Filter>, opts: SubscribeOptions) => RelaySubscription,
  filters: ReadonlyArray<Filter>,
  opts: {
    timeoutMs: number;
    signal?: AbortSignal | undefined;
    id?: string | undefined;
  },
): Promise<RelayFetchResult> {
  throwIfAborted(opts.signal);
  const events: Event[] = [];
  const seen = new Set<string>();
  let end: RelayFetchEnd = { type: "timeout" };

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    // `subscribe` may fire onEose/onClose synchronously, before `sub`/`timer`
    // are assigned: done() then only records the close reason for the sub
    // subscribe is about to return.
    // oxlint-disable-next-line eslint/prefer-const -- armed only after subscribe() returns
    let timer: ReturnType<typeof setTimeout> | undefined;
    let sub: ReturnType<typeof subscribe> | undefined;
    let pendingCloseReason = "fetch complete";
    const done = (err?: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      disposeAbort();
      clearTimeout(timer);
      let reason = "aborted";
      if (err instanceof Error) {
        reason = err.message;
      } else if (err === undefined) {
        reason = "fetch complete";
      }
      pendingCloseReason = reason;
      sub?.close(reason);
      if (err === undefined) {
        resolve();
      } else {
        // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards abort/signal reasons verbatim
        reject(err);
      }
    };

    const disposeAbort = onAbort(opts.signal, () => {
      if (opts.signal !== undefined) {
        done(abortReason(opts.signal));
      }
    });

    // Subscribe before arming the timeout: a synchronous throw (e.g. an invalid
    // custom id) must reject without leaving an armed timer behind.
    try {
      sub = subscribe(filters, {
        id: opts.id,
        signal: opts.signal,
        closeOnEose: true,
        onEvent(event) {
          if (seen.has(event.id)) {
            return;
          }
          seen.add(event.id);
          events.push(event);
        },
        onEose(hints) {
          end = hints === undefined ? { type: "eose" } : { type: "eose", hints };
          done();
        },
        onClose(reason, params) {
          // The Subscription's own abort listener may close it before ours runs;
          // an aborted signal still rejects the fetch with the signal's reason.
          if (settled) {
            return;
          }
          if (opts.signal?.aborted === true) {
            done(abortReason(opts.signal));
            return;
          }
          // A remote CLOSED (or transport drop) still returns collected events.
          end =
            params === undefined ? { type: "closed", reason } : { type: "closed", reason, params };
          done();
        },
      });
    } catch (error) {
      disposeAbort();
      // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards the subscribe() throw verbatim
      reject(error);
      return;
    }

    // A synchronous onEose/onClose inside subscribe() already settled the
    // fetch: close the returned sub with the recorded reason and arm nothing.
    if (settled) {
      sub.close(pendingCloseReason);
      return;
    }
    timer = setTimeout(() => {
      end = { type: "timeout" };
      done();
    }, opts.timeoutMs);
  });

  return { events, end };
}
