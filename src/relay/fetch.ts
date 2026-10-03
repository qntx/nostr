import { abortReason, onAbort, throwIfAborted } from "../core/abort.ts";
import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { subscriptionToAsyncIterable } from "./subscription.ts";
import type { Closer, RelaySubscription, SubscribeOptions } from "./subscription.ts";

/** How a one-shot {@link Relay.fetch} REQ ended. */
export type RelayFetchEnd =
  | { readonly type: "eose" }
  | { readonly type: "closed"; readonly reason: string }
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
      sub.close(reason);
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

    const timer = setTimeout(() => {
      end = { type: "timeout" };
      done();
    }, opts.timeoutMs);

    const sub = subscribe(filters, {
      id: opts.id,
      signal: opts.signal,
      closeOnEose: true,
      onevent(event) {
        if (seen.has(event.id)) {
          return;
        }
        seen.add(event.id);
        events.push(event);
      },
      oneose() {
        end = { type: "eose" };
        done();
      },
      onclose(reason) {
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
        end = { type: "closed", reason };
        done();
      },
    });
  });

  return { events, end };
}
