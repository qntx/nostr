import { abortReason, onAbort, throwIfAborted } from "../core/abort.ts";
import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { invokeSafely } from "../core/report.ts";
import { RelayClosedError } from "./error.ts";
import type { Pool } from "./pool.ts";
import type { Relay } from "./relay.ts";
import type { Closer } from "./subscription.ts";
import { uniqueRelayUrls } from "./url.ts";

export type RoutedJob = {
  urls: ReadonlyArray<string>;
  filters: ReadonlyArray<Filter>;
  id?: string | undefined;
};

export type FanInOptions = {
  /** First receipt only (deduped across jobs). `relayUrl` is the normalized relay URL. */
  onevent?: ((event: Event, relayUrl: string) => void) | undefined;
  oneose?: (() => void) | undefined;
  onclose?: ((reason: string) => void) | undefined;
  signal?: AbortSignal | undefined;
  /** Armed at fan-in only. Never forwarded to relay.subscribe. */
  eoseTimeoutMs?: number | undefined;
  alreadyHaveEvent?: ((id: string) => boolean) | undefined;
  /** Every receipt from every relay, including skipped duplicates. */
  receivedEvent?: ((id: string, relayUrl: string) => void) | undefined;
  closeOnEose?: boolean | undefined;
  /** Optional. ensureRelay uses Pool.#opts.connectTimeoutMs when omitted. */
  connectTimeoutMs?: number | undefined;
};

/**
 * Aggregate EOSE/close across routed jobs. One `seen` set. `pending` counts URL list entries
 * (duplicates included). `pendingEose` counts unique `jobIndex:url` keys.
 */
export function fanIn(pool: Pool, jobs: ReadonlyArray<RoutedJob>, opts: FanInOptions = {}): Closer {
  const seen = new Set<string>();
  const closers: Closer[] = [];
  let closed = false;
  let eoseFired = false;
  let sawEose = false;
  let eoseTimer: ReturnType<typeof setTimeout> | undefined;
  const eoseDone = new Set<string>();
  const eoseAttempted = new Set<string>();
  let pendingEose = 0;
  let pending = 0;

  const fireEose = () => {
    if (closed || eoseFired) {
      return;
    }
    eoseFired = true;
    if (eoseTimer !== undefined) {
      clearTimeout(eoseTimer);
      eoseTimer = undefined;
    }
    invokeSafely(() => opts.oneose?.());
  };

  /**
   * Remove one relay from the pending-EOSE set. `eosed` credits a real EOSE; a CLOSED or a connect
   * failure only drops the wait — the aggregate `oneose` fires once every remaining relay ended AND
   * at least one actually EOSE'd.
   */
  const settleEose = (jobIndex: number, url: string, eosed: boolean) => {
    const key = `${jobIndex}:${url}`;
    if (eoseDone.has(key)) {
      return;
    }
    eoseDone.add(key);
    if (eosed) {
      sawEose = true;
    }
    pendingEose -= 1;
    if (pendingEose === 0 && sawEose) {
      fireEose();
    }
  };

  const settleClose = () => {
    closed = true;
    disposeAbort();
    if (eoseTimer !== undefined) {
      clearTimeout(eoseTimer);
      eoseTimer = undefined;
    }
  };

  const closeAll = (reason?: string) => {
    if (closed) {
      return;
    }
    settleClose();
    for (const c of closers) {
      c.close(reason);
    }
    invokeSafely(() => opts.onclose?.(reason ?? "closed by client"));
  };

  if (opts.signal?.aborted === true) {
    closed = true;
    invokeSafely(() => opts.onclose?.("aborted"));
    return { close: closeAll };
  }

  const disposeAbort = onAbort(opts.signal, () => closeAll("aborted"));

  const failUrl = (jobIndex: number, key: string): void => {
    settleEose(jobIndex, key, false);
    pending -= 1;
    if (pending <= 0 && closers.length === 0 && !closed) {
      settleClose();
      invokeSafely(() => opts.onclose?.("all relays failed"));
    }
  };

  const attach = (relay: Relay, job: RoutedJob, jobIndex: number): void => {
    if (closed) {
      return;
    }
    const received = opts.receivedEvent;
    const sub = relay.subscribe([...job.filters], {
      id: jobs.length === 1 ? job.id : undefined,
      closeOnEose: opts.closeOnEose,
      alreadyHaveEvent: (id) => {
        let have = seen.has(id);
        invokeSafely(() => {
          have = have || Boolean(opts.alreadyHaveEvent?.(id));
        });
        return have;
      },
      receivedEvent:
        received === undefined ? undefined : (id) => invokeSafely(() => received(id, relay.url)),
      onevent: (event) => {
        seen.add(event.id);
        invokeSafely(() => opts.onevent?.(event, relay.url));
      },
      oneose: () => settleEose(jobIndex, relay.url, true),
      onclose: (reason) => {
        settleEose(jobIndex, relay.url, false);
        pending -= 1;
        if (pending <= 0 && !closed) {
          settleClose();
          invokeSafely(() => opts.onclose?.(reason));
        }
      },
    });
    closers.push(sub);
  };

  for (const [jobIndex, job] of jobs.entries()) {
    // Equivalent spellings of one relay URL attach exactly once per job.
    for (const key of uniqueRelayUrls(job.urls)) {
      pending += 1;
      const eoseKey = `${jobIndex}:${key}`;
      if (!eoseAttempted.has(eoseKey)) {
        eoseAttempted.add(eoseKey);
        pendingEose += 1;
      }

      const tryAttach = (relay: Relay): void => {
        try {
          attach(relay, job, jobIndex);
        } catch (error) {
          if (error instanceof RelayClosedError) {
            failUrl(jobIndex, key);
            return;
          }
          throw error;
        }
      };

      void (async (): Promise<void> => {
        let relay: Relay;
        try {
          relay = await pool.ensureRelay(key, {
            signal: opts.signal,
            timeoutMs: opts.connectTimeoutMs,
          });
        } catch {
          // ensureRelay rejected only — not tryAttach throws (those must not look like connect failure).
          const existing = pool.getRelay(key);
          if (existing !== undefined) {
            tryAttach(existing);
            return;
          }
          failUrl(jobIndex, key);
          return;
        }
        tryAttach(relay);
      })();
    }
  }

  if (opts.eoseTimeoutMs !== undefined && pending > 0) {
    eoseTimer = setTimeout(() => {
      eoseTimer = undefined;
      fireEose();
    }, opts.eoseTimeoutMs);
  }

  if (pending === 0) {
    queueMicrotask(() => {
      if (closed) {
        return;
      }
      settleClose();
      invokeSafely(() => opts.onclose?.("no relays"));
    });
  }

  return { close: closeAll };
}

export async function fetchRouted(
  pool: Pool,
  jobs: ReadonlyArray<RoutedJob>,
  opts: {
    timeoutMs?: number | undefined;
    signal?: AbortSignal | undefined;
    connectTimeoutMs?: number | undefined;
    /** Every event of every relay batch, including cross-relay duplicates. */
    onevent?: ((event: Event, relayUrl: string) => void) | undefined;
  } = {},
): Promise<Event[]> {
  throwIfAborted(opts.signal);
  const byId = new Map<string, Event>();
  await Promise.all(
    jobs.flatMap((job) => {
      return uniqueRelayUrls(job.urls).map(async (url) => {
        let batch: ReadonlyArray<Event>;
        let relayUrl: string;
        try {
          const relay = await pool.ensureRelay(url, {
            signal: opts.signal,
            timeoutMs: opts.connectTimeoutMs,
          });
          relayUrl = relay.url;
          const result = await relay.fetch([...job.filters], {
            timeoutMs: opts.timeoutMs,
            signal: opts.signal,
          });
          batch = result.events;
        } catch {
          // An abort rejects the whole call; per-relay failures are skipped.
          if (opts.signal?.aborted === true) {
            throw abortReason(opts.signal);
          }
          return;
        }
        // The whole batch lands before callbacks so a throwing onevent cannot
        // drop events; listener errors are reported, never propagated.
        for (const event of batch) {
          if (!byId.has(event.id)) {
            byId.set(event.id, event);
          }
        }
        for (const event of batch) {
          invokeSafely(() => opts.onevent?.(event, relayUrl));
        }
      });
    }),
  );
  return [...byId.values()];
}
