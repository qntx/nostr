import { throwIfAborted } from "../core/abort.ts";
import { errorMessage, toError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import { canonicalizeFilter } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import { storageFromItems } from "../nips/nip77.ts";
import type { NegentropyStorageVector } from "../nips/nip77.ts";
import type { Pool } from "../relay/pool.ts";
import type { EventStore, PutResult } from "../storage/types.ts";
import { SyncDirection } from "./types.ts";
import type { SyncOptions, SyncSummary } from "./types.ts";

export type SyncDeps = {
  pool: Pool;
  storage: EventStore;
  persistEvents: boolean;
  assertAlive: () => void;
  /**
   * The client's single ingest path: index (with relay URL) → meta → persistence. `persist: false`
   * when this function already wrote storage via an awaited `putMany`.
   */
  ingest: (event: Event, relayUrl?: string, opts?: { persist?: boolean }) => void;
  /** Record a relay sighting for an id already in the index. */
  markSeen: (id: string, relayUrl: string) => void;
  defaultRelays: (urls?: ReadonlyArray<string>) => ReadonlyArray<string>;
};

const SYNC_ID_BATCH = 100;
const SYNC_UPLOAD_CONCURRENCY = 8;

function uniqueIds(ids: ReadonlyArray<string>): string[] {
  return [...new Set(ids)];
}

function emptySummary(): SyncSummary {
  return {
    local: [],
    remote: [],
    sent: [],
    received: [],
    sendFailures: {},
    persistFailures: {},
  };
}

function mergeSyncSummary(into: SyncSummary, other: SyncSummary): SyncSummary {
  const sendFailures = { ...into.sendFailures, ...other.sendFailures };
  const persistFailures = { ...into.persistFailures, ...other.persistFailures };
  return {
    local: uniqueIds([...into.local, ...other.local]),
    remote: uniqueIds([...into.remote, ...other.remote]),
    sent: uniqueIds([...into.sent, ...other.sent]),
    received: uniqueIds([...into.received, ...other.received]),
    sendFailures,
    persistFailures,
  };
}

/**
 * NIP-77 sync against one relay: reconcile, then optionally upload local-only events and/or
 * download remote-only events. `observe: false` skips putMany and ingest; received ids are still
 * listed. `persistEvents: false` skips putMany, still ingests when observe is on.
 */
export async function syncToRelay(
  deps: SyncDeps,
  url: string,
  filter: Filter,
  opts?: Omit<SyncOptions, "relays">,
): Promise<SyncSummary> {
  deps.assertAlive();
  throwIfAborted(opts?.signal);
  const direction = opts?.direction ?? SyncDirection.Down;
  const canon = canonicalizeFilter(filter);
  const items = await deps.storage.negentropyItems(canon);
  const storage: NegentropyStorageVector = storageFromItems(items);
  const relay = await deps.pool.ensureRelay(url, { signal: opts?.signal });
  const { have, need } = await relay.negReconcile(canon, storage, {
    timeoutMs: opts?.timeoutMs,
    signal: opts?.signal,
  });

  const sent: string[] = [];
  const received: string[] = [];
  const sendFailures: Record<string, string> = {};
  const persistFailures: Record<string, Error> = {};
  const summary: SyncSummary = {
    local: have,
    remote: need,
    sent,
    received,
    sendFailures,
    persistFailures,
  };

  if (opts?.dryRun === true) {
    return summary;
  }

  if ((direction === SyncDirection.Up || direction === SyncDirection.Both) && have.length > 0) {
    const found = await deps.storage.query([{ ids: have }]);
    const foundById = new Map(found.map((event) => [event.id, event]));
    for (const id of have) {
      if (!foundById.has(id)) {
        sendFailures[id] = "event not found in local store";
      }
    }
    for (let i = 0; i < found.length; i += SYNC_UPLOAD_CONCURRENCY) {
      const chunk = found.slice(i, i + SYNC_UPLOAD_CONCURRENCY);
      // Upload chunks are rate-limited serially.
      // oxlint-disable-next-line no-await-in-loop
      await Promise.all(
        chunk.map(async (event) => {
          try {
            const results = await deps.pool.publish([url], event, {
              timeoutMs: opts?.timeoutMs,
            });
            const ok = results.some((r) => r.status === "ok");
            if (ok) {
              sent.push(event.id);
            } else {
              const [first] = results;
              sendFailures[event.id] =
                first === undefined
                  ? "publish failed"
                  : first.status === "failed"
                    ? errorMessage(first.error)
                    : first.message;
            }
          } catch (error) {
            sendFailures[event.id] = errorMessage(error);
          }
        }),
      );
    }
  }

  if ((direction === SyncDirection.Down || direction === SyncDirection.Both) && need.length > 0) {
    const shouldObserve = opts?.observe !== false;
    for (let i = 0; i < need.length; i += SYNC_ID_BATCH) {
      const batch = need.slice(i, i + SYNC_ID_BATCH);
      throwIfAborted(opts?.signal);
      // Every relay that delivered an event is recorded once it is ingested.
      const urlsById = new Map<string, string[]>();
      // Id batches are fetched serially so backpressure stays bounded.
      // oxlint-disable-next-line no-await-in-loop
      const events = await deps.pool.fetch([url], [{ ids: batch }], {
        timeoutMs: opts?.timeoutMs,
        signal: opts?.signal,
        onevent: shouldObserve
          ? (event, relayUrl) => {
              const urls = urlsById.get(event.id);
              if (urls === undefined) {
                urlsById.set(event.id, [relayUrl]);
              } else if (!urls.includes(relayUrl)) {
                urls.push(relayUrl);
              }
            }
          : undefined,
      });
      if (!shouldObserve) {
        for (const event of events) {
          received.push(event.id);
        }
        continue;
      }
      const ingestAll = (event: Event): void => {
        const urls = urlsById.get(event.id) ?? [];
        deps.ingest(event, urls[0], { persist: false });
        for (const url of urls.slice(1)) {
          deps.markSeen(event.id, url);
        }
      };
      if (!deps.persistEvents) {
        for (const event of events) {
          ingestAll(event);
          received.push(event.id);
        }
        continue;
      }
      // The awaited putMany reports persistFailures; accepted events then go
      // through the ingest path with persistence already done.
      let results: PutResult[];
      try {
        // Persisted serially per batch so failures land on the right ids.
        // oxlint-disable-next-line no-await-in-loop
        results = await deps.storage.putMany(events);
      } catch (error) {
        const thrown = toError(error);
        for (const event of events) {
          persistFailures[event.id] = thrown;
        }
        break;
      }
      for (const [j, event] of events.entries()) {
        if (results[j] === "rejected" || results[j] === "invalid") {
          continue;
        }
        ingestAll(event);
        received.push(event.id);
      }
    }
  }

  return summary;
}

/**
 * NIP-77 sync against the given relays (or Client default relays). Independent sessions run in
 * parallel. Fulfilled summaries are merged; if every relay rejects, throws the first rejection in
 * URL order.
 */
export async function sync(
  deps: SyncDeps,
  filter: Filter,
  opts?: SyncOptions,
): Promise<SyncSummary> {
  deps.assertAlive();
  const urls = deps.defaultRelays(opts?.relays);
  const results = await Promise.allSettled(
    urls.map(async (url) => syncToRelay(deps, url, filter, opts)),
  );
  let merged = emptySummary();
  let fulfilled = 0;
  let firstRejection: unknown;
  for (const result of results) {
    if (result.status === "fulfilled") {
      fulfilled += 1;
      merged = mergeSyncSummary(merged, result.value);
    } else {
      firstRejection ??= result.reason;
    }
  }
  if (urls.length > 0 && fulfilled === 0) {
    throw firstRejection;
  }
  return merged;
}
