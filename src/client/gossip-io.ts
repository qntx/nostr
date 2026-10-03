import type { Event } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import type { Gossip } from "../gossip/gossip.ts";
import { fanIn, fetchRouted } from "../relay/fan-in.ts";
import type { FanInOptions, RoutedJob } from "../relay/fan-in.ts";
import type { Pool } from "../relay/pool.ts";
import type { Closer } from "../relay/subscription.ts";
import { ClientError } from "./types.ts";

/** Remainder is one job on defaults; throw before any REQ when defaults are empty. */
export function jobsForFilters(
  gossip: Gossip,
  filters: ReadonlyArray<Filter>,
  defaultRelays: () => ReadonlyArray<string>,
): RoutedJob[] {
  const routed = filters.map((f) => gossip.route(f));
  const needsDefaults = routed.some((r) => r.remainder !== undefined);
  const defaults = needsDefaults ? defaultRelays() : undefined;
  const jobs: RoutedJob[] = [];
  for (const r of routed) {
    for (const [url, sub] of r.perRelay) {
      jobs.push({ urls: [url], filters: [sub] });
    }
    if (r.remainder !== undefined) {
      if (defaults === undefined) {
        throw new ClientError("unrouted remainder without default relays");
      }
      jobs.push({ urls: defaults, filters: [r.remainder] });
    }
  }
  return jobs;
}

export async function fetchGossip(
  pool: Pool,
  gossip: Gossip,
  filters: ReadonlyArray<Filter>,
  defaultRelays: () => ReadonlyArray<string>,
  opts?: {
    timeoutMs?: number | undefined;
    signal?: AbortSignal | undefined;
    onevent?: ((event: Event, relayUrl: string) => void) | undefined;
  },
): Promise<Event[]> {
  return fetchRouted(pool, jobsForFilters(gossip, filters, defaultRelays), {
    timeoutMs: opts?.timeoutMs,
    signal: opts?.signal,
    onevent: opts?.onevent,
  });
}

export function subscribeGossip(
  pool: Pool,
  gossip: Gossip,
  filters: ReadonlyArray<Filter>,
  defaultRelays: () => ReadonlyArray<string>,
  opts: FanInOptions,
): Closer {
  const jobs = jobsForFilters(gossip, filters, defaultRelays);
  if (jobs.length === 0) {
    queueMicrotask(() => opts.oneose?.());
    return {
      close: () => {
        /* empty */
      },
    };
  }
  return fanIn(pool, jobs, opts);
}
