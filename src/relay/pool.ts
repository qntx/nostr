import { abortReason, throwIfAborted } from "../core/abort.ts";
import { MessageError } from "../core/error.ts";
import type { Event, EventTemplate } from "../core/event.ts";
import { canonicalizeFilters } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import { assertSubscriptionId } from "../core/message.ts";
import type { CountResult } from "../core/message.ts";
import { invokeSafely } from "../core/report.ts";
import { normalizeURL } from "../core/util.ts";
import { RelayConnectionError, RelayPublishError } from "./error.ts";
import { fanIn, fetchRouted } from "./fan-in.ts";
import { Relay, RelayStatus } from "./relay.ts";
import type { PublishResult, RelayOptions, SubscribeOptions } from "./relay.ts";
import { isInsecureRelayUrl } from "./url.ts";
import type { WebSocketConstructor } from "./websocket.ts";

/** Pool-wide options applied to every managed relay. */
export type PoolOptions = {
  websocketImplementation?: WebSocketConstructor | undefined;
  verifyEvent?: RelayOptions["verifyEvent"];
  publishTimeoutMs?: number | undefined;
  connectTimeoutMs?: number | undefined;
  enableReconnect?: boolean | undefined;
  reconnectBackoffMs?: number[] | undefined;
  enablePing?: boolean | undefined;
  pingIntervalMs?: number | undefined;
  pingTimeoutMs?: number | undefined;
  /**
   * When set, automatically answer NIP-42 AUTH challenges for relays that send them. Return
   * undefined to skip a given relay URL.
   */
  automaticallyAuth?:
    | ((relayURL: string) => ((event: EventTemplate) => Promise<Event>) | undefined)
    | undefined;
  /** When false (default), ensureRelay rejects isInsecureRelayUrl unless trusted. */
  allowInsecure?: boolean | undefined;
  trustedInsecureUrls?: ReadonlyArray<string> | undefined;
  /** Close unused relays. Unset/0 = disabled. */
  idleTimeoutMs?: number | undefined;
  idleCleanupIntervalMs?: number | undefined;
  onIdleRelaysClosed?: ((urls: string[]) => void) | undefined;
  /**
   * Soft cap on connected non-pinned relays. When `ensureRelay` would create a new non-pinned relay
   * at the cap, the least-recently-used idle one is closed first (idle = no subscriptions and no
   * in-flight requests). If none is idle the connect proceeds anyway — the cap never fails a
   * request.
   */
  maxRelays?: number | undefined;
  /** Normalized URLs never closed by idle cleanup or `maxRelays` eviction. */
  pinnedUrls?: ReadonlyArray<string> | undefined;
};

/** Per-relay publish outcome: the relay's OK reply or an error string. */
export type PoolPublishResult = {
  url: string;
  result?: PublishResult;
  error?: string;
};

/** Multi-relay subscribe options: callbacks also receive the normalized relay URL. */
export type PoolSubscribeOptions = Omit<SubscribeOptions, "onevent" | "receivedEvent"> & {
  onevent?: (event: Event, relayUrl: string) => void;
  receivedEvent?: (id: string, relayUrl: string) => void;
};

/** Per-relay NIP-45 COUNT result (or its error). */
export type PoolCountResult = {
  url: string;
  count?: number;
  approximate?: boolean;
  hll?: string;
  error?: string;
};

function isIdle(relay: Relay): boolean {
  return (
    relay.status !== RelayStatus.Connecting &&
    relay.subscriptionCount === 0 &&
    relay.inFlightCount === 0
  );
}

/** Multi-relay coordinator: connection reuse, cross-relay event dedup, fan-out publish. */
export class Pool {
  readonly #relays = new Map<string, Relay>();
  readonly #opts: PoolOptions;
  readonly #lastActivity = new Map<string, number>();
  readonly #idleTimeoutMs: number;
  #idleTimer: ReturnType<typeof setInterval> | undefined;
  #allowInsecure: boolean;
  #trustedInsecure: Set<string>;
  #pinned: Set<string>;

  constructor(opts: PoolOptions = {}) {
    this.#opts = opts;
    this.#allowInsecure = opts.allowInsecure ?? false;
    this.#trustedInsecure = new Set((opts.trustedInsecureUrls ?? []).map(normalizeURL));
    this.#pinned = new Set((opts.pinnedUrls ?? []).map(normalizeURL));
    this.#idleTimeoutMs = opts.idleTimeoutMs ?? 0;
    if (this.#idleTimeoutMs > 0) {
      this.#idleTimer = setInterval(
        () => this.cleanIdleRelays(),
        opts.idleCleanupIntervalMs ?? 30_000,
      );
    }
  }

  setAllowInsecure(allow: boolean): void {
    this.#allowInsecure = allow;
  }

  setTrustedInsecureUrls(urls: ReadonlyArray<string>): void {
    this.#trustedInsecure = new Set(urls.map(normalizeURL));
  }

  setPinnedUrls(urls: ReadonlyArray<string>): void {
    this.#pinned = new Set(urls.map(normalizeURL));
  }

  /**
   * Drop cached AUTH rejections and re-fire pending challenges on every pooled relay, so a later
   * `setSigner` takes effect without reconnect.
   */
  resetAuth(): void {
    for (const relay of this.#relays.values()) {
      relay.resetAuth();
    }
  }

  cleanIdleRelays(): void {
    if (this.#idleTimeoutMs <= 0) {
      return;
    }
    const now = Date.now();
    const idle: string[] = [];
    for (const [url, relay] of this.#relays) {
      if (this.#pinned.has(url) || !isIdle(relay)) {
        continue;
      }
      const last = this.#lastActivity.get(url) ?? 0;
      if (!relay.connected || now - last >= this.#idleTimeoutMs) {
        idle.push(url);
      }
    }
    for (const url of this.#lastActivity.keys()) {
      if (!this.#relays.has(url)) {
        this.#lastActivity.delete(url);
      }
    }
    if (idle.length === 0) {
      return;
    }
    this.close(idle);
    invokeSafely(() => this.#opts.onIdleRelaysClosed?.(idle));
  }

  #touch(url: string): void {
    this.#lastActivity.set(url, Date.now());
  }

  #rejectInsecure(url: string, norm: string): void {
    if (this.#allowInsecure) {
      return;
    }
    if (!isInsecureRelayUrl(url)) {
      return;
    }
    if (this.#trustedInsecure.has(norm)) {
      return;
    }
    throw new RelayConnectionError("insecure relay connection blocked", norm);
  }

  #stopIdleCleanup(): void {
    if (this.#idleTimer === undefined) {
      return;
    }
    clearInterval(this.#idleTimer);
    this.#idleTimer = undefined;
  }

  /**
   * Soft cap: closing the least-recently-used idle non-pinned relay when a new non-pinned relay
   * would push the count past `maxRelays`. Busy relays are never evicted; with none idle the cap is
   * exceeded rather than failing.
   */
  #enforceMaxRelays(incoming: string): void {
    const cap = this.#opts.maxRelays;
    if (cap === undefined || this.#pinned.has(incoming)) {
      return;
    }
    let count = 0;
    let oldestUrl: string | undefined;
    let oldestAt = Number.POSITIVE_INFINITY;
    for (const [url, relay] of this.#relays) {
      if (this.#pinned.has(url)) {
        continue;
      }
      count += 1;
      if (!isIdle(relay)) {
        continue;
      }
      const at = this.#lastActivity.get(url) ?? 0;
      if (at < oldestAt) {
        oldestAt = at;
        oldestUrl = url;
      }
    }
    if (count >= cap && oldestUrl !== undefined) {
      this.close([oldestUrl]);
    }
  }

  async ensureRelay(
    url: string,
    opts?: { signal?: AbortSignal | undefined; timeoutMs?: number | undefined },
  ): Promise<Relay> {
    const norm = normalizeURL(url);
    this.#rejectInsecure(url, norm);
    let relay = this.#relays.get(norm);
    if (!relay) {
      this.#enforceMaxRelays(norm);
      const signFn = this.#opts.automaticallyAuth?.(norm) ?? undefined;
      const created = new Relay(norm, {
        websocketImplementation: this.#opts.websocketImplementation,
        verifyEvent: this.#opts.verifyEvent,
        publishTimeoutMs: this.#opts.publishTimeoutMs,
        connectTimeoutMs: this.#opts.connectTimeoutMs,
        enableReconnect: this.#opts.enableReconnect,
        reconnectBackoffMs: this.#opts.reconnectBackoffMs,
        enablePing: this.#opts.enablePing,
        pingIntervalMs: this.#opts.pingIntervalMs,
        pingTimeoutMs: this.#opts.pingTimeoutMs,
        authSigner: signFn,
      });
      // Only drop from the pool on terminal close (reconnect keeps the entry).
      // oxlint-disable-next-line unicorn/prefer-add-event-listener -- Relay.onclose is a property callback, not an EventTarget
      created.onclose = () => {
        this.#relays.delete(norm);
        this.#lastActivity.delete(norm);
      };
      if (signFn) {
        created.onauth = () => {
          void (async (): Promise<void> => {
            try {
              await created.auth(signFn);
            } catch {
              // auth failure surfaces on subsequent CLOSED/OK; avoid unhandled rejection
            }
          })();
        };
      }
      this.#relays.set(norm, created);
      relay = created;
    }
    this.#touch(norm);
    if (!relay.connected) {
      try {
        await relay.connect({
          signal: opts?.signal,
          timeoutMs: opts?.timeoutMs ?? this.#opts.connectTimeoutMs,
        });
      } catch (error) {
        // Keep the entry when reconnect is enabled so open subscriptions can recover.
        if (this.#opts.enableReconnect !== true) {
          this.#relays.delete(norm);
          this.#lastActivity.delete(norm);
        }
        throw error;
      }
    }
    return relay;
  }

  close(urls?: string[]): void {
    if (!urls) {
      this.#stopIdleCleanup();
      for (const relay of this.#relays.values()) {
        relay.close();
      }
      this.#relays.clear();
      this.#lastActivity.clear();
      return;
    }
    for (const url of urls) {
      const norm = normalizeURL(url);
      this.#relays.get(norm)?.close();
      this.#relays.delete(norm);
      this.#lastActivity.delete(norm);
    }
  }

  /**
   * Subscribe across relays. Deduplicates by event id. Returns a closer; callbacks receive every
   * new event once.
   */
  subscribe(
    relays: string[],
    filters: Filter[],
    opts: PoolSubscribeOptions = {},
  ): { close: (reason?: string) => void } {
    if (filters.length === 0) {
      throw new MessageError("REQ requires at least one filter");
    }
    if (opts.id !== undefined) {
      assertSubscriptionId(opts.id);
    }
    const canonical = canonicalizeFilters(filters);
    return fanIn(this, [{ urls: relays, filters: canonical, id: opts.id }], {
      onevent: opts.onevent,
      oneose: opts.oneose,
      onclose: opts.onclose,
      signal: opts.signal,
      eoseTimeoutMs: opts.eoseTimeoutMs,
      alreadyHaveEvent: opts.alreadyHaveEvent,
      receivedEvent: opts.receivedEvent,
      closeOnEose: opts.closeOnEose,
      connectTimeoutMs: this.#opts.connectTimeoutMs,
    });
  }

  /** Fetch events until each connected relay EOSE or timeout; dedupe by id. */
  async fetch(
    relays: string[],
    filters: Filter[],
    opts?: {
      timeoutMs?: number | undefined;
      signal?: AbortSignal | undefined;
      /** Every event of every relay batch, including cross-relay duplicates. */
      onevent?: ((event: Event, relayUrl: string) => void) | undefined;
    },
  ): Promise<Event[]> {
    if (filters.length === 0) {
      throw new MessageError("REQ requires at least one filter");
    }
    return fetchRouted(this, [{ urls: relays, filters: canonicalizeFilters(filters) }], {
      timeoutMs: opts?.timeoutMs,
      signal: opts?.signal,
      connectTimeoutMs: this.#opts.connectTimeoutMs,
      onevent: opts?.onevent,
    });
  }

  /** Publish to all listed relays; returns per-relay outcomes. */
  async publish(
    relays: string[],
    event: Event,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PoolPublishResult[]> {
    const results = await Promise.all(
      relays.map(async (url): Promise<PoolPublishResult> => {
        try {
          const relay = await this.ensureRelay(url, {
            timeoutMs: this.#opts.connectTimeoutMs,
          });
          this.#touch(relay.url);
          const result = await relay.publish(event, { timeoutMs: opts?.timeoutMs });
          return { url: relay.url, result };
        } catch (error) {
          return { url, error: error instanceof Error ? error.message : String(error) };
        }
      }),
    );
    return results;
  }

  /** First successful publish (Promise.any semantics). */
  async publishAny(
    relays: string[],
    event: Event,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PoolPublishResult> {
    return Promise.any(
      relays.map(async (url) => {
        const relay = await this.ensureRelay(url, {
          timeoutMs: this.#opts.connectTimeoutMs,
        });
        this.#touch(relay.url);
        const result = await relay.publish(event, { timeoutMs: opts?.timeoutMs });
        if (!result.ok) {
          throw new RelayPublishError(result.message || "rejected", relay.url);
        }
        return { url: relay.url, result };
      }),
    );
  }

  /**
   * NIP-45 COUNT across relays. Per-relay outcomes; failures do not throw. Counts are not summed —
   * each relay reports independently (may overlap).
   */
  async count(
    relays: string[],
    filters: Filter[],
    opts?: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined },
  ): Promise<PoolCountResult[]> {
    throwIfAborted(opts?.signal);
    const canonical = canonicalizeFilters(filters);
    const results = await Promise.all(
      relays.map(async (url): Promise<PoolCountResult> => {
        try {
          const relay = await this.ensureRelay(url, {
            signal: opts?.signal,
            timeoutMs: this.#opts.connectTimeoutMs,
          });
          this.#touch(relay.url);
          const payload: CountResult = await relay.count(canonical, {
            timeoutMs: opts?.timeoutMs,
            signal: opts?.signal,
          });
          const out: PoolCountResult = { url: relay.url, count: payload.count };
          if (payload.approximate !== undefined) {
            out.approximate = payload.approximate;
          }
          if (payload.hll !== undefined) {
            out.hll = payload.hll;
          }
          return out;
        } catch (error) {
          // An abort rejects the whole call; per-relay failures are reported.
          if (opts?.signal?.aborted === true) {
            throw abortReason(opts.signal);
          }
          return { url, error: error instanceof Error ? error.message : String(error) };
        }
      }),
    );
    return results;
  }

  listRelays(): string[] {
    return [...this.#relays.keys()];
  }

  /** Lookup a pooled relay, including disconnected reconnecting entries. */
  getRelay(url: string): Relay | undefined {
    try {
      return this.#relays.get(normalizeURL(url));
    } catch {
      return this.#relays.get(url);
    }
  }

  /** Currently connected URLs. Unlike listRelays(), excludes reconnecting/disconnected entries. */
  connectedUrls(): string[] {
    const urls: string[] = [];
    for (const [url, relay] of this.#relays) {
      if (relay.connected) {
        urls.push(url);
      }
    }
    return urls;
  }
}
