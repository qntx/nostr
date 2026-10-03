import { abortReason, throwIfAborted } from "../core/abort.ts";
import { Emitter } from "../core/emitter.ts";
import { MessageError, toError } from "../core/error.ts";
import type { Event, EventTemplate } from "../core/event.ts";
import { canonicalizeFilters } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import { assertSubscriptionId } from "../core/message.ts";
import type { CountResult } from "../core/message.ts";
import { normalizeURL } from "../core/util.ts";
import { RelayConnectionError, RelayPublishError, RelaySuspendedError } from "./error.ts";
import { fanIn, fetchRouted } from "./fan-in.ts";
import { Relay, RelayStatus } from "./relay.ts";
import type { RelayFetchEnd, RelayOptions, SubscribeOptions } from "./relay.ts";
import type { Closer } from "./subscription.ts";
import { isInsecureRelayUrl, uniqueRelayUrls } from "./url.ts";

/** Per-relay tolerance for events that fail id/signature verification. */
export type InvalidEventPolicy = {
  /** Invalid events tolerated within `windowMs`; exceeding it suspends the relay. */
  limit: number;
  windowMs: number;
  /** How long a suspended relay stays closed before it may reconnect. */
  cooldownMs: number;
};

/** Pool-wide options applied to every managed relay. */
export type PoolOptions = Omit<RelayOptions, "authSigner"> & {
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
  /**
   * Soft cap on connected non-pinned relays. When `ensureRelay` would create a new non-pinned relay
   * at the cap, the least-recently-used idle one is closed first (idle = no subscriptions and no
   * in-flight requests). If none is idle the connect proceeds anyway — the cap never fails a
   * request.
   */
  maxRelays?: number | undefined;
  /** Normalized URLs never closed by idle cleanup or `maxRelays` eviction. */
  pinnedUrls?: ReadonlyArray<string> | undefined;
  /**
   * When set, a relay whose `limit`-th-plus-one EVENT fails id/signature verification inside a
   * `windowMs` sliding window is disconnected and suspended for `cooldownMs`. During suspension
   * `ensureRelay` rejects with {@link RelaySuspendedError}; once it lifts, live subscriptions resume
   * through the normal reconnect path. Unset = events are dropped without counting, as before.
   */
  invalidEventPolicy?: InvalidEventPolicy | undefined;
};

/** Typed event payloads for {@link Pool.on}. */
export type PoolEventMap = {
  /** Normalized URLs closed by an idle-cleanup pass. */
  idle: ReadonlyArray<string>;
  /**
   * A relay suspended for exceeding `invalidEventPolicy`: `url` is the normalized relay URL and
   * `until` the epoch-ms time the suspension lifts.
   */
  suspend: { readonly url: string; readonly until: number };
};

/** Per-relay publish outcome: the relay's OK verdict or a transport-level failure. */
export type PoolPublishResult =
  | { readonly url: string; readonly status: "ok"; readonly message: string }
  | { readonly url: string; readonly status: "rejected"; readonly message: string }
  | { readonly url: string; readonly status: "failed"; readonly error: Error };

/** Multi-relay subscribe options: callbacks also receive the normalized relay URL. */
export type PoolSubscribeOptions = Omit<SubscribeOptions, "onevent" | "receivedEvent"> & {
  onevent?: ((event: Event, relayUrl: string) => void) | undefined;
  receivedEvent?: ((id: string, relayUrl: string) => void) | undefined;
};

/** Per-relay one-shot fetch outcome: collected events plus how its REQ ended. */
export type PoolFetchResult = {
  readonly url: string;
  readonly events: ReadonlyArray<Event>;
  readonly end: RelayFetchEnd | { readonly type: "failed"; readonly error: Error };
};

/** Per-relay NIP-45 COUNT result (or a transport-level failure). */
export type PoolCountResult =
  | ({ readonly url: string; readonly status: "ok" } & CountResult)
  | { readonly url: string; readonly status: "failed"; readonly error: Error };

const countOk = (url: string, payload: CountResult): PoolCountResult => ({
  url,
  status: "ok",
  ...payload,
});

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
  readonly #relayOptions: Omit<RelayOptions, "authSigner">;
  readonly #automaticallyAuth: PoolOptions["automaticallyAuth"];
  readonly #maxRelays: number | undefined;
  readonly #invalidEventPolicy: InvalidEventPolicy | undefined;
  readonly #events = new Emitter<PoolEventMap>();
  readonly #lastActivity = new Map<string, number>();
  readonly #idleTimeoutMs: number;
  #idleTimer: ReturnType<typeof setInterval> | undefined;
  #allowInsecure: boolean;
  #trustedInsecure: Set<string>;
  #pinned: Set<string>;
  /** Per-relay timestamps of verification failures inside the sliding window. */
  readonly #invalidEvents = new Map<string, number[]>();
  /** Normalized URL → epoch ms when its suspension lifts. */
  readonly #suspendedUntil = new Map<string, number>();
  readonly #resumeTimers = new Map<string, ReturnType<typeof setTimeout>>();

  constructor(opts: PoolOptions = {}) {
    const {
      automaticallyAuth,
      allowInsecure,
      trustedInsecureUrls,
      idleTimeoutMs,
      idleCleanupIntervalMs,
      maxRelays,
      pinnedUrls,
      invalidEventPolicy,
      ...relayOptions
    } = opts;
    this.#relayOptions = relayOptions;
    this.#automaticallyAuth = automaticallyAuth;
    this.#maxRelays = maxRelays;
    this.#invalidEventPolicy = invalidEventPolicy;
    this.#allowInsecure = allowInsecure ?? false;
    this.#trustedInsecure = new Set((trustedInsecureUrls ?? []).map(normalizeURL));
    this.#pinned = new Set((pinnedUrls ?? []).map(normalizeURL));
    this.#idleTimeoutMs = idleTimeoutMs ?? 0;
    if (this.#idleTimeoutMs > 0) {
      this.#idleTimer = setInterval(() => this.cleanIdleRelays(), idleCleanupIntervalMs ?? 30_000);
    }
  }

  /**
   * Listen for a pool event. Multiple listeners per type are allowed and fire in registration
   * order; a throwing listener is reported and does not break the dispatch. Returns an unsubscribe
   * function.
   */
  on<K extends keyof PoolEventMap>(
    type: K,
    listener: (payload: PoolEventMap[K]) => void,
  ): () => void {
    return this.#events.on(type, listener);
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
    this.closeRelays(idle);
    this.#events.emit("idle", idle);
  }

  #touch(url: string): void {
    this.#lastActivity.set(url, Date.now());
  }

  /**
   * Count one verification failure for `norm`; on the `limit + 1`-th inside `windowMs` suspend the
   * relay: drop its connection (subscriptions kept), record `until`, and emit `suspend`.
   */
  #noteInvalidEvent(norm: string): void {
    const policy = this.#invalidEventPolicy;
    if (policy === undefined) {
      return;
    }
    const now = Date.now();
    const window = (this.#invalidEvents.get(norm) ?? []).filter((at) => now - at < policy.windowMs);
    window.push(now);
    if (window.length <= policy.limit) {
      this.#invalidEvents.set(norm, window);
      return;
    }
    this.#invalidEvents.delete(norm);
    if (this.#suspendedUntil.has(norm)) {
      return;
    }
    const until = now + policy.cooldownMs;
    this.#suspendedUntil.set(norm, until);
    this.#relays.get(norm)?.disconnect();
    const resume = setTimeout(() => {
      this.#resumeTimers.delete(norm);
      this.#suspendedUntil.delete(norm);
      const relay = this.#relays.get(norm);
      if (relay === undefined || relay.connected || relay.subscriptionCount === 0) {
        return;
      }
      void (async (): Promise<void> => {
        try {
          await relay.connect();
        } catch {
          // With enableReconnect the relay's own backoff retries; otherwise the
          // next ensureRelay attempt reconnects on demand.
        }
      })();
    }, policy.cooldownMs);
    this.#resumeTimers.set(norm, resume);
    this.#events.emit("suspend", { url: norm, until });
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
    const cap = this.#maxRelays;
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
      this.closeRelays([oldestUrl]);
    }
  }

  async ensureRelay(
    url: string,
    opts?: { signal?: AbortSignal | undefined; timeoutMs?: number | undefined },
  ): Promise<Relay> {
    const norm = normalizeURL(url);
    this.#rejectInsecure(url, norm);
    const suspendedUntil = this.#suspendedUntil.get(norm);
    if (suspendedUntil !== undefined) {
      if (Date.now() < suspendedUntil) {
        throw new RelaySuspendedError(norm, suspendedUntil);
      }
      this.#suspendedUntil.delete(norm);
    }
    let relay = this.#relays.get(norm);
    if (!relay) {
      this.#enforceMaxRelays(norm);
      const signFn = this.#automaticallyAuth?.(norm) ?? undefined;
      const created = new Relay(norm, { ...this.#relayOptions, authSigner: signFn });
      // Only drop from the pool on terminal close (reconnect keeps the entry).
      created.on("close", () => {
        this.#relays.delete(norm);
        this.#lastActivity.delete(norm);
      });
      created.on("invalidevent", () => {
        this.#noteInvalidEvent(norm);
      });
      if (signFn) {
        created.on("auth", () => {
          void (async (): Promise<void> => {
            try {
              await created.auth(signFn);
            } catch {
              // auth failure surfaces on subsequent CLOSED/OK; avoid unhandled rejection
            }
          })();
        });
      }
      this.#relays.set(norm, created);
      relay = created;
    }
    this.#touch(norm);
    if (!relay.connected) {
      try {
        await relay.connect({
          signal: opts?.signal,
          timeoutMs: opts?.timeoutMs ?? this.#relayOptions.connectTimeoutMs,
        });
      } catch (error) {
        // Keep the entry when reconnect is enabled so open subscriptions can recover.
        if (this.#relayOptions.enableReconnect !== true) {
          this.#relays.delete(norm);
          this.#lastActivity.delete(norm);
        }
        throw error;
      }
    }
    return relay;
  }

  /** Close every pooled relay and clear all pool state. */
  close(): void {
    this.#stopIdleCleanup();
    for (const timer of this.#resumeTimers.values()) {
      clearTimeout(timer);
    }
    this.#resumeTimers.clear();
    this.#suspendedUntil.clear();
    this.#invalidEvents.clear();
    for (const relay of this.#relays.values()) {
      relay.close();
    }
    this.#relays.clear();
    this.#lastActivity.clear();
  }

  /** Close and forget the listed relays; other pooled relays are untouched. */
  closeRelays(urls: ReadonlyArray<string>): void {
    for (const url of urls) {
      const norm = normalizeURL(url);
      const timer = this.#resumeTimers.get(norm);
      if (timer !== undefined) {
        clearTimeout(timer);
        this.#resumeTimers.delete(norm);
      }
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
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts: PoolSubscribeOptions = {},
  ): Closer {
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
      connectTimeoutMs: this.#relayOptions.connectTimeoutMs,
    });
  }

  /**
   * One-shot fetch per relay: each entry reports its own events and end reason (`eose`, `closed`,
   * `timeout`), or `failed` when the connect or REQ itself errored. An abort rejects the whole
   * call. Events are not deduped across relays — use {@link fetch} for that.
   */
  async fetchEach(
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts?: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined },
  ): Promise<PoolFetchResult[]> {
    if (filters.length === 0) {
      throw new MessageError("REQ requires at least one filter");
    }
    throwIfAborted(opts?.signal);
    const canonical = canonicalizeFilters(filters);
    return Promise.all(
      uniqueRelayUrls(relays).map(async (url): Promise<PoolFetchResult> => {
        try {
          const relay = await this.ensureRelay(url, {
            signal: opts?.signal,
            timeoutMs: this.#relayOptions.connectTimeoutMs,
          });
          this.#touch(relay.url);
          const result = await relay.fetch([...canonical], {
            timeoutMs: opts?.timeoutMs,
            signal: opts?.signal,
          });
          return { url, events: result.events, end: result.end };
        } catch (error) {
          // An abort rejects the whole call; per-relay failures are reported.
          if (opts?.signal?.aborted === true) {
            throw abortReason(opts.signal);
          }
          return {
            url,
            events: [],
            end: { type: "failed", error: toError(error) },
          };
        }
      }),
    );
  }

  /** Fetch events until each connected relay EOSE or timeout; dedupe by id. */
  async fetch(
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
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
      connectTimeoutMs: this.#relayOptions.connectTimeoutMs,
      onevent: opts?.onevent,
    });
  }

  /** Publish to all listed relays; returns per-relay outcomes. */
  async publish(
    relays: ReadonlyArray<string>,
    event: Event,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PoolPublishResult[]> {
    return Promise.all(
      uniqueRelayUrls(relays).map(async (url): Promise<PoolPublishResult> => {
        try {
          const relay = await this.ensureRelay(url, {
            timeoutMs: this.#relayOptions.connectTimeoutMs,
          });
          this.#touch(relay.url);
          const result = await relay.publish(event, { timeoutMs: opts?.timeoutMs });
          return result.ok
            ? { url, status: "ok", message: result.message }
            : { url, status: "rejected", message: result.message };
        } catch (error) {
          return { url, status: "failed", error: toError(error) };
        }
      }),
    );
  }

  /** First successful publish (Promise.any semantics). */
  async publishAny(
    relays: ReadonlyArray<string>,
    event: Event,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<Extract<PoolPublishResult, { status: "ok" }>> {
    return Promise.any(
      uniqueRelayUrls(relays).map(async (url) => {
        const relay = await this.ensureRelay(url, {
          timeoutMs: this.#relayOptions.connectTimeoutMs,
        });
        this.#touch(relay.url);
        const result = await relay.publish(event, { timeoutMs: opts?.timeoutMs });
        if (!result.ok) {
          throw new RelayPublishError(result.message || "rejected", relay.url);
        }
        return { url, status: "ok" as const, message: result.message };
      }),
    );
  }

  /**
   * NIP-45 COUNT across relays. Per-relay outcomes; failures do not throw. Counts are not summed —
   * each relay reports independently (may overlap).
   */
  async count(
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts?: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined },
  ): Promise<PoolCountResult[]> {
    throwIfAborted(opts?.signal);
    const canonical = canonicalizeFilters(filters);
    return Promise.all(
      uniqueRelayUrls(relays).map(async (url): Promise<PoolCountResult> => {
        try {
          const relay = await this.ensureRelay(url, {
            signal: opts?.signal,
            timeoutMs: this.#relayOptions.connectTimeoutMs,
          });
          this.#touch(relay.url);
          const payload: CountResult = await relay.count(canonical, {
            timeoutMs: opts?.timeoutMs,
            signal: opts?.signal,
          });
          return countOk(url, payload);
        } catch (error) {
          // An abort rejects the whole call; per-relay failures are reported.
          if (opts?.signal?.aborted === true) {
            throw abortReason(opts.signal);
          }
          return { url, status: "failed", error: toError(error) };
        }
      }),
    );
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
