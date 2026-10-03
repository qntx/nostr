import { raceSignal, throwIfAborted } from "../core/abort.ts";
import { Emitter } from "../core/emitter.ts";
import { MessageError, WasmPoisonedError } from "../core/error.ts";
import type { Event, EventTemplate } from "../core/event.ts";
import { canonicalizeFilter, canonicalizeFilters } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import {
  assertSubscriptionId,
  createSubscriptionId,
  encodeClientMessage,
  parseRelayMessage,
} from "../core/message.ts";
import type { ClientMessage, CountResult, SubscriptionId } from "../core/message.ts";
import { normalizeURL } from "../core/util.ts";
import { verifyEvent } from "../core/verifier.ts";
import type { EventVerifier } from "../core/verifier.ts";
import { isAuthRequired } from "../nips/nip42.ts";
import type { NegentropyStorageVector } from "../nips/nip77.ts";
import { RelayAuth } from "./auth.ts";
import { CountTracker } from "./count-tracker.ts";
import {
  RelayClosedError,
  RelayConnectionError,
  RelayError,
  RelayPublishError,
  RelayTimeoutError,
} from "./error.ts";
import { fetchFilters, streamFilters } from "./fetch.ts";
import type { RelayFetchResult } from "./fetch.ts";
import { dispatchNegMessage, failAllNegSessions, runTrackedNegSession } from "./neg-session.ts";
import type { NegSession } from "./neg-session.ts";
import { OkTracker } from "./ok-tracker.ts";
import type { PublishResult } from "./ok-tracker.ts";
import { DEFAULT_PING_INTERVAL_MS, DEFAULT_PING_TIMEOUT_MS, PingLoop } from "./ping.ts";
import { SubscriptionRegistry } from "./subscription-registry.ts";
import type { Closer, RelaySubscription, SubscribeOptions } from "./subscription.ts";
import { getWebSocketImplementation } from "./websocket.ts";
import type { WebSocketConstructor, WebSocketLike } from "./websocket.ts";

/**
 * Relay lifecycle states:
 *
 * - `initialized` — constructed; `connect()` not yet attempted.
 * - `connecting` — a `connect()` attempt is in flight (socket opening / resubscribing).
 * - `connected` — socket open; REQ/EVENT/COUNT flow.
 * - `disconnected` — socket down: a reconnect is scheduled when `enableReconnect` has live
 *   subscriptions to restore, or `disconnect()` severed manually (REQ state kept).
 * - `closed` — terminal until the next `connect()`: `close()` or a socket death without a scheduled
 *   reconnect.
 */
export const RelayStatus = {
  Initialized: "initialized",
  Connecting: "connecting",
  Connected: "connected",
  Disconnected: "disconnected",
  Closed: "closed",
} as const;
/** Union of the {@link RelayStatus} values. */
export type RelayStatusName = (typeof RelayStatus)[keyof typeof RelayStatus];

/** Per-relay options: socket override, verification, timeouts, reconnect, ping, NIP-42 auth. */
export type RelayOptions = {
  websocketImplementation?: WebSocketConstructor | undefined;
  verifyEvent?: EventVerifier | undefined;
  publishTimeoutMs?: number | undefined;
  connectTimeoutMs?: number | undefined;
  /**
   * When true, unexpected disconnects schedule reconnect with backoff and re-fire open
   * subscriptions. Default false.
   */
  enableReconnect?: boolean | undefined;
  /** Backoff delays in ms between reconnect attempts. */
  reconnectBackoffMs?: ReadonlyArray<number> | undefined;
  enablePing?: boolean | undefined;
  pingIntervalMs?: number | undefined;
  pingTimeoutMs?: number | undefined;
  /** When set, CLOSED/OK `auth-required:` triggers AUTH then retries the REQ/EVENT/COUNT. */
  authSigner?: ((template: EventTemplate) => Promise<Event>) | undefined;
};

/** Typed event payloads for {@link Relay.on}: lifecycle and protocol notifications. */
export type RelayEventMap = {
  /** A NIP-01 NOTICE message from the relay. */
  notice: string;
  /** Terminal close of the relay (a transient disconnect with reconnect does not fire it). */
  close: undefined;
  /** Fired when the relay sends a NIP-42 AUTH challenge. */
  auth: string;
  /** Fired after a successful reconnect (not the initial connect). */
  reconnect: undefined;
  /**
   * Fired when a delivered EVENT fails id/signature verification, just before the event is dropped.
   * A poisoned verifier dropping events does not fire it. EVENTs that do not match the
   * subscription's filters are dropped silently and are not counted here.
   */
  invalidevent: undefined;
};

type SocketHandlers = {
  onOpen: () => void;
  onError: () => void;
  onClose: () => void;
  onMessage: (ev: unknown) => void;
  ws: WebSocketLike;
};

export const DEFAULT_REQUEST_TIMEOUT_MS = 4400;
export const DEFAULT_CONNECT_TIMEOUT_MS = 5000;

const DEFAULT_BACKOFF = [1000, 2000, 5000, 10_000, 20_000, 30_000, 60_000];

const noop = (): void => {
  // placeholder until the Promise executor captures resolve/reject
};

/**
 * Single-relay NIP-01 client. Connection lifecycle, REQ/CLOSE, EVENT publish ACK, AUTH, COUNT,
 * NIP-77, optional reconnect.
 */
export class Relay {
  readonly url: string;
  #ws: WebSocketLike | undefined;
  #gen = 0;
  #status: RelayStatusName = RelayStatus.Initialized;
  #connecting: Promise<void> | undefined;
  #connectFinish: ((err?: unknown) => void) | undefined;
  #connectTimer: ReturnType<typeof setTimeout> | undefined;
  #socketHandlers: SocketHandlers | undefined;
  readonly #subscriptions: SubscriptionRegistry;
  readonly #ok = new OkTracker();
  readonly #countRequests = new CountTracker();
  readonly #authState: RelayAuth;
  readonly #ensureAuthed: () => Promise<boolean>;
  readonly #neg = new Map<SubscriptionId, NegSession>();
  readonly #WS: WebSocketConstructor;
  readonly #verify: EventVerifier;
  #verifyDead = false;
  readonly #publishTimeoutMs: number;
  readonly #connectTimeoutMs: number;
  readonly #enableReconnect: boolean;
  readonly #backoff: ReadonlyArray<number>;
  #serial = 0;
  readonly #authSigner: ((template: EventTemplate) => Promise<Event>) | undefined;
  /** `close()`/`disconnect()` was called; cleared by the next `connect()`. */
  #manualStop = false;
  #reconnectAttempts = 0;
  #reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  readonly #enablePing: boolean;
  readonly #ping: PingLoop;
  readonly #events = new Emitter<RelayEventMap>();

  constructor(url: string, opts: RelayOptions = {}) {
    this.url = normalizeURL(url);
    this.#WS = opts.websocketImplementation ?? getWebSocketImplementation();
    this.#verify = opts.verifyEvent ?? verifyEvent;
    this.#publishTimeoutMs = opts.publishTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.#connectTimeoutMs = opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.#enableReconnect = opts.enableReconnect ?? false;
    this.#backoff = opts.reconnectBackoffMs ?? DEFAULT_BACKOFF;
    this.#enablePing = opts.enablePing ?? false;
    this.#authSigner = opts.authSigner;
    this.#ping = new PingLoop({
      send: (message) => this.#send(message),
      nextSubId: (prefix) => this.nextSubId(prefix),
      getWs: () => this.#ws,
      closeWs: () => {
        const ws = this.#ws;
        if (ws && ws.readyState === this.#WS.OPEN) {
          try {
            ws.close();
          } catch {
            // ignore
          }
        }
      },
      pingIntervalMs: opts.pingIntervalMs ?? DEFAULT_PING_INTERVAL_MS,
      pingTimeoutMs: opts.pingTimeoutMs ?? DEFAULT_PING_TIMEOUT_MS,
    });
    this.#subscriptions = new SubscriptionRegistry({
      isOpen: () => this.#isOpen(),
      enableReconnect: this.#enableReconnect,
      send: (message) => this.#send(message),
      scheduleReconnect: () => this.#scheduleReconnect(),
      acceptEvent: (event) => this.#acceptEvent(event),
    });
    this.#authState = new RelayAuth({
      url: this.url,
      isOpen: () => this.#isOpen(),
      // oxlint-disable-next-line typescript/promise-function-async -- returns the tracker promise directly
      sendAuth: (event, timeoutMs) =>
        this.#ok.track(event.id, {
          timeoutMs,
          timeoutError: () => new RelayTimeoutError("auth timed out", this.url),
          sendError: () => new RelayPublishError("auth send failed", this.url),
          send: () => this.#send(["AUTH", event]),
        }),
      defaultTimeoutMs: this.#publishTimeoutMs,
    });
    this.#ensureAuthed = this.#authState.ensureAuthed.bind(this.#authState, this.#authSigner);
  }

  /** Latest NIP-42 challenge, if any. */
  get challenge(): string | undefined {
    return this.#authState.challenge;
  }

  get connected(): boolean {
    return this.#isOpen();
  }

  get status(): RelayStatusName {
    return this.#status;
  }

  #isOpen(): boolean {
    return this.#status === RelayStatus.Connected;
  }

  #setStatus(next: RelayStatusName): void {
    this.#status = next;
  }

  get generation(): number {
    return this.#gen;
  }

  get reconnectEnabled(): boolean {
    return this.#enableReconnect;
  }

  /** User subscriptions only; dummy ping REQs are not counted. */
  get subscriptionCount(): number {
    return this.#subscriptions.size;
  }

  /** One-shot requests still awaiting a relay reply (EVENT ACK, COUNT, NEG). */
  get inFlightCount(): number {
    return this.#ok.size + this.#countRequests.size + this.#neg.size;
  }

  /**
   * Listen for a relay event. Multiple listeners per type are allowed and fire in registration
   * order; a throwing listener is reported and does not break the dispatch. Returns an unsubscribe
   * function.
   */
  on<K extends keyof RelayEventMap>(
    type: K,
    listener: (payload: RelayEventMap[K]) => void,
  ): () => void {
    return this.#events.on(type, listener);
  }

  static async connect(
    url: string,
    opts?: RelayOptions & { signal?: AbortSignal },
  ): Promise<Relay> {
    const relay = new Relay(url, opts);
    await relay.connect({ signal: opts?.signal });
    return relay;
  }

  async connect(opts?: {
    signal?: AbortSignal | undefined;
    timeoutMs?: number | undefined;
  }): Promise<void> {
    if (this.#isOpen()) {
      return;
    }
    // A connect attempt is never owned by a caller's signal: joiners race
    // their own signal against the shared attempt; only close() cancels it.
    if (this.#connecting) {
      await raceSignal(this.#connecting, opts?.signal);
      return;
    }
    throwIfAborted(opts?.signal);

    const gen = ++this.#gen;
    this.#manualStop = false;
    this.#clearReconnectTimer();
    this.#setStatus(RelayStatus.Connecting);

    const timeoutMs = opts?.timeoutMs ?? this.#connectTimeoutMs;

    let resolveConnect: () => void = noop;
    let rejectConnect: (err: unknown) => void = noop;
    let settled = false;
    let ws: WebSocketLike | undefined;

    const connecting = new Promise<void>((resolve, reject) => {
      resolveConnect = resolve;
      rejectConnect = reject;
    });

    const release = (): void => {
      if (ws === undefined) {
        return;
      }
      this.#removeSocketListeners(handlers);
      if (this.#socketHandlers === handlers) {
        this.#socketHandlers = undefined;
      }
      try {
        if (ws.readyState !== this.#WS.CLOSED && ws.readyState !== this.#WS.CLOSING) {
          ws.close();
        }
      } catch {
        // ignore
      }
      if (this.#ws === ws) {
        this.#ws = undefined;
      }
    };

    // Stale-generation guard: events from a superseded socket release it before returning;
    // onMessage is the exception — it only ignores them.
    const guarded = (fn: () => void): (() => void) => {
      return () => {
        if (gen !== this.#gen) {
          release();
          return;
        }
        fn();
      };
    };

    const finish = (err?: unknown): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (this.#connectTimer === timer) {
        this.#connectTimer = undefined;
      }
      if (this.#connectFinish === finish) {
        this.#connectFinish = undefined;
      }
      if (this.#connecting === connecting) {
        this.#connecting = undefined;
      }
      if (err === undefined) {
        resolveConnect();
      } else {
        rejectConnect(err);
      }
    };

    this.#connecting = connecting;
    this.#connectFinish = finish;

    const timer = setTimeout(
      guarded(() => {
        release();
        finish(new RelayTimeoutError("connection timed out", this.url));
        if (gen === this.#gen) {
          this.#handleSocketDeath("connection timed out", { fromConnectAttempt: true, gen });
        }
      }),
      timeoutMs,
    );
    this.#connectTimer = timer;

    try {
      ws = new this.#WS(this.url);
    } catch (error) {
      finish(error);
      if (gen === this.#gen) {
        this.#handleSocketDeath("connection failed", { fromConnectAttempt: true, gen });
      }
      await raceSignal(connecting, opts?.signal);
      return;
    }
    this.#ws = ws;

    const onOpen = guarded((): void => {
      this.#setStatus(RelayStatus.Connected);
      const wasReconnect = this.#reconnectAttempts > 0;
      this.#authState.resetConnection();
      if (!this.#subscriptions.replayAll()) {
        this.#setStatus(RelayStatus.Disconnected);
        release();
        finish(new RelayConnectionError("connection failed", this.url));
        if (this.#enableReconnect && !this.#manualStop && this.#subscriptions.size > 0) {
          this.#scheduleReconnect();
        }
        return;
      }
      this.#reconnectAttempts = 0;
      if (this.#enablePing) {
        this.#ping.start();
      } else {
        this.#ping.stop();
      }
      if (wasReconnect) {
        this.#events.emit("reconnect", undefined);
      }
      finish();
    });
    const onError = guarded((): void => {
      const fromConnectAttempt = !settled;
      release();
      finish(new RelayConnectionError("connection failed", this.url));
      if (gen === this.#gen) {
        this.#handleSocketDeath("connection failed", { fromConnectAttempt, gen });
      }
    });
    const onClose = guarded((): void => {
      const fromConnectAttempt = !settled;
      release();
      if (fromConnectAttempt) {
        finish(new RelayConnectionError("websocket closed", this.url));
      }
      if (gen === this.#gen) {
        this.#handleSocketDeath("websocket closed", { fromConnectAttempt, gen });
      }
    });
    const onMessage = (ev: unknown): void => {
      if (gen !== this.#gen) {
        return;
      }
      const data = typeof ev === "object" && ev !== null && "data" in ev ? ev.data : ev;
      this.#onMessage(String(data));
    };

    const handlers: SocketHandlers = { onOpen, onError, onClose, onMessage, ws };
    this.#socketHandlers = handlers;
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onError);
    ws.addEventListener("close", onClose);
    ws.addEventListener("message", onMessage);

    await raceSignal(connecting, opts?.signal);
  }

  #removeSocketListeners(h: SocketHandlers): void {
    try {
      h.ws.removeEventListener("open", h.onOpen);
      h.ws.removeEventListener("error", h.onError);
      h.ws.removeEventListener("close", h.onClose);
      h.ws.removeEventListener("message", h.onMessage);
    } catch {
      // ignore
    }
  }

  #detachSocketHandlers(): void {
    const h = this.#socketHandlers;
    if (!h) {
      return;
    }
    this.#removeSocketListeners(h);
    this.#socketHandlers = undefined;
  }

  /** Graceful shutdown: disables reconnect and closes all subscriptions. */
  close(): void {
    this.#gen += 1;
    this.#setStatus(RelayStatus.Closed);
    this.#manualStop = true;
    this.#clearReconnectTimer();
    if (this.#connectTimer !== undefined) {
      clearTimeout(this.#connectTimer);
      this.#connectTimer = undefined;
    }
    this.#ping.stop();
    this.#connectFinish?.(new RelayClosedError("relay closed", this.url));
    try {
      this.#subscriptions.closeAll("relay closed");
    } finally {
      this.#failPending(new RelayClosedError("relay closed", this.url));
      this.#detachSocketHandlers();
      this.#teardownSocket();
      this.#events.emit("close", undefined);
    }
  }

  /**
   * Sever the socket while keeping every subscription: unlike {@link close}, open REQ state is
   * preserved and reconnect stays suppressed — the next {@link connect} re-subscribes all of them.
   * {@link Pool} uses this to suspend a relay without tearing down its live subscriptions.
   */
  disconnect(): void {
    this.#gen += 1;
    this.#setStatus(RelayStatus.Disconnected);
    this.#manualStop = true;
    this.#clearReconnectTimer();
    if (this.#connectTimer !== undefined) {
      clearTimeout(this.#connectTimer);
      this.#connectTimer = undefined;
    }
    this.#ping.stop();
    this.#connectFinish?.(new RelayClosedError("relay disconnected", this.url));
    this.#failPending(new RelayClosedError("relay disconnected", this.url));
    this.#detachSocketHandlers();
    this.#teardownSocket();
  }

  #teardownSocket(): void {
    try {
      this.#ws?.close();
    } catch {
      // ignore
    }
    this.#ws = undefined;
  }

  #clearReconnectTimer(): void {
    if (this.#reconnectTimer !== undefined) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }
  }

  #failPending(err: Error): void {
    this.#ok.rejectAll(err);
    this.#countRequests.rejectAll(err);
    failAllNegSessions(this.#neg, err);
  }

  /** Unexpected socket death. Keep subscriptions if reconnecting. */
  #handleSocketDeath(reason: string, opts: { fromConnectAttempt?: boolean; gen: number }): void {
    if (opts.gen !== this.#gen) {
      return;
    }
    // Stale-gen guards retire every later event from this socket (error+close pairs collapse).
    this.#gen += 1;
    this.#ping.stop();
    this.#detachSocketHandlers();
    this.#ws = undefined;
    this.#failPending(new RelayClosedError(reason, this.url));

    const canReconnect = this.#enableReconnect && !this.#manualStop && this.#subscriptions.size > 0;

    if (canReconnect) {
      this.#setStatus(RelayStatus.Disconnected);
      this.#scheduleReconnect();
      return;
    }

    // Transitional: subscription close callbacks below observe `disconnected` first.
    this.#setStatus(RelayStatus.Disconnected);

    if (opts.fromConnectAttempt !== true || this.#subscriptions.size > 0) {
      this.#subscriptions.closeAll(reason);
      if (!this.#manualStop) {
        this.#events.emit("close", undefined);
      }
    }

    this.#setStatus(RelayStatus.Closed);
  }

  #scheduleReconnect(): void {
    if (this.#reconnectTimer !== undefined) {
      return;
    }
    if (this.#isOpen()) {
      return;
    }
    const delay =
      this.#backoff[Math.min(this.#reconnectAttempts, this.#backoff.length - 1)] ?? 60_000;
    this.#reconnectAttempts += 1;
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (this.#manualStop || this.#isOpen()) {
        return;
      }
      void (async (): Promise<void> => {
        try {
          await this.connect();
        } catch {
          if (
            this.#enableReconnect &&
            !this.#manualStop &&
            this.#subscriptions.size > 0 &&
            !this.#isOpen()
          ) {
            this.#scheduleReconnect();
          }
        }
      })();
    }, delay);
  }

  #send(message: ClientMessage | string): void {
    if (!this.#ws || !this.#isOpen()) {
      throw new RelayClosedError("not connected", this.url);
    }
    const raw = typeof message === "string" ? message : encodeClientMessage(message);
    this.#ws.send(raw);
  }

  #onMessage(raw: string): void {
    let msg;
    try {
      msg = parseRelayMessage(raw);
    } catch {
      return;
    }

    switch (msg[0]) {
      case "EVENT": {
        const [, subId, event] = msg;
        if (this.#ping.hasWaiter(subId)) {
          return;
        }
        this.#subscriptions.handleEvent(subId, event);
        break;
      }
      case "EOSE": {
        const [, subId] = msg;
        if (this.#ping.finishDummyPing(subId)) {
          return;
        }
        this.#subscriptions.handleEose(subId);
        break;
      }
      case "CLOSED": {
        const [, subId, reason] = msg;
        if (this.#ping.finishDummyPing(subId)) {
          return;
        }
        const countWaiter = this.#countRequests.get(subId);
        if (countWaiter) {
          if (isAuthRequired(reason) && this.#authSigner && !countWaiter.authRetried) {
            countWaiter.authRetried = true;
            void this.#countRequests.authRetry(countWaiter, {
              ensureAuthed: this.#ensureAuthed,
              isOpen: () => this.#isOpen(),
              failError: () => new RelayClosedError(reason || "COUNT closed", this.url),
              send: () => this.#send(["COUNT", subId, ...countWaiter.filters]),
            });
            return;
          }
          countWaiter.reject(new RelayClosedError(reason || "COUNT closed", this.url));
          return;
        }
        const sub = this.#subscriptions.get(subId);
        if (!sub) {
          return;
        }
        if (isAuthRequired(reason) && this.#authSigner && sub.beginAuthRetry()) {
          void this.#subscriptions.authRetry(sub, reason, this.#ensureAuthed);
          return;
        }
        this.#subscriptions.drop(sub, reason);
        break;
      }
      case "OK": {
        const [, eventId, ok, message] = msg;
        const waiter = this.#ok.handleOk(
          eventId,
          ok,
          message,
          (w) =>
            !ok &&
            isAuthRequired(message) &&
            w.event !== undefined &&
            !w.authRetried &&
            this.#authSigner !== undefined,
        );
        if (!waiter) {
          return;
        }
        waiter.authRetried = true;
        void this.#ok.authRetry(waiter, message, {
          ensureAuthed: this.#ensureAuthed,
          isOpen: () => this.#isOpen(),
          send: (event) => this.#send(["EVENT", event]),
        });
        return;
      }
      case "COUNT": {
        const [, countId, payload] = msg;
        const waiter = this.#countRequests.get(countId);
        if (!waiter) {
          return;
        }
        waiter.resolve(payload);
        break;
      }
      case "NEG-MSG":
      case "NEG-ERR":
        dispatchNegMessage(this.#neg, msg);
        break;
      case "NOTICE": {
        const [, notice] = msg;
        this.#events.emit("notice", notice);
        break;
      }
      case "AUTH": {
        const [, authChallenge] = msg;
        this.#authState.handleChallenge(authChallenge);
        this.#events.emit("auth", authChallenge);
        break;
      }
    }
  }

  /** Low-level REQ with callbacks. Survives reconnect when enableReconnect is on. */
  subscribe(filters: ReadonlyArray<Filter>, opts: SubscribeOptions = {}): RelaySubscription {
    if (filters.length === 0) {
      throw new MessageError("REQ requires at least one filter");
    }
    if (!this.#isOpen() && !this.#enableReconnect) {
      throw new RelayClosedError("not connected", this.url);
    }
    const canonical = canonicalizeFilters(filters);
    return this.#subscriptions.open(canonical, opts);
  }

  #acceptEvent(event: Event): boolean {
    if (this.#verifyDead) {
      return false;
    }
    try {
      const ok = this.#verify(event);
      if (!ok) {
        this.#events.emit("invalidevent", undefined);
      }
      return ok;
    } catch (error) {
      if (error instanceof WasmPoisonedError) {
        this.#verifyDead = true;
        this.#events.emit("notice", "wasm-poisoned: instance aborted");
        return false;
      }
      throw error;
    }
  }

  /** AsyncIterable of events for filters until the subscription is closed. */
  stream(
    filters: ReadonlyArray<Filter>,
    opts?: { signal?: AbortSignal | undefined; id?: string | undefined },
  ): AsyncIterable<Event> & Closer {
    return streamFilters((f, o) => this.subscribe(f, o), filters, opts);
  }

  /**
   * One-shot query: collect events until the REQ ends, then close. `end` reports how it ended —
   * relay `EOSE`, relay `CLOSED` (with its reason), or the local timeout; events received before a
   * CLOSED or the deadline are still returned. Abort rejects; a failed (re)connect rejects.
   */
  async fetch(
    filters: ReadonlyArray<Filter>,
    opts?: {
      timeoutMs?: number | undefined;
      signal?: AbortSignal | undefined;
      id?: string | undefined;
    },
  ): Promise<RelayFetchResult> {
    if (filters.length === 0) {
      throw new MessageError("REQ requires at least one filter");
    }
    const canonical = canonicalizeFilters(filters);
    if (!this.#isOpen()) {
      await this.connect({ signal: opts?.signal });
    }
    return fetchFilters((f, o) => this.subscribe(f, o), canonical, {
      timeoutMs: opts?.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      signal: opts?.signal,
      id: opts?.id,
    });
  }

  /**
   * Publish an event and wait for OK. A concurrent publish of the same event id joins the in-flight
   * publish instead of racing it — the joiner's `timeoutMs` does not apply.
   */
  async publish(event: Event, opts?: { timeoutMs?: number | undefined }): Promise<PublishResult> {
    if (!this.#isOpen()) {
      throw new RelayClosedError("not connected", this.url);
    }
    const existing = this.#ok.inFlight(event.id);
    if (existing !== undefined) {
      return existing;
    }
    const timeoutMs = opts?.timeoutMs ?? this.#publishTimeoutMs;
    return this.#ok.track(event.id, {
      timeoutMs,
      timeoutError: () => new RelayTimeoutError("publish timed out", this.url),
      sendError: () => new RelayPublishError("publish failed", this.url),
      event,
      send: () => this.#send(["EVENT", event]),
    });
  }

  /**
   * NIP-45 COUNT: ask the relay how many events match `filters`. Resolves with the COUNT payload
   * (count / optional approximate / optional hll).
   */
  async count(
    filters: ReadonlyArray<Filter>,
    opts?: {
      id?: string | undefined;
      timeoutMs?: number | undefined;
      signal?: AbortSignal | undefined;
    },
  ): Promise<CountResult> {
    if (!this.#isOpen()) {
      throw new RelayClosedError("not connected", this.url);
    }
    if (filters.length === 0) {
      throw new RelayError("COUNT requires at least one filter", this.url);
    }
    throwIfAborted(opts?.signal);
    const canonical = canonicalizeFilters(filters);

    const id = opts?.id === undefined ? this.nextSubId("count") : createSubscriptionId(opts.id);
    const timeoutMs = opts?.timeoutMs ?? this.#publishTimeoutMs;

    return this.#countRequests.track(id, {
      timeoutMs,
      timeoutError: () => new RelayTimeoutError("count timed out", this.url),
      sendError: () => new RelayPublishError("count failed", this.url),
      filters: [...canonical],
      signal: opts?.signal,
      send: () => this.#send(["COUNT", id, ...canonical]),
    });
  }

  /** NIP-42 AUTH: sign the current challenge and wait for OK. */
  async auth(
    sign: (template: EventTemplate) => Promise<Event>,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PublishResult> {
    return this.#authState.auth(sign, opts);
  }

  /**
   * Clear a cached AUTH rejection for the current challenge so a later `auth()` signs again. A
   * successful auth and in-flight answers are kept. When a challenge is pending and unanswered, an
   * `auth` event is re-fired so the pool's automatic auth can run once more.
   */
  resetAuth(): void {
    const challenge = this.#authState.resetRejection();
    if (challenge !== undefined) {
      this.#events.emit("auth", challenge);
    }
  }

  /**
   * NIP-77: run Negentropy reconciliation against this relay. Returns the local-only (`have`) and
   * remote-only (`need`) event ids. Does not upload or download events.
   *
   * `timeoutMs` is a single wall-clock deadline for the whole session (`NEG-OPEN` through the last
   * `NEG-MSG`), not a per-message budget. Default: {@link RelayOptions.publishTimeoutMs}.
   */
  async negReconcile(
    filter: Filter,
    storage: NegentropyStorageVector,
    opts?: {
      id?: string | undefined;
      timeoutMs?: number | undefined;
      signal?: AbortSignal | undefined;
    },
  ): Promise<{ have: string[]; need: string[] }> {
    if (!this.#isOpen()) {
      throw new RelayClosedError("not connected", this.url);
    }
    throwIfAborted(opts?.signal);
    const id = opts?.id === undefined ? this.nextSubId("neg") : assertSubscriptionId(opts.id);
    return runTrackedNegSession({
      sessions: this.#neg,
      id,
      storage,
      filter: canonicalizeFilter(filter),
      timeoutMs: opts?.timeoutMs ?? this.#publishTimeoutMs,
      signal: opts?.signal,
      send: (message) => this.#send(message),
      url: this.url,
    });
  }

  /** Generate a unique subscription id for this relay instance. */
  nextSubId(prefix = "sub"): string {
    this.#serial += 1;
    return `${prefix}:${this.#serial}`;
  }
}

export type { CountResult } from "../core/message.ts";
export type { PublishResult } from "./ok-tracker.ts";
export type { RelayFetchEnd, RelayFetchResult } from "./fetch.ts";
export type { SubscribeOptions, SubscriptionHandlers } from "./subscription.ts";
