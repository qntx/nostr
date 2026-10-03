import { abortReason, onAbort, raceSignal, throwIfAborted } from "../core/abort.ts";
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
import { invokeSafely } from "../core/report.ts";
import { normalizeURL } from "../core/util.ts";
import { verifyEvent } from "../core/verifier.ts";
import type { EventVerifier } from "../core/verifier.ts";
import { isAuthRequired, makeAuthEvent } from "../nips/nip42.ts";
import { Nip77Error } from "../nips/nip77.ts";
import type { NegentropyStorageVector } from "../nips/nip77.ts";
import { NoSignerError } from "../signer/error.ts";
import {
  RelayClosedError,
  RelayConnectionError,
  RelayError,
  RelayPublishError,
  RelayTimeoutError,
} from "./error.ts";
import {
  createNegSession,
  failNegErr,
  failNegSession,
  pushNegMsg,
  runWiredNegSession,
} from "./neg-session.ts";
import type { NegSession } from "./neg-session.ts";
import { DEFAULT_PING_INTERVAL_MS, DEFAULT_PING_TIMEOUT_MS, PingLoop } from "./ping.ts";
import {
  armEoseTimeout,
  closeAllSubscriptions,
  dropSubscription,
  fetchFilters,
  onSubEose,
  onSubEvent,
  openExclusive,
  resubscribeAll,
  streamFilters,
  subscribeLive,
} from "./subscribe.ts";
import type { LiveCtx, LiveGroup, RelayFetchResult } from "./subscribe.ts";
import type { Closer, RelaySubscription, SubscribeOptions, Subscription } from "./subscription.ts";
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

/** A relay's NIP-01 OK reply to a published event. */
export type PublishResult = {
  ok: boolean;
  message: string;
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
   * A poisoned verifier dropping events does not fire it.
   */
  invalidevent: undefined;
};

type PublishWaiter = {
  resolve: (result: PublishResult) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  event?: Event;
  authRetried?: boolean;
  timeoutMs: number;
  /** The owning publish()/auth() promise — joiners on the same event id settle with it. */
  promise: Promise<PublishResult>;
};

type CountWaiter = {
  resolve: (result: CountResult) => void;
  reject: (err: unknown) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  filters: Filter[];
  authRetried: boolean;
  timeoutMs: number;
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
  readonly #subs = new Map<SubscriptionId, Subscription>();
  readonly #liveByFp = new Map<string, LiveGroup>();
  readonly #liveBySubId = new Map<SubscriptionId, LiveGroup>();
  readonly #live: LiveCtx;
  readonly #publishes = new Map<string, PublishWaiter>();
  readonly #counts = new Map<string, CountWaiter>();
  readonly #neg = new Map<SubscriptionId, NegSession>();
  readonly #WS: WebSocketConstructor;
  readonly #verify: EventVerifier;
  #verifyDead = false;
  readonly #publishTimeoutMs: number;
  readonly #connectTimeoutMs: number;
  readonly #enableReconnect: boolean;
  readonly #backoff: ReadonlyArray<number>;
  #serial = 0;
  #challenge: string | undefined;
  #authedChallenge: string | undefined;
  /** Challenge value already answered on this connection; duplicates are not re-signed. */
  #answeredChallenge: string | undefined;
  /** Settled OK verdict for `#answeredChallenge`; set only once the relay replies. */
  #answeredResult: PublishResult | undefined;
  #authPromise: Promise<PublishResult> | undefined;
  readonly #authSigner: ((template: EventTemplate) => Promise<Event>) | undefined;
  /** `close()`/`disconnect()` was called; cleared by the next `connect()`. */
  #manualStop = false;
  #reconnectAttempts = 0;
  #reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  readonly #enablePing: boolean;
  readonly #ping: PingLoop;
  readonly #listeners: { [K in keyof RelayEventMap]: Set<(payload: RelayEventMap[K]) => void> } = {
    notice: new Set(),
    close: new Set(),
    auth: new Set(),
    reconnect: new Set(),
    invalidevent: new Set(),
  };

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
    this.#live = {
      liveByFp: this.#liveByFp,
      liveBySubId: this.#liveBySubId,
      subs: this.#subs,
      connected: () => this.#isOpen(),
      enableReconnect: () => this.#enableReconnect,
      send: (message) => this.#send(message),
      scheduleReconnect: () => this.#scheduleReconnect(),
      acceptEvent: (event) => this.#acceptEvent(event),
      armEoseTimeout,
    };
  }

  /** Latest NIP-42 challenge, if any. */
  get challenge(): string | undefined {
    return this.#challenge;
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
    return this.#subs.size;
  }

  /** One-shot requests still awaiting a relay reply (EVENT ACK, COUNT, NEG). */
  get inFlightCount(): number {
    return this.#publishes.size + this.#counts.size + this.#neg.size;
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
    const set = this.#listeners[type];
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }

  #emit<K extends keyof RelayEventMap>(type: K, payload: RelayEventMap[K]): void {
    // snapshot: listeners may unsubscribe or register during dispatch
    // oxlint-disable-next-line no-useless-spread -- intentional snapshot copy
    for (const listener of [...this.#listeners[type]]) {
      invokeSafely(() => listener(payload));
    }
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

    const timer = setTimeout(() => {
      if (gen !== this.#gen) {
        release();
        return;
      }
      release();
      finish(new RelayTimeoutError("connection timed out", this.url));
      if (gen === this.#gen) {
        this.#handleSocketDeath("connection timed out", { fromConnectAttempt: true, gen });
      }
    }, timeoutMs);
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

    const onOpen = (): void => {
      if (gen !== this.#gen) {
        release();
        return;
      }
      this.#setStatus(RelayStatus.Connected);
      const wasReconnect = this.#reconnectAttempts > 0;
      this.#challenge = undefined;
      this.#authPromise = undefined;
      this.#authedChallenge = undefined;
      this.#answeredChallenge = undefined;
      this.#answeredResult = undefined;
      if (!resubscribeAll(this.#live)) {
        this.#setStatus(RelayStatus.Disconnected);
        release();
        finish(new RelayConnectionError("connection failed", this.url));
        if (this.#enableReconnect && !this.#manualStop && this.#subs.size > 0) {
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
        this.#emit("reconnect", undefined);
      }
      finish();
    };
    const onError = (): void => {
      if (gen !== this.#gen) {
        release();
        return;
      }
      const fromConnectAttempt = !settled;
      release();
      finish(new RelayConnectionError("connection failed", this.url));
      if (gen === this.#gen) {
        this.#handleSocketDeath("connection failed", { fromConnectAttempt, gen });
      }
    };
    const onClose = (): void => {
      if (gen !== this.#gen) {
        release();
        return;
      }
      const fromConnectAttempt = !settled;
      release();
      if (fromConnectAttempt) {
        finish(new RelayConnectionError("websocket closed", this.url));
      }
      if (gen === this.#gen) {
        this.#handleSocketDeath("websocket closed", { fromConnectAttempt, gen });
      }
    };
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
      closeAllSubscriptions(this.#live, "relay closed");
    } finally {
      this.#failPending(new RelayClosedError("relay closed", this.url));
      this.#detachSocketHandlers();
      this.#teardownSocket();
      this.#emit("close", undefined);
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

  #rejectPublishes(err: Error): void {
    for (const [, waiter] of this.#publishes) {
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
    this.#publishes.clear();
  }

  #rejectCounts(err: Error): void {
    for (const [, waiter] of this.#counts) {
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
    this.#counts.clear();
  }

  #rejectNeg(err: Error): void {
    for (const session of this.#neg.values()) {
      failNegSession(session, err);
    }
    this.#neg.clear();
  }

  #failPending(err: Error): void {
    this.#rejectPublishes(err);
    this.#rejectCounts(err);
    this.#rejectNeg(err);
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

    const canReconnect = this.#enableReconnect && !this.#manualStop && this.#subs.size > 0;

    if (canReconnect) {
      this.#setStatus(RelayStatus.Disconnected);
      this.#scheduleReconnect();
      return;
    }

    // Transitional: subscription close callbacks below observe `disconnected` first.
    this.#setStatus(RelayStatus.Disconnected);

    if (opts.fromConnectAttempt !== true || this.#subs.size > 0) {
      closeAllSubscriptions(this.#live, reason);
      if (!this.#manualStop) {
        this.#emit("close", undefined);
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
            this.#subs.size > 0 &&
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
        onSubEvent(this.#live, subId, event);
        break;
      }
      case "EOSE": {
        const [, subId] = msg;
        if (this.#ping.finishDummyPing(subId)) {
          return;
        }
        onSubEose(this.#live, subId);
        break;
      }
      case "CLOSED": {
        const [, subId, reason] = msg;
        if (this.#ping.finishDummyPing(subId)) {
          return;
        }
        const countWaiter = this.#counts.get(subId);
        if (countWaiter) {
          if (isAuthRequired(reason) && this.#authSigner && !countWaiter.authRetried) {
            countWaiter.authRetried = true;
            void this.#authThenRecount(subId, countWaiter, reason);
            return;
          }
          countWaiter.reject(new RelayClosedError(reason || "COUNT closed", this.url));
          return;
        }
        const sub = this.#subs.get(subId);
        if (!sub) {
          return;
        }
        if (isAuthRequired(reason) && this.#authSigner && !sub.authRetried) {
          sub.authRetried = true;
          void this.#authThenResubscribe(sub, reason);
          return;
        }
        dropSubscription(this.#live, sub, reason);
        break;
      }
      case "OK": {
        const [, eventId, ok, message] = msg;
        const waiter = this.#publishes.get(eventId);
        if (!waiter) {
          return;
        }
        if (
          !ok &&
          isAuthRequired(message) &&
          waiter.event !== undefined &&
          waiter.authRetried !== true &&
          this.#authSigner
        ) {
          waiter.authRetried = true;
          void this.#authThenRepublish(waiter, eventId, message);
          return;
        }
        clearTimeout(waiter.timer);
        this.#publishes.delete(eventId);
        waiter.resolve({ ok, message });
        break;
      }
      case "COUNT": {
        const [, countId, payload] = msg;
        const waiter = this.#counts.get(countId);
        if (!waiter) {
          return;
        }
        waiter.resolve(payload);
        break;
      }
      case "NEG-MSG": {
        const [, negId, hex] = msg;
        const session = this.#neg.get(negId);
        if (!session) {
          return;
        }
        pushNegMsg(session, hex);
        break;
      }
      case "NEG-ERR": {
        const [, negId, reason] = msg;
        const session = this.#neg.get(negId);
        if (!session) {
          return;
        }
        failNegErr(session, reason);
        break;
      }
      case "NOTICE": {
        const [, notice] = msg;
        this.#emit("notice", notice);
        break;
      }
      case "AUTH": {
        const [, authChallenge] = msg;
        // A re-sent identical challenge keeps the in-flight/settled dedupe;
        // only a new challenge value resets the answer state.
        if (authChallenge !== this.#challenge) {
          this.#authPromise = undefined;
          this.#authedChallenge = undefined;
          this.#answeredChallenge = undefined;
          this.#answeredResult = undefined;
        }
        this.#challenge = authChallenge;
        this.#emit("auth", authChallenge);
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
    if (opts.closeOnEose === true) {
      return openExclusive(this.#live, canonical, opts);
    }
    return subscribeLive(this.#live, canonical, opts);
  }

  #acceptEvent(event: Event): boolean {
    if (this.#verifyDead) {
      return false;
    }
    try {
      const ok = this.#verify(event);
      if (!ok) {
        this.#emit("invalidevent", undefined);
      }
      return ok;
    } catch (error) {
      if (error instanceof WasmPoisonedError) {
        this.#verifyDead = true;
        this.#emit("notice", "wasm-poisoned: instance aborted");
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
    const existing = this.#publishes.get(event.id);
    if (existing?.event !== undefined) {
      return existing.promise;
    }
    const timeoutMs = opts?.timeoutMs ?? this.#publishTimeoutMs;

    const promise = new Promise<PublishResult>((resolve, reject) => {
      const waiter: PublishWaiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          if (this.#publishes.get(event.id) === waiter) {
            this.#publishes.delete(event.id);
            reject(new RelayTimeoutError("publish timed out", this.url));
          }
        }, timeoutMs),
        event,
        timeoutMs,
        get promise() {
          return promise;
        },
      };
      this.#publishes.set(event.id, waiter);
      try {
        this.#send(["EVENT", event]);
      } catch (error) {
        clearTimeout(waiter.timer);
        if (this.#publishes.get(event.id) === waiter) {
          this.#publishes.delete(event.id);
        }
        reject(error instanceof Error ? error : new RelayPublishError("publish failed", this.url));
      }
    });
    return promise;
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

    return new Promise<CountResult>((resolve, reject) => {
      const waiter: CountWaiter = {
        resolve: (result) => {
          if (waiter.timer !== undefined) {
            clearTimeout(waiter.timer);
          }
          waiter.timer = undefined;
          this.#counts.delete(id);
          cleanup();
          resolve(result);
        },
        reject: (err) => {
          if (waiter.timer !== undefined) {
            clearTimeout(waiter.timer);
          }
          waiter.timer = undefined;
          this.#counts.delete(id);
          cleanup();
          // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards abort/signal reasons verbatim
          reject(err);
        },
        timer: undefined,
        filters: [...canonical],
        authRetried: false,
        timeoutMs,
      };
      const cleanup = onAbort(opts?.signal, () => {
        if (opts?.signal) {
          waiter.reject(abortReason(opts.signal));
        }
      });
      waiter.timer = setTimeout(() => {
        waiter.reject(new RelayTimeoutError("count timed out", this.url));
      }, timeoutMs);
      this.#counts.set(id, waiter);

      try {
        this.#send(["COUNT", id, ...canonical]);
      } catch (error) {
        waiter.reject(
          error instanceof Error ? error : new RelayPublishError("count failed", this.url),
        );
      }
    });
  }

  /** NIP-42 AUTH: sign the current challenge and wait for OK. */
  async auth(
    sign: (template: EventTemplate) => Promise<Event>,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PublishResult> {
    const challenge = this.#challenge;
    if (challenge === undefined || challenge === "") {
      throw new RelayError("no AUTH challenge received from relay", this.url);
    }
    if (this.#authPromise) {
      return this.#authPromise;
    }
    if (this.#answeredChallenge === challenge && this.#answeredResult !== undefined) {
      return this.#answeredResult;
    }

    const pending = (async () => {
      const template = makeAuthEvent(this.url, challenge);
      let event: Event;
      try {
        event = await sign(template);
      } catch (error) {
        // A lazy signer may legitimately have nothing to sign with; ignore the
        // challenge quietly — the connection stays open without an AUTH frame.
        if (error instanceof NoSignerError) {
          return { ok: false, message: "auth: no signer" };
        }
        throw error;
      }
      if (!this.#isOpen()) {
        throw new RelayClosedError("not connected", this.url);
      }
      const timeoutMs = opts?.timeoutMs ?? this.#publishTimeoutMs;

      const authPromise = new Promise<PublishResult>((resolve, reject) => {
        const waiter: PublishWaiter = {
          resolve: (result) => {
            // Cache the relay's settled verdict: a repeated challenge replays
            // it without re-signing. Timeouts and send failures never reach
            // here, so a later auth() signs again.
            if (this.#challenge === challenge) {
              this.#answeredChallenge = challenge;
              this.#answeredResult = result;
            }
            resolve(result);
          },
          reject,
          timer: setTimeout(() => {
            if (this.#publishes.get(event.id) === waiter) {
              this.#publishes.delete(event.id);
              reject(new RelayTimeoutError("auth timed out", this.url));
            }
          }, timeoutMs),
          timeoutMs,
          get promise() {
            return authPromise;
          },
        };
        this.#publishes.set(event.id, waiter);
        try {
          this.#send(["AUTH", event]);
        } catch (error) {
          clearTimeout(waiter.timer);
          if (this.#publishes.get(event.id) === waiter) {
            this.#publishes.delete(event.id);
          }
          reject(
            error instanceof Error ? error : new RelayPublishError("auth send failed", this.url),
          );
        }
      });
      return authPromise;
    })();
    this.#authPromise = pending;
    try {
      const result = await pending;
      if (result.ok && this.#challenge === challenge) {
        this.#authedChallenge = challenge;
      }
      return result;
    } finally {
      if (this.#authPromise === pending) {
        this.#authPromise = undefined;
      }
    }
  }

  /**
   * Clear a cached AUTH rejection for the current challenge so a later `auth()` signs again. A
   * successful auth and in-flight answers are kept. When a challenge is pending and unanswered, an
   * `auth` event is re-fired so the pool's automatic auth can run once more.
   */
  resetAuth(): void {
    if (this.#answeredResult !== undefined && !this.#answeredResult.ok) {
      this.#answeredChallenge = undefined;
      this.#answeredResult = undefined;
    }
    if (this.#challenge !== undefined && this.#challenge !== this.#authedChallenge) {
      const challenge = this.#challenge;
      this.#emit("auth", challenge);
    }
  }

  async #ensureAuthed(): Promise<boolean> {
    const signer = this.#authSigner;
    if (!signer) {
      return false;
    }
    for (let i = 0; i < 3; i++) {
      if (this.#challenge === undefined || this.#challenge === "") {
        return false;
      }
      if (this.#authedChallenge === this.#challenge) {
        return true;
      }
      const signed = this.#challenge;
      // oxlint-disable-next-line no-await-in-loop -- auth retries are sequential: each round waits for the new AUTH challenge
      const result = await this.auth(signer);
      if (this.#authedChallenge === this.#challenge) {
        return true;
      }
      if (!result.ok) {
        if (this.#challenge === undefined || this.#challenge === "" || this.#challenge === signed) {
          return false;
        }
        continue;
      }
    }
    return this.#authedChallenge === this.#challenge;
  }

  async #authThenResubscribe(sub: Subscription, reason: string): Promise<void> {
    try {
      if (!(await this.#ensureAuthed())) {
        dropSubscription(this.#live, sub, reason);
        return;
      }
      if (sub.closed || !this.#isOpen()) {
        dropSubscription(this.#live, sub, reason);
        return;
      }
      sub.eosed = false;
      const group = this.#liveBySubId.get(sub.id);
      if (group) {
        for (const att of group.attachments) {
          att.eosed = false;
        }
      }
      this.#send(["REQ", sub.id, ...sub.replayFilters()]);
    } catch {
      dropSubscription(this.#live, sub, reason);
    }
  }

  async #authThenRecount(id: string, waiter: CountWaiter, reason: string): Promise<void> {
    if (waiter.timer !== undefined) {
      clearTimeout(waiter.timer);
      waiter.timer = undefined;
    }
    const fail = () => {
      waiter.reject(new RelayClosedError(reason || "COUNT closed", this.url));
    };
    try {
      const ok = await this.#ensureAuthed();
      if (this.#counts.get(id) !== waiter) {
        return;
      }
      if (!ok) {
        fail();
        return;
      }
      if (!this.#isOpen()) {
        fail();
        return;
      }
      waiter.timer = setTimeout(() => {
        waiter.reject(new RelayTimeoutError("count timed out", this.url));
      }, waiter.timeoutMs);
      this.#send(["COUNT", id, ...waiter.filters]);
    } catch (error) {
      if (!this.#counts.has(id)) {
        return;
      }
      waiter.reject(
        error instanceof Error ? error : new RelayClosedError(reason || "COUNT closed", this.url),
      );
    }
  }

  async #authThenRepublish(waiter: PublishWaiter, eventId: string, message: string): Promise<void> {
    if (waiter.timer !== undefined) {
      clearTimeout(waiter.timer);
      waiter.timer = undefined;
    }
    const finish = (result: PublishResult) => {
      if (waiter.timer !== undefined) {
        clearTimeout(waiter.timer);
      }
      if (this.#publishes.get(eventId) === waiter) {
        this.#publishes.delete(eventId);
      }
      waiter.resolve(result);
    };
    try {
      if (!waiter.event) {
        finish({ ok: false, message });
        return;
      }
      const ok = await this.#ensureAuthed();
      if (this.#publishes.get(eventId) !== waiter) {
        return;
      }
      if (!ok) {
        finish({ ok: false, message });
        return;
      }
      if (!this.#isOpen()) {
        finish({ ok: false, message });
        return;
      }
      waiter.timer = setTimeout(() => {
        if (this.#publishes.get(eventId) === waiter) {
          this.#publishes.delete(eventId);
          waiter.reject(new RelayTimeoutError("publish timed out", this.url));
        }
      }, waiter.timeoutMs);
      this.#send(["EVENT", waiter.event]);
    } catch {
      if (!this.#publishes.has(eventId)) {
        return;
      }
      finish({ ok: false, message });
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
    const canonical = canonicalizeFilter(filter);

    const id = opts?.id === undefined ? this.nextSubId("neg") : assertSubscriptionId(opts.id);
    const timeoutMs = opts?.timeoutMs ?? this.#publishTimeoutMs;
    const prev = this.#neg.get(id);
    if (prev) {
      failNegSession(prev, new Nip77Error("closed: replaced by new NEG-OPEN"));
    }
    const session = createNegSession();
    this.#neg.set(id, session);

    try {
      return await runWiredNegSession({
        session,
        storage,
        filter: canonical,
        id,
        timeoutMs,
        signal: opts?.signal,
        send: (message) => this.#send(message),
        url: this.url,
      });
    } finally {
      if (this.#neg.get(id) === session) {
        this.#neg.delete(id);
        try {
          this.#send(["NEG-CLOSE", id]);
        } catch {
          // connection already gone
        }
      }
    }
  }

  /** Generate a unique subscription id for this relay instance. */
  nextSubId(prefix = "sub"): string {
    this.#serial += 1;
    return `${prefix}:${this.#serial}`;
  }
}

export type { CountResult } from "../core/message.ts";
export type { RelayFetchEnd, RelayFetchResult } from "./subscribe.ts";
export type { SubscribeOptions, SubscriptionHandlers } from "./subscription.ts";
