import { randomBytes } from "@noble/hashes/utils.js";

import { throwIfAborted } from "../core/abort.ts";
import { errorMessage } from "../core/error.ts";
import type { Event, EventTemplate, UnsignedEvent } from "../core/event.ts";
import { signedMatchesUnsigned, validateSignedEvent } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { Kind } from "../core/kind.ts";
import { invokeSafely } from "../core/report.ts";
import { Tag } from "../core/tag.ts";
import { bytesToHex, isHex32, nowSeconds } from "../core/util.ts";
import { verifyEvent } from "../core/verifier.ts";
import {
  Nip46Error,
  decodeNip46Response,
  encodeNip46Request,
  parseBunkerURL,
  parseNostrConnectURI,
} from "../nips/nip46.ts";
import type { BunkerPointer, ClientMetadata, Nip46Request } from "../nips/nip46.ts";
import type { NostrSigner } from "./types.ts";

/** Subscribe options used by NIP-46 transport (structural subset of Pool). */
export type Nip46SubscribeOptions = {
  signal?: AbortSignal | undefined;
  onEvent?: ((event: Event) => void) | undefined;
  onClose?: ((reason: string) => void) | undefined;
};

/**
 * Structural relay transport for NIP-46 RPC. Satisfied by {@link import("../relay/pool.ts").Pool};
 * constructed above the signer layer so `signer` never imports `relay` (see AGENTS.md).
 */
export type Nip46Transport = {
  subscribe: (
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts?: Nip46SubscribeOptions,
  ) => { close: (reason?: string) => void };
  publish: (
    relays: ReadonlyArray<string>,
    event: Event,
  ) => Promise<
    ReadonlyArray<{
      readonly status: "ok" | "rejected" | "failed";
      readonly message?: string;
      readonly error?: Error;
    }>
  >;
  close: () => void;
};

/** Options for {@link Nip46Signer}: transport, timeouts, and relay hints. */
export type Nip46SignerOptions = {
  /** Shared transport. When set, the signer does not close it on {@link Nip46Signer.close}. */
  pool?: Nip46Transport | undefined;
  /**
   * Factory for a private transport when `pool` is omitted. Typical: `() => new Pool({
   * websocketImplementation, enableReconnect: true })`.
   */
  createPool?: (() => Nip46Transport) | undefined;
  /**
   * Relays used when the bunker pointer has none, and merged uniquely onto a nonempty pointer
   * (pointer first).
   */
  relays?: ReadonlyArray<string> | undefined;
  /** Bunker connection secret when the pointer or bunker:// URL has none. */
  secret?: string | undefined;
  /**
   * Local client identity used to encrypt and sign RPC (not the remote user key). Must implement
   * `nip44Encrypt`/`nip44Decrypt` — the NIP-46 encryption layer is NIP-44. Construction rejects a
   * signer without them.
   */
  clientSigner: NostrSigner;
  /** Called when bunker returns `auth_url` for a pending request. */
  onAuthUrl?: ((url: string) => void) | undefined;
  /** Per-request timeout in ms. Default 30s. */
  timeoutMs?: number | undefined;
  /**
   * Timeout in ms applied after the bunker replies `auth_url`: the request keeps waiting for the
   * real response until this elapses. Default 300s.
   */
  authTimeoutMs?: number | undefined;
  /** Requested permissions sent with `connect` (`method[:kind]` list). */
  perms?: ReadonlyArray<string> | undefined;
  /** Client metadata sent with bunker-initiated `connect`. */
  metadata?: ClientMetadata | undefined;
};

/** The client-signer surface NIP-46 needs: signing plus the NIP-44 encryption layer. */
type ClientSigner = Pick<NostrSigner, "getPublicKey" | "signEvent"> &
  Required<Pick<NostrSigner, "nip44Encrypt" | "nip44Decrypt">>;

/**
 * Validate `opts.clientSigner` up front — a missing signer or one without NIP-44 cannot run the RPC
 * encryption layer, so construction fails closed with {@link Nip46Error} rather than timing out
 * mid-handshake.
 */
function requireClientSigner(opts: Nip46SignerOptions): ClientSigner {
  const signer = opts.clientSigner;
  if (signer === undefined) {
    throw new Nip46Error("Nip46Signer requires clientSigner");
  }
  const { nip44Encrypt, nip44Decrypt } = signer;
  if (typeof nip44Encrypt !== "function" || typeof nip44Decrypt !== "function") {
    throw new Nip46Error("clientSigner must implement nip44Encrypt and nip44Decrypt");
  }
  // Member calls keep the signer's `this` (e.g. KeysSigner private state).
  return {
    getPublicKey: async () => signer.getPublicKey(),
    signEvent: async (unsigned) => signer.signEvent(unsigned),
    nip44Encrypt: async (peer, plaintext) => nip44Encrypt.call(signer, peer, plaintext),
    nip44Decrypt: async (peer, payload) => nip44Decrypt.call(signer, peer, payload),
  };
}

async function clientPublicKeyOf(signer: ClientSigner): Promise<string> {
  const reported = await signer.getPublicKey();
  if (!isHex32(reported)) {
    throw new Nip46Error("remote signer returned an invalid public key");
  }
  const pubkey = reported;
  if (!isHex32(pubkey)) {
    throw new Nip46Error("clientSigner returned an invalid public key");
  }
  return pubkey;
}

function resolveTransport(opts: Nip46SignerOptions): { pool: Nip46Transport; ownsPool: boolean } {
  if (opts.pool) {
    return { pool: opts.pool, ownsPool: false };
  }
  if (opts.createPool) {
    return { pool: opts.createPool(), ownsPool: true };
  }
  throw new Nip46Error(
    "Nip46Signer requires pool or createPool (inject Pool from @qntx/nostr/relay)",
  );
}

function applyPointerOpts(pointer: BunkerPointer, opts: Nip46SignerOptions): BunkerPointer {
  let next: BunkerPointer = {
    pubkey: pointer.pubkey.toLowerCase(),
    relays: [...pointer.relays],
    secret: pointer.secret,
  };
  if (opts.secret !== undefined && next.secret === undefined) {
    next = { ...next, secret: opts.secret };
  }

  const relays = next.relays.length > 0 ? next.relays : [...(opts.relays ?? [])];
  if (relays.length === 0) {
    throw new Nip46Error("no relays for bunker connection");
  }
  if (next.relays.length > 0 && opts.relays !== undefined && opts.relays.length > 0) {
    const merged = [...next.relays];
    for (const r of opts.relays) {
      if (!merged.includes(r)) {
        merged.push(r);
      }
    }
    return { ...next, relays: merged };
  }
  return { ...next, relays };
}

function resolveBunkerPointer(input: string | BunkerPointer): BunkerPointer {
  if (typeof input !== "string") {
    return {
      pubkey: input.pubkey.toLowerCase(),
      relays: [...input.relays],
      secret: input.secret,
    };
  }

  const bunker = parseBunkerURL(input);
  if (bunker) {
    return bunker;
  }

  throw new Nip46Error("invalid bunker input (expected bunker:// URL or BunkerPointer)");
}

type PendingRequest = {
  resolve: (v: string) => void;
  reject: (e: Error) => void;
  method: string;
  timer?: ReturnType<typeof setTimeout>;
};

/**
 * NIP-46 remote signer (bunker / nostrconnect). Implements {@link NostrSigner}; never holds the
 * remote user's secret key. Network I/O is injected via {@link Nip46Transport} (no relay import).
 */
export class Nip46Signer implements NostrSigner {
  readonly #pool: Nip46Transport;
  readonly #ownsPool: boolean;
  readonly #clientSigner: ClientSigner;
  readonly #clientPubkey: string;
  readonly #pointer: BunkerPointer;
  readonly #onAuthUrl: ((url: string) => void) | undefined;
  readonly #timeoutMs: number;
  readonly #authTimeoutMs: number;
  readonly #perms: ReadonlyArray<string> | undefined;
  readonly #metadata: ClientMetadata | undefined;
  #relays: string[];
  readonly #listeners = new Map<string, PendingRequest>();
  #sub: { close: (reason?: string) => void } | undefined;
  #open = false;
  #cachedRemotePubkey: string | undefined;

  private constructor(
    clientSigner: ClientSigner,
    clientPubkey: string,
    pointer: BunkerPointer,
    pool: Nip46Transport,
    ownsPool: boolean,
    opts: Nip46SignerOptions,
  ) {
    if (pointer.relays.length === 0) {
      throw new Nip46Error("bunker pointer has no relays");
    }
    this.#clientSigner = clientSigner;
    this.#clientPubkey = clientPubkey;
    this.#pointer = {
      pubkey: pointer.pubkey.toLowerCase(),
      relays: [...pointer.relays],
      secret: pointer.secret,
    };
    this.#relays = [...pointer.relays];
    this.#pool = pool;
    this.#ownsPool = ownsPool;
    this.#onAuthUrl = opts.onAuthUrl;
    this.#timeoutMs = opts.timeoutMs ?? 30_000;
    this.#authTimeoutMs = opts.authTimeoutMs ?? 300_000;
    this.#perms = opts.perms;
    this.#metadata = opts.metadata;
  }

  get bunker(): Readonly<BunkerPointer> {
    return {
      pubkey: this.#pointer.pubkey,
      relays: [...this.#relays],
      secret: this.#pointer.secret,
    };
  }

  get clientPublicKey(): string {
    return this.#clientPubkey;
  }

  /**
   * Subscribe to an already-known bunker pointer. Does not send the `connect` RPC (reconnect
   * without a new handshake). Requires `clientSigner` — reconnect must reuse the original client
   * identity. Async because the client public key comes from the signer.
   */
  static async fromBunker(pointer: BunkerPointer, opts: Nip46SignerOptions): Promise<Nip46Signer> {
    const clientSigner = requireClientSigner(opts);
    const clientPubkey = await clientPublicKeyOf(clientSigner);
    const resolved = applyPointerOpts(pointer, opts);
    const { pool, ownsPool } = resolveTransport(opts);
    const signer = new Nip46Signer(clientSigner, clientPubkey, resolved, pool, ownsPool, opts);
    signer.#startSubscription();
    return signer;
  }

  /**
   * Connect using a `bunker://` URL or pre-parsed pointer. Invalid strings throw. A NIP-05
   * identifier is not a bunker pointer. When both pointer and `opts.relays` are nonempty, unique
   * `opts.relays` are appended.
   */
  static async connect(
    input: string | BunkerPointer,
    opts: Nip46SignerOptions,
  ): Promise<Nip46Signer> {
    const pointer = resolveBunkerPointer(input);
    const signer = await Nip46Signer.fromBunker(pointer, opts);
    try {
      await signer.connectRemote();
      try {
        await signer.switchRelays();
      } catch {
        // Bunker may not implement switch_relays.
      }
      await signer.getPublicKey();
      return signer;
    } catch (error) {
      await signer.close();
      throw error;
    }
  }

  /**
   * Wait for a bunker to complete a client-initiated `nostrconnect://` handshake. Requires
   * `clientSigner` whose pubkey matches the URI client pubkey (build the URI with
   * {@link createNostrConnectURI} and the signer's public key).
   */
  static async fromNostrConnectURI(
    connectionURI: string,
    opts: Nip46SignerOptions & {
      signal?: AbortSignal;
      handshakeTimeoutMs?: number;
    },
  ): Promise<Nip46Signer> {
    throwIfAborted(opts.signal);
    const clientSigner = requireClientSigner(opts);
    const params = parseNostrConnectURI(connectionURI);

    const { pool, ownsPool } = resolveTransport(opts);
    const handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 300_000;

    // The signer's pubkey resolves async while the handshake subscription is already live —
    // subscribing must stay synchronous so early handshake events are not missed.
    const clientPubkeyPromise = clientPublicKeyOf(clientSigner);

    return new Promise((resolve, reject) => {
      let settled = false;
      let handshaking = false;
      // `let` + later assignment: pool.subscribe may fire onClose synchronously (pre-aborted
      // signal via fanIn) before a const initializer would complete.
      // oxlint-disable-next-line eslint/prefer-const
      let sub: { close: (reason?: string) => void } | undefined;
      const finish = (err?: Error, signer?: Nip46Signer) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        sub?.close(err ? "failed" : "connected");
        if (err) {
          if (ownsPool) {
            pool.close();
          }
          reject(err);
        } else if (signer) {
          resolve(signer);
        }
      };

      const timer = setTimeout(() => {
        finish(new Nip46Error("nostrconnect handshake timed out"));
      }, handshakeTimeoutMs);

      // The URI's client pubkey gates the handshake: the signer must own that key.
      void (async () => {
        try {
          const pubkey = await clientPubkeyPromise;
          if (pubkey !== params.clientPubkey) {
            finish(
              new Nip46Error("clientSigner public key does not match nostrconnect client pubkey"),
            );
          }
        } catch (error) {
          finish(error instanceof Error ? error : new Nip46Error(String(error)));
        }
      })();

      sub = pool.subscribe(
        params.relays,
        [{ kinds: [Kind.NostrConnect], "#p": [params.clientPubkey], limit: 0 }],
        {
          signal: opts.signal,
          onEvent: (event) => {
            void (async () => {
              try {
                const clientPubkey = await clientPubkeyPromise;
                if (settled || clientPubkey !== params.clientPubkey) {
                  return;
                }
                const payload = await clientSigner.nip44Decrypt(event.pubkey, event.content);
                const response = decodeNip46Response(payload);
                if (response.result !== params.secret) {
                  return;
                }
                // A duplicate connect response must not spin up a second signer.
                if (handshaking) {
                  return;
                }
                handshaking = true;

                const pointer: BunkerPointer = {
                  pubkey: event.pubkey.toLowerCase(),
                  relays: params.relays,
                  secret: params.secret,
                };
                const signer = new Nip46Signer(
                  clientSigner,
                  clientPubkey,
                  pointer,
                  pool,
                  ownsPool,
                  opts,
                );
                signer.#startSubscription();
                try {
                  await signer.switchRelays();
                } catch {
                  // Relay switch at connect time is best-effort.
                }
                try {
                  await signer.getPublicKey();
                  finish(undefined, signer);
                } catch (error: unknown) {
                  // Do not leak the signer's subscription on a shared pool.
                  await signer.close();
                  finish(error instanceof Error ? error : new Nip46Error(String(error)));
                }
              } catch {
                // ignore non-matching events
              }
            })();
          },
          onClose: (reason) => {
            if (reason !== "connected" && reason !== "failed") {
              finish(new Nip46Error(`nostrconnect subscription closed: ${reason}`));
            }
          },
        },
      );
    });
  }

  #startSubscription(): void {
    this.#sub?.close();
    this.#sub = this.#pool.subscribe(
      this.#relays,
      [
        {
          kinds: [Kind.NostrConnect],
          authors: [this.#pointer.pubkey],
          "#p": [this.#clientPubkey],
          limit: 0,
        },
      ],
      {
        onEvent: (event) => {
          void this.#handleResponseEvent(event);
        },
        onClose: () => {
          this.#sub = undefined;
        },
      },
    );
    this.#open = true;
  }

  async #handleResponseEvent(event: Event): Promise<void> {
    try {
      const payload = await this.#clientSigner.nip44Decrypt(event.pubkey, event.content);
      const { id, result, error } = decodeNip46Response(payload);

      if (result === "auth_url" && this.#listeners.has(id)) {
        const listener = this.#listeners.get(id);
        if (!listener) {
          return;
        }
        if (error !== undefined && error !== "") {
          invokeSafely(() => this.#onAuthUrl?.(error));
        }
        clearTimeout(listener.timer);
        listener.timer = this.#requestTimer(id, listener, this.#authTimeoutMs);
        return;
      }

      const listener = this.#dropRequest(id);
      if (!listener) {
        return;
      }
      if (error !== undefined && error !== "") {
        listener.reject(new Nip46Error(error));
      } else if (result === undefined) {
        listener.reject(new Nip46Error("empty NIP-46 response"));
      } else {
        listener.resolve(result);
      }
    } catch {
      // ignore decrypt failures from unrelated events
    }
  }

  async connectRemote(overrides?: {
    metadata?: ClientMetadata | undefined;
    perms?: ReadonlyArray<string> | undefined;
  }): Promise<void> {
    const metadata = overrides?.metadata ?? this.#metadata;
    const perms = overrides?.perms ?? this.#perms;
    const params = [this.#pointer.pubkey, this.#pointer.secret ?? ""];
    const hasPerms = perms !== undefined && perms.length > 0;
    if (hasPerms || metadata !== undefined) {
      params.push(hasPerms ? perms.join(",") : "");
    }
    if (metadata !== undefined) {
      params.push(JSON.stringify(metadata));
    }
    const result = await this.#sendRequest("connect", params);
    if (result === "ack") {
      return;
    }
    const { secret } = this.#pointer;
    if (secret !== undefined && secret !== "" && result === secret) {
      return;
    }
    throw new Nip46Error(`connect result is not ack or secret: ${result}`);
  }

  /**
   * Ask the bunker for its preferred relay list and resubscribe when it changes. Spec result is a
   * JSON array of URLs, or `null` when nothing changes.
   */
  async switchRelays(): Promise<string[] | undefined> {
    const resp = await this.#sendRequest("switch_relays", []);
    if (resp === "null") {
      return undefined;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(resp);
    } catch (error) {
      throw new Nip46Error("invalid switch_relays JSON", {
        cause: error,
      });
    }
    if (
      !Array.isArray(parsed) ||
      parsed.length === 0 ||
      !parsed.every((x) => typeof x === "string")
    ) {
      throw new Nip46Error("invalid switch_relays result");
    }
    this.#relays = parsed;
    this.#startSubscription();
    return parsed;
  }

  /** Courtesy session teardown. Always closes the local signer afterwards. */
  async logout(): Promise<void> {
    try {
      const resp = await this.#sendRequest("logout", []);
      if (resp !== "ack") {
        throw new Nip46Error(`logout result is not ack: ${resp}`);
      }
    } finally {
      await this.close();
    }
  }

  async ping(): Promise<void> {
    const resp = await this.#sendRequest("ping", []);
    if (resp !== "pong") {
      throw new Nip46Error(`ping result is not pong: ${resp}`);
    }
  }

  async getPublicKey(): Promise<string> {
    if (this.#cachedRemotePubkey === undefined) {
      const pk = await this.#sendRequest("get_public_key", []);
      if (!isHex32(pk)) {
        throw new Nip46Error("bunker returned invalid pubkey");
      }
      this.#cachedRemotePubkey = pk;
    }
    return this.#cachedRemotePubkey;
  }

  async signEvent(unsigned: UnsignedEvent): Promise<Event> {
    const template: EventTemplate = {
      kind: unsigned.kind,
      tags: unsigned.tags,
      content: unsigned.content,
      created_at: unsigned.created_at,
    };
    const resp = await this.#sendRequest("sign_event", [JSON.stringify(template)]);
    let signed: unknown;
    try {
      signed = JSON.parse(resp);
    } catch (error) {
      throw new Nip46Error("bunker returned invalid sign_event JSON", {
        cause: error,
      });
    }
    if (!validateSignedEvent(signed) || !verifyEvent(signed)) {
      throw new Nip46Error("bunker returned improperly signed event");
    }
    if (!signedMatchesUnsigned(signed, unsigned)) {
      throw new Nip46Error("signed event does not match unsigned template");
    }
    return signed;
  }

  async nip04Encrypt(peer: string, plaintext: string): Promise<string> {
    return this.#sendRequest("nip04_encrypt", [peer, plaintext]);
  }

  async nip04Decrypt(peer: string, ciphertext: string): Promise<string> {
    return this.#sendRequest("nip04_decrypt", [peer, ciphertext]);
  }

  async nip44Encrypt(peer: string, plaintext: string): Promise<string> {
    return this.#sendRequest("nip44_encrypt", [peer, plaintext]);
  }

  async nip44Decrypt(peer: string, payload: string): Promise<string> {
    return this.#sendRequest("nip44_decrypt", [peer, payload]);
  }

  async close(): Promise<void> {
    this.#open = false;
    for (const [, listener] of this.#listeners) {
      clearTimeout(listener.timer);
      listener.reject(new Nip46Error("signer closed"));
    }
    this.#listeners.clear();
    this.#sub?.close("signer closed");
    this.#sub = undefined;
    if (this.#ownsPool) {
      this.#pool.close();
    }
  }

  async #sendRequest(method: string, params: string[]): Promise<string> {
    if (!this.#open) {
      throw new Nip46Error("signer is closed");
    }
    if (!this.#sub) {
      this.#startSubscription();
    }

    const id = bytesToHex(randomBytes(16));
    const req: Nip46Request = { id, method, params };
    const encrypted = await this.#clientSigner.nip44Encrypt(
      this.#pointer.pubkey,
      encodeNip46Request(req),
    );

    const unsigned: UnsignedEvent = {
      kind: Kind.NostrConnect,
      tags: [Tag.p(this.#pointer.pubkey)],
      content: encrypted,
      created_at: nowSeconds(),
      pubkey: this.#clientPubkey,
    };
    const event = await this.#clientSigner.signEvent(unsigned);
    // The client signer is untrusted code: check it actually signed the request we sent.
    if (!verifyEvent(event)) {
      throw new Nip46Error("clientSigner returned an improperly signed request event");
    }
    if (!signedMatchesUnsigned(event, unsigned)) {
      throw new Nip46Error("clientSigner signed an event that does not match the request");
    }

    const resultPromise = new Promise<string>((resolve, reject) => {
      const listener: PendingRequest = { resolve, reject, method };
      listener.timer = this.#requestTimer(id, listener, this.#timeoutMs);
      this.#listeners.set(id, listener);
    });

    let replies;
    try {
      replies = await this.#pool.publish(this.#relays, event);
    } catch (error) {
      this.#dropRequest(id);
      throw error;
    }
    if (!replies.some((reply) => reply.status === "ok")) {
      const listener = this.#dropRequest(id);
      const detail = replies
        .map((reply) => (reply.status === "failed" ? errorMessage(reply.error) : reply.message))
        .filter((message): message is string => Boolean(message))
        .join("; ");
      listener?.reject(new Nip46Error(`request not accepted by any relay: ${detail}`));
    }
    return resultPromise;
  }

  #dropRequest(id: string): PendingRequest | undefined {
    const listener = this.#listeners.get(id);
    if (!listener) {
      return undefined;
    }
    clearTimeout(listener.timer);
    this.#listeners.delete(id);
    return listener;
  }

  #requestTimer(id: string, listener: PendingRequest, ms: number): ReturnType<typeof setTimeout> {
    return setTimeout(() => {
      this.#dropRequest(id);
      listener.reject(new Nip46Error(`NIP-46 request timed out: ${listener.method}`));
    }, ms);
  }
}
