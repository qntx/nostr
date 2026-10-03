import { NostrError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import type { Gossip } from "../gossip/gossip.ts";
import type { ReplyTo } from "../nips/nip17.ts";
import type { Rumor } from "../nips/nip59.ts";
import type { PoolOptions, PoolPublishResult } from "../relay/pool.ts";
import type { NostrSigner } from "../signer/types.ts";
import type { StorageError } from "../storage/error.ts";
import type { EventStore } from "../storage/types.ts";
import type { ReactiveEventStore } from "../store/reactive.ts";

/** Direction of a {@link Client.sync} run: upload, download, or both. */
export const SyncDirection = {
  Up: "up",
  Down: "down",
  Both: "both",
} as const;

/** Union of the {@link SyncDirection} values. */
export type SyncDirectionName = (typeof SyncDirection)[keyof typeof SyncDirection];

/** Options for {@link Client.sync} (NIP-77 set reconciliation). */
export type SyncOptions = {
  relays?: ReadonlyArray<string> | undefined;
  direction?: SyncDirectionName | undefined;
  /**
   * Wall-clock deadline for the Negentropy reconciliation session (`NEG-OPEN` through `NEG-CLOSE`),
   * in milliseconds. One clock for the whole session — not reset per `NEG-MSG`. Default: the relay
   * `publishTimeoutMs`. Upload/download phases reuse this value as their per-call timeout.
   */
  timeoutMs?: number | undefined;
  signal?: AbortSignal | undefined;
  dryRun?: boolean | undefined;
  /** When false, skip observe/storage on downloaded events. Default true. */
  observe?: boolean | undefined;
};

/** Outcome of a {@link Client.sync} run: ids compared, sent, received, and failures. */
export type SyncSummary = {
  local: string[];
  remote: string[];
  sent: string[];
  received: string[];
  sendFailures: Record<string, string>;
  persistFailures: Record<string, string>;
};

/**
 * Options for the {@link Client} constructor. Pool fields are forwarded to {@link Pool}; the
 * client-only fields are documented here.
 */
export type ClientOptions = Omit<PoolOptions, "automaticallyAuth"> & {
  signer?: NostrSigner | undefined;
  relays?: ReadonlyArray<string> | undefined;
  /**
   * When true (default), answer NIP-42 AUTH automatically. The signer is read at challenge time, so
   * `setSigner()` applies to live connections; challenges received while no signer is set are
   * ignored.
   */
  automaticAuth?: boolean | undefined;
  gossip?: Gossip | undefined;
  /**
   * Local event store. Defaults to {@link MemoryEventStore}. Browser apps that want persistence must
   * pass {@link IndexedDbEventStore} and `await open()`.
   */
  storage?: EventStore | undefined;
  /**
   * Synchronous reactive index that mirrors every ingested event before callbacks and persistence.
   * Defaults to a new {@link ReactiveEventStore}.
   */
  index?: ReactiveEventStore | undefined;
  /**
   * When true (default), every ingested event is written to storage. Set false to disable automatic
   * persistence while keeping the store for manual use.
   */
  persistEvents?: boolean | undefined;
};

/** Typed event payloads for {@link Client.on}. */
export type ClientEventMap = {
  /**
   * Storage I/O failures: live `putMany` flush and `fetchEvents({ localFirst: true })` query. Those
   * paths do not throw.
   */
  storageerror: StorageError;
};

export type FetchEventsOptions = {
  relays?: ReadonlyArray<string> | undefined;
  timeoutMs?: number | undefined;
  signal?: AbortSignal | undefined;
  gossip?: boolean | undefined;
  /** When true, query local storage first and merge with network results. Defaults to false. */
  localFirst?: boolean | undefined;
  /** When false, skip writing fetched events to storage/observe. Default true. */
  observe?: boolean | undefined;
  /**
   * Every event of every relay batch, including duplicates across relays. `relayUrl` is the
   * normalized URL of the relay that delivered it.
   */
  onevent?: ((event: Event, relayUrl: string) => void) | undefined;
};

/** Options for {@link Client.fetchEach}: one-shot per-relay fetch, no gossip routing. */
export type FetchEachOptions = {
  relays?: ReadonlyArray<string> | undefined;
  timeoutMs?: number | undefined;
  signal?: AbortSignal | undefined;
  /** When false, skip writing fetched events to storage/observe. Default true. */
  observe?: boolean | undefined;
};

export type SubscribeOptions = {
  relays?: ReadonlyArray<string> | undefined;
  /**
   * First receipt of each event only (deduped across relays). `relayUrl` is the normalized URL of
   * the relay that delivered it first.
   */
  onevent?: ((event: Event, relayUrl: string) => void) | undefined;
  /** Every receipt from every relay, including duplicates skipped by dedupe. */
  receivedEvent?: ((id: string, relayUrl: string) => void) | undefined;
  oneose?: (() => void) | undefined;
  onclose?: ((reason: string) => void) | undefined;
  signal?: AbortSignal | undefined;
  id?: string | undefined;
  /**
   * If set, fire `oneose` once after this many ms if not all relays have EOSEd. Does not close the
   * subscription.
   */
  eoseTimeoutMs?: number | undefined;
  /** Fan out REQs via NIP-65 gossip routes when available. */
  gossip?: boolean | undefined;
  /** When false, skip writing received events to storage/observe. Default true. */
  observe?: boolean | undefined;
};

export type PublishOptions = {
  relays?: ReadonlyArray<string> | undefined;
  timeoutMs?: number | undefined;
  gossip?: boolean | undefined;
  /** When false, skip writing the published event to storage/observe. Default true. */
  observe?: boolean | undefined;
};

/** Options for sending a NIP-17 private message. */
export type SendPrivateMessageOptions = {
  readonly subject?: string | undefined;
  readonly replyTo?: ReplyTo | undefined;
  readonly created_at?: number | undefined;
  readonly timeoutMs?: number | undefined;
  readonly observe?: boolean | undefined;
};

/** Result of sending a NIP-17 DM: the rumor plus per-recipient wrap publish results. */
export type PrivateMessageSendResult = {
  rumor: Rumor;
  wraps: ReadonlyArray<{
    recipient: string;
    wrap: Event;
    results: PoolPublishResult[];
  }>;
};

/** An unwrapped NIP-17 private message: the received gift wrap and its inner rumor. */
export type ReceivedPrivateMessage = {
  wrap: Event;
  rumor: Rumor;
  /** Normalized URL of the relay that delivered the wrap, when known. */
  relayUrl?: string | undefined;
};

/** Options for fetching NIP-17 private-message history. */
export type FetchPrivateMessagesOptions = {
  readonly since?: number | undefined;
  readonly until?: number | undefined;
  readonly timeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly observe?: boolean | undefined;
};

/** Options for a live NIP-17 private-message subscription. */
export type SubscribePrivateMessagesOptions = {
  readonly since?: number | undefined;
  readonly onevent?: ((msg: ReceivedPrivateMessage) => void) | undefined;
  readonly oneose?: (() => void) | undefined;
  readonly onclose?: ((reason: string) => void) | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly eoseTimeoutMs?: number | undefined;
  readonly observe?: boolean | undefined;
};

/** Client lifecycle, configuration, or abort failure (not cryptographic). */
export class ClientError extends NostrError {
  override name = "ClientError";
}
