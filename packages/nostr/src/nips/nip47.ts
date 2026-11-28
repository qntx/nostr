import { sha256 } from "@noble/hashes/sha2.js";

import { abortReason, onAbort, raceSignal, throwIfAborted } from "../core/abort.ts";
import { NostrError } from "../core/error.ts";
import type { Event, UnsignedEvent } from "../core/event.ts";
import type { Filter } from "../core/filter.ts";
import { invokeSafely } from "../core/report.ts";
import { bytesToHex, hexToBytes, isRecord, nowSeconds } from "../core/util.ts";
import type { EventVerifier } from "../core/verifier.ts";
import { verifyEvent } from "../core/verifier.ts";
import { parseBolt11 } from "./nip57.ts";

/** NIP-47 wallet-service info event kind. */
export const NWC_INFO_KIND = 13194;
/** NIP-47 request kind. */
export const NWC_REQUEST_KIND = 23194;
/** NIP-47 response kind. */
export const NWC_RESPONSE_KIND = 23195;
/** NWC-02 notification kind encrypted with NIP-04. */
export const NWC_NOTIFICATION_NIP04_KIND = 23196;
/** NWC-02 notification kind encrypted with NIP-44 v2. */
export const NWC_NOTIFICATION_KIND = 23197;

const MAX_STRING_LEN = 65_535;
const MAX_PAYLOAD_LEN = 1_048_576;
const ASCII_WS = /[\t\n\f\r ]+/;

/** Encryption schemes NIP-47 can negotiate. */
export type NwcEncryption = "nip44_v2" | "nip04";
/** NIP-47 methods implemented by this codec. */
export type NwcMethod =
  | "pay_invoice"
  | "make_invoice"
  | "lookup_invoice"
  | "get_balance"
  | "get_info"
  | "list_transactions"
  | "get_budget";
/** NIP-47 error codes; unknown wallet codes are preserved in `walletCode` and map to OTHER. */
export type NwcErrorCode =
  | "RATE_LIMITED"
  | "NOT_IMPLEMENTED"
  | "INSUFFICIENT_BALANCE"
  | "QUOTA_EXCEEDED"
  | "RESTRICTED"
  | "UNAUTHORIZED"
  | "INTERNAL"
  | "UNSUPPORTED_ENCRYPTION"
  | "OTHER"
  | "PAYMENT_FAILED"
  | "NOT_FOUND";

const ERROR_CODES: ReadonlyArray<NwcErrorCode> = [
  "RATE_LIMITED",
  "NOT_IMPLEMENTED",
  "INSUFFICIENT_BALANCE",
  "QUOTA_EXCEEDED",
  "RESTRICTED",
  "UNAUTHORIZED",
  "INTERNAL",
  "UNSUPPORTED_ENCRYPTION",
  "OTHER",
  "PAYMENT_FAILED",
  "NOT_FOUND",
];

/** A parsed `nostr+walletconnect://` connection URI. */
export type NwcConnection = {
  readonly walletPubkey: string;
  readonly relays: ReadonlyArray<string>;
  readonly secret: Uint8Array;
  readonly lud16?: string | undefined;
};

/** Parsed kind-13194 wallet metadata. */
export type NwcInfo = {
  readonly methods: ReadonlyArray<string>;
  /** Undefined when the info event has no `encryption` tag (spec: NIP-04 only). */
  readonly encryptions: ReadonlyArray<string> | undefined;
  readonly extensions: ReadonlyArray<string>;
  readonly notifications: ReadonlyArray<string>;
};

export type NwcMetadata = Readonly<Record<string, unknown>>;
export type NwcTransactionState = "pending" | "settled" | "accepted" | "expired" | "failed";
/** Wire-shaped transaction record (`make_invoice`, `lookup_invoice`, lists, notifications). */
export type NwcTransaction = {
  readonly type: "incoming" | "outgoing";
  readonly state?: NwcTransactionState | undefined;
  readonly invoice?: string | undefined;
  readonly description?: string | undefined;
  readonly description_hash?: string | undefined;
  readonly preimage?: string | undefined;
  readonly payment_hash: string;
  readonly amount: number;
  readonly fees_paid?: number | undefined;
  readonly created_at: number;
  readonly expires_at?: number | undefined;
  readonly settled_at?: number | undefined;
  readonly metadata?: NwcMetadata | undefined;
};

export type NwcPayInvoiceParams = {
  readonly invoice: string;
  readonly amount?: number | undefined;
  readonly metadata?: NwcMetadata | undefined;
};
export type NwcMakeInvoiceParams = {
  readonly amount: number;
  readonly description?: string | undefined;
  readonly description_hash?: string | undefined;
  readonly expiry?: number | undefined;
  readonly metadata?: NwcMetadata | undefined;
};
export type NwcLookupInvoiceParams = {
  readonly payment_hash?: string | undefined;
  readonly invoice?: string | undefined;
};
export type NwcListTransactionsParams = {
  readonly from?: number | undefined;
  readonly until?: number | undefined;
  readonly limit?: number | undefined;
  readonly offset?: number | undefined;
  readonly unpaid?: boolean | undefined;
  readonly type?: "incoming" | "outgoing" | undefined;
};
export type NwcPayResult = {
  readonly preimage: string;
  readonly fees_paid?: number | undefined;
};
export type NwcBalance = { readonly balance: number };
export type NwcWalletInfo = {
  readonly alias?: string | undefined;
  readonly color?: string | undefined;
  readonly pubkey?: string | undefined;
  readonly network?: string | undefined;
  readonly block_height?: number | undefined;
  readonly block_hash?: string | undefined;
  readonly methods: ReadonlyArray<string>;
  readonly extensions?: ReadonlyArray<string> | undefined;
  readonly notifications?: ReadonlyArray<string> | undefined;
};
export type NwcTransactionList = {
  readonly transactions: ReadonlyArray<NwcTransaction>;
  readonly total_count?: number | undefined;
};
export type NwcBudget = {
  readonly used_budget: number;
  readonly total_budget: number;
  readonly renews_at?: number | undefined;
  readonly renewal_period: "daily" | "weekly" | "monthly" | "yearly" | "never";
};

/** Typed NIP-47 request payload. */
export type NwcRequest =
  | { readonly method: "pay_invoice"; readonly params: NwcPayInvoiceParams }
  | { readonly method: "make_invoice"; readonly params: NwcMakeInvoiceParams }
  | { readonly method: "lookup_invoice"; readonly params: NwcLookupInvoiceParams }
  | { readonly method: "get_balance"; readonly params: Record<string, never> }
  | { readonly method: "get_info"; readonly params: Record<string, never> }
  | { readonly method: "list_transactions"; readonly params: NwcListTransactionsParams }
  | { readonly method: "get_budget"; readonly params: Record<string, never> };

/** Typed NIP-47 result payload, discriminated by `method`. */
export type NwcResult =
  | ({ readonly method: "pay_invoice" } & NwcPayResult)
  | {
      readonly method: "make_invoice" | "lookup_invoice";
      readonly transaction: NwcTransaction;
    }
  | ({ readonly method: "get_balance" } & NwcBalance)
  | ({ readonly method: "get_info" } & NwcWalletInfo)
  | ({ readonly method: "list_transactions" } & NwcTransactionList)
  | { readonly method: "get_budget"; readonly budget: NwcBudget | undefined };

export type NwcWalletErrorInfo = {
  readonly code: NwcErrorCode;
  /** The wire code verbatim, including codes outside the NIP-47 list. */
  readonly walletCode: string;
  readonly message: string;
};
export type NwcResponse =
  | { readonly ok: true; readonly result: NwcResult }
  | { readonly ok: false; readonly error: NwcWalletErrorInfo };
export type NwcNotification = {
  readonly type: "payment_received" | "payment_sent";
  readonly transaction: NwcTransaction;
};
/** A signed request plus the data needed to decrypt and match its response. */
export type NwcSentRequest = {
  readonly event: Event;
  readonly method: NwcMethod;
  readonly encryption: NwcEncryption;
};

/** Structural signer subset; `KeysSigner` satisfies it without this module importing `signer`. */
export type NwcSigner = {
  getPublicKey: () => Promise<string>;
  signEvent: (unsigned: UnsignedEvent) => Promise<Event>;
  nip44Encrypt?: ((peer: string, plaintext: string) => Promise<string>) | undefined;
  nip44Decrypt?: ((peer: string, payload: string) => Promise<string>) | undefined;
  nip04Encrypt?: ((peer: string, plaintext: string) => Promise<string>) | undefined;
  nip04Decrypt?: ((peer: string, payload: string) => Promise<string>) | undefined;
};

/** Structural relay-pool subset used by {@link NwcClient}; `Pool` satisfies it. */
export type NwcTransport = {
  subscribe: (
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts?: {
      signal?: AbortSignal | undefined;
      onEvent?: ((event: Event) => void) | undefined;
      onEose?: (() => void) | undefined;
      onClose?: ((reason: string) => void) | undefined;
    },
  ) => { close: (reason?: string) => void };
  publish: (
    relays: ReadonlyArray<string>,
    event: Event,
  ) => Promise<
    ReadonlyArray<{
      readonly url: string;
      readonly status: "ok" | "rejected" | "failed";
      readonly message?: string | undefined;
      readonly error?: Error | undefined;
    }>
  >;
  fetch: (
    relays: ReadonlyArray<string>,
    filters: ReadonlyArray<Filter>,
    opts?: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined },
  ) => Promise<ReadonlyArray<Event>>;
};

/** Every local NWC failure: URI, codec, negotiation, transport refusal, close, preimage mismatch. */
export class NwcError extends NostrError {
  override name = "NwcError";
}

/** The wallet service answered with an error payload. */
export class NwcWalletError extends NwcError {
  override name = "NwcWalletError";
  readonly code: NwcErrorCode;
  readonly walletCode: string;

  constructor(error: NwcWalletErrorInfo, options?: ErrorOptions) {
    super(error.message, options);
    this.code = error.code;
    this.walletCode = error.walletCode;
  }
}

/** No valid response arrived before the request deadline; the payment outcome is unknown. */
export class NwcTimeoutError extends NwcError {
  override name = "NwcTimeoutError";
}

function invalid(message: string): NwcError {
  return new NwcError(message);
}

const isHex64Lower = (value: string): boolean => /^[0-9a-f]{64}$/.test(value);

function isLoopbackWs(url: string): boolean {
  const match = /^ws:\/\/(localhost|127\.0\.0\.1)(?::(?<port>[0-9]{1,5}))?([/?#].*)?$/.exec(url);
  if (match === null) {
    return false;
  }
  const port = match.groups?.["port"];
  return port === undefined || Number(port) <= 65_535;
}

/**
 * Parse `nostr+walletconnect://<pubkey>?relay=wss://…&secret=<64hex>[&lud16=…]`. Protocol hex is
 * lowercase-only. The returned secret is a fresh buffer owned by the caller; `fill(0)` it once a
 * signer holds the key. Error messages never echo the URI or secret.
 */
export function parseNwcUri(uri: string): NwcConnection {
  if (!uri.startsWith("nostr+walletconnect://")) {
    throw invalid("invalid NWC connection URI scheme");
  }
  const rest = uri.slice("nostr+walletconnect://".length);
  const queryAt = rest.indexOf("?");
  if (queryAt === -1) {
    throw invalid("NWC connection URI requires a query");
  }
  const walletPubkey = rest.slice(0, queryAt);
  if (!isHex64Lower(walletPubkey)) {
    throw invalid("NWC wallet pubkey must be 64 lowercase hex characters");
  }
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(rest.slice(queryAt + 1));
  } catch {
    throw invalid("invalid NWC connection URI query");
  }
  const secretHex = params.get("secret");
  if (secretHex === null || !isHex64Lower(secretHex)) {
    throw invalid("NWC secret must be 64 lowercase hex characters");
  }
  const relays = params.getAll("relay");
  if (relays.length === 0) {
    throw invalid("NWC connection URI requires at least one relay");
  }
  for (const relay of relays) {
    if (!relay.startsWith("wss://") && !isLoopbackWs(relay)) {
      throw invalid("NWC relay must use wss:// or loopback ws://");
    }
  }
  const lud16 = params.get("lud16") ?? undefined;
  return {
    walletPubkey,
    relays,
    secret: hexToBytes(secretHex),
    ...(lud16 === undefined ? {} : { lud16 }),
  };
}

const splitAscii = (value: string): string[] => value.split(ASCII_WS).filter((part) => part !== "");

/** Parse a kind-13194 info event. Signature verification is the caller's concern. */
export function parseInfoEvent(event: Event): NwcInfo {
  if (event.kind !== NWC_INFO_KIND) {
    throw invalid(`info event kind must be ${NWC_INFO_KIND}`);
  }
  let encryptions: ReadonlyArray<string> | undefined;
  let extensions: ReadonlyArray<string> = [];
  let notifications: ReadonlyArray<string> = [];
  for (const [name, value] of event.tags) {
    if (value === undefined) {
      continue;
    }
    if (name === "encryption") {
      encryptions = splitAscii(value);
    } else if (name === "extensions") {
      extensions = splitAscii(value);
    } else if (name === "notifications") {
      notifications = splitAscii(value);
    }
  }
  return {
    methods: splitAscii(event.content),
    encryptions,
    extensions,
    notifications,
  };
}

/** Pick the best common encryption: NIP-44 v2 when offered, otherwise NIP-04. */
export function negotiateEncryption(info: NwcInfo): NwcEncryption {
  if (info.encryptions === undefined) {
    return "nip04";
  }
  if (info.encryptions.includes("nip44_v2")) {
    return "nip44_v2";
  }
  if (info.encryptions.includes("nip04")) {
    return "nip04";
  }
  throw invalid("wallet offers no supported encryption");
}

function requireUint(value: number | undefined, name: string, required = false): void {
  if (value === undefined && !required) {
    return;
  }
  if (value === undefined || !Number.isSafeInteger(value) || value < 0) {
    throw invalid(`${name} must be a non-negative safe integer`);
  }
}

function requireString(value: string | undefined, name: string, required = false): void {
  if (value === undefined && !required) {
    return;
  }
  if (typeof value !== "string" || value.length > MAX_STRING_LEN) {
    throw invalid(`${name} must be a string of at most 65535 characters`);
  }
}

function validateMetadata(metadata: NwcMetadata | undefined): void {
  if (metadata !== undefined && !isRecord(metadata)) {
    throw invalid("metadata must be an object");
  }
}

function validateRequestParams(request: NwcRequest): void {
  switch (request.method) {
    case "pay_invoice":
      requireString(request.params.invoice, "invoice", true);
      requireUint(request.params.amount, "amount");
      validateMetadata(request.params.metadata);
      break;
    case "make_invoice":
      requireUint(request.params.amount, "amount", true);
      requireString(request.params.description, "description");
      requireString(request.params.description_hash, "description_hash");
      requireUint(request.params.expiry, "expiry");
      validateMetadata(request.params.metadata);
      break;
    case "lookup_invoice":
      requireString(request.params.payment_hash, "payment_hash");
      requireString(request.params.invoice, "invoice");
      if (request.params.payment_hash === undefined && request.params.invoice === undefined) {
        throw invalid("lookup_invoice requires payment_hash or invoice");
      }
      break;
    case "list_transactions":
      requireUint(request.params.from, "from");
      requireUint(request.params.until, "until");
      requireUint(request.params.limit, "limit");
      requireUint(request.params.offset, "offset");
      if (request.params.unpaid !== undefined && typeof request.params.unpaid !== "boolean") {
        throw invalid("unpaid must be boolean");
      }
      if (
        request.params.type !== undefined &&
        request.params.type !== "incoming" &&
        request.params.type !== "outgoing"
      ) {
        throw invalid("transaction type must be incoming or outgoing");
      }
      break;
    case "get_balance":
    case "get_info":
    case "get_budget":
      break;
  }
}

function omitUndefined(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

/** Serialize a request payload in the stable key order shared with nk-core. */
export function encodeRequestPayload(request: NwcRequest): string {
  validateRequestParams(request);
  let params: Record<string, unknown>;
  switch (request.method) {
    case "pay_invoice":
      params = omitUndefined({
        invoice: request.params.invoice,
        amount: request.params.amount,
        metadata: request.params.metadata,
      });
      break;
    case "make_invoice":
      params = omitUndefined({
        amount: request.params.amount,
        description: request.params.description,
        description_hash: request.params.description_hash,
        expiry: request.params.expiry,
        metadata: request.params.metadata,
      });
      break;
    case "lookup_invoice":
      params = omitUndefined({
        payment_hash: request.params.payment_hash,
        invoice: request.params.invoice,
      });
      break;
    case "list_transactions":
      params = omitUndefined({
        from: request.params.from,
        until: request.params.until,
        limit: request.params.limit,
        offset: request.params.offset,
        unpaid: request.params.unpaid,
        type: request.params.type,
      });
      break;
    case "get_balance":
    case "get_info":
    case "get_budget":
      params = {};
      break;
  }
  return JSON.stringify({ method: request.method, params });
}

async function encryptWith(
  signer: NwcSigner,
  encryption: NwcEncryption,
  peer: string,
  plaintext: string,
): Promise<string> {
  const fn = encryption === "nip44_v2" ? signer.nip44Encrypt : signer.nip04Encrypt;
  if (fn === undefined) {
    throw invalid(`signer does not support ${encryption} encryption`);
  }
  return fn.call(signer, peer, plaintext);
}

async function decryptWith(
  signer: NwcSigner,
  encryption: NwcEncryption,
  peer: string,
  ciphertext: string,
): Promise<string> {
  const fn = encryption === "nip44_v2" ? signer.nip44Decrypt : signer.nip04Decrypt;
  if (fn === undefined) {
    throw invalid(`signer does not support ${encryption} decryption`);
  }
  return fn.call(signer, peer, ciphertext);
}

/** Encrypt, sign, and tag a kind-23194 request. */
export async function encodeRequest(
  signer: NwcSigner,
  walletPubkey: string,
  request: NwcRequest,
  options: {
    readonly encryption: NwcEncryption;
    readonly expiration?: number | undefined;
    readonly createdAt?: number | undefined;
  },
): Promise<NwcSentRequest> {
  const plaintext = encodeRequestPayload(request);
  const content = await encryptWith(signer, options.encryption, walletPubkey, plaintext);
  const tags: string[][] = [
    ["p", walletPubkey],
    ["encryption", options.encryption],
  ];
  if (options.expiration !== undefined) {
    requireUint(options.expiration, "expiration", true);
    tags.push(["expiration", String(options.expiration)]);
  }
  const createdAt = options.createdAt ?? nowSeconds();
  requireUint(createdAt, "created_at", true);
  const unsigned: UnsignedEvent = {
    pubkey: await signer.getPublicKey(),
    kind: NWC_REQUEST_KIND,
    tags,
    content,
    created_at: createdAt,
  };
  const event = await signer.signEvent(unsigned);
  return { event, method: request.method, encryption: options.encryption };
}

function tagValues(event: Event, name: string): string[] {
  const values: string[] = [];
  for (const [key, value] of event.tags) {
    if (key === name && value !== undefined) {
      values.push(value);
    }
  }
  return values;
}

/** Cheap authentic-envelope check for a response to `sent`; includes signature verification. */
export function isResponseTo(
  event: Event,
  sent: NwcSentRequest,
  verify: EventVerifier = verifyEvent,
): boolean {
  const [walletPubkey] = tagValues(sent.event, "p");
  return (
    event.kind === NWC_RESPONSE_KIND &&
    walletPubkey !== undefined &&
    event.pubkey === walletPubkey &&
    tagValues(event, "e").includes(sent.event.id) &&
    tagValues(event, "p").includes(sent.event.pubkey) &&
    verify(event)
  );
}

const isUint = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function failShape(message: string): never {
  throw invalid(message);
}

function optString(value: unknown, name: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string" || value.length > MAX_STRING_LEN) {
    failShape(`${name} must be a string of at most 65535 characters`);
  }
  return value;
}

function reqString(value: unknown, name: string): string {
  const parsed = optString(value, name);
  if (parsed === undefined) {
    failShape(`${name} is required`);
  }
  return parsed;
}

function optUintField(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isUint(value)) {
    failShape(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function reqUintField(value: unknown, name: string): number {
  const parsed = optUintField(value, name);
  if (parsed === undefined) {
    failShape(`${name} is required`);
  }
  return parsed;
}

function optMetadataOut(value: unknown): NwcMetadata | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isRecord(value)) {
    failShape("metadata must be an object");
  }
  return value;
}

function stringList(value: unknown, name: string): ReadonlyArray<string> {
  if (!Array.isArray(value)) {
    failShape(`${name} must be an array`);
  }
  return value.map((entry) => reqString(entry, name));
}

function optStringList(value: unknown, name: string): ReadonlyArray<string> | undefined {
  return value === undefined || value === null ? undefined : stringList(value, name);
}

const TX_STATES: ReadonlyArray<NwcTransactionState> = [
  "pending",
  "settled",
  "accepted",
  "expired",
  "failed",
];

function parseTransaction(record: Record<string, unknown>): NwcTransaction {
  const { type } = record;
  if (type !== "incoming" && type !== "outgoing") {
    failShape("transaction type must be incoming or outgoing");
  }
  const rawState = optString(record["state"], "state");
  const state = TX_STATES.find((entry) => entry === rawState);
  const invoice = optString(record["invoice"], "invoice");
  const description = optString(record["description"], "description");
  const descriptionHash = optString(record["description_hash"], "description_hash");
  const preimage = optString(record["preimage"], "preimage");
  const feesPaid = optUintField(record["fees_paid"], "fees_paid");
  const expiresAt = optUintField(record["expires_at"], "expires_at");
  const settledAt = optUintField(record["settled_at"], "settled_at");
  const metadata = optMetadataOut(record["metadata"]);
  return {
    type,
    ...(state === undefined ? {} : { state }),
    ...(invoice === undefined ? {} : { invoice }),
    ...(description === undefined ? {} : { description }),
    ...(descriptionHash === undefined ? {} : { description_hash: descriptionHash }),
    ...(preimage === undefined ? {} : { preimage }),
    payment_hash: reqString(record["payment_hash"], "payment_hash"),
    amount: reqUintField(record["amount"], "amount"),
    ...(feesPaid === undefined ? {} : { fees_paid: feesPaid }),
    created_at: reqUintField(record["created_at"], "created_at"),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    ...(settledAt === undefined ? {} : { settled_at: settledAt }),
    ...(metadata === undefined ? {} : { metadata }),
  };
}

function parseBudget(record: Record<string, unknown>): NwcBudget | undefined {
  if (Object.keys(record).length === 0) {
    return undefined;
  }
  const renewal = reqString(record["renewal_period"], "renewal_period");
  if (!["daily", "weekly", "monthly", "yearly", "never"].includes(renewal)) {
    failShape("renewal_period is invalid");
  }
  const renewsAt = optUintField(record["renews_at"], "renews_at");
  if (renewal === "never") {
    if (renewsAt !== undefined) {
      failShape("renews_at is forbidden when renewal_period is never");
    }
  } else if (renewsAt === undefined) {
    failShape("renews_at is required unless renewal_period is never");
  }
  return {
    used_budget: reqUintField(record["used_budget"], "used_budget"),
    total_budget: reqUintField(record["total_budget"], "total_budget"),
    ...(renewsAt === undefined ? {} : { renews_at: renewsAt }),
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- membership checked above
    renewal_period: renewal as NwcBudget["renewal_period"],
  };
}

// oxlint-disable-next-line typescript/consistent-return -- the NwcMethod switch is exhaustive
function parseResult(method: NwcMethod, result: unknown): NwcResult {
  if (!isRecord(result)) {
    failShape("result must be an object");
  }
  switch (method) {
    case "pay_invoice": {
      const feesPaid = optUintField(result["fees_paid"], "fees_paid");
      return {
        method,
        preimage: reqString(result["preimage"], "preimage"),
        ...(feesPaid === undefined ? {} : { fees_paid: feesPaid }),
      };
    }
    case "make_invoice":
    case "lookup_invoice":
      return { method, transaction: parseTransaction(result) };
    case "get_balance":
      return { method, balance: reqUintField(result["balance"], "balance") };
    case "get_info": {
      const alias = optString(result["alias"], "alias");
      const color = optString(result["color"], "color");
      const pubkey = optString(result["pubkey"], "pubkey");
      const network = optString(result["network"], "network");
      const blockHeight = optUintField(result["block_height"], "block_height");
      const blockHash = optString(result["block_hash"], "block_hash");
      const extensions = optStringList(result["extensions"], "extensions");
      const notifications = optStringList(result["notifications"], "notifications");
      return {
        method,
        ...(alias === undefined ? {} : { alias }),
        ...(color === undefined ? {} : { color }),
        ...(pubkey === undefined ? {} : { pubkey }),
        ...(network === undefined ? {} : { network }),
        ...(blockHeight === undefined ? {} : { block_height: blockHeight }),
        ...(blockHash === undefined ? {} : { block_hash: blockHash }),
        methods: stringList(result["methods"], "methods"),
        ...(extensions === undefined ? {} : { extensions }),
        ...(notifications === undefined ? {} : { notifications }),
      };
    }
    case "list_transactions": {
      const rawTransactions = result["transactions"];
      if (!Array.isArray(rawTransactions)) {
        failShape("transactions must be an array");
      }
      const transactions = rawTransactions.map((entry) => {
        if (!isRecord(entry)) {
          failShape("transaction must be an object");
        }
        return parseTransaction(entry);
      });
      const totalCount = optUintField(result["total_count"], "total_count");
      return {
        method,
        transactions,
        ...(totalCount === undefined ? {} : { total_count: totalCount }),
      };
    }
    case "get_budget":
      return { method, budget: parseBudget(result) };
  }
}

function errorCode(wire: string): NwcErrorCode {
  return ERROR_CODES.find((code) => code === wire) ?? "OTHER";
}

/**
 * Validate a decrypted response payload. Exactly one of `result`/`error` must be non-null; absent
 * keys count as null so wallets that omit them (notably @getalby/sdk) are accepted.
 */
export function parseResponsePayload(method: NwcMethod, json: string): NwcResponse {
  if (json.length > MAX_PAYLOAD_LEN) {
    throw invalid("response payload too large");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(json);
  } catch {
    throw invalid("response payload is not valid JSON");
  }
  if (!isRecord(payload)) {
    throw invalid("response payload must be an object");
  }
  if (payload["result_type"] !== method) {
    throw invalid("response result_type does not match the request method");
  }
  const rawResult = payload["result"];
  const rawError = payload["error"];
  const hasResult = rawResult !== undefined && rawResult !== null;
  const hasError = rawError !== undefined && rawError !== null;
  if (hasResult === hasError) {
    throw invalid("response requires exactly one of result and error");
  }
  if (hasError) {
    if (!isRecord(rawError)) {
      throw invalid("response error must be an object");
    }
    const walletCode = reqString(rawError["code"], "error.code");
    return {
      ok: false,
      error: {
        code: errorCode(walletCode),
        walletCode,
        message: reqString(rawError["message"], "error.message"),
      },
    };
  }
  return { ok: true, result: parseResult(method, rawResult) };
}

/** Verify the response envelope, decrypt it with the request's scheme, and validate its payload. */
export async function decodeResponse(
  signer: NwcSigner,
  event: Event,
  sent: NwcSentRequest,
  opts?: { verify?: EventVerifier | undefined },
): Promise<NwcResponse> {
  if (!isResponseTo(event, sent, opts?.verify ?? verifyEvent)) {
    throw invalid("event is not an authentic response to the request");
  }
  let plaintext: string;
  try {
    plaintext = await decryptWith(signer, sent.encryption, event.pubkey, event.content);
  } catch (error) {
    throw new NwcError("response decryption failed", { cause: error });
  }
  return parseResponsePayload(sent.method, plaintext);
}

/** Validate a decrypted NWC-02 notification payload. Unknown notification types yield undefined. */
export function parseNotificationPayload(json: string): NwcNotification | undefined {
  if (json.length > MAX_PAYLOAD_LEN) {
    throw invalid("notification payload too large");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(json);
  } catch {
    throw invalid("notification payload is not valid JSON");
  }
  if (!isRecord(payload)) {
    throw invalid("notification payload must be an object");
  }
  const type = payload["notification_type"];
  if (type !== "payment_received" && type !== "payment_sent") {
    return undefined;
  }
  const { notification } = payload;
  if (!isRecord(notification)) {
    throw invalid("notification must be an object");
  }
  return { type, transaction: parseTransaction(notification) };
}

/** Verify, decrypt, and decode a notification for this client. */
export async function decodeNotification(
  signer: NwcSigner,
  event: Event,
  opts: {
    readonly walletPubkey: string;
    readonly encryption: NwcEncryption;
    readonly verify?: EventVerifier | undefined;
  },
): Promise<NwcNotification | undefined> {
  const expectedKind =
    opts.encryption === "nip44_v2" ? NWC_NOTIFICATION_KIND : NWC_NOTIFICATION_NIP04_KIND;
  const self = await signer.getPublicKey();
  if (
    event.kind !== expectedKind ||
    event.pubkey !== opts.walletPubkey ||
    !tagValues(event, "p").includes(self) ||
    !(opts.verify ?? verifyEvent)(event)
  ) {
    throw invalid("event is not an authentic wallet notification");
  }
  let plaintext: string;
  try {
    plaintext = await decryptWith(signer, opts.encryption, event.pubkey, event.content);
  } catch (error) {
    throw new NwcError("notification decryption failed", { cause: error });
  }
  return parseNotificationPayload(plaintext);
}

export type NwcClientOptions = {
  readonly connection: Pick<NwcConnection, "walletPubkey" | "relays">;
  readonly signer: NwcSigner;
  readonly pool: NwcTransport;
  readonly verify?: EventVerifier | undefined;
  readonly timeoutMs?: number | undefined;
};
export type NwcCallOptions = {
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number | undefined;
};

type InFlight = { reject: (error: Error) => void };

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (error: Error) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((_resolve, _reject) => {
    resolve = _resolve;
    reject = _reject;
  });
  return { promise, resolve, reject };
}

/** Nostr Wallet Connect client session. Does not own or close the injected pool. */
export class NwcClient {
  readonly walletPubkey: string;
  readonly relays: ReadonlyArray<string>;
  readonly #signer: NwcSigner;
  readonly #pool: NwcTransport;
  readonly #verify: EventVerifier;
  readonly #timeoutMs: number;
  #info: Promise<NwcInfo> | undefined;
  #encryption: Promise<NwcEncryption> | undefined;
  readonly #inFlight = new Set<InFlight>();
  readonly #notificationClosers = new Set<{ close: () => void }>();
  #closed = false;

  constructor(opts: NwcClientOptions) {
    this.walletPubkey = opts.connection.walletPubkey;
    this.relays = opts.connection.relays;
    this.#signer = opts.signer;
    this.#pool = opts.pool;
    this.#verify = opts.verify ?? verifyEvent;
    this.#timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /** Fetch and memoize the newest authentic kind-13194 info event. Failures are not memoized. */
  async info(opts?: NwcCallOptions): Promise<NwcInfo> {
    throwIfAborted(opts?.signal);
    this.#assertOpen();
    if (this.#info !== undefined) {
      return raceSignal(this.#info, opts?.signal);
    }
    const pending = (async (): Promise<NwcInfo> => {
      const events = await this.#pool.fetch(
        this.relays,
        [{ kinds: [NWC_INFO_KIND], authors: [this.walletPubkey], limit: 1 }],
        { timeoutMs: this.#timeoutMs },
      );
      let newest: Event | undefined;
      for (const event of events) {
        if (
          event.pubkey === this.walletPubkey &&
          this.#verify(event) &&
          (newest === undefined ||
            event.created_at > newest.created_at ||
            (event.created_at === newest.created_at && event.id < newest.id))
        ) {
          newest = event;
        }
      }
      if (newest === undefined) {
        throw invalid("wallet info event not found");
      }
      return parseInfoEvent(newest);
    })();
    this.#info = pending;
    void (async (): Promise<void> => {
      try {
        await pending;
      } catch {
        if (this.#info === pending) {
          this.#info = undefined;
        }
      }
    })();
    return raceSignal(pending, opts?.signal);
  }

  /** Negotiate and memoize the encryption scheme from the wallet info event. */
  async encryption(opts?: NwcCallOptions): Promise<NwcEncryption> {
    throwIfAborted(opts?.signal);
    this.#assertOpen();
    if (this.#encryption !== undefined) {
      return raceSignal(this.#encryption, opts?.signal);
    }
    const pending = (async (): Promise<NwcEncryption> => negotiateEncryption(await this.info()))();
    this.#encryption = pending;
    void (async (): Promise<void> => {
      try {
        await pending;
      } catch {
        if (this.#encryption === pending) {
          this.#encryption = undefined;
        }
      }
    })();
    return raceSignal(pending, opts?.signal);
  }

  async getInfo(opts?: NwcCallOptions): Promise<NwcWalletInfo> {
    const result = await this.#call({ method: "get_info", params: {} }, opts);
    if (result.method !== "get_info") {
      throw invalid("unexpected response method");
    }
    const { method: _method, ...info } = result;
    return info;
  }

  async getBalance(opts?: NwcCallOptions): Promise<NwcBalance> {
    const result = await this.#call({ method: "get_balance", params: {} }, opts);
    if (result.method !== "get_balance") {
      throw invalid("unexpected response method");
    }
    return { balance: result.balance };
  }

  async payInvoice(params: NwcPayInvoiceParams, opts?: NwcCallOptions): Promise<NwcPayResult> {
    const result = await this.#call({ method: "pay_invoice", params }, opts);
    if (result.method !== "pay_invoice") {
      throw invalid("unexpected response method");
    }
    const invoice = parseBolt11(params.invoice);
    if (invoice?.paymentHash !== undefined) {
      let preimage: Uint8Array;
      try {
        preimage = hexToBytes(result.preimage);
      } catch {
        throw invalid("payment preimage is not hex");
      }
      if (bytesToHex(sha256(preimage)) !== bytesToHex(invoice.paymentHash)) {
        throw invalid("payment preimage does not match the invoice payment hash");
      }
    }
    return {
      preimage: result.preimage,
      ...(result.fees_paid === undefined ? {} : { fees_paid: result.fees_paid }),
    };
  }

  async makeInvoice(params: NwcMakeInvoiceParams, opts?: NwcCallOptions): Promise<NwcTransaction> {
    const result = await this.#call({ method: "make_invoice", params }, opts);
    if (result.method !== "make_invoice") {
      throw invalid("unexpected response method");
    }
    return result.transaction;
  }

  async lookupInvoice(
    params: NwcLookupInvoiceParams,
    opts?: NwcCallOptions,
  ): Promise<NwcTransaction> {
    const result = await this.#call({ method: "lookup_invoice", params }, opts);
    if (result.method !== "lookup_invoice") {
      throw invalid("unexpected response method");
    }
    return result.transaction;
  }

  async listTransactions(
    params: NwcListTransactionsParams = {},
    opts?: NwcCallOptions,
  ): Promise<NwcTransactionList> {
    const result = await this.#call({ method: "list_transactions", params }, opts);
    if (result.method !== "list_transactions") {
      throw invalid("unexpected response method");
    }
    return {
      transactions: result.transactions,
      ...(result.total_count === undefined ? {} : { total_count: result.total_count }),
    };
  }

  async getBudget(opts?: NwcCallOptions): Promise<NwcBudget | undefined> {
    const result = await this.#call({ method: "get_budget", params: {} }, opts);
    if (result.method !== "get_budget") {
      throw invalid("unexpected response method");
    }
    return result.budget;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw invalid("client closed");
    }
  }

  async #call(request: NwcRequest, opts?: NwcCallOptions): Promise<NwcResult> {
    throwIfAborted(opts?.signal);
    this.#assertOpen();
    const timeoutMs = opts?.timeoutMs ?? this.#timeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      throw invalid("timeoutMs must be a positive safe integer");
    }
    const encryption = await raceSignal(this.encryption(), opts?.signal);
    throwIfAborted(opts?.signal);
    const createdAt = nowSeconds();
    const sent = await encodeRequest(this.#signer, this.walletPubkey, request, {
      encryption,
      createdAt,
      expiration: createdAt + Math.ceil(timeoutMs / 1000),
    });
    return new Promise<NwcResult>((resolve, reject) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let disposeAbort: (() => void) | undefined;
      let inFlight: InFlight | undefined;
      const subs: Array<{ close: (reason?: string) => void }> = [];

      const cleanup = (): void => {
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        disposeAbort?.();
        disposeAbort = undefined;
        for (const sub of subs.splice(0)) {
          sub.close("nwc request complete");
        }
        if (inFlight !== undefined) {
          this.#inFlight.delete(inFlight);
          inFlight = undefined;
        }
      };
      const finish = (fn: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        fn();
      };
      const fail = (error: Error): void => {
        finish(() => reject(error));
      };
      const succeed = (result: NwcResult): void => {
        finish(() => resolve(result));
      };

      inFlight = { reject: (error) => fail(error) };
      this.#inFlight.add(inFlight);

      let relayEosed = false;
      let relaysEnded = 0;
      const live = deferred<undefined>();
      const firstLive = live.promise;
      const onSubscriptionEose = (): void => {
        if (!relayEosed) {
          relayEosed = true;
          live.resolve(undefined);
        }
      };
      const onSubscriptionClose = (): void => {
        relaysEnded += 1;
        if (!relayEosed && relaysEnded === this.relays.length) {
          live.reject(invalid("wallet response subscription failed"));
        }
      };
      const filter = {
        kinds: [NWC_RESPONSE_KIND],
        authors: [this.walletPubkey],
        "#e": [sent.event.id],
        "#p": [sent.event.pubkey],
      };
      for (const relay of this.relays) {
        subs.push(
          this.#pool.subscribe([relay], [filter], {
            onEvent: (event) => {
              if (!isResponseTo(event, sent, this.#verify)) {
                return;
              }
              void (async (): Promise<void> => {
                try {
                  const decoded = await decodeResponse(this.#signer, event, sent, {
                    verify: this.#verify,
                  });
                  if (!decoded.ok) {
                    fail(new NwcWalletError(decoded.error));
                    return;
                  }
                  succeed(decoded.result);
                } catch (error) {
                  fail(error instanceof NwcError ? error : new NwcError("invalid wallet response"));
                }
              })();
            },
            onEose: onSubscriptionEose,
            onClose: onSubscriptionClose,
          }),
        );
      }

      let publishStarted = false;
      timer = setTimeout(() => {
        if (publishStarted) {
          fail(new NwcTimeoutError("wallet response timed out"));
        } else {
          fail(invalid("no wallet relay became ready before the request timeout"));
        }
      }, timeoutMs);
      disposeAbort = onAbort(opts?.signal, () => {
        const signal = opts?.signal;
        if (signal === undefined) {
          return;
        }
        const reason = abortReason(signal);
        // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- abort must preserve signal.reason exactly
        finish(() => reject(reason));
      });

      void (async (): Promise<void> => {
        try {
          await firstLive;
        } catch (error) {
          fail(
            error instanceof NwcError
              ? error
              : new NwcError("wallet response subscription failed", { cause: error }),
          );
          return;
        }
        if (settled) {
          return;
        }
        publishStarted = true;
        let outcomes;
        try {
          outcomes = await this.#pool.publish(this.relays, sent.event);
        } catch (error) {
          fail(new NwcError("wallet request publish failed", { cause: error }));
          return;
        }
        const accepted = outcomes.some((outcome) => outcome.status === "ok");
        if (!accepted) {
          const details = outcomes
            .map((outcome) => {
              const reason = outcome.message ?? outcome.error?.message ?? "no reason given";
              return `${outcome.url}: ${outcome.status} (${reason})`;
            })
            .join("; ");
          fail(invalid(`no relay accepted the wallet request: ${details}`));
        }
      })();
    });
  }

  /**
   * Subscribe to NWC-02 notifications for the negotiated encryption. Resolves once the live
   * subscription is installed. Invalid, forged, and unknown notifications are skipped silently;
   * listener exceptions are reported without killing delivery.
   */
  async subscribeNotifications(
    onNotification: (notification: NwcNotification) => void,
    opts?: { signal?: AbortSignal | undefined },
  ): Promise<{ close: () => void }> {
    throwIfAborted(opts?.signal);
    this.#assertOpen();
    let encryption: NwcEncryption;
    let client: string;
    try {
      encryption = await raceSignal(this.encryption(), opts?.signal);
      client = await raceSignal(this.#signer.getPublicKey(), opts?.signal);
    } catch (error) {
      if (opts?.signal?.aborted === true) {
        throw abortReason(opts.signal);
      }
      throw error instanceof NwcError
        ? error
        : new NwcError("notification setup failed", { cause: error });
    }
    throwIfAborted(opts?.signal);
    let closed = false;
    let sub: { close: (reason?: string) => void } | undefined;
    const handle = {
      close: (): void => {
        if (closed) {
          return;
        }
        closed = true;
        disposeAbort();
        this.#notificationClosers.delete(handle);
        sub?.close("nwc notifications closed");
      },
    };
    const disposeAbort = onAbort(opts?.signal, () => handle.close());
    const kind = encryption === "nip44_v2" ? NWC_NOTIFICATION_KIND : NWC_NOTIFICATION_NIP04_KIND;
    try {
      sub = this.#pool.subscribe(
        this.relays,
        [{ kinds: [kind], authors: [this.walletPubkey], "#p": [client], limit: 0 }],
        {
          onEvent: (event) => {
            void (async (): Promise<void> => {
              try {
                const notification = await decodeNotification(this.#signer, event, {
                  walletPubkey: this.walletPubkey,
                  encryption,
                  verify: this.#verify,
                });
                if (notification !== undefined && !closed) {
                  invokeSafely(() => onNotification(notification));
                }
              } catch {
                // forged and malformed notifications never interrupt the live subscription
              }
            })();
          },
        },
      );
    } catch (error) {
      disposeAbort();
      throw new NwcError("notification subscription failed", { cause: error });
    }
    this.#notificationClosers.add(handle);
    if (opts?.signal?.aborted === true) {
      const reason = abortReason(opts.signal);
      handle.close();
      throw reason;
    }
    return handle;
  }

  /** Close notification subscriptions and reject every in-flight request. The pool stays open. */
  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    for (const handle of this.#notificationClosers) {
      handle.close();
    }
    this.#notificationClosers.clear();
    for (const item of this.#inFlight) {
      item.reject(invalid("client closed"));
    }
    this.#inFlight.clear();
  }
}
