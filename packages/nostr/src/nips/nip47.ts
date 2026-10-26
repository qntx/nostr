import { NostrError } from "../core/error.ts";
import type { Event, UnsignedEvent } from "../core/event.ts";
import { hexToBytes } from "../core/index.ts";
import { verifyEvent } from "../core/verifier.ts";

/**
 * NIP-47 Nostr Wallet Connect, client side only: parse a `nostr+walletconnect://` URI, read a
 * wallet's info event, and send NIP-44-encrypted requests / validate + decrypt responses. The
 * wallet-service side (decodeRequest, encodeResponse, notifications) is out of scope — WD-066.
 */
export const NWC_INFO_KIND = 13194;
export const NWC_REQUEST_KIND = 23194;
export const NWC_RESPONSE_KIND = 23195;

/** `encryption` tag value this client always uses; a wallet that does not list it cannot be served. */
export const NWC_ENCRYPTION_NIP44 = "nip44_v2";

/** Max chars for any string field carried inside an encrypted payload. */
const MAX_STRING_LEN = 65_535;
/** Max chars of a decrypted request/response payload. */
const MAX_PAYLOAD_LEN = 1_048_576;

export type NwcMethod =
  | "pay_invoice"
  | "make_invoice"
  | "lookup_invoice"
  | "get_balance"
  | "get_info";

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

const NWC_ERROR_CODES: ReadonlyArray<NwcErrorCode> = [
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

export class NwcError extends NostrError {
  override name = "NwcError";
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * The minimal signer surface an NWC client needs — structurally identical to `Nip59Crypto`, kept as
 * its own type so `nips/nip47` never imports `signer` (layer rule).
 */
export type NwcCrypto = {
  getPublicKey: () => Promise<string>;
  signEvent: (unsigned: UnsignedEvent) => Promise<Event>;
  nip44Encrypt: (peer: string, plaintext: string) => Promise<string>;
  nip44Decrypt: (peer: string, payload: string) => Promise<string>;
};

export type NwcMetadata = Record<string, unknown>;

export type NwcRequest =
  | {
      method: "pay_invoice";
      params: { invoice: string; amount?: number; metadata?: NwcMetadata };
    }
  | {
      method: "make_invoice";
      params: {
        amount: number;
        description?: string;
        description_hash?: string;
        expiry?: number;
        metadata?: NwcMetadata;
      };
    }
  | {
      method: "lookup_invoice";
      params: { payment_hash?: string; invoice?: string };
    }
  | { method: "get_balance"; params: Record<string, never> }
  | { method: "get_info"; params: Record<string, never> };

/** The transaction record `make_invoice` and `lookup_invoice` return. */
export type NwcTransaction = {
  type?: "incoming" | "outgoing";
  state?: string;
  invoice?: string;
  description?: string;
  description_hash?: string;
  preimage?: string;
  payment_hash?: string;
  amount: number;
  fees_paid?: number;
  created_at: number;
  expires_at?: number;
  settled_at?: number;
  metadata?: NwcMetadata;
};

export type NwcResult =
  | { method: "pay_invoice"; preimage: string; fees_paid?: number }
  | { method: "make_invoice" | "lookup_invoice"; transaction: NwcTransaction }
  | { method: "get_balance"; balance: number }
  | {
      method: "get_info";
      alias?: string;
      color?: string;
      pubkey?: string;
      network?: string;
      block_height?: number;
      block_hash?: string;
      methods: ReadonlyArray<string>;
      extensions?: ReadonlyArray<string>;
    };

export type NwcResponse =
  // oxlint-disable-next-line typescript/no-restricted-types -- wire shape: `error` is null on success
  | { resultType: NwcMethod; result: NwcResult; error: null }
  | {
      resultType: NwcMethod;
      // oxlint-disable-next-line typescript/no-restricted-types -- wire shape: `result` is null on failure
      result: null;
      error: { code: NwcErrorCode; message: string };
    };

export type NwcConnection = {
  walletPubkey: string;
  relays: ReadonlyArray<string>;
  secret: Uint8Array;
  lud16?: string;
};

export type NwcInfo = {
  /** Supported method names verbatim from the info event content, space-separated there. */
  methods: ReadonlyArray<string>;
  /** `encryption` tag entries; empty when the tag is absent (spec: implies nip04-only). */
  encryptions: ReadonlyArray<string>;
  /** `extensions` tag entries; empty when absent. */
  extensions: ReadonlyArray<string>;
  /** True when `encryption` includes `nip44_v2` — a client that only speaks NIP-44 needs it. */
  nip44: boolean;
};

/** A sent request kept for `decodeResponse`: the signed event plus the method it carries. */
export type NwcSentRequest = { event: Event; method: NwcMethod };

const isHex64 = (value: string): boolean => /^[0-9a-f]{64}$/i.test(value);

function isLoopbackWs(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "ws:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
}

/** Parse `nostr+walletconnect://<pubkey>?relay=wss://…&secret=<64hex>[&lud16=…]`. */
export function parseConnectionUri(uri: string): NwcConnection {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new NwcError("INVALID_URI", "connection URI does not parse");
  }
  if (parsed.protocol !== "nostr+walletconnect:") {
    throw new NwcError("INVALID_URI", `unexpected scheme: ${parsed.protocol}`);
  }
  const walletPubkey = decodeURIComponent(parsed.hostname);
  if (!isHex64(walletPubkey)) {
    throw new NwcError("INVALID_URI", "wallet pubkey must be 64 hex chars");
  }
  const secretHex = parsed.searchParams.get("secret");
  if (secretHex === null || !isHex64(secretHex)) {
    throw new NwcError("INVALID_URI", "secret must be 64 hex chars");
  }
  const relays = parsed.searchParams.getAll("relay");
  if (relays.length === 0) {
    throw new NwcError("INVALID_URI", "at least one relay is required");
  }
  for (const relay of relays) {
    if (!relay.startsWith("wss://") && !isLoopbackWs(relay)) {
      throw new NwcError("INVALID_URI", `relay must be wss:// (or ws://localhost): ${relay}`);
    }
  }
  const lud16 = parsed.searchParams.get("lud16") ?? undefined;
  return {
    walletPubkey: walletPubkey.toLowerCase(),
    relays,
    secret: hexToBytes(secretHex.toLowerCase()),
    ...(lud16 === undefined ? {} : { lud16 }),
  };
}

const whitespace = /\s+/;

/** Read a kind-13194 info event: supported methods, `encryption` tag, `extensions` tag. */
export function parseInfoEvent(event: Event): NwcInfo {
  if (event.kind !== NWC_INFO_KIND) {
    throw new NwcError("INVALID_EVENT", `info event kind must be ${NWC_INFO_KIND}`);
  }
  const methods = event.content.split(whitespace).filter((m) => m !== "");
  let encryptions: ReadonlyArray<string> = [];
  let extensions: ReadonlyArray<string> = [];
  for (const [key, value] of event.tags) {
    if (key === "encryption" && value !== undefined) {
      encryptions = value.split(whitespace).filter((e) => e !== "");
    } else if (key === "extensions" && value !== undefined) {
      extensions = value.split(whitespace).filter((e) => e !== "");
    }
  }
  return {
    methods,
    encryptions,
    extensions,
    nip44: encryptions.includes(NWC_ENCRYPTION_NIP44),
  };
}

/**
 * Encrypt `request` for `walletPubkey`, sign it as a kind-23194 request with `p` + `encryption`
 * tags (plus `expiration` when given), and return the signed event with its method for
 * `decodeResponse`.
 */
export async function encodeRequest(
  crypto: NwcCrypto,
  walletPubkey: string,
  request: NwcRequest,
  options?: { expiration?: number; createdAt?: number },
): Promise<NwcSentRequest> {
  const payload = JSON.stringify({ method: request.method, params: request.params });
  const content = await crypto.nip44Encrypt(walletPubkey, payload);
  const tags: string[][] = [
    ["p", walletPubkey],
    ["encryption", NWC_ENCRYPTION_NIP44],
  ];
  if (options?.expiration !== undefined) {
    tags.push(["expiration", String(Math.floor(options.expiration))]);
  }
  const unsigned: UnsignedEvent = {
    pubkey: await crypto.getPublicKey(),
    kind: NWC_REQUEST_KIND,
    tags,
    content,
    created_at: options?.createdAt ?? Math.floor(Date.now() / 1000),
  };
  const event = await crypto.signEvent(unsigned);
  return { event, method: request.method };
}

const isMsat = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function optString(value: unknown): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length > MAX_STRING_LEN) {
    throw new NwcError("INVALID_RESPONSE", "string field missing or too long");
  }
  return value;
}

function optMsat(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isMsat(value)) {
    throw new NwcError("INVALID_RESPONSE", "amount must be a non-negative safe integer");
  }
  return value;
}

function optUint(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isMsat(value)) {
    throw new NwcError("INVALID_RESPONSE", "timestamp must be a non-negative safe integer");
  }
  return value;
}

function reqString(value: unknown, name: string): string {
  const out = optString(value);
  if (out === undefined) {
    throw new NwcError("INVALID_RESPONSE", `${name} is required`);
  }
  return out;
}

function reqMsat(value: unknown, name: string): number {
  const out = optMsat(value);
  if (out === undefined) {
    throw new NwcError("INVALID_RESPONSE", `${name} is required`);
  }
  return out;
}

function optMetadata(value: unknown): NwcMetadata | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new NwcError("INVALID_RESPONSE", "metadata must be an object");
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- shape checked above
  return value as NwcMetadata;
}

function stringList(value: unknown, name: string): ReadonlyArray<string> {
  if (!Array.isArray(value)) {
    throw new NwcError("INVALID_RESPONSE", `${name} must be a string array`);
  }
  return value.map((entry) => reqString(entry, name));
}

function optStringList(value: unknown, name: string): ReadonlyArray<string> | undefined {
  return value === undefined ? undefined : stringList(value, name);
}

function parseTransaction(result: Record<string, unknown>): NwcTransaction {
  const { type } = result;
  if (type !== undefined && type !== "incoming" && type !== "outgoing") {
    throw new NwcError("INVALID_RESPONSE", "transaction type must be incoming|outgoing");
  }
  const state = optString(result["state"]);
  const invoice = optString(result["invoice"]);
  const description = optString(result["description"]);
  const descriptionHash = optString(result["description_hash"]);
  const preimage = optString(result["preimage"]);
  const paymentHash = optString(result["payment_hash"]);
  const feesPaid = optMsat(result["fees_paid"]);
  const expiresAt = optUint(result["expires_at"]);
  const settledAt = optUint(result["settled_at"]);
  const metadata = optMetadata(result["metadata"]);
  return {
    ...(type === undefined ? {} : { type }),
    ...(state === undefined ? {} : { state }),
    ...(invoice === undefined ? {} : { invoice }),
    ...(description === undefined ? {} : { description }),
    ...(descriptionHash === undefined ? {} : { description_hash: descriptionHash }),
    ...(preimage === undefined ? {} : { preimage }),
    ...(paymentHash === undefined ? {} : { payment_hash: paymentHash }),
    amount: reqMsat(result["amount"], "amount"),
    ...(feesPaid === undefined ? {} : { fees_paid: feesPaid }),
    created_at: reqMsat(result["created_at"], "created_at"),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    ...(settledAt === undefined ? {} : { settled_at: settledAt }),
    ...(metadata === undefined ? {} : { metadata }),
  };
}

function parseResult(resultType: NwcMethod, result: unknown): NwcResult {
  if (typeof result !== "object" || result === null || Array.isArray(result)) {
    throw new NwcError("INVALID_RESPONSE", "result must be an object");
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- shape checked above
  const record = result as Record<string, unknown>;
  let parsed: NwcResult;
  switch (resultType) {
    case "pay_invoice": {
      const feesPaid = optMsat(record["fees_paid"]);
      parsed = {
        method: "pay_invoice",
        preimage: reqString(record["preimage"], "preimage"),
        ...(feesPaid === undefined ? {} : { fees_paid: feesPaid }),
      };
      break;
    }
    case "make_invoice":
    case "lookup_invoice":
      parsed = { method: resultType, transaction: parseTransaction(record) };
      break;
    case "get_balance":
      parsed = { method: "get_balance", balance: reqMsat(record["balance"], "balance") };
      break;
    case "get_info": {
      const alias = optString(record["alias"]);
      const color = optString(record["color"]);
      const pubkey = optString(record["pubkey"]);
      const network = optString(record["network"]);
      const blockHeight = optUint(record["block_height"]);
      const blockHash = optString(record["block_hash"]);
      const extensions = optStringList(record["extensions"], "extensions");
      parsed = {
        method: "get_info",
        ...(alias === undefined ? {} : { alias }),
        ...(color === undefined ? {} : { color }),
        ...(pubkey === undefined ? {} : { pubkey }),
        ...(network === undefined ? {} : { network }),
        ...(blockHeight === undefined ? {} : { block_height: blockHeight }),
        ...(blockHash === undefined ? {} : { block_hash: blockHash }),
        methods: stringList(record["methods"], "methods"),
        ...(extensions === undefined ? {} : { extensions }),
      };
      break;
    }
  }
  return parsed;
}

/**
 * Validate and decrypt a kind-23195 response to `request`: kind, a valid signature, wallet
 * authorship (event pubkey = the request's `p` tag), `e` = request id, `p` = our pubkey,
 * `result_type` = the request method, and exactly one of `result`/`error`. Field-level checks: msat
 * amounts are non-negative safe integers, strings are capped at {@link MAX_STRING_LEN}.
 */
export async function decodeResponse(
  crypto: NwcCrypto,
  event: Event,
  request: NwcSentRequest,
): Promise<NwcResponse> {
  if (event.kind !== NWC_RESPONSE_KIND) {
    throw new NwcError("INVALID_EVENT", `response kind must be ${NWC_RESPONSE_KIND}`);
  }
  const walletPubkey = request.event.tags.find(([k]) => k === "p")?.[1];
  if (walletPubkey === undefined || event.pubkey !== walletPubkey) {
    throw new NwcError("INVALID_EVENT", "response author is not the wallet pubkey");
  }
  if (!event.tags.some(([k, v]) => k === "e" && v === request.event.id)) {
    throw new NwcError("INVALID_EVENT", "response e tag does not name the request id");
  }
  const self = await crypto.getPublicKey();
  if (!event.tags.some(([k, v]) => k === "p" && v === self)) {
    throw new NwcError("INVALID_EVENT", "response p tag is not our pubkey");
  }
  if (!verifyEvent(event)) {
    throw new NwcError("INVALID_EVENT", "response signature invalid");
  }
  const plaintext = await crypto.nip44Decrypt(event.pubkey, event.content);
  if (plaintext.length > MAX_PAYLOAD_LEN) {
    throw new NwcError("INVALID_RESPONSE", "response payload too large");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(plaintext);
  } catch {
    throw new NwcError("INVALID_RESPONSE", "response payload is not JSON");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new NwcError("INVALID_RESPONSE", "response payload must be an object");
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- shape checked above
  const record = payload as Record<string, unknown>;
  if (record["result_type"] !== request.method) {
    throw new NwcError("INVALID_RESPONSE", "result_type does not match the request method");
  }
  const hasResult = record["result"] !== null && record["result"] !== undefined;
  const hasError = record["error"] !== null && record["error"] !== undefined;
  if (hasResult === hasError) {
    throw new NwcError("INVALID_RESPONSE", "exactly one of result/error is required");
  }
  if (hasError) {
    const { error } = record;
    if (typeof error !== "object" || error === null || Array.isArray(error)) {
      throw new NwcError("INVALID_RESPONSE", "error must be an object");
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- shape checked above
    const errRecord = error as Record<string, unknown>;
    const code = NWC_ERROR_CODES.find((c) => c === errRecord["code"]);
    if (code === undefined) {
      throw new NwcError("INVALID_RESPONSE", "error code is not a NIP-47 code");
    }
    return {
      resultType: request.method,
      result: null,
      error: { code, message: reqString(errRecord["message"], "message") },
    };
  }
  return {
    resultType: request.method,
    result: parseResult(request.method, record["result"]),
    error: null,
  };
}
