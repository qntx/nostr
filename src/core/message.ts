import { MessageError } from "./error.ts";
import type { Event } from "./event.ts";
import { validateSignedEvent } from "./event.ts";
import type { Filter } from "./filter.ts";
import { SUBSCRIPTION_ID_MAX_CHARS } from "./limits.ts";
import { bytesToHex, hexToBytes, isRecord } from "./util.ts";

/** NIP-01 subscription id: 1..64 chars. */
export type SubscriptionId = string;

/** Validate a subscription id; throws {@link MessageError} unless 1..64 chars. */
export function assertSubscriptionId(id: string): SubscriptionId {
  if (id.length === 0 || id.length > SUBSCRIPTION_ID_MAX_CHARS) {
    throw new MessageError(`subscription id length must be 1..${SUBSCRIPTION_ID_MAX_CHARS}`);
  }
  return id;
}

/** Validate the given id, or mint a random 16-hex-char subscription id. */
export function createSubscriptionId(id?: string): SubscriptionId {
  if (id !== undefined) {
    return assertSubscriptionId(id);
  }
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/** Client → relay messages (NIP-01 + NIP-42 AUTH + NIP-45 COUNT + NIP-77). */
export type ClientMessage =
  | ["EVENT", Event]
  | ["REQ", SubscriptionId, ...Filter[]]
  | ["CLOSE", SubscriptionId]
  | ["AUTH", Event]
  | ["COUNT", SubscriptionId, ...Filter[]]
  | ["NEG-OPEN", SubscriptionId, Filter, string]
  | ["NEG-MSG", SubscriptionId, string]
  | ["NEG-CLOSE", SubscriptionId];

/** Relay → client messages. */
export type RelayMessage =
  | ["EVENT", SubscriptionId, Event]
  | ["OK", string, boolean, string]
  | ["EOSE", SubscriptionId]
  | ["CLOSED", SubscriptionId, string]
  | ["NOTICE", string]
  | ["AUTH", string]
  | ["COUNT", SubscriptionId, CountResult]
  | ["NEG-MSG", SubscriptionId, string]
  | ["NEG-ERR", SubscriptionId, string];

/** NIP-45 COUNT reply payload. */
export type CountResult = {
  count: number;
  approximate?: boolean;
  /**
   * Optional 512-char hex HyperLogLog sketch (256 registers). Merge sketches with `mergeCountHll`.
   * Estimation is unspecified by NIP-45 and not provided.
   */
  hll?: string;
};

const HLL_BYTES = 256; // 512 hex chars (NIP-45; hex only, not base64)
const HLL_HEX_LEN = HLL_BYTES * 2;
const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Register-wise max of NIP-45 HyperLogLog sketches. Output is always lowercase 512 hex. Empty input
 * is the zero sketch (identity).
 */
export function mergeCountHll(hexes: ReadonlyArray<string>): string {
  const merged = new Uint8Array(HLL_BYTES);
  for (const hex of hexes) {
    if (hex.length !== HLL_HEX_LEN || !HEX_RE.test(hex)) {
      throw new MessageError("invalid NIP-45 HLL sketch: expected 512-char hex");
    }
    const bytes = hexToBytes(hex);
    for (const [i, b] of bytes.entries()) {
      const m = merged[i];
      if (m !== undefined && b > m) {
        merged[i] = b;
      }
    }
  }
  return bytesToHex(merged);
}

/** Serialize a client->relay message to its NIP-01 JSON wire form. */
export function encodeClientMessage(message: ClientMessage): string {
  return JSON.stringify(message);
}

/** Serialize a relay->client message to its NIP-01 JSON wire form. */
export function encodeRelayMessage(message: RelayMessage): string {
  return JSON.stringify(message);
}

/** Parse a client->relay JSON message; throws {@link MessageError} on malformed input. */
export function parseClientMessage(raw: string): ClientMessage {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new MessageError("client message is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || typeof parsed[0] !== "string") {
    throw new MessageError("client message must be a non-empty JSON array");
  }
  const items: unknown[] = parsed;
  const [type] = items;
  switch (type) {
    case "EVENT":
      if (items.length !== 2 || !validateSignedEvent(items[1])) {
        throw new MessageError("invalid EVENT client message");
      }
      return ["EVENT", items[1]];

    case "REQ":
      if (items.length < 3 || typeof items[1] !== "string") {
        throw new MessageError("invalid REQ client message");
      }
      return ["REQ", items[1], ...parseWireFilters(items.slice(2), "REQ")];

    case "CLOSE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid CLOSE client message");
      }
      return ["CLOSE", items[1]];

    case "AUTH":
      if (items.length !== 2 || !validateSignedEvent(items[1])) {
        throw new MessageError("invalid AUTH client message");
      }
      return ["AUTH", items[1]];

    case "COUNT":
      if (items.length < 3 || typeof items[1] !== "string") {
        throw new MessageError("invalid COUNT client message");
      }
      return ["COUNT", items[1], ...parseWireFilters(items.slice(2), "COUNT")];

    case "NEG-OPEN":
      if (items.length === 5) {
        throw new MessageError("obsolete 5-element NEG-OPEN; expected [NEG-OPEN, id, filter, hex]");
      }
      if (
        items.length !== 4 ||
        typeof items[1] !== "string" ||
        !isWireFilter(items[2]) ||
        !isNegHex(items[3])
      ) {
        throw new MessageError("invalid NEG-OPEN client message");
      }
      return ["NEG-OPEN", items[1], items[2], items[3].toLowerCase()];

    case "NEG-MSG":
      if (items.length !== 3 || typeof items[1] !== "string" || !isNegHex(items[2])) {
        throw new MessageError("invalid NEG-MSG client message");
      }
      return ["NEG-MSG", items[1], items[2].toLowerCase()];

    case "NEG-CLOSE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid NEG-CLOSE client message");
      }
      return ["NEG-CLOSE", items[1]];

    default:
      throw new MessageError(`unknown client message type: ${String(type)}`);
  }
}

/** Parse a relay->client JSON message; throws {@link MessageError} on malformed input. */
export function parseRelayMessage(raw: string): RelayMessage {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new MessageError("relay message is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || typeof parsed[0] !== "string") {
    throw new MessageError("relay message must be a non-empty JSON array");
  }
  const items: unknown[] = parsed;
  const [type] = items;
  switch (type) {
    case "EVENT":
      if (items.length !== 3 || typeof items[1] !== "string" || !validateSignedEvent(items[2])) {
        throw new MessageError("invalid EVENT relay message");
      }
      return ["EVENT", items[1], items[2]];

    case "OK":
      if (
        items.length !== 4 ||
        typeof items[1] !== "string" ||
        typeof items[2] !== "boolean" ||
        typeof items[3] !== "string"
      ) {
        throw new MessageError("invalid OK relay message");
      }
      return ["OK", items[1], items[2], items[3]];

    case "EOSE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid EOSE relay message");
      }
      return ["EOSE", items[1]];

    case "CLOSED":
      if (items.length !== 3 || typeof items[1] !== "string" || typeof items[2] !== "string") {
        throw new MessageError("invalid CLOSED relay message");
      }
      return ["CLOSED", items[1], items[2]];

    case "NOTICE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid NOTICE relay message");
      }
      return ["NOTICE", items[1]];

    case "AUTH":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid AUTH relay message");
      }
      return ["AUTH", items[1]];

    case "COUNT": {
      const payload = items.at(2);
      if (
        items.length !== 3 ||
        typeof items[1] !== "string" ||
        !isRecord(payload) ||
        typeof payload["count"] !== "number"
      ) {
        throw new MessageError("invalid COUNT relay message");
      }
      const result: CountResult = { count: payload["count"] };
      if (typeof payload["approximate"] === "boolean") {
        result.approximate = payload["approximate"];
      }
      const hll = parseCountHll(payload["hll"]);
      if (hll !== undefined) {
        result.hll = hll;
      }
      return ["COUNT", items[1], result];
    }
    case "NEG-MSG":
      if (items.length !== 3 || typeof items[1] !== "string" || !isNegHex(items[2])) {
        throw new MessageError("invalid NEG-MSG relay message");
      }
      return ["NEG-MSG", items[1], items[2].toLowerCase()];

    case "NEG-ERR":
      if (
        (items.length !== 3 && items.length !== 4) ||
        typeof items[1] !== "string" ||
        typeof items[2] !== "string"
      ) {
        throw new MessageError("invalid NEG-ERR relay message");
      }
      return ["NEG-ERR", items[1], items[2]];

    default:
      throw new MessageError(`unknown relay message type: ${String(type)}`);
  }
}

function parseCountHll(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length !== HLL_HEX_LEN || !HEX_RE.test(value)) {
    return undefined;
  }
  return value.toLowerCase();
}

function isWireFilter(value: unknown): value is Filter {
  return isRecord(value);
}

function parseWireFilters(items: unknown[], kind: string): Filter[] {
  const filters: Filter[] = [];
  for (const item of items) {
    if (!isWireFilter(item)) {
      throw new MessageError(`invalid ${kind} filter`);
    }
    filters.push(item);
  }
  return filters;
}

function isNegHex(value: unknown): value is string {
  return (
    typeof value === "string" && value.length > 0 && value.length % 2 === 0 && HEX_RE.test(value)
  );
}
