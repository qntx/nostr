import { MessageError } from "./error.ts";
import type { Event } from "./event.ts";
import { validateSignedEvent } from "./event.ts";
import { canonicalizeFilter, canonicalizeFilters } from "./filter.ts";
import type { Filter } from "./filter.ts";
import { SUBSCRIPTION_ID_MAX_CHARS } from "./limits.ts";
import type { Mutable } from "./util.ts";
import { bytesToHex, hexToBytes, isRecord } from "./util.ts";

/** NIP-01 subscription id: 1..64 chars. */
export type SubscriptionId = string;

/** Validate a subscription id; throws {@link MessageError} unless 1..64 Unicode scalar values. */
export function assertSubscriptionId(id: string): SubscriptionId {
  // Iterating a string yields code points, so astral chars count once (NIP-01's "chars").
  let length = 0;
  for (const _ of id) {
    length += 1;
  }
  if (length === 0 || length > SUBSCRIPTION_ID_MAX_CHARS) {
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
  readonly count: number;
  readonly approximate?: boolean | undefined;
  /**
   * Optional 512-char hex HyperLogLog sketch (256 registers). Merge sketches with `mergeCountHll`.
   * Estimation is unspecified by NIP-45 and not provided.
   */
  readonly hll?: string | undefined;
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
  // REQ/COUNT/NEG-OPEN filters are canonicalized so the wire form matches nk-core.
  switch (message[0]) {
    case "REQ":
    case "COUNT": {
      const [type, id, ...filters] = message;
      return JSON.stringify([type, id, ...canonicalizeFilters(filters)]);
    }
    case "NEG-OPEN":
      return JSON.stringify(["NEG-OPEN", message[1], canonicalizeFilter(message[2]), message[3]]);
    default:
      return JSON.stringify(message);
  }
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
      return ["REQ", assertSubscriptionId(items[1]), ...parseWireFilters(items.slice(2), "REQ")];

    case "CLOSE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid CLOSE client message");
      }
      return ["CLOSE", assertSubscriptionId(items[1])];

    case "AUTH":
      if (items.length !== 2 || !validateSignedEvent(items[1])) {
        throw new MessageError("invalid AUTH client message");
      }
      return ["AUTH", items[1]];

    case "COUNT":
      if (items.length < 3 || typeof items[1] !== "string") {
        throw new MessageError("invalid COUNT client message");
      }
      return [
        "COUNT",
        assertSubscriptionId(items[1]),
        ...parseWireFilters(items.slice(2), "COUNT"),
      ];

    case "NEG-OPEN":
      if (items.length === 5) {
        throw new MessageError("obsolete 5-element NEG-OPEN; expected [NEG-OPEN, id, filter, hex]");
      }
      if (
        items.length !== 4 ||
        typeof items[1] !== "string" ||
        !isRecord(items[2]) ||
        !isNegHex(items[3])
      ) {
        throw new MessageError("invalid NEG-OPEN client message");
      }
      return [
        "NEG-OPEN",
        assertSubscriptionId(items[1]),
        parseWireFilter(items[2], "NEG-OPEN"),
        items[3].toLowerCase(),
      ];

    case "NEG-MSG":
      if (items.length !== 3 || typeof items[1] !== "string" || !isNegHex(items[2])) {
        throw new MessageError("invalid NEG-MSG client message");
      }
      return ["NEG-MSG", assertSubscriptionId(items[1]), items[2].toLowerCase()];

    case "NEG-CLOSE":
      if (items.length !== 2 || typeof items[1] !== "string") {
        throw new MessageError("invalid NEG-CLOSE client message");
      }
      return ["NEG-CLOSE", assertSubscriptionId(items[1])];

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
      return ["EVENT", assertSubscriptionId(items[1]), items[2]];

    case "OK":
      if (
        items.length !== 4 ||
        typeof items[1] !== "string" ||
        !HEX64_LOWER_RE.test(items[1]) ||
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
      return ["EOSE", assertSubscriptionId(items[1])];

    case "CLOSED":
      if (items.length !== 3 || typeof items[1] !== "string" || typeof items[2] !== "string") {
        throw new MessageError("invalid CLOSED relay message");
      }
      return ["CLOSED", assertSubscriptionId(items[1]), items[2]];

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
      const count = isRecord(payload) ? payload["count"] : undefined;
      if (
        items.length !== 3 ||
        typeof items[1] !== "string" ||
        !isRecord(payload) ||
        typeof count !== "number" ||
        !Number.isSafeInteger(count) ||
        count < 0
      ) {
        throw new MessageError("invalid COUNT relay message");
      }
      const result: Mutable<CountResult> = { count };
      if (typeof payload["approximate"] === "boolean") {
        result.approximate = payload["approximate"];
      }
      const hll = parseCountHll(payload["hll"]);
      if (hll !== undefined) {
        result.hll = hll;
      }
      return ["COUNT", assertSubscriptionId(items[1]), result];
    }
    case "NEG-MSG":
      if (items.length !== 3 || typeof items[1] !== "string" || !isNegHex(items[2])) {
        throw new MessageError("invalid NEG-MSG relay message");
      }
      return ["NEG-MSG", assertSubscriptionId(items[1]), items[2].toLowerCase()];

    case "NEG-ERR":
      if (
        (items.length !== 3 && items.length !== 4) ||
        typeof items[1] !== "string" ||
        typeof items[2] !== "string"
      ) {
        throw new MessageError("invalid NEG-ERR relay message");
      }
      return ["NEG-ERR", assertSubscriptionId(items[1]), items[2]];

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

const HEX64_RE = /^[0-9a-fA-F]{64}$/;
const HEX64_LOWER_RE = /^[0-9a-f]{64}$/;

/**
 * Validates a wire filter per NIP-01: `ids`/`authors` are 64-hex arrays (normalized lowercase),
 * `kinds` are integers in 0..=65535, `since`/`until`/`limit` non-negative integers, `search` a
 * string, and `#<single letter>` arrays of strings (`#e`/`#p` lowercased). Multi-letter `#` keys
 * and unknown non-`#` keys are dropped; wrong types throw {@link MessageError}.
 */
function parseWireFilter(value: unknown, kind: string): Filter {
  if (!isRecord(value)) {
    throw new MessageError(`invalid ${kind} filter`);
  }
  const fail = (): MessageError => new MessageError(`invalid ${kind} filter`);
  const out: Mutable<Filter> = {};
  for (const [key, v] of Object.entries(value)) {
    if (key.startsWith("#")) {
      if (!/^#[a-zA-Z]$/.test(key)) {
        continue;
      }
      if (!Array.isArray(v) || !v.every((x): x is string => typeof x === "string")) {
        throw fail();
      }
      out[`#${key.slice(1)}`] = key === "#e" || key === "#p" ? v.map((x) => x.toLowerCase()) : v;
    } else if (key === "ids" || key === "authors") {
      if (
        !Array.isArray(v) ||
        !v.every((x): x is string => typeof x === "string" && HEX64_RE.test(x))
      ) {
        throw fail();
      }
      out[key] = v.map((x) => x.toLowerCase());
    } else if (key === "kinds") {
      if (
        !Array.isArray(v) ||
        !v.every(
          (x): x is number => typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= 65535,
        )
      ) {
        throw fail();
      }
      out.kinds = v;
    } else if (key === "since" || key === "until" || key === "limit") {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        throw fail();
      }
      out[key] = v;
    } else if (key === "search") {
      if (typeof v !== "string") {
        throw fail();
      }
      out.search = v;
    }
  }
  return out;
}

function parseWireFilters(items: unknown[], kind: string): Filter[] {
  return items.map((item) => parseWireFilter(item, kind));
}

function isNegHex(value: unknown): value is string {
  return (
    typeof value === "string" && value.length > 0 && value.length % 2 === 0 && HEX_RE.test(value)
  );
}
