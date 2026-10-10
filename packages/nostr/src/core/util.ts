import {
  bytesToHex as nobleBytesToHex,
  hexToBytes as nobleHexToBytes,
} from "@noble/hashes/utils.js";

import { HexError, UrlError } from "./error.ts";
import { SECRET_KEY_BYTES } from "./limits.ts";

export const utf8Encoder: TextEncoder = new TextEncoder();
export const utf8Decoder: TextDecoder = new TextDecoder();

const HEX32_RE = /^[0-9a-f]{64}$/;
const HEX64_RE = /^[0-9a-f]{128}$/;

/** Lowercase hex encode. */
export function bytesToHex(bytes: Uint8Array): string {
  return nobleBytesToHex(bytes);
}

/** Decode lowercase or mixed-case hex to bytes. */
export function hexToBytes(hex: string): Uint8Array {
  try {
    return nobleHexToBytes(hex);
  } catch (error) {
    throw new HexError(`invalid hex string of length ${hex.length}`, {
      cause: error,
    });
  }
}

/** True when value is canonical NIP-01 lowercase hex of 32 bytes (64 chars). */
export function isHex32(value: string): boolean {
  return HEX32_RE.test(value);
}

/** True when value is canonical NIP-01 lowercase hex of 64 bytes (128 chars). */
export function isHex64(value: string): boolean {
  return HEX64_RE.test(value);
}

/** Caller input of any case: lowercases first, then requires canonical hex shape. */
export function assertHex32(value: string, label: string): string {
  const normalized = value.toLowerCase();
  if (!isHex32(normalized)) {
    throw new HexError(`invalid ${label}: expected 64-char hex`);
  }
  return normalized;
}

export function assertByteLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new HexError(`invalid ${label} length: expected ${expected}, got ${bytes.length}`);
  }
}

export function assertSecretKeyBytes(bytes: Uint8Array): void {
  assertByteLength(bytes, SECRET_KEY_BYTES, "secret key");
}

/** Current unix time in whole seconds (NIP-01 `created_at`). */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Structural guard: a plain record (not `null`, not an array). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * True when `value` contains a UTF-16 surrogate code unit without its other half (NIP-01 events
 * reject these; `JSON.parse` accepts `\ud800`-style escapes, so validate after parsing).
 * Char-by-char because Hermes may lack `String.prototype.isWellFormed`.
 */
export function hasLoneSurrogate(value: string): boolean {
  // Iterating by code point skips proper pairs; only unpaired surrogates match.
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code !== undefined && code >= 0xd800 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * Deep form of {@link hasLoneSurrogate}: true when any string in `value` — including record keys —
 * carries an unpaired surrogate. `JSON.parse` accepts `\ud800`-style escapes that serde_json
 * rejects, so JSON codecs validate the parsed value with this before the shape checks to keep both
 * languages agreeing on the invalid-JSON error (N10).
 */
export function containsLoneSurrogate(value: unknown): boolean {
  if (typeof value === "string") {
    return hasLoneSurrogate(value);
  }
  if (Array.isArray(value)) {
    return value.some(containsLoneSurrogate);
  }
  if (isRecord(value)) {
    return Object.entries(value).some(
      ([key, entry]) => hasLoneSurrogate(key) || containsLoneSurrogate(entry),
    );
  }
  return false;
}

/** Mutable view of a readonly exported type, for local construction. */
export type Mutable<T> = { -readonly [K in keyof T]: T[K] };

/**
 * Normalize a relay URL to a stable form: `http:`/`https:` are rewritten to `ws:`/`wss:` (a bare
 * host gets `wss://`), any other scheme throws UrlError. The result has a lowercased host, the
 * default port removed, duplicate path slashes collapsed, a sorted query, and no fragment. `URL`
 * serialization keeps a trailing `/` on the root path (`wss://a.example/`).
 */
export function normalizeURL(url: string): string {
  try {
    let input = url;
    if (!input.includes("://")) {
      input = `wss://${input}`;
    }
    const p = new URL(input);
    if (p.protocol === "http:") {
      p.protocol = "ws:";
    } else if (p.protocol === "https:") {
      p.protocol = "wss:";
    }
    if (p.protocol !== "ws:" && p.protocol !== "wss:") {
      throw new UrlError(`unsupported relay URL scheme: ${p.protocol}`);
    }
    p.pathname = p.pathname.replaceAll(/\/+/g, "/");
    if (p.pathname.endsWith("/") && p.pathname.length > 1) {
      p.pathname = p.pathname.slice(0, -1);
    }
    if ((p.port === "80" && p.protocol === "ws:") || (p.port === "443" && p.protocol === "wss:")) {
      p.port = "";
    }
    p.searchParams.sort();
    p.hash = "";
    return p.toString();
  } catch (error) {
    if (error instanceof UrlError) {
      throw error;
    }
    throw new UrlError(`invalid URL: ${url}`, {
      cause: error,
    });
  }
}

/**
 * Normalize each entry like {@link normalizeURL}; empty or invalid entries are skipped and the
 * results are deduplicated in first-seen order.
 */
export function normalizeRelayUrls(urls: Iterable<string>): string[] {
  const seen = new Set<string>();
  for (const url of urls) {
    if (url === "") {
      continue;
    }
    try {
      seen.add(normalizeURL(url));
    } catch {
      // invalid relay urls are skipped
    }
  }
  return [...seen];
}
