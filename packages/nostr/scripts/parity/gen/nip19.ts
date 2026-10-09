/// <reference types="node" />
// Generates vectors/nip19/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-19 codec's wire output as frozen vectors shared by the
// TS test suite (tests/vectors/nip19.test.ts) and the nk-* Rust crates.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { bech32 } from "@scure/base";

import { hexToBytes, utf8Encoder } from "../../../src/core/util.ts";
import {
  Bech32MaxSize,
  naddrEncode,
  neventEncode,
  nip19Decode,
  noteEncode,
  nprofileEncode,
  npubEncode,
} from "../../../src/index.ts";
import { encodeEntity, toJson } from "./entities.ts";
import type { EntityJson } from "./entities.ts";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";
const SK = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
const ID = "05bf4c8f85e9c7c58d4f5b5c5cd1a1552d4a1d9b8a4d78d9c4f5a95ba3c4f0a4";

// secp256k1 group order and neighbors, for nsec scalar validation (N2).
const SCALAR_MAX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
const SCALAR_ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const SCALAR_ABOVE = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip19");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

// Recorded once by scripts/parity/cross-check.ts against the local
// 3rdparty/nostr-tools checkout (not wired into CI — see that script's header).
const CROSS_CHECK =
  "nostr-tools 2.24.1 @7fa1ef4: 47/63 agree; the 16 diffs are nostr-tools " +
  "laxness, not vector bugs — it has no kind bound (N1: 65536 encodes/" +
  "decodes), no nsec scalar check (N2), no 255-byte TLV limit, no 32-byte " +
  "payload check on npub/note/nsec, and no hex validation on encoders";

/**
 * Crafts a bech32 string from raw payload bytes — inputs the public encoders cannot produce.
 * `limit` is lifted for inputs meant to exceed it.
 */
function craft(prefix: string, data: Uint8Array, limit: number | false = Bech32MaxSize): string {
  return bech32.encode(prefix, bech32.toWords(data), limit);
}

/** TLV helper for hand-built payloads. */
function tlv(type: number, value: Uint8Array | number[]): Uint8Array {
  const bytes = Uint8Array.from(value);
  return new Uint8Array([type, bytes.length, ...bytes]);
}

/** Case shapes: {input, decoded, encoded}, {input, error}, {encode, encoded}, {encode, error}. */
type Case = {
  input?: string;
  encode?: EntityJson;
  decoded?: EntityJson;
  encoded?: string;
  error?: string;
};

const errorOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (error) {
    return error instanceof Error ? error.name : "Error";
  }
  throw new Error("generator bug: expected a thrown error");
};

const decodedOrThrow = (input: string): EntityJson => toJson(nip19Decode(input));

const cases: Case[] = [];

/**
 * Decode success case; `encoded` is the canonical re-encoding (equal to /// `input` for canonical
 * inputs, the fixed point for crafted ones).
 */
function decodeOk(input: string): void {
  const decoded = decodedOrThrow(input);
  cases.push({ input, decoded, encoded: encodeEntity(decoded) });
}

function decodeErr(input: string): void {
  cases.push({ input, error: errorOf(() => nip19Decode(input)) });
}

/** Encode case: records the canonical output or the thrown error class. */
function encodeCase(entity: EntityJson): void {
  try {
    const encoded = encodeEntity(entity);
    cases.push({ encode: entity, decoded: decodedOrThrow(encoded), encoded });
  } catch (error) {
    cases.push({
      encode: entity,
      error: error instanceof Error ? error.name : "Error",
    });
  }
}

const RELAYS = ["wss://relay.example.com", "wss://nostr.例え.jp"];
const NON_ASCII_RELAY = "wss://r.例え.jp/パス";

const profile: EntityJson = { type: "nprofile", pubkey: PK, relays: RELAYS };
const eventFull: EntityJson = {
  type: "nevent",
  id: ID,
  relays: RELAYS,
  author: PK2,
  kind: 1,
};
const eventBare: EntityJson = { type: "nevent", id: ID, relays: [] };
const address: EntityJson = {
  type: "naddr",
  identifier: "banana",
  pubkey: PK,
  kind: 30023,
  relays: RELAYS,
};
const addressEmpty: EntityJson = {
  type: "naddr",
  identifier: "",
  pubkey: PK,
  kind: 0,
  relays: [],
};

// Every prefix, encode + decode round trips.
encodeCase({ type: "npub", pubkey: PK });
encodeCase({ type: "note", id: ID });
encodeCase({ type: "nsec", secret: SK });
encodeCase(profile);
encodeCase(eventFull);
encodeCase(eventBare);
encodeCase(address);
encodeCase(addressEmpty);
encodeCase({ type: "nevent", id: ID, relays: [], author: PK2 });
encodeCase({ type: "nevent", id: ID, relays: [], kind: 0 });
encodeCase({ type: "nprofile", pubkey: PK, relays: [] });
encodeCase({ type: "nprofile", pubkey: PK, relays: [NON_ASCII_RELAY] });

// The official npub/nsec/nprofile examples decode on both paths.
for (const official of [
  "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
  "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
  "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
  "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p",
]) {
  decodeOk(official);
}

// Whole-string uppercase decodes to the same entity and re-encodes lowercase.
const npubCanonical = npubEncode(PK);
decodeOk(npubCanonical.toUpperCase());
// Mixed case is rejected.
{
  const mixed = `${npubCanonical.slice(0, 8)}${npubCanonical.charAt(8).toUpperCase()}${npubCanonical.slice(9)}`;
  decodeErr(mixed);
}

// A wrong checksum is rejected.
decodeErr(`${npubCanonical.slice(0, -1)}${npubCanonical.endsWith("q") ? "p" : "q"}`);

// TLV wire cases: crafted bytes the public encoders never emit.
{
  // Ascending TLV order still decodes (encoders write descending).
  const unsorted = new Uint8Array([
    ...tlv(0, hexToBytes(PK)),
    ...tlv(1, utf8Encoder.encode("wss://a")),
    ...tlv(1, utf8Encoder.encode("wss://b")),
  ]);
  decodeOk(craft("nprofile", unsorted));
}
{
  // Duplicate single-valued TLVs keep the first value; relays keep all.
  const dup = new Uint8Array([
    ...tlv(0, hexToBytes(PK)),
    ...tlv(0, hexToBytes(PK2)),
    ...tlv(1, utf8Encoder.encode("wss://a")),
    ...tlv(1, utf8Encoder.encode("wss://b")),
    ...tlv(2, hexToBytes(PK2)),
    ...tlv(2, hexToBytes(PK)),
    ...tlv(3, [0, 0, 0, 7]),
    ...tlv(3, [0, 0, 0, 9]),
  ]);
  decodeOk(craft("nevent", dup));
}
{
  // Unknown TLV types are ignored.
  const unknown = new Uint8Array([
    ...tlv(42, utf8Encoder.encode("mystery")),
    ...tlv(0, hexToBytes(PK)),
    ...tlv(99, [1, 2, 3]),
  ]);
  decodeOk(craft("nprofile", unknown));
}
{
  // Invalid UTF-8 in the identifier and a relay decodes lossy (U+FFFD).
  const lossy = new Uint8Array([
    ...tlv(0, [0x66, 0x80]),
    ...tlv(1, [0xff]),
    ...tlv(2, hexToBytes(PK)),
    ...tlv(3, [0, 0, 0, 1]),
  ]);
  decodeOk(craft("naddr", lossy));
}
{
  // An empty author TLV (0 bytes) is a present-but-invalid author → error on
  // nevent; on naddr TLV 0 an empty identifier is valid and exercised above.
  decodeErr(craft("nevent", tlv(2, [])));
  // A truncated TLV stream and a truncated TLV value are rejected.
  decodeErr(craft("nprofile", new Uint8Array([1])));
  decodeErr(craft("nprofile", new Uint8Array([1, 9, 1, 2])));
  // Missing required TLVs.
  decodeErr(craft("nprofile", new Uint8Array([])));
  decodeErr(craft("nevent", tlv(1, utf8Encoder.encode("wss://a"))));
  decodeErr(craft("naddr", tlv(0, utf8Encoder.encode("x"))));
  decodeErr(
    craft("naddr", new Uint8Array([...tlv(0, utf8Encoder.encode("x")), ...tlv(2, hexToBytes(PK))])),
  );
}
{
  // Wrong-length single-valued TLVs.
  decodeErr(craft("nprofile", tlv(0, new Uint8Array(16))));
  decodeErr(
    craft("nevent", new Uint8Array([...tlv(0, hexToBytes(ID)), ...tlv(2, new Uint8Array(16))])),
  );
  decodeErr(craft("nevent", new Uint8Array([...tlv(0, hexToBytes(ID)), ...tlv(3, [0, 1])])));
  decodeErr(
    craft(
      "naddr",
      new Uint8Array([...tlv(0, []), ...tlv(2, new Uint8Array(16)), ...tlv(3, [0, 0, 0, 1])]),
    ),
  );
}

// Kind boundaries (N1): 65535 encodes/decodes; 65536 fails on encode and decode.
encodeCase({ ...address, kind: 65535 });
encodeCase({ ...eventFull, kind: 65535 });
cases.push(
  {
    encode: { ...address, kind: 65536 },
    error: errorOf(() => naddrEncode({ identifier: "", pubkey: PK, kind: 65536, relays: [] })),
  },
  {
    encode: { ...eventFull, kind: 65536 },
    error: errorOf(() => neventEncode({ id: ID, relays: [], author: PK2, kind: 65536 })),
  },
);
{
  const badKind = new Uint8Array([
    ...tlv(0, []),
    ...tlv(2, hexToBytes(PK)),
    ...tlv(3, [0, 1, 0, 0]), // 65536 big-endian
  ]);
  decodeErr(craft("naddr", badKind));
  const badEventKind = new Uint8Array([
    ...tlv(0, hexToBytes(ID)),
    ...tlv(3, [0xff, 0xff, 0xff, 0xff]),
  ]);
  decodeErr(craft("nevent", badEventKind));
}

// Relay hint longer than 255 bytes: encode fails; a TLV 255-byte relay is fine.
{
  const longRelay = `wss://${"a".repeat(300)}`;
  cases.push(
    {
      encode: { type: "nprofile", pubkey: PK, relays: [longRelay] },
      error: errorOf(() => nprofileEncode({ pubkey: PK, relays: [longRelay] })),
    },
    {
      encode: { ...address, identifier: "x".repeat(300) },
      error: errorOf(() =>
        naddrEncode({ identifier: "x".repeat(300), pubkey: PK, kind: 30023, relays: [] }),
      ),
    },
  );
  // 255-byte relay encodes fine.
  const relay255 = `wss://${"a".repeat(248)}`;
  encodeCase({ type: "nprofile", pubkey: PK, relays: [relay255] });
}

// Invalid nsec scalars (N2): zero, the curve order, above it.
decodeErr(craft("nsec", new Uint8Array(32)));
decodeErr(craft("nsec", hexToBytes(SCALAR_ORDER)));
decodeErr(craft("nsec", hexToBytes(SCALAR_ABOVE)));
// n - 1 is a valid scalar.
encodeCase({ type: "nsec", secret: SCALAR_MAX });

// Wrong-length payloads for the bare prefixes.
for (const prefix of ["npub", "note", "nsec"]) {
  decodeErr(craft(prefix, new Uint8Array(16)));
  decodeErr(craft(prefix, new Uint8Array(33)));
}
// Unknown prefix with a valid checksum.
decodeErr(craft("nrelay", utf8Encoder.encode("wss://relay.example")));

// Length boundary: a 3117-byte naddr payload encodes to exactly 5000 chars;
// 3118 bytes encodes to 5001 and is rejected.
{
  const pad = (total: number): Uint8Array => {
    const parts: number[] = [
      ...tlv(0, utf8Encoder.encode("d")),
      ...tlv(2, hexToBytes(PK)),
      ...tlv(3, [0, 0, 0, 1]),
    ];
    while (parts.length < total) {
      const room = Math.min(total - parts.length - 2, 255);
      parts.push(99, room, ...Array.from({ length: room }, () => 0x55));
    }
    return new Uint8Array(parts);
  };
  const atLimit = craft("naddr", pad(3117));
  if (atLimit.length !== Bech32MaxSize) {
    throw new Error(`generator bug: expected 5000 chars, got ${atLimit.length}`);
  }
  decodeOk(atLimit);
  const overLimit = craft("naddr", pad(3118), false);
  if (overLimit.length !== Bech32MaxSize + 1) {
    throw new Error(`generator bug: expected 5001 chars, got ${overLimit.length}`);
  }
  decodeErr(overLimit);
}

// Non-canonical padding: a trailing field element with a nonzero pad bit
// round-trips no real bytes; `@scure/base` (and our Rust side) reject it.
{
  const bytes = new Uint8Array(32).fill(0x42);
  const words = bech32.toWords(bytes);
  // 32 bytes → 52 words = 260 bits; the last word carries 1 data bit + 4 pad
  // bits. Force a pad bit on while keeping the data bits.
  const last = words.at(-1);
  if (last === undefined) {
    throw new Error("generator bug: empty words");
  }
  // Set pad bit 0 without a bitwise op (lint bans `|`): bit 0 already on
  // leaves the word unchanged, off adds one.
  words[words.length - 1] = last - (last % 2) + 1;
  decodeErr(bech32.encode("npub", words, Bech32MaxSize));
}

// Bad hex input to the hex-taking encoders throws HexError, not Nip19Error.
cases.push(
  {
    encode: { type: "npub", pubkey: "nothex" },
    error: errorOf(() => npubEncode("nothex")),
  },
  {
    encode: { type: "note", id: "ab" },
    error: errorOf(() => noteEncode("ab")),
  },
  {
    encode: { type: "nprofile", pubkey: "zz", relays: [] },
    error: errorOf(() => nprofileEncode({ pubkey: "zz", relays: [] })),
  },
  {
    encode: { type: "nevent", id: "xyz", relays: [] },
    error: errorOf(() => neventEncode({ id: "xyz", relays: [] })),
  },
  {
    encode: { type: "naddr", identifier: "x", pubkey: "0", kind: 1, relays: [] },
    error: errorOf(() => naddrEncode({ identifier: "x", pubkey: "0", kind: 1, relays: [] })),
  },
);
// nsecEncode validates only the byte length (scalar validation is a decode rule);
// 0xab… is a valid scalar, so the code also decodes.
encodeCase({ type: "nsec", secret: "ab".repeat(32) });

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip19.codec",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    cross_check: CROSS_CHECK,
  },
  cases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip19 codec: ${cases.length} cases written`);
