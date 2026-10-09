/// <reference types="node" />
// Differential-input generator for the TS ↔ nk-core parity harness (NK1-08).
//
//   bun packages/nostr/scripts/parity/diff.ts --seed <n> --count <n> --out target/parity
//
// One seeded PRNG (mulberry32 — deterministic, no Math.random) produces
// `--count` cases per capability and writes one JSONL file per capability into
// `--out`: the first line is {"capability", "seed", "count"} and every
// following line is {"i", "input", "out" | "err"}. Inputs are raw JSON text so
// number spellings (1e3, 1.0, -0), duplicate keys, and dropped keys survive;
// crates/nk-vectors/tests/diff.rs replays them through nk-core (NK_DIFF_DIR).
//
// Capabilities: core.event.serialize, core.event.id, core.filter.match,
// core.filter.canonicalize, core.message.client, core.message.relay,
// nip19.codec.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";

import { getEventHash, serializeEvent } from "../../src/core/event.ts";
import type { Event, UnsignedEvent } from "../../src/core/event.ts";
import { canonicalizeFilter, matchFilter } from "../../src/core/filter.ts";
import type { Filter } from "../../src/core/filter.ts";
import {
  encodeClientMessage,
  encodeRelayMessage,
  parseClientMessage,
  parseRelayMessage,
} from "../../src/core/message.ts";
import { hexToBytes } from "../../src/core/util.ts";
import { decode as nip19Decode } from "../../src/nips/nip19.ts";
import type { EntityJson } from "./gen/entities.ts";
import { encodeEntity, toJson } from "./gen/entities.ts";

/* oxlint-disable no-bitwise -- a PRNG is bit arithmetic by design */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
/* oxlint-enable no-bitwise */

// `r` is rebound per capability so each file draws its own seeded stream.
let r = mulberry32(0);

function int(bound: number): number {
  return Math.floor(r() * bound);
}
function pick<T>(items: ReadonlyArray<T>): T {
  const item = items[int(items.length)];
  if (item === undefined) {
    throw new Error("pick called with an empty array");
  }
  return item;
}
function chance(p: number): boolean {
  return r() < p;
}
function useStream(seed: number): void {
  r = mulberry32(seed);
}

const ASCII =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-:./#@!%&*()+={}[]|;'?~";
// Valid Unicode only — a lone surrogate in the input JSON is rejected by
// serde_json before any capability runs, so it cannot be generated here.
const EDGE_CHARS = [
  '"',
  "\\",
  "\n",
  "\r",
  "\t",
  "\b",
  "\f",
  "\u0000",
  "\u0001",
  "\u001A",
  "\u001B",
  "\u001F",
  "\u007F",
  "\u0085",
  "\u2028",
  "\u2029",
  "<",
  ">",
  "&",
  "'",
  "\uD83D\uDE00", // astral: surrogate pair, not a lone surrogate
  "\uD83C\uDF89",
  "\uD834\uDD1E",
  "\u4E2D",
  "\u00E9",
  "e\u0301",
  "\uD83E\uDD80",
  "\u20AC",
];

function randString(maxLen = 32): string {
  const len = int(maxLen + 1);
  const chars: string[] = [];
  for (let i = 0; i < len; i++) {
    chars.push(chance(0.35) ? pick(EDGE_CHARS) : ASCII.charAt(int(ASCII.length)));
  }
  return chars.join("");
}

const HEX_DIGITS = "0123456789abcdef";

function randHex(chars: number, { anyCase = false } = {}): string {
  let out = "";
  for (let i = 0; i < chars; i++) {
    out += HEX_DIGITS[int(16)];
  }
  return anyCase ? out.toUpperCase() : out;
}

// Integer spellings the wire grammar must normalize to `n` (rulings 8/9):
// `1e3`, `1.0`, `-0` all parse to plain integers on both sides.
function intSpelling(n: number): string {
  if (n === 0) {
    return chance(0.2) ? "-0" : "0";
  }
  if (n % 1000 === 0 && n <= 9000 && chance(0.4)) {
    return `${n / 1000}e3`;
  }
  if (n % 100 === 0 && n <= 900 && chance(0.4)) {
    return `${n / 100}e2`;
  }
  if (chance(0.15)) {
    return `${n}.0`;
  }
  return String(n);
}

// Integers at or inside the safe-integer boundary (rejection above it is part
// of the parity contract).
function randSafeInt(): number {
  return pick([
    0, 1, 2, 7, 42, 100, 999, 1000, 65535, 65536, 999_999, 1_700_000_000, 4_294_967_295,
    4_294_967_296, 9_007_199_254_740_990, 9_007_199_254_740_991,
  ]);
}

function randKind(): number {
  return pick([
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    40,
    41,
    42,
    1111,
    1984,
    9734,
    9735,
    10000,
    10002,
    1063,
    22242,
    30000,
    30023,
    31990,
    39701,
    65535,
    int(65536),
  ]);
}

function randTagName(): string {
  return pick(["e", "p", "a", "d", "t", "r", "k", "q", "x", "client", "emoji"]);
}

function randTag(): string[] {
  const tag = [randTagName()];
  const values = int(4);
  for (let i = 0; i < values; i++) {
    if (tag[0] === "e" || tag[0] === "p") {
      tag.push(chance(0.7) ? randHex(64, { anyCase: chance(0.3) }) : randString(16));
    } else {
      tag.push(randString(24));
    }
  }
  return tag;
}

function randTags(): string[][] {
  return Array.from({ length: int(6) }, randTag);
}

// Assembles the unsigned-event JSON text by hand so number spellings and
// duplicate keys stay under generator control.
function rawUnsignedEvent({ corrupt = 0.15 } = {}): string {
  const pubkey = chance(corrupt)
    ? pick([
        JSON.stringify(randHex(64, { anyCase: true })),
        JSON.stringify(randHex(63)),
        JSON.stringify(`${randHex(64)}z`),
        "42",
      ])
    : JSON.stringify(randHex(64));
  const kindSpell = chance(corrupt)
    ? pick(["65536", "-1", "1.5", '"one"', "9007199254740992"])
    : intSpelling(randKind());
  const createdSpell = chance(corrupt)
    ? pick(["-1", "9007199254740992", "1e16", "3.5", '"now"'])
    : intSpelling(randSafeInt());
  const tags = chance(corrupt)
    ? pick([JSON.stringify("nope"), JSON.stringify([[]]), JSON.stringify([[1, 2]]), "7"])
    : JSON.stringify(randTags());
  const content = chance(corrupt)
    ? pick(["7", "null", "true", "[1]"])
    : JSON.stringify(randString(200));
  const fields = [
    `"pubkey":${pubkey}`,
    `"created_at":${createdSpell}`,
    `"kind":${kindSpell}`,
    `"tags":${tags}`,
    `"content":${content}`,
  ];
  if (chance(0.08)) {
    fields.push(`"extra_${int(100)}":${JSON.stringify(randString(8))}`);
  }
  if (chance(0.08)) {
    // Duplicate key: JSON.parse and serde_json both last-win.
    fields.splice(int(fields.length), 0, `"kind":${pick(["65536", "0", "1.5"])}`);
  }
  if (chance(0.06)) {
    fields.splice(int(fields.length), 1); // drop a required field
  }
  // Shuffle field order; parse order is irrelevant to validity.
  fields.sort(() => r() - 0.5);
  return `{${fields.join(",")}}`;
}

// Signed event with the canonical wire-key order (id, pubkey, created_at,
// kind, tags, content, sig) so the relay/client re-encode paths — TS
// JSON.stringify passthrough vs nk-core write_signed — emit identical bytes.
function eventJson({ corrupt = 0.1 } = {}): string {
  const bad = (hex: string): string => pick([hex.toUpperCase(), hex.slice(0, -2), `${hex}zz`]);
  const id = JSON.stringify(chance(corrupt) ? bad(randHex(64)) : randHex(64));
  const pubkey = JSON.stringify(chance(corrupt) ? bad(randHex(64)) : randHex(64));
  const sig = JSON.stringify(chance(corrupt) ? bad(randHex(128)) : randHex(128));
  const kind = chance(corrupt) ? "65536" : intSpelling(randKind());
  const created = chance(corrupt)
    ? pick(["-1", "9007199254740992", "1.5"])
    : intSpelling(randSafeInt());
  const tags = chance(corrupt / 2)
    ? pick([JSON.stringify([[]]), JSON.stringify("x")])
    : JSON.stringify(randTags());
  const content = chance(corrupt / 2) ? "null" : JSON.stringify(randString(120));
  return `{"id":${id},"pubkey":${pubkey},"created_at":${created},"kind":${kind},"tags":${tags},"content":${content},"sig":${sig}}`;
}

// A filter in the shared input domain: every key is either a known field
// nk-core parses or one both sides drop (unknown / multi-letter `#`).
function filterJson(): string {
  const fields: string[] = [];
  const hexList = (count: number): string =>
    `[${Array.from({ length: count }, () =>
      JSON.stringify(randHex(64, { anyCase: chance(0.3) })),
    ).join(",")}]`;
  if (chance(0.5)) {
    fields.push(`"ids":${chance(0.15) ? "[]" : hexList(int(4) + 1)}`);
  }
  if (chance(0.4)) {
    fields.push(`"authors":${chance(0.15) ? "[]" : hexList(int(3) + 1)}`);
  }
  if (chance(0.5)) {
    const kinds = Array.from({ length: int(5) + 1 }, () => intSpelling(randKind()));
    fields.push(`"kinds":${chance(0.1) ? "[]" : `[${kinds.join(",")}]`}`);
  }
  if (chance(0.3)) {
    fields.push(`"since":${intSpelling(randSafeInt())}`);
  }
  if (chance(0.3)) {
    fields.push(`"until":${intSpelling(randSafeInt())}`);
  }
  if (chance(0.3)) {
    fields.push(`"limit":${intSpelling(int(500))}`);
  }
  if (chance(0.25)) {
    fields.push(`"search":${JSON.stringify(randString(24))}`);
  }
  for (const letter of ["e", "p", "t", "d", "a", "q"]) {
    if (chance(0.3)) {
      const values = Array.from({ length: int(4) + 1 }, () =>
        JSON.stringify(
          letter === "e" || letter === "p"
            ? chance(0.6)
              ? randHex(64, { anyCase: chance(0.4) })
              : randString(12)
            : randString(16),
        ),
      );
      fields.push(`"#${letter}":${chance(0.1) ? "[]" : `[${values.join(",")}]`}`);
    }
  }
  if (chance(0.2)) {
    // Dropped by both implementations (multi-letter `#` or unknown key).
    fields.push(pick([`"#client":["x"]`, `"zzz":${int(9)}`, `"custom":["a","b"]`]));
  }
  fields.sort(() => r() - 0.5);
  return `{${fields.join(",")}}`;
}

function subId(): string {
  const kind = int(10);
  if (kind === 0) {
    return ""; // invalid: empty
  }
  if (kind === 1) {
    return randString(66); // invalid: over 64 scalar values
  }
  if (kind === 2) {
    return "😀".repeat(64); // valid: exactly 64 scalar values (astral)
  }
  if (kind === 3) {
    return "😀".repeat(65); // invalid: 65 scalar values
  }
  if (kind === 4) {
    return `${randString(30)}😀${randString(33)}`;
  }
  return randString(int(64) + 1);
}

function negHex({ bad = false } = {}): string {
  if (bad) {
    return pick(["", "abc", "zz", "0x12", "😀😀"]);
  }
  return randHex(2 * (int(32) + 1), { anyCase: chance(0.4) });
}

// Each client/relay message is assembled as raw text so arity, key order,
// number spellings, and corrupted items stay under generator control. Roughly
// one in six messages is malformed on purpose — rejection is parity-checked.
function clientMessageText(): string {
  const label = pick([
    "EVENT",
    "REQ",
    "REQ",
    "COUNT",
    "CLOSE",
    "AUTH",
    "NEG-OPEN",
    "NEG-MSG",
    "NEG-CLOSE",
    "BOGUS",
  ]);
  const id = JSON.stringify(subId());
  switch (label) {
    case "EVENT":
      return `["EVENT",${eventJson({ corrupt: 0.12 })}]`;
    case "AUTH":
      return `["AUTH",${eventJson({ corrupt: 0.12 })}]`;
    case "REQ":
    case "COUNT": {
      const filters = Array.from({ length: int(4) }, () =>
        chance(0.12) ? pick(["7", '"x"', "null"]) : filterJson(),
      );
      const head = chance(0.08) ? "7" : id;
      return `["${label}",${head}${filters.length > 0 ? "," : ""}${filters.join(",")}]`;
    }
    case "CLOSE":
      return `["CLOSE",${id}]`;
    case "NEG-OPEN": {
      if (chance(0.1)) {
        // Obsolete 5-item form: both parsers reject it.
        return `["NEG-OPEN",${id},${filterJson()},${JSON.stringify(negHex())},"legacy"]`;
      }
      const hexPart = chance(0.15)
        ? JSON.stringify(negHex({ bad: true }))
        : JSON.stringify(negHex());
      return `["NEG-OPEN",${id},${chance(0.1) ? "7" : filterJson()},${hexPart}]`;
    }
    case "NEG-MSG":
      return `["NEG-MSG",${id},${JSON.stringify(negHex({ bad: chance(0.15) }))}]`;
    case "NEG-CLOSE":
      return `["NEG-CLOSE",${id}]`;
    default:
      return pick([
        `["${label}"]`,
        `[${JSON.stringify(randString(8))}]`,
        `["REQ",${id}]`,
        `{"type":"${label}"}`,
        `["EVENT",${eventJson()},7]`,
      ]);
  }
}

function relayMessageText(): string {
  const label = pick([
    "EVENT",
    "OK",
    "EOSE",
    "CLOSED",
    "NOTICE",
    "AUTH",
    "COUNT",
    "COUNT",
    "NEG-MSG",
    "NEG-ERR",
    "BOGUS",
  ]);
  const id = JSON.stringify(subId());
  const message = JSON.stringify(randString(40));
  switch (label) {
    case "EVENT":
      return `["EVENT",${id},${eventJson({ corrupt: 0.12 })}]`;
    case "OK": {
      const okId = chance(0.15)
        ? pick([randHex(64, { anyCase: true }), randHex(63), `${randHex(64)}z`])
        : randHex(64);
      const accepted = chance(0.15) ? '"yes"' : chance(0.5) ? "true" : "false";
      return `["OK",${JSON.stringify(okId)},${accepted},${message}]`;
    }
    case "EOSE":
      return `["EOSE",${id}]`;
    case "CLOSED":
      return `["CLOSED",${id},${message}]`;
    case "AUTH":
      return `["AUTH",${message}]`;
    case "NOTICE":
      return `["NOTICE",${message}]`;
    case "COUNT": {
      const count = chance(0.2)
        ? pick(["-1", "9007199254740992", "3.5", '"5"', "null", "9007199254740993"])
        : intSpelling(randSafeInt());
      const parts = [`"count":${count}`];
      if (chance(0.5)) {
        parts.push(chance(0.25) ? `"approximate":"yes"` : `"approximate":${String(chance(0.5))}`);
      }
      if (chance(0.5)) {
        const hll = chance(0.3)
          ? pick([randHex(512, { anyCase: true }), randHex(511), `${randHex(512)}z`, "42"])
          : randHex(512);
        parts.push(`"hll":${JSON.stringify(hll)}`);
      }
      if (chance(0.15)) {
        parts.push(`"extra":${int(9)}`);
      }
      return `["COUNT",${id},{${parts.join(",")}}]`;
    }
    case "NEG-MSG":
      return `["NEG-MSG",${id},${JSON.stringify(negHex({ bad: chance(0.15) }))}]`;
    case "NEG-ERR": {
      const tail = chance(0.2) ? `,${JSON.stringify(randString(8))}` : "";
      return `["NEG-ERR",${id},${message}${tail}]`;
    }
    default:
      return pick([
        `["${label}",${id}]`,
        `[${JSON.stringify(randString(8))}]`,
        `["NOTICE"]`,
        "[]",
        '"NOTICE"',
        `["OK",${JSON.stringify(randHex(64))},true]`,
      ]);
  }
}

// An event whose filter fields can be copied into a matching filter so hit
// and miss cases both occur naturally.
function matchInputText(): string {
  const id = randHex(64);
  const pubkey = randHex(64);
  const kind = randKind();
  const created = randSafeInt();
  const tags = randTags();
  const content = randString(120);
  const event = `{"id":"${id}","pubkey":"${pubkey}","created_at":${intSpelling(created)},"kind":${kind},"tags":${JSON.stringify(tags)},"content":${JSON.stringify(content)},"sig":"${randHex(128)}"}`;
  const fields: string[] = [];
  if (chance(0.5)) {
    fields.push(`"ids":["${chance(0.6) ? id : randHex(64)}","${randHex(64)}"]`);
  }
  if (chance(0.5)) {
    fields.push(`"authors":["${chance(0.6) ? pubkey : randHex(64)}","${randHex(64)}"]`);
  }
  if (chance(0.5)) {
    fields.push(`"kinds":[${chance(0.6) ? String(kind) : String(randKind())},${randKind()}]`);
  }
  if (chance(0.4)) {
    fields.push(
      `"since":${intSpelling(chance(0.6) ? Math.max(0, created - int(100)) : randSafeInt())}`,
    );
  }
  if (chance(0.4)) {
    fields.push(
      `"until":${intSpelling(chance(0.6) ? Math.min(9_007_199_254_740_991, created + int(100)) : randSafeInt())}`,
    );
  }
  for (const tag of tags) {
    const name = tag.at(0);
    if (name === undefined || name.length !== 1 || !chance(0.5)) {
      continue;
    }
    const values = tag.slice(1);
    if (values.length === 0) {
      continue;
    }
    fields.push(`"#${name}":[${values.map((v) => JSON.stringify(v)).join(",")}]`);
  }
  if (chance(0.3)) {
    fields.push(`"#t":[${JSON.stringify(randString(8))}]`);
  }
  const filter = `{${fields.join(",")}}`;
  return `{"filter":${filter},"event":${event}}`;
}

// NIP-19 stream. `input` is `{"op":"encode","entity":<EntityJson>}` or
// `{"op":"decode","input":"<bech32>"}`; outputs are the encoded string or the
// normalized entity JSON on success, the error class on failure.

// A 64-char hex field for pointers: mostly canonical, occasionally corrupted.
// Any-case hex stays in the domain — TS `assertHex32` lowercases first and
// nk-core's `from_hex` accepts mixed case, so both accept the same inputs.
function randHex32(corrupt: boolean): string {
  if (corrupt) {
    return pick([randHex(62), randHex(66), `${randHex(60)}zzzz`, randString(64), ""]);
  }
  return randHex(64, { anyCase: chance(0.2) });
}

// A 32-byte secret for `nsec` encode entities. Well-formed secrets must be
// valid scalars: nk-core's `SecretKey` type cannot express an invalid scalar,
// so encode-side scalar rejection has no TS counterpart. Invalid scalars are
// exercised on the decode side instead (both decoders reject them).
function randSecretHex(): string {
  if (chance(0.12)) {
    return pick([randHex(62), randHex(66), `${randHex(60)}zz`]);
  }
  let hex = randHex(64);
  while (!secp256k1.utils.isValidSecretKey(hexToBytes(hex))) {
    hex = randHex(64);
  }
  return hex;
}

function randNip19Kind(corrupt: boolean): number {
  if (corrupt) {
    return pick([0, 1, 4, 42, 30023, 65534, 65535, 65536, 65537, 70000, int(131_072)]);
  }
  return pick([0, 1, 4, 42, 30023, 65534, 65535, int(65536)]);
}

function randRelays(corrupt: boolean): string[] {
  const relays: string[] = [];
  const count = int(4);
  for (let i = 0; i < count; i++) {
    if (corrupt && chance(0.06)) {
      relays.push("r".repeat(200 + int(80))); // over 255 bytes: encode error
      continue;
    }
    relays.push(
      pick([
        "wss://relay.example.com",
        "wss://nostr.例え.jp",
        `wss://${randString(16)}`,
        randString(20),
        "",
      ]),
    );
  }
  return relays;
}

// `encode` inputs may carry corrupt hex fields, out-of-range kinds, and
// over-length relays. `forDecode` entities are always encodable in TS (their
// strings feed decode inputs); an nsec secret may still hold an invalid
// scalar — encodable, and both decoders reject it.
function randEntityJson(corrupt: boolean): EntityJson {
  switch (int(6)) {
    case 0:
      return {
        type: "nprofile",
        pubkey: randHex32(corrupt && chance(0.15)),
        relays: randRelays(corrupt),
      };
    case 1:
      return {
        type: "nevent",
        id: randHex32(corrupt && chance(0.15)),
        relays: randRelays(corrupt),
        ...(chance(0.7) ? { author: chance(0.08) ? "" : randHex32(corrupt && chance(0.15)) } : {}),
        ...(chance(0.7) ? { kind: randNip19Kind(corrupt) } : {}),
      };
    case 2:
      return {
        type: "naddr",
        identifier: randString(24),
        pubkey: randHex32(corrupt && chance(0.15)),
        kind: randNip19Kind(corrupt),
        relays: randRelays(corrupt),
      };
    case 3:
      return {
        type: "nsec",
        secret: corrupt ? randSecretHex() : randHex(64, { anyCase: chance(0.3) }),
      };
    case 4:
      return { type: "npub", pubkey: randHex32(corrupt && chance(0.15)) };
    default:
      return { type: "note", id: randHex32(corrupt && chance(0.15)) };
  }
}

const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Mutations that may keep the string valid (all-uppercase is legal bech32) —
// both decoders must agree on whatever comes out.
function mutateBech32(s: string): string {
  switch (int(10)) {
    case 0:
      return s.toUpperCase();
    case 1: {
      const i = int(s.length);
      const c = s.charAt(i);
      const flipped = c.toLowerCase() === c ? c.toUpperCase() : c.toLowerCase();
      return s.slice(0, i) + flipped + s.slice(i + 1);
    }
    case 2: {
      const i = int(s.length);
      return s.slice(0, i) + BECH32_CHARS.charAt(int(32)) + s.slice(i + 1);
    }
    case 3:
      return s.slice(0, Math.max(1, s.length - 1 - int(8)));
    case 4:
      return s + BECH32_CHARS.charAt(int(32));
    case 5:
      return s + pick(["!", " ", "b", "i", "o", "1", "😀"]);
    case 6:
      return `nostr:${s}`;
    case 7:
      return `nfoo${s.slice(s.indexOf("1"))}`;
    case 8:
      return s.slice(1);
    default:
      return `${s} `;
  }
}

function nip19CaseText(): string {
  const roll = int(20);
  if (roll < 8) {
    return JSON.stringify({ op: "encode", entity: randEntityJson(true) });
  }
  if (roll < 19) {
    const encoded = encodeEntity(randEntityJson(false));
    return JSON.stringify({
      op: "decode",
      input: chance(0.45) ? mutateBech32(encoded) : encoded,
    });
  }
  return JSON.stringify({
    op: "decode",
    input: pick([randString(24), "", `nostr:${randHex(20)}`, randHex(64)]),
  });
}

type CaseRecord = { i: number; input: string; out?: unknown; err?: string };

function capture(run: () => unknown): { out?: unknown; err?: string } {
  try {
    return { out: run() };
  } catch (error) {
    return { err: error instanceof Error ? error.constructor.name : "Error" };
  }
}

// oxlint-disable-next-line no-unnecessary-type-parameters
function parseJson<T>(raw: string): T {
  // The input is generator-produced JSON text; the cast narrows `unknown` to
  // the shape the capability's public API expects.
  // oxlint-disable-next-line no-unsafe-type-assertion
  return JSON.parse(raw) as T;
}

type Capability = { name: string; make: () => CaseRecord };

const CAPABILITIES: ReadonlyArray<Capability> = [
  {
    name: "core.event.serialize",
    make: () => {
      const input = rawUnsignedEvent();
      return { i: 0, input, ...capture(() => serializeEvent(parseJson<UnsignedEvent>(input))) };
    },
  },
  {
    name: "core.event.id",
    make: () => {
      const input = rawUnsignedEvent();
      return { i: 0, input, ...capture(() => getEventHash(parseJson<UnsignedEvent>(input))) };
    },
  },
  {
    name: "core.filter.match",
    make: () => {
      const input = matchInputText();
      return {
        i: 0,
        input,
        ...capture(() => {
          const { filter, event } = parseJson<{ filter: Filter; event: Event }>(input);
          return matchFilter(filter, event);
        }),
      };
    },
  },
  {
    name: "core.filter.canonicalize",
    make: () => {
      const input = filterJson();
      return {
        i: 0,
        input,
        ...capture(() => JSON.stringify(canonicalizeFilter(parseJson<Filter>(input)))),
      };
    },
  },
  {
    name: "core.message.client",
    make: () => {
      const input = clientMessageText();
      return {
        i: 0,
        input,
        ...capture(() => encodeClientMessage(parseClientMessage(input))),
      };
    },
  },
  {
    name: "core.message.relay",
    make: () => {
      const input = relayMessageText();
      return {
        i: 0,
        input,
        ...capture(() => encodeRelayMessage(parseRelayMessage(input))),
      };
    },
  },
  {
    name: "nip19.codec",
    make: () => {
      const input = nip19CaseText();
      return {
        i: 0,
        input,
        ...capture(() => {
          const req = parseJson<{ op: string; entity?: EntityJson; input?: string }>(input);
          if (req.op === "encode" && req.entity !== undefined) {
            return encodeEntity(req.entity);
          }
          if (req.input === undefined) {
            throw new Error("decode case without input");
          }
          return toJson(nip19Decode(req.input));
        }),
      };
    },
  },
];

function parseArgs(): { seed: number; count: number; out: string } {
  const args = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const at = args.indexOf(flag);
    return at === -1 ? undefined : args.at(at + 1);
  };
  const seed = Number(get("--seed") ?? "0");
  const count = Number(get("--count") ?? "0");
  const out = get("--out") ?? "target/parity";
  if (!Number.isInteger(seed) || !Number.isInteger(count) || count <= 0) {
    throw new Error("usage: diff.ts --seed <n> --count <n> [--out <dir>]");
  }
  return { seed, count, out };
}

const { seed, count, out } = parseArgs();
mkdirSync(out, { recursive: true });

for (const capability of CAPABILITIES) {
  useStream(seed); // same seed → same stream for every capability
  const lines: string[] = [JSON.stringify({ capability: capability.name, seed, count })];
  for (let i = 0; i < count; i++) {
    lines.push(JSON.stringify({ ...capability.make(), i }));
  }
  writeFileSync(join(out, `${capability.name}.jsonl`), `${lines.join("\n")}\n`);
  console.log(`${capability.name}: ${count} cases`);
}
