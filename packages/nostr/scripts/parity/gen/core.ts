/// <reference types="node" />
// Generates vectors/core/*.json — run with
// `bun packages/nostr/scripts/parity/gen/core.ts`.
// Captures the TS core's wire output as frozen vectors shared by the TS test
// suite (tests/vectors/core.test.ts) and the nk-* Rust crates.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { EventBuilder } from "../../../src/core/builder.ts";
import type { ProfileMetadata } from "../../../src/core/builder.ts";
import {
  serializeEvent,
  getEventHash,
  itemCompare,
  isReplaceableWinner,
  signedMatchesUnsigned,
  sortedEvents,
  validateSignedEvent,
} from "../../../src/core/event.ts";
import type { Event, UnsignedEvent } from "../../../src/core/event.ts";
import {
  canonicalizeFilter,
  filterFingerprint,
  getFilterLimit,
  matchFilter,
} from "../../../src/core/filter.ts";
import type { Filter } from "../../../src/core/filter.ts";
import {
  isAddressableKind,
  isEphemeralKind,
  isRegularKind,
  isReplaceableKind,
  classifyKind,
} from "../../../src/core/kind.ts";
import {
  encodeClientMessage,
  encodeRelayMessage,
  mergeCountHll,
} from "../../../src/core/message.ts";
import { formatEventAddress, parseEventAddress, Tag } from "../../../src/core/tag.ts";
import {
  bytesToHex,
  hexToBytes,
  isHex32,
  normalizeURL,
  utf8Encoder,
} from "../../../src/core/util.ts";

const PK = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";
const SK = "0000000000000000000000000000000000000000000000000000000000000003";
const SK_PK = bytesToHex(schnorr.getPublicKey(hexToBytes(SK)));
const AUX = "0000000000000000000000000000000000000000000000000000000000000001";

const ALL_CONTROLS = Array.from({ length: 32 }, (_, i) => String.fromCodePoint(i)).join("");

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/core");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

function emit(capability: string, file: string, cases: unknown, crossCheck?: string): void {
  const doc = {
    schema: 1,
    capability,
    source: {
      kind: "generated",
      generator: "@qntx/nostr",
      version,
      cross_check: crossCheck ?? null,
    },
    cases,
  };
  writeFileSync(join(vectors, file), `${JSON.stringify(doc, null, 2)}\n`);
}

// Recorded once by scripts/parity/cross-check.ts against the local
// 3rdparty/nostr-tools checkout (not wired into CI — see that script's header).
const CROSS_CHECK_IDS = "nostr-tools 2.24.1 @7fa1ef4: getEventHash/serializeEvent ids match (5/5)";
const CROSS_CHECK_SIGS = "nostr-tools 2.24.1 @7fa1ef4: verifyEvent signatures match (3/3)";
const CROSS_CHECK_KINDS =
  "nostr-tools 2.24.1 @7fa1ef4: is*Kind booleans agree inside the NIP-01 ranges; kind 45/999 " +
  "isRegularKind and 40000+ classifyKind differ by definition (nostr-tools uses `<10000 except " +
  "0/3` and reports `unknown`/`parameterized`)";
const CROSS_CHECK_URLS =
  "nostr-tools 2.24.1 @7fa1ef4: 38/40 agree; ftp://* differs — nostr-tools keeps non-ws schemes, " +
  "normalizeURL here rejects them with UrlError";

// Events must be emitted in the canonical field order used on the wire.
function canonEvent(e: Event): Event {
  return {
    id: e.id,
    pubkey: e.pubkey,
    created_at: e.created_at,
    kind: e.kind,
    tags: e.tags,
    content: e.content,
    sig: e.sig,
  };
}

function sign(unsigned: UnsignedEvent, secretKey: string, aux: string): Event {
  const serialized = serializeEvent(unsigned);
  const id = bytesToHex(sha256(utf8Encoder.encode(serialized)));
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), hexToBytes(secretKey), hexToBytes(aux)));
  return canonEvent({ ...unsigned, id, sig });
}

const unsignedCases: UnsignedEvent[] = [
  { pubkey: PK, created_at: 1700000000, kind: 1, tags: [["t", "smoke"]], content: "hello" },
  {
    pubkey: PK,
    created_at: 0,
    kind: 30023,
    tags: [
      ["d", ""],
      ["e", "ab".repeat(32), "wss://relay.example", "reply", PK],
    ],
    content: `${ALL_CONTROLS}"\\  `,
  },
  {
    pubkey: PK,
    created_at: 9999999999,
    kind: 65535,
    tags: [],
    content: "emoji 😀🦀 astral 𐀀 non-ascii ñü日本語",
  },
  {
    pubkey: PK,
    created_at: 42,
    kind: 4,
    tags: [["x"], ["p", PK, "wss://r.example", "pet"]],
    content: "",
  },
  {
    pubkey: PK,
    created_at: 9007199254740991,
    kind: 0,
    tags: [["d", "sep\u2028\u2029"]],
    content: "del \u007F line \u2028 para \u2029 end",
  },
];

const serialize = unsignedCases.map((unsigned) => ({
  unsigned,
  serialized: serializeEvent(unsigned),
  id: getEventHash(unsigned),
}));

const signed = [
  {
    secretKey: SK,
    aux: AUX,
    unsigned: {
      pubkey: SK_PK,
      created_at: 1700000000,
      kind: 1,
      tags: [["t", "hi"]],
      content: "gm",
    },
  },
  {
    secretKey: SK,
    aux: "f".repeat(64),
    unsigned: {
      pubkey: SK_PK,
      created_at: 1,
      kind: 30023,
      tags: [
        ["d", "article"],
        ["t", "nostr"],
        ["t", "rust"],
      ],
      content: `long form ${ALL_CONTROLS}`,
    },
  },
  {
    secretKey: "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf",
    aux: AUX,
    unsigned: {
      pubkey: "",
      created_at: 2000000000,
      kind: 0,
      tags: [],
      content: '{"name":"q"}',
    },
  },
].map((c) => {
  const pk = bytesToHex(schnorr.getPublicKey(hexToBytes(c.secretKey)));
  const unsigned = { ...c.unsigned, pubkey: pk };
  return {
    secretKey: c.secretKey,
    aux: c.aux,
    unsigned,
    event: sign(unsigned, c.secretKey, c.aux),
  };
});

const [firstSigned] = signed;
if (firstSigned === undefined) {
  throw new Error("signed vector cases must not be empty");
}

// A valid base event to patch into invalid wire events (canonical key order).
const baseEvent = firstSigned.event;
const evRaw = (patch: Record<string, unknown>): string =>
  JSON.stringify({ ...baseEvent, ...patch });

const invalidEvents: Array<{ reason: string; raw: string }> = [
  { reason: "uppercase id", raw: evRaw({ id: baseEvent.id.toUpperCase() }) },
  { reason: "uppercase pubkey", raw: evRaw({ pubkey: baseEvent.pubkey.toUpperCase() }) },
  { reason: "uppercase sig", raw: evRaw({ sig: baseEvent.sig.toUpperCase() }) },
  { reason: "id too short", raw: evRaw({ id: baseEvent.id.slice(0, 62) }) },
  { reason: "id too long", raw: evRaw({ id: `${baseEvent.id}00` }) },
  { reason: "pubkey too short", raw: evRaw({ pubkey: baseEvent.pubkey.slice(0, 62) }) },
  { reason: "sig too short", raw: evRaw({ sig: baseEvent.sig.slice(0, 126) }) },
  { reason: "sig not hex", raw: evRaw({ sig: "z".repeat(128) }) },
  { reason: "kind 65536", raw: evRaw({ kind: 65536 }) },
  { reason: "kind -1", raw: evRaw({ kind: -1 }) },
  { reason: "kind float", raw: evRaw({ kind: 1.5 }) },
  { reason: "kind string", raw: evRaw({ kind: "1" }) },
  { reason: "created_at float", raw: evRaw({ created_at: 1700000000.5 }) },
  { reason: "created_at string", raw: evRaw({ created_at: "1700000000" }) },
  { reason: "created_at -1", raw: evRaw({ created_at: -1 }) },
  { reason: "content number", raw: evRaw({ content: 42 }) },
  { reason: "tags not array", raw: evRaw({ tags: "none" }) },
  { reason: "tag not array", raw: evRaw({ tags: ["t"] }) },
  { reason: "empty tag", raw: evRaw({ tags: [[]] }) },
  { reason: "non-string tag item", raw: evRaw({ tags: [["e", 5]] }) },
  { reason: "missing id", raw: JSON.stringify({ ...baseEvent, id: undefined }) },
  { reason: "missing sig", raw: JSON.stringify({ ...baseEvent, sig: undefined }) },
  { reason: "not an object", raw: "[1,2,3]" },
];

// Raw JSON text exercises rulings 7–10: duplicate keys (last wins), integer
// spellings (`1e3`, `1.0`, `-0`), the 2^53-1 bound, and lone surrogates. These
// cannot be produced by patching a parsed object, so they are built as text.
const baseFields: Array<[string, string]> = [
  ["id", JSON.stringify(baseEvent.id)],
  ["pubkey", JSON.stringify(baseEvent.pubkey)],
  ["created_at", String(baseEvent.created_at)],
  ["kind", String(baseEvent.kind)],
  ["tags", JSON.stringify(baseEvent.tags)],
  ["content", JSON.stringify(baseEvent.content)],
  ["sig", JSON.stringify(baseEvent.sig)],
];

const evText = (fields: Array<[string, string]>): string =>
  `{${fields.map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(",")}}`;

const evFieldPatched = (key: string, value: string): Array<[string, string]> =>
  baseFields.map(([k, v]): [string, string] => [k, k === key ? value : v]);

const evPatched = (key: string, value: string): string => evText(evFieldPatched(key, value));

/** Canonical parse result: field order id, pubkey, created_at, kind, tags, content, sig. */
const evParsed = (raw: string): string => {
  const o: unknown = JSON.parse(raw);
  if (!validateSignedEvent(o)) {
    throw new Error(`generator bug: valid case does not validate: ${raw}`);
  }
  return JSON.stringify({
    id: o.id,
    pubkey: o.pubkey,
    created_at: o.created_at,
    kind: o.kind,
    tags: o.tags,
    content: o.content,
    sig: o.sig,
  });
};

const validWireEvents: Array<[string, string]> = [
  // Duplicate keys: the last value wins (ECMAScript JSON.parse semantics).
  ["dup kind 7 then 1", evText([...baseFields, ["kind", "1"]])],
  ["dup kind bad then good", evText([...evFieldPatched("kind", "99999"), ["kind", "1"]])],
  // An invalid earlier duplicate is discarded when a later one is valid
  // (ruling 7 lenient capture: the first value must not abort the map).
  [
    "dup id invalid then valid",
    evText([...evFieldPatched("id", "123"), ["id", JSON.stringify(baseEvent.id)]]),
  ],
  [
    "dup created_at invalid then valid",
    evText([...evFieldPatched("created_at", '"x"'), ["created_at", String(baseEvent.created_at)]]),
  ],
  ["dup tags invalid then valid", evText([...evFieldPatched("tags", '"x"'), ["tags", "[]"]])],
  // An escaped id cannot borrow the input; it still decodes (owned path).
  ["id escaped hex", evPatched("id", String.raw`"${"a".repeat(63)}\u0061"`)],
  // Integer spellings normalize to plain integers.
  ["created_at 1e3", evPatched("created_at", "1e3")],
  ["created_at float .0", evPatched("created_at", "1700000000.0")],
  ["created_at -0", evPatched("created_at", "-0")],
  ["kind 1e3", evPatched("kind", "1e3")],
  ["kind -0", evPatched("kind", "-0")],
  ["created_at max safe", evPatched("created_at", "9007199254740991")],
  // Large integral spellings pin correctly-rounded f64 parsing (NK-ADR-012
  // ruling 8: serde_json float_roundtrip): above 2^52 a sloppy parse loses
  // one ulp and emits an integer one below the written value.
  ["created_at max safe .0", evPatched("created_at", "9007199254740991.0")],
  ["created_at 2^53-2 .0", evPatched("created_at", "9007199254740990.0")],
  ["created_at 2^52+1 .0", evPatched("created_at", "4503599627370497.0")],
  ["kind max .0", evPatched("kind", "65535.0")],
  // A proper surrogate pair is a valid astral character.
  ["content emoji escape", evPatched("content", String.raw`"\ud83d\ude00"`)],
];
const validEventCases = validWireEvents.map(([reason, raw]) => ({
  reason,
  raw,
  parsed: evParsed(raw),
}));

const invalidWireEvents: Array<{ reason: string; raw: string }> = [
  { reason: "created_at 2^53", raw: evPatched("created_at", "9007199254740992") },
  { reason: "created_at 2^53+1", raw: evPatched("created_at", "9007199254740993") },
  { reason: "kind 1e40", raw: evPatched("kind", "1e40") },
  // Integral f64 but past 2^53-1: still rejected (ruling 9).
  {
    reason: "created_at max finite float",
    raw: evPatched("created_at", "1.7976931348623157e308"),
  },
  { reason: "content lone surrogate", raw: evPatched("content", String.raw`"a\ud800"`) },
  {
    reason: "tag value lone surrogate",
    raw: evPatched("tags", String.raw`[["t","x\udfff"]]`),
  },
  // Wrong JSON types are captured per field and fail validation.
  { reason: "id non-string", raw: evPatched("id", "123") },
  { reason: "id object", raw: evPatched("id", "{}") },
  { reason: "pubkey array", raw: evPatched("pubkey", "[]") },
  { reason: "created_at array", raw: evPatched("created_at", "[]") },
  { reason: "created_at null", raw: evPatched("created_at", "null") },
  { reason: "kind bool", raw: evPatched("kind", "true") },
  { reason: "tags object", raw: evPatched("tags", "{}") },
  { reason: "tags non-array", raw: evPatched("tags", '"x"') },
  { reason: "tags non-array element", raw: evPatched("tags", "[5]") },
  { reason: "tags non-string element", raw: evPatched("tags", '[["e",5]]') },
  { reason: "tags later elements drained", raw: evPatched("tags", '[[5],["a"]]') },
  { reason: "content number", raw: evPatched("content", "123") },
  { reason: "sig null", raw: evPatched("sig", "null") },
];

// Events for filter matching (canonical order).
const evA = canonEvent({
  id: "a".repeat(64),
  pubkey: PK,
  created_at: 1000,
  kind: 1,
  tags: [
    ["e", "b".repeat(64)],
    ["p", PK],
    ["t", "nostr"],
  ],
  content: "a",
  sig: "c".repeat(128),
});
const evB = canonEvent({
  id: "b".repeat(64),
  pubkey: "f".repeat(64),
  created_at: 2000,
  kind: 30023,
  tags: [
    ["d", "post"],
    ["a", `30023:${PK}:post`],
    ["custom", "v1", "v2"],
  ],
  content: "b",
  sig: "d".repeat(128),
});
// Uppercase e/p tag values: matching is case-insensitive on both sides.
const evC = canonEvent({
  id: "e".repeat(64),
  pubkey: PK,
  created_at: 1000,
  kind: 1,
  tags: [
    ["e", "B".repeat(64)],
    ["p", PK.toUpperCase()],
  ],
  content: "c",
  sig: "c".repeat(128),
});
// Distinct uppercase/lowercase single-letter tag names.
const evD = canonEvent({
  id: "d".repeat(64),
  pubkey: PK,
  created_at: 1500,
  kind: 1,
  tags: [
    ["A", "x"],
    ["a", "y"],
  ],
  content: "d",
  sig: "c".repeat(128),
});

const matchFilterCases: Array<{ filter: Filter; event: Event; matches: boolean }> = [
  { filter: { ids: ["a".repeat(64)] }, event: evA, matches: true },
  { filter: { ids: ["A".repeat(64)] }, event: evA, matches: true },
  { filter: { ids: ["b".repeat(64)] }, event: evA, matches: false },
  { filter: { ids: [] }, event: evA, matches: false },
  { filter: { authors: [PK.toUpperCase()] }, event: evA, matches: true },
  { filter: { authors: ["f".repeat(64)] }, event: evA, matches: false },
  { filter: { authors: [] }, event: evA, matches: false },
  { filter: { kinds: [1, 7] }, event: evA, matches: true },
  { filter: { kinds: [6] }, event: evA, matches: false },
  { filter: { since: 1000 }, event: evA, matches: true },
  { filter: { since: 1001 }, event: evA, matches: false },
  { filter: { until: 1000 }, event: evA, matches: true },
  { filter: { until: 999 }, event: evA, matches: false },
  { filter: { "#e": ["b".repeat(64)] }, event: evA, matches: true },
  { filter: { "#e": ["B".repeat(64)] }, event: evA, matches: true },
  { filter: { "#e": ["c".repeat(64)] }, event: evA, matches: false },
  { filter: { "#p": [PK] }, event: evA, matches: true },
  { filter: { "#p": [PK.toUpperCase()] }, event: evA, matches: true },
  { filter: { "#t": ["nostr"] }, event: evA, matches: true },
  { filter: { "#t": ["NOSTR"] }, event: evA, matches: false },
  // Multi-letter # keys are outside NIP-01 and ignored entirely.
  { filter: { "#custom": ["v1"] }, event: evB, matches: true },
  { filter: { "#custom": ["v2"] }, event: evB, matches: true },
  { filter: { "#d": ["post"] }, event: evB, matches: true },
  { filter: { "#a": [`30023:${PK}:post`] }, event: evB, matches: true },
  { filter: { "#missing": ["x"] }, event: evA, matches: true },
  { filter: { "#1": ["x"] }, event: evA, matches: true },
  { filter: { "#e": ["b".repeat(64)] }, event: evC, matches: true },
  { filter: { "#p": [PK] }, event: evC, matches: true },
  { filter: { "#A": ["x"] }, event: evD, matches: true },
  { filter: { "#a": ["x"] }, event: evD, matches: false },
  { filter: { "#a": ["y"] }, event: evD, matches: true },
  { filter: { since: 2000, until: 2000 }, event: evB, matches: true },
  { filter: { ids: ["a".repeat(64), "A".repeat(64)] }, event: evA, matches: true },
  { filter: {}, event: evA, matches: true },
  {
    filter: { kinds: [1], authors: [PK], since: 500, until: 1500, "#e": ["b".repeat(64)] },
    event: evA,
    matches: true,
  },
  {
    filter: { kinds: [1], "#e": ["b".repeat(64)], "#t": ["other"] },
    event: evA,
    matches: false,
  },
];

const filterLimitInputs: Filter[] = [
  {},
  { ids: [] },
  { kinds: [] },
  { authors: [] },
  { ids: ["a".repeat(64), "b".repeat(64)] },
  { limit: 10 },
  { ids: ["a".repeat(64)], limit: 10 },
  { kinds: [0, 3], authors: [PK] },
  { kinds: [0, 3], authors: [PK, "f".repeat(64)] },
  { kinds: [30023], authors: [PK], "#d": ["a", "b"] },
  { kinds: [30023, 1], authors: [PK] },
  { kinds: [1], authors: [PK] },
  { limit: 5, kinds: [0, 3], authors: [PK] },
  { "#d": [] },
  { ids: ["a".repeat(64), "A".repeat(64)] },
  { kinds: [0, 0, 3], authors: [PK, PK.toUpperCase()] },
  { kinds: [30023], authors: [PK], "#d": ["a", "a"] },
  { ids: ["a".repeat(64), "a".repeat(64)], limit: 10 },
];
const filterLimitCases = filterLimitInputs.map((filter) => ({
  filter,
  limit: getFilterLimit(filter),
}));

// Unknown non-# keys and multi-letter # keys are dropped on canonicalization
// in both languages, so vector inputs may carry them.
const canonicalizeInputs = [
  { ids: ["B".repeat(64), "a".repeat(64)] },
  { kinds: [30023, 1, 0] },
  { authors: [PK.toUpperCase(), "f".repeat(64)], "#e": ["F".repeat(64), "a".repeat(64)] },
  { "#t": ["b", "a"], since: 5, limit: 3, "#p": [PK.toUpperCase()] },
  { ids: ["a".repeat(64), "A".repeat(64), "b".repeat(64)] },
  { kinds: [1, 1, 0] },
  { "#t": ["b", "a", "b"] },
  { "#e": ["A".repeat(64), "a".repeat(64)] },
  { "#custom": ["x"], kinds: [1] },
  { "#A": ["x"], "#a": ["y"] },
  { "#t": ["\uFFFD", "😀", "z"] },
  { "#t": [] },
  { limit: 0, search: "s", since: 2, until: 9 },
  { kinds: [1], zzz: 1, custom: ["b", "a"] },
];
const canonicalizeCases = canonicalizeInputs.map((input) => ({
  input,
  canonicalJson: JSON.stringify(canonicalizeFilter(input as Filter)),
}));

const fingerprintInputs: Filter[][] = [
  [{ kinds: [1] }],
  [
    { kinds: [1, 0], since: 10 },
    { "#e": ["B".repeat(64), "a".repeat(64)], authors: [PK.toUpperCase()] },
  ],
  [{ ids: [] }],
  // The serialized parts are sorted by UTF-16 code units: "😀" precedes "�".
  [{ "#t": ["\uFFFD"] }, { "#t": ["😀"] }],
  [{ "#A": ["x"], "#a": ["y"] }],
  [{ kinds: [1], "#custom": ["x"] }],
  [{ ids: ["A".repeat(64), "a".repeat(64)] }],
];
const fingerprintCases = fingerprintInputs.map((filters) => ({
  filters,
  fingerprint: filterFingerprint(filters),
}));

// Canonical wire messages: encode(parse(raw)) === raw unless `encoded` differs.
const evMsg = encodeClientMessage(["EVENT", baseEvent]);
const authMsg = encodeClientMessage(["AUTH", baseEvent]);
const clientMessages = [
  { raw: evMsg },
  {
    raw: encodeClientMessage([
      "REQ",
      "sub1",
      { kinds: [1] },
      { authors: [PK], "#e": ["a".repeat(64)] },
    ]),
  },
  {
    // encodeClientMessage canonicalizes; parse drops the unknown non-# key.
    raw: '["REQ","sub",{"foo":1,"ids":[]}]',
    encoded: '["REQ","sub",{"ids":[]}]',
  },
  {
    raw: encodeClientMessage([
      "REQ",
      "sub2",
      { ids: ["B".repeat(64), "a".repeat(64)], "#custom": ["x"] },
    ]),
  },
  {
    // Wire parse lowercases ids/#e and drops multi-letter # keys and unknowns.
    raw: `["REQ","s",{"ids":["${"A".repeat(64)}"],"#e":["${"B".repeat(64)}"],"#custom":["x"],"junk":1}]`,
    encoded: `["REQ","s",{"#e":["${"b".repeat(64)}"],"ids":["${"a".repeat(64)}"]}]`,
  },
  {
    // Duplicate keys: last wins; integer spellings serialize as plain integers.
    raw: '["REQ","s",{"kinds":[9],"kinds":[1],"limit":1e2}]',
    encoded: '["REQ","s",{"kinds":[1],"limit":100}]',
  },
  {
    // An invalid earlier duplicate is discarded when a later one is valid.
    raw: '["REQ","s",{"since":"x","since":5}]',
    encoded: '["REQ","s",{"since":5}]',
  },
  {
    raw: '["REQ","s",{"kinds":[{}],"kinds":[7]}]',
    encoded: '["REQ","s",{"kinds":[7]}]',
  },
  {
    raw: `["REQ","s",{"ids":[123],"ids":["${"e".repeat(64)}"]}]`,
    encoded: `["REQ","s",{"ids":["${"e".repeat(64)}"]}]`,
  },
  {
    raw: '["REQ","s",{"limit":null,"limit":3}]',
    encoded: '["REQ","s",{"limit":3}]',
  },
  {
    raw: '["REQ","s",{"since":1e3,"until":2.0,"limit":-0}]',
    encoded: '["REQ","s",{"limit":0,"since":1000,"until":2}]',
  },
  {
    // 2^53-1 spelled .0 must round-trip exactly (float_roundtrip, ruling 8).
    raw: '["REQ","s",{"until":9007199254740991.0}]',
    encoded: '["REQ","s",{"until":9007199254740991}]',
  },
  { raw: encodeClientMessage(["CLOSE", "sub1"]) },
  { raw: authMsg },
  { raw: encodeClientMessage(["COUNT", "c1", { kinds: [0] }]) },
  { raw: encodeClientMessage(["NEG-OPEN", "sub", { kinds: [1] }, "aabb00"]) },
  {
    raw: encodeClientMessage(["NEG-OPEN", "sub", { kinds: [2, 1], "#custom": ["x"] }, "aabb"]),
  },
  {
    raw: '["NEG-OPEN","sub",{"kinds":[1]},"AABB"]',
    encoded: '["NEG-OPEN","sub",{"kinds":[1]},"aabb"]',
  },
  { raw: encodeClientMessage(["NEG-MSG", "sub", "deadbeef"]) },
  { raw: '["NEG-MSG","sub","FF00"]', encoded: '["NEG-MSG","sub","ff00"]' },
  { raw: encodeClientMessage(["NEG-CLOSE", "sub"]) },
  // Subscription id boundary: 64 scalar values accepted (incl. astral), 65 rejected.
  { raw: encodeClientMessage(["CLOSE", "a".repeat(64)]) },
  { raw: `["CLOSE","${"\u{1F600}".repeat(64)}"]` },
];

const relayMessages = [
  { raw: encodeRelayMessage(["EVENT", "sub1", baseEvent]) },
  { raw: encodeRelayMessage(["OK", "a".repeat(64), true, ""]) },
  { raw: encodeRelayMessage(["OK", "a".repeat(64), false, "invalid: bad sig"]) },
  { raw: encodeRelayMessage(["EOSE", "sub1"]) },
  { raw: encodeRelayMessage(["CLOSED", "sub1", "auth-required: we only allow authd"]) },
  { raw: encodeRelayMessage(["NOTICE", "rate limited"]) },
  { raw: encodeRelayMessage(["AUTH", "challenge-string"]) },
  { raw: encodeRelayMessage(["COUNT", "sub1", { count: 7 }]) },
  {
    raw: encodeRelayMessage([
      "COUNT",
      "sub1",
      { count: 7, approximate: true, hll: "ab".repeat(256) },
    ]),
  },
  // COUNT with uppercase hll normalizes to lowercase on parse.
  {
    raw: `["COUNT","s",{"count":3,"hll":"${"AB".repeat(256)}"}]`,
    encoded: encodeRelayMessage(["COUNT", "s", { count: 3, hll: "ab".repeat(256) }]),
  },
  { raw: encodeRelayMessage(["NEG-MSG", "sub", "deadbeef"]) },
  { raw: '["NEG-MSG","sub","AABB"]', encoded: '["NEG-MSG","sub","aabb"]' },
  { raw: encodeRelayMessage(["NEG-ERR", "sub", "error: something"]) },
  // The optional 4th NEG-ERR element is ignored.
  {
    raw: '["NEG-ERR","sub","error: something","ignored"]',
    encoded: '["NEG-ERR","sub","error: something"]',
  },
  // COUNT accepts the max safe integer; non-bool approximate and invalid hll are ignored.
  { raw: encodeRelayMessage(["COUNT", "s", { count: 9007199254740991 }]) },
  {
    // Duplicate keys: last wins; `1e2` normalizes to 100.
    raw: '["COUNT","s",{"count":1,"count":2}]',
    encoded: '["COUNT","s",{"count":2}]',
  },
  {
    raw: '["COUNT","s",{"count":1e2}]',
    encoded: '["COUNT","s",{"count":100}]',
  },
  {
    raw: '["COUNT","s",{"count":3,"approximate":"yes","hll":"zz"}]',
    encoded: '["COUNT","s",{"count":3}]',
  },
  // Subscription id boundary on the relay direction (64 scalar values incl. astral).
  { raw: `["EOSE","${"a".repeat(64)}"]` },
  { raw: `["EOSE","${"\u{1F600}".repeat(64)}"]` },
];

const invalidClientMessages = [
  "not json",
  "{}",
  "[]",
  '["REQ"]',
  '["REQ","sub"]',
  '["REQ",1,{"kinds":[1]}]',
  '["REQ","sub",42]',
  '["REQ","sub",null]',
  `["REQ","s",{"ids":["${"z".repeat(64)}"]}]`,
  '["REQ","s",{"ids":[123]}]',
  `["REQ","s",{"ids":"${"a".repeat(64)}"}]`,
  `["REQ","s",{"authors":["${"a".repeat(63)}"]}]`,
  '["REQ","s",{"kinds":[65536]}]',
  '["REQ","s",{"kinds":[-1]}]',
  '["REQ","s",{"kinds":[1.5]}]',
  '["REQ","s",{"kinds":"x"}]',
  '["REQ","s",{"since":-1}]',
  '["REQ","s",{"since":"x"}]',
  '["REQ","s",{"until":1.5}]',
  '["REQ","s",{"since":9007199254740992}]',
  '["REQ","s",{"limit":-1}]',
  '["REQ","s",{"limit":-0.5}]',
  '["REQ","s",{"limit":1e20}]',
  '["REQ","s",{"kinds":[1e10]}]',
  '["REQ","s",{"search":1}]',
  '["REQ","s",{"#e":"x"}]',
  '["REQ","s",{"#t":[1]}]',
  '["REQ","s",{"since":[]}]',
  '["REQ","s",{"since":null}]',
  '["REQ","s",{"until":{}}]',
  '["REQ","s",{"limit":true}]',
  '["REQ","s",{"kinds":[1,"x"]}]',
  '["REQ","s",{"kinds":[{}]}]',
  // Elements after the first invalid one are still drained (ruling 7).
  '["REQ","s",{"kinds":[{},"x"]}]',
  '["REQ","s",{"ids":[{}]}]',
  '["REQ","s",{"ids":[123,"x"]}]',
  '["REQ","s",{"#t":[1,"x"]}]',
  `["REQ","s",{"ids":["${"a".repeat(63)}"]}]`,
  '["REQ","s",{"search":[]}]',
  // A later invalid duplicate still wins and fails the filter.
  '["REQ","s",{"since":5,"since":"x"}]',
  '["REQ","s",{"kinds":[7],"kinds":"x"}]',
  '["COUNT","s",{"authors":[1]}]',
  '["NEG-OPEN","s",{"limit":"x"},"aabb"]',
  '["EVENT"]',
  '["EVENT",{}]',
  `["EVENT",${JSON.stringify(baseEvent)},{}]`,
  '["CLOSE"]',
  '["CLOSE","a","b"]',
  '["AUTH",{}]',
  '["COUNT","s"]',
  '["COUNT","s",[]]',
  '["NEG-OPEN","s",{"kinds":[1]}]',
  '["NEG-OPEN","s",{"kinds":[1]},"aabb","extra"]',
  '["NEG-OPEN","s",{"kinds":[1]},"abc"]',
  '["NEG-OPEN","s",{"kinds":[1]},"zz"]',
  '["NEG-OPEN","s",42,"aabb"]',
  '["NEG-OPEN","s",{"kinds":[1]},42]',
  '["NEG-MSG","s"]',
  '["NEG-MSG","s",""]',
  '["NEG-MSG","s","a"]',
  '["NEG-MSG","s",42]',
  '["CLOSE",42]',
  '["NEG-CLOSE"]',
  '["NEG-CLOSE","s","x"]',
  '["UNKNOWN","s"]',
  '["REQ","",{"kinds":[1]}]',
  `["CLOSE","${"a".repeat(65)}"]`,
  `["CLOSE","${"\u{1F600}".repeat(65)}"]`,
  `["NEG-MSG","${"a".repeat(65)}","aabb"]`,
];

const invalidRelayMessages = [
  "not json",
  "{}",
  "[]",
  '["EVENT","s"]',
  '["EVENT","s",{}]',
  `["EVENT",1,${JSON.stringify(baseEvent)}]`,
  '["OK","id","true",""]',
  '["OK","id",true]',
  `["OK","${"a".repeat(64)}","yes",""]`,
  `["OK","${"a".repeat(64)}",true,5]`,
  '["EOSE"]',
  '["EOSE","s","x"]',
  '["EOSE",42]',
  '["CLOSED","s"]',
  '["CLOSED","s",5]',
  '["NOTICE"]',
  '["NOTICE","a","b"]',
  '["NOTICE",42]',
  '["AUTH"]',
  '["AUTH",[1]]',
  '["COUNT","s",{"count":-1}]',
  '["COUNT","s",{"count":1.5}]',
  '["COUNT","s",{"count":-0.5}]',
  '["COUNT","s",{"count":1e20}]',
  '["COUNT","s","x"]',
  '["COUNT","s",[]]',
  '["COUNT","s"]',
  '["NEG-MSG","s",42]',
  '["NEG-MSG","s","abc"]',
  '["NEG-MSG","s",""]',
  '["NEG-ERR","s"]',
  '["NEG-ERR","s",1]',
  '["UNKNOWN","s"]',
  // Ruling 5: OK requires a 64-char lowercase hex event id.
  '["OK","id",true,""]',
  `["OK","${"a".repeat(64).toUpperCase()}",true,""]`,
  `["OK","${"a".repeat(63)}",true,""]`,
  // Ruling 6: subscription ids validated on parse (1..=64 scalar values).
  '["EOSE",""]',
  `["EOSE","${"a".repeat(65)}"]`,
  `["EOSE","${"\u{1F600}".repeat(65)}"]`,
  `["CLOSED","${"a".repeat(65)}","x"]`,
  `["NEG-MSG","${"a".repeat(65)}","aabb"]`,
  `["NEG-ERR","${"a".repeat(65)}","error"]`,
  // COUNT rejects counts above the safe-integer bound.
  '["COUNT","s",{"count":9007199254740992}]',
  '["COUNT","s",{"count":9007199254740993}]',
];

const mergeHllCases = [
  { inputs: [] as string[], output: mergeCountHll([]) },
  { inputs: ["00".repeat(256)], output: mergeCountHll(["00".repeat(256)]) },
  {
    inputs: ["0f".repeat(256), "f0".repeat(256)],
    output: mergeCountHll(["0f".repeat(256), "f0".repeat(256)]),
  },
  {
    inputs: ["AB".repeat(256)],
    output: mergeCountHll(["ab".repeat(256)]),
  },
];

const kinds = [
  0, 1, 2, 3, 4, 44, 45, 999, 1000, 9999, 10000, 19999, 20000, 29999, 30000, 39999, 40000, 65535,
].map((kind) => ({
  kind,
  regular: isRegularKind(kind),
  replaceable: isReplaceableKind(kind),
  ephemeral: isEphemeralKind(kind),
  addressable: isAddressableKind(kind),
  class: classifyKind(kind),
}));

const addressCases = [
  `30023:${PK}:post`,
  `30023:${PK.toUpperCase()}:post`,
  `0:${PK}:`,
  `1:${PK}:with:colons`,
  `65535:${PK}:x`,
  `65536:${PK}:x`,
  `99999:${PK}:x`,
  `100000:${PK}:x`,
  `1:${PK.slice(0, 62)}:x`,
  "1:nothex:x",
  ":x:y",
  `1:${PK}`,
  `1:${PK}`,
  "nope",
  "",
].map((input) => ({ op: "parse", input, parsed: parseEventAddress(input) ?? null }));

const addressFormats = [
  { kind: 30023, pubkey: PK, identifier: "post" },
  { kind: 0, pubkey: PK.toUpperCase(), identifier: "" },
  { kind: 1, pubkey: PK, identifier: "a:b:c" },
].map((c) => ({
  op: "format",
  kind: c.kind,
  pubkey: c.pubkey,
  identifier: c.identifier,
  formatted: formatEventAddress(c.kind, c.pubkey, c.identifier),
}));

const normalizeUrlCases = [
  "example.com",
  "EXAMPLE.com",
  "WSS://A.EXAMPLE",
  "http://a.example:80/x",
  "https://a.example:443",
  "http://a.example:443/x",
  "https://a.example:80/x",
  "http://a.example:80",
  "http://a.example:8080/x",
  "wss://a.example:443/x",
  "wss://a.example:8443/x",
  "wss://a.example:80/x",
  "ws://a.example:443/x",
  "ws://a.example:80/x",
  "wss://a.example//a///b/",
  "wss://a.example//",
  "wss://a.example///",
  "wss://a.example/?b=2&a=1&a=0",
  "wss://a.example/?a=1&a=2&b=0&a=3",
  "wss://a.example/?q=a+b",
  "wss://a.example/?q=a%2Bb",
  "wss://a.example/?q=a%20b",
  "wss://a.example/?",
  "wss://a.example/?#x",
  "wss://a.example/path#frag",
  "#frag",
  "wss://a.example",
  "relay.example:4443/p?q=z",
  "wss://u:p@a.example",
  "wss://127.0.0.1:7777/x",
  "wss://[::1]:8080/x",
  "wss://bücher.example",
  "ftp://a.example",
  "ftp://x",
  "wss://",
  "ws://exa mple.com",
  "http://",
  "",
  "not a url",
  "wss://a.example/üñí",
].map((input) => {
  try {
    return { input, output: normalizeURL(input) };
  } catch (error) {
    // Failure vectors name the error class so Rust can assert ErrorKind.
    return { input, error: error instanceof Error ? error.constructor.name : "Error" };
  }
});

emit("core.event.serialize", "event-serialize.json", serialize, CROSS_CHECK_IDS);
emit("core.event.sign", "event-sign.json", signed, CROSS_CHECK_SIGS);
emit("core.event.validate", "event-validate.json", [
  ...[...invalidEvents, ...invalidWireEvents].map((c) => ({
    reason: c.reason,
    raw: c.raw,
    error: "EventValidationError",
  })),
  ...validEventCases,
]);
emit(
  "core.filter.match",
  "filter-match.json",
  matchFilterCases.map((c) => ({
    filter: c.filter,
    event: c.event,
    matches: matchFilter(c.filter, c.event),
  })),
);
emit("core.filter.limit", "filter-limit.json", filterLimitCases);
emit("core.filter.canonicalize", "filter-canonicalize.json", canonicalizeCases);
emit("core.filter.fingerprint", "filter-fingerprint.json", fingerprintCases);
emit("core.message.client", "message-client.json", [
  ...clientMessages,
  ...invalidClientMessages.map((raw) => ({ raw, error: "MessageError" })),
]);
emit("core.message.relay", "message-relay.json", [
  ...relayMessages,
  ...invalidRelayMessages.map((raw) => ({ raw, error: "MessageError" })),
]);
emit("core.count.hll", "count-hll.json", [
  ...mergeHllCases,
  { inputs: ["ab".repeat(255)], error: "MessageError" },
  { inputs: ["zz".repeat(256)], error: "MessageError" },
]);
// 32-byte hex decode: `caller` accepts any case and normalizes to lowercase;
// `wire` is strict lowercase only (both must be exactly 64 characters).
const hexInputs: Array<{ op: "caller" | "wire"; input: string }> = [
  { op: "caller", input: "ab".repeat(32) },
  { op: "caller", input: "AB".repeat(32) },
  { op: "caller", input: "aB9f".repeat(16) },
  { op: "caller", input: "zz".repeat(32) },
  { op: "caller", input: "ab".repeat(31) },
  { op: "caller", input: "ab".repeat(33) },
  { op: "caller", input: "abc" },
  { op: "caller", input: "" },
  { op: "wire", input: "ab".repeat(32) },
  { op: "wire", input: "AB".repeat(32) },
  { op: "wire", input: "aB".repeat(32) },
  { op: "wire", input: "ab".repeat(31) },
  { op: "wire", input: "ab".repeat(33) },
  { op: "wire", input: "zz".repeat(32) },
];
const hexCases = hexInputs.map((c) => {
  if (c.op === "wire") {
    return isHex32(c.input)
      ? { op: c.op, input: c.input, output: c.input }
      : { op: c.op, input: c.input, error: "HexError" };
  }
  let output: string | undefined;
  try {
    const bytes = hexToBytes(c.input);
    if (bytes.length === 32) {
      output = bytesToHex(bytes);
    }
  } catch {
    // falls through to the error case
  }
  return output === undefined
    ? { op: c.op, input: c.input, error: "HexError" }
    : { op: c.op, input: c.input, output };
});

// --- core.builder --------------------------------------------------------
// Every constructor is frozen at a fixed pubkey/created_at; outputs are the
// UnsignedEvent wire JSON (Rust serde field order: pubkey, created_at, kind,
// tags, content).
const BUILD_PK = PK;
const BUILD_AT = 1_700_000_000;
const BUILD_RELAY = "wss://r.example/nostr";

function unsignedJson(u: UnsignedEvent): string {
  return JSON.stringify({
    pubkey: u.pubkey,
    created_at: u.created_at,
    kind: u.kind,
    tags: u.tags,
    content: u.content,
  });
}

const builderTargets = {
  kind1: sign(
    { pubkey: SK_PK, created_at: 1, kind: 1, tags: [["t", "nostr"]], content: 'esc " \\ \n 😀' },
    SK,
    AUX,
  ),
  protectedKind1: sign(
    { pubkey: SK_PK, created_at: 1, kind: 1, tags: [["-"]], content: "p" },
    SK,
    AUX,
  ),
  kind0: sign(
    {
      pubkey: SK_PK,
      created_at: 1,
      kind: 0,
      tags: [],
      content: JSON.stringify({ name: "alice" }),
    },
    SK,
    AUX,
  ),
  kind20: sign({ pubkey: SK_PK, created_at: 1, kind: 20, tags: [], content: "img" }, SK, AUX),
  protectedKind20: sign(
    { pubkey: SK_PK, created_at: 1, kind: 20, tags: [["-"]], content: "secret" },
    SK,
    AUX,
  ),
  addressable: sign(
    { pubkey: SK_PK, created_at: 1, kind: 34235, tags: [["d", "ep1"]], content: "v" },
    SK,
    AUX,
  ),
  addressableNoD: sign(
    { pubkey: SK_PK, created_at: 1, kind: 34235, tags: [], content: "v" },
    SK,
    AUX,
  ),
};

type BuilderInput =
  | { op: "text_note"; content: string }
  | { op: "new"; kind: number; content: string; tags: string[][] }
  | { op: "metadata"; meta: ProfileMetadata }
  | { op: "contacts"; pubkeys: string[] }
  | {
      op: "deletion";
      reason: string;
      targets: ReadonlyArray<string | { id: string; kind?: number } | { address: string }>;
    }
  | { op: "reaction"; target: Event; content: string; relay?: string }
  | { op: "repost"; target: Event; relay: string }
  | { op: "generic_repost"; target: Event; relay: string; p_pubkey?: string };

const builderInputs: BuilderInput[] = [
  { op: "text_note", content: "hello nostr" },
  { op: "text_note", content: `${ALL_CONTROLS}"\\😀` },
  {
    op: "new",
    kind: 42,
    content: "chained",
    tags: [
      ["t", "nostr"],
      ["e", "ab".repeat(32)],
    ],
  },
  {
    op: "metadata",
    meta: { name: "alice", about: "dev 😀", nip05: "a@b.example", website: "https://a.example" },
  },
  // Shuffled input order still emits declaration order.
  {
    op: "metadata",
    meta: { lud16: "x@y", name: "shuffled", about: "z", display_name: "D" },
  },
  { op: "metadata", meta: {} },
  { op: "contacts", pubkeys: [PK.toUpperCase(), SK_PK] },
  {
    op: "deletion",
    reason: "spam",
    targets: [
      "cd".repeat(32).toUpperCase(),
      { id: "ab".repeat(32), kind: 1 },
      { address: `30023:${PK}:d1` },
      { id: "ef".repeat(32) },
      { id: "ab".repeat(32), kind: 1 },
      { address: `0:${SK_PK}:` },
    ],
  },
  { op: "reaction", target: builderTargets.kind1, content: "+" },
  { op: "reaction", target: builderTargets.kind1, content: "🔥", relay: BUILD_RELAY },
  { op: "reaction", target: builderTargets.addressable, content: "+" },
  { op: "reaction", target: builderTargets.addressable, content: "+", relay: BUILD_RELAY },
  { op: "reaction", target: builderTargets.addressableNoD, content: "+" },
  { op: "reaction", target: builderTargets.kind0, content: "+" },
  { op: "repost", target: builderTargets.kind1, relay: BUILD_RELAY },
  { op: "repost", target: builderTargets.protectedKind1, relay: BUILD_RELAY },
  { op: "repost", target: builderTargets.kind20, relay: BUILD_RELAY },
  { op: "generic_repost", target: builderTargets.kind20, relay: BUILD_RELAY },
  { op: "generic_repost", target: builderTargets.kind0, relay: BUILD_RELAY },
  { op: "generic_repost", target: builderTargets.addressable, relay: BUILD_RELAY },
  { op: "generic_repost", target: builderTargets.addressableNoD, relay: BUILD_RELAY },
  { op: "generic_repost", target: builderTargets.protectedKind20, relay: BUILD_RELAY },
  {
    op: "generic_repost",
    target: builderTargets.kind20,
    relay: BUILD_RELAY,
    p_pubkey: "11".repeat(32),
  },
  { op: "generic_repost", target: builderTargets.kind1, relay: BUILD_RELAY },
];

const builderCases = builderInputs.map((input) => {
  try {
    let builder: EventBuilder;
    switch (input.op) {
      case "text_note":
        builder = EventBuilder.textNote(input.content);
        break;
      case "new":
        builder = new EventBuilder(input.kind, input.content);
        builder.tags(input.tags);
        break;
      case "metadata":
        builder = EventBuilder.metadata(input.meta);
        break;
      case "contacts":
        builder = EventBuilder.contacts(input.pubkeys);
        break;
      case "deletion":
        builder = EventBuilder.deletion(input.targets, input.reason);
        break;
      case "reaction":
        builder = EventBuilder.reaction(
          input.target,
          input.content,
          input.relay === undefined ? undefined : { relayHint: input.relay },
        );
        break;
      case "repost":
        builder = EventBuilder.repost(input.target, { relayHint: input.relay });
        break;
      case "generic_repost": {
        const opts: { relayHint: string; pPubkey?: string } = { relayHint: input.relay };
        if (input.p_pubkey !== undefined) {
          opts.pPubkey = input.p_pubkey;
        }
        builder = EventBuilder.genericRepost(input.target, opts);
        break;
      }
    }
    return Object.assign(input, {
      unsignedJson: unsignedJson(builder.createdAt(BUILD_AT).buildUnsigned(BUILD_PK)),
    });
  } catch (error) {
    return Object.assign(input, {
      error: error instanceof Error ? error.constructor.name : "Error",
    });
  }
});

// --- core.tag.build ------------------------------------------------------
// Every Tag constructor across its optional-position permutations (the
// NIP-10/NIP-02 "" padding). Cases the typed Rust API cannot express carry
// `rust: false`; the Rust runner asserts the skipped count.
const TAG_ID = "ab".repeat(32);
// RelayUrl normalizes to a trailing slash; use a normalized-stable URL so the
// typed Rust constructors reproduce the tag verbatim.
const TAG_RELAY = "wss://r.example/";
const tagBuildCases = [
  { op: "e", id: TAG_ID, tag: Tag.e(TAG_ID) },
  { op: "e", id: TAG_ID.toUpperCase(), tag: Tag.e(TAG_ID.toUpperCase()) },
  { op: "e", id: TAG_ID, relay: TAG_RELAY, tag: Tag.e(TAG_ID, TAG_RELAY) },
  { op: "e", id: TAG_ID, marker: "reply", tag: Tag.e(TAG_ID, undefined, "reply") },
  { op: "e", id: TAG_ID, pubkey: PK, tag: Tag.e(TAG_ID, undefined, undefined, PK) },
  {
    op: "e",
    id: TAG_ID,
    relay: TAG_RELAY,
    marker: "reply",
    pubkey: PK,
    tag: Tag.e(TAG_ID, TAG_RELAY, "reply", PK),
  },
  {
    op: "e",
    id: TAG_ID.toUpperCase(),
    relay: TAG_RELAY,
    pubkey: PK.toUpperCase(),
    tag: Tag.e(TAG_ID.toUpperCase(), TAG_RELAY, undefined, PK.toUpperCase()),
  },
  // Relay strings the typed Rust RelayUrl cannot express are TS-only.
  {
    op: "e",
    id: TAG_ID,
    relay: "not a url",
    tag: Tag.e(TAG_ID, "not a url"),
    rust: false,
  },
  { op: "p", pubkey: PK, tag: Tag.p(PK) },
  { op: "p", pubkey: PK.toUpperCase(), tag: Tag.p(PK.toUpperCase()) },
  { op: "p", pubkey: PK, relay: TAG_RELAY, tag: Tag.p(PK, TAG_RELAY) },
  {
    op: "p",
    pubkey: PK,
    relay: TAG_RELAY,
    petname: "alice",
    tag: Tag.p(PK, TAG_RELAY, "alice"),
  },
  { op: "p", pubkey: PK, petname: "alice", tag: Tag.p(PK, undefined, "alice") },
  {
    op: "p",
    pubkey: PK,
    relay: "not a url",
    tag: Tag.p(PK, "not a url"),
    rust: false,
  },
  { op: "a", address: `30023:${PK}:post`, tag: Tag.a(`30023:${PK}:post`) },
  {
    op: "a",
    address: `30023:${PK}:post`,
    relay: TAG_RELAY,
    tag: Tag.a(`30023:${PK}:post`, TAG_RELAY),
  },
  // TS keeps the coordinate verbatim; Tag::address would normalize the pubkey.
  {
    op: "a",
    address: `30023:${PK.toUpperCase()}:post`,
    tag: Tag.a(`30023:${PK.toUpperCase()}:post`),
    rust: false,
  },
  {
    op: "a",
    address: `30023:${PK}:post`,
    relay: "not a url",
    tag: Tag.a(`30023:${PK}:post`, "not a url"),
    rust: false,
  },
  { op: "d", identifier: "post", tag: Tag.d("post") },
  { op: "d", identifier: "", tag: Tag.d("") },
  { op: "d", identifier: "with:colon", tag: Tag.d("with:colon") },
  { op: "t", hashtag: "nostr", tag: Tag.t("nostr") },
  { op: "t", hashtag: "😀", tag: Tag.t("😀") },
  { op: "r", url: "https://x.example/a", tag: Tag.r("https://x.example/a") },
  {
    op: "r",
    url: "https://x.example/a",
    marker: "mention",
    tag: Tag.r("https://x.example/a", "mention"),
  },
  { op: "k", kind: 1, tag: Tag.k(1) },
  { op: "k", kind: 65535, tag: Tag.k(65535) },
  // A string kind is not expressible through the typed Rust Kind input.
  { op: "k", kind: "1", tag: Tag.k("1"), rust: false },
];

// --- core.event.order ----------------------------------------------------
// sortEvents (newest-first), itemCompare (oldest-first) and isReplaceableWinner
// over event lists with created_at ties broken by lexicographic id.
const ordEvent = (id: string, created_at: number): Event =>
  canonEvent({
    id,
    pubkey: PK,
    created_at,
    kind: 1,
    tags: [],
    content: "x",
    sig: "c".repeat(128),
  });

const ordA = ordEvent("a".repeat(64), 2000);
const ordB = ordEvent("b".repeat(64), 2000);
const ordC = ordEvent("c".repeat(64), 1000);
const ordD = ordEvent("d".repeat(64), 3000);
const ord1 = ordEvent("1".repeat(64), 777);
const ord2 = ordEvent("2".repeat(64), 777);
const ord3 = ordEvent("3".repeat(64), 777);

const ordList = [ordB, ordC, ordD, ordA];
const ordTies = [ord3, ord1, ord2];
const eventOrderCases = [
  {
    op: "sort",
    events: ordList,
    order: sortedEvents(ordList).map((e) => e.id),
  },
  {
    op: "item",
    events: ordList,
    order: ordList.toSorted(itemCompare).map((e) => e.id),
  },
  // Pure id ordering when every created_at is equal.
  {
    op: "sort",
    events: ordTies,
    order: sortedEvents(ordTies).map((e) => e.id),
  },
  { op: "item", events: ordTies, order: ordTies.toSorted(itemCompare).map((e) => e.id) },
  { op: "winner", candidate: ordD, incumbent: ordA, wins: isReplaceableWinner(ordD, ordA) },
  { op: "winner", candidate: ordA, incumbent: ordD, wins: isReplaceableWinner(ordA, ordD) },
  { op: "winner", candidate: ordA, incumbent: ordB, wins: isReplaceableWinner(ordA, ordB) },
  { op: "winner", candidate: ordB, incumbent: ordA, wins: isReplaceableWinner(ordB, ordA) },
  { op: "winner", candidate: ordA, incumbent: ordA, wins: isReplaceableWinner(ordA, ordA) },
];

// --- core.event.signed-matches -------------------------------------------
// signedMatchesUnsigned / Event::matches_unsigned: one match plus each field
// mismatch (kind, content, created_at, tags order/values, pubkey). TS compares
// pubkeys case-insensitively and skips a falsy unsigned pubkey; the typed Rust
// API cannot express those inputs, so they are TS-only.
const matchBase: UnsignedEvent = {
  pubkey: SK_PK,
  created_at: 1700000000,
  kind: 1,
  tags: [
    ["t", "a"],
    ["e", TAG_ID],
  ],
  content: "gm",
};
const matchEvent = sign(matchBase, SK, AUX);

const signedMatchesCases = [
  { unsigned: matchBase, event: matchEvent, matches: signedMatchesUnsigned(matchEvent, matchBase) },
  ...[
    { ...matchBase, kind: 2 },
    { ...matchBase, content: "other" },
    { ...matchBase, created_at: 1700000001 },
    {
      ...matchBase,
      tags: [
        ["e", TAG_ID],
        ["t", "a"],
      ],
    },
    {
      ...matchBase,
      tags: [
        ["t", "b"],
        ["e", TAG_ID],
      ],
    },
    { ...matchBase, pubkey: PK },
  ].map((unsigned) => ({
    unsigned,
    event: matchEvent,
    matches: signedMatchesUnsigned(matchEvent, unsigned),
  })),
  {
    unsigned: { ...matchBase, pubkey: SK_PK.toUpperCase() },
    event: matchEvent,
    matches: signedMatchesUnsigned(matchEvent, {
      ...matchBase,
      pubkey: SK_PK.toUpperCase(),
    }),
    rust: false,
  },
  {
    unsigned: { ...matchBase, pubkey: "" },
    event: matchEvent,
    matches: signedMatchesUnsigned(matchEvent, { ...matchBase, pubkey: "" }),
    rust: false,
  },
  {
    unsigned: matchBase,
    event: { ...matchEvent, pubkey: matchEvent.pubkey.toUpperCase() },
    matches: signedMatchesUnsigned(
      { ...matchEvent, pubkey: matchEvent.pubkey.toUpperCase() },
      matchBase,
    ),
    rust: false,
  },
];

emit("core.tag.build", "tag-build.json", tagBuildCases);
emit("core.event.order", "event-order.json", eventOrderCases);
emit("core.event.signed-matches", "event-signed-matches.json", signedMatchesCases);
emit("core.kind.classify", "kind-classify.json", kinds, CROSS_CHECK_KINDS);
emit("core.tag.address", "tag-address.json", [...addressCases, ...addressFormats]);
emit("core.hex", "hex.json", hexCases);
emit("core.url.normalize", "url-normalize.json", normalizeUrlCases, CROSS_CHECK_URLS);
emit("core.builder", "builder.json", builderCases);
console.log("wrote vectors/core/*.json");
