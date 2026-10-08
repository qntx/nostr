/// <reference types="node" />
// Generates vectors/core/*.json — run with
// `bun packages/nostr/scripts/parity/gen/core.ts`.
// Captures the TS core's wire output as frozen vectors shared by the TS test
// suite (tests/vectors/core.test.ts) and the nk-* Rust crates.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { serializeEvent, getEventHash } from "../../../src/core/event.ts";
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
import { formatEventAddress, parseEventAddress } from "../../../src/core/tag.ts";
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

function emit(capability: string, file: string, cases: unknown): void {
  const doc = {
    schema: 1,
    capability,
    source: { kind: "generated", generator: "@qntx/nostr", version },
    cases,
  };
  writeFileSync(join(vectors, file), `${JSON.stringify(doc, null, 2)}\n`);
}

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
  { reason: "content number", raw: evRaw({ content: 42 }) },
  { reason: "tags not array", raw: evRaw({ tags: "none" }) },
  { reason: "tag not array", raw: evRaw({ tags: ["t"] }) },
  { reason: "empty tag", raw: evRaw({ tags: [[]] }) },
  { reason: "non-string tag item", raw: evRaw({ tags: [["e", 5]] }) },
  { reason: "missing id", raw: JSON.stringify({ ...baseEvent, id: undefined }) },
  { reason: "missing sig", raw: JSON.stringify({ ...baseEvent, sig: undefined }) },
  { reason: "not an object", raw: "[1,2,3]" },
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
  { filter: { "#custom": ["v1"] }, event: evB, matches: true },
  { filter: { "#custom": ["v2"] }, event: evB, matches: false },
  { filter: { "#d": ["post"] }, event: evB, matches: true },
  { filter: { "#a": [`30023:${PK}:post`] }, event: evB, matches: true },
  { filter: { "#missing": ["x"] }, event: evA, matches: false },
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
];
const filterLimitCases = filterLimitInputs.map((filter) => ({
  filter,
  limit: getFilterLimit(filter),
}));

// Inputs carry keys outside the Filter type on purpose: canonicalization must
// preserve unknown fields verbatim.
const canonicalizeInputs = [
  { ids: ["B".repeat(64), "a".repeat(64)] },
  { kinds: [30023, 1, 0] },
  { authors: [PK.toUpperCase(), "f".repeat(64)], "#e": ["F".repeat(64), "a".repeat(64)] },
  { "#t": ["b", "a"], since: 5, limit: 3, "#p": [PK.toUpperCase()] },
  { search: "hello", zzz: "keep", limit: 1 },
  { "#e": ["a".repeat(64)], custom: ["b", "a"] },
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
    raw: encodeClientMessage(["REQ", "sub", { ids: [], foo: 1 } as Filter]),
  },
  { raw: encodeClientMessage(["CLOSE", "sub1"]) },
  { raw: authMsg },
  { raw: encodeClientMessage(["COUNT", "c1", { kinds: [0] }]) },
  { raw: encodeClientMessage(["NEG-OPEN", "sub", { kinds: [1] }, "aabb00"]) },
  {
    raw: '["NEG-OPEN","sub",{"kinds":[1]},"AABB"]',
    encoded: '["NEG-OPEN","sub",{"kinds":[1]},"aabb"]',
  },
  { raw: encodeClientMessage(["NEG-MSG", "sub", "deadbeef"]) },
  { raw: '["NEG-MSG","sub","FF00"]', encoded: '["NEG-MSG","sub","ff00"]' },
  { raw: encodeClientMessage(["NEG-CLOSE", "sub"]) },
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
  '["NEG-MSG","s"]',
  '["NEG-MSG","s",""]',
  '["NEG-MSG","s","a"]',
  '["NEG-CLOSE"]',
  '["NEG-CLOSE","s","x"]',
  '["UNKNOWN","s"]',
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
  '["EOSE"]',
  '["EOSE","s","x"]',
  '["CLOSED","s"]',
  '["NOTICE"]',
  '["NOTICE","a","b"]',
  '["AUTH"]',
  '["COUNT","s",{"count":-1}]',
  '["COUNT","s",{"count":1.5}]',
  '["COUNT","s","x"]',
  '["COUNT","s"]',
  '["NEG-MSG","s","abc"]',
  '["NEG-MSG","s",""]',
  '["NEG-ERR","s"]',
  '["NEG-ERR","s",1]',
  '["UNKNOWN","s"]',
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

emit("core.event.serialize", "event-serialize.json", serialize);
emit("core.event.sign", "event-sign.json", signed);
emit(
  "core.event.validate",
  "event-validate.json",
  invalidEvents.map((c) => ({ reason: c.reason, raw: c.raw, error: "EventValidationError" })),
);
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

emit("core.kind.classify", "kind-classify.json", kinds);
emit("core.tag.address", "tag-address.json", [...addressCases, ...addressFormats]);
emit("core.hex", "hex.json", hexCases);
emit("core.url.normalize", "url-normalize.json", normalizeUrlCases);
console.log("wrote vectors/core/*.json");
