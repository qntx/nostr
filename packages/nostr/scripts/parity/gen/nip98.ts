/// <reference types="node" />
// Generates vectors/nip98/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-98 `getToken`/`unpackEventFromToken`/`validateAuthEvent`
// semantics as frozen vectors shared by the TS test suite
// (tests/vectors/nip98.test.ts) and the nk-* Rust crates.
//
// Events are signed deterministically: a fixed secret key plus a fixed BIP-340
// auxiliary rand injected through the `SigningBackend` (same aux path as
// vectors/core), so Rust's `Keys::sign_event_with_aux` reproduces `id`/`sig`
// byte-for-byte. `getToken` serializes in the canonical wire order
// (id, pubkey, created_at, kind, tags, content, sig), so its output is the
// token both languages produce.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { base64 } from "@scure/base";

import type { Event, EventTemplate } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import type { SigningBackend } from "../../../src/core/key.ts";
import { bytesToHex, hexToBytes, utf8Encoder } from "../../../src/core/util.ts";
import { getToken } from "../../../src/nips/nip98.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip98");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const SECRET_KEY = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const AUX = "42".repeat(32);
const NOW = 1_700_000_000;

const auxBytes = hexToBytes(AUX);
const backend: SigningBackend = {
  publicKey: (sk) => schnorr.getPublicKey(sk),
  sign: (id, sk) => schnorr.sign(id, sk, auxBytes),
};
const keys = Keys.fromSecretKey(SECRET_KEY, backend);

function sign(template: EventTemplate): Event {
  return signEvent({ ...template, pubkey: keys.publicKey }, keys);
}

/** The raw bytes `hashPayload` feeds SHA-256 for a TS payload argument. */
function payloadBytes(payload: unknown): Uint8Array {
  if (typeof payload === "string") {
    return utf8Encoder.encode(payload);
  }
  if (payload instanceof Uint8Array) {
    return payload;
  }
  return utf8Encoder.encode(JSON.stringify(payload));
}

type AuthCase = {
  url: string;
  method: string;
  /** Raw request body as hex; absent means no payload argument. */
  payload_hex?: string;
  /** Non-bytes payload (JSON.stringify'd by TS) — Rust-incompatible. */
  payload_json?: unknown;
  content: string;
  created_at: number;
  event: unknown;
  token: string;
  header: string;
  rust?: false;
};

type UnpackCase = {
  token: string;
  event?: unknown;
  error?: string;
};

type ValidateCase = {
  event: unknown;
  url: string;
  method: string;
  payload_hex?: string;
  payload_json?: unknown;
  now: number;
  max_skew_secs: number;
  result: boolean;
  rust?: false;
};

const authCases: AuthCase[] = [];
const unpackCases: UnpackCase[] = [];
const validateCases: ValidateCase[] = [];

async function authCase(
  url: string,
  method: string,
  payload: unknown,
  content: string,
  created_at: number,
  rust: boolean,
): Promise<{ event: Event; token: string }> {
  let signed: Event | undefined;
  const token = await getToken(
    url,
    method,
    (template) => {
      const event = sign(template);
      signed = event;
      return event;
    },
    { content, payload, now: created_at },
  );
  if (signed === undefined) {
    throw new Error("generator bug: signer was not called");
  }
  const event = signed;
  authCases.push({
    url,
    method,
    ...(payload === undefined ? {} : { payload_hex: bytesToHex(payloadBytes(payload)) }),
    ...(typeof payload === "object" && !(payload instanceof Uint8Array) && payload !== null
      ? { payload_json: payload }
      : {}),
    content,
    created_at,
    event,
    token,
    header: `Nostr ${token}`,
    ...(rust ? {} : { rust: false as const }),
  });
  return { event, token };
}

const primary = await authCase(
  "https://api.example.com/upload?x=1",
  "POST",
  undefined,
  "",
  NOW,
  true,
);
const payloadSigned = await authCase(
  "https://api.example.com/upload?x=1",
  "POST",
  new Uint8Array([1, 2, 3, 0, 255]),
  "",
  NOW,
  true,
);
await authCase(
  "https://api.example.com/upload",
  "PUT",
  "raw-body-string",
  "Uploading media file",
  NOW,
  true,
);
await authCase("https://api.example.com/", "get", undefined, "émoji ⚡ content", NOW, true);
// Empty-string payload is still a payload (SHA-256 of empty bytes).
await authCase("https://api.example.com/", "HEAD", "", "", NOW, true);
// Object payloads are JSON.stringify'd — the Rust API takes raw bytes only.
await authCase("https://api.example.com/", "POST", { name: "file.png", size: 12 }, "", NOW, false);

// A token with real '=' padding, for the unpadded-acceptance case: the wire
// JSON length must not be a multiple of 3 — vary the content length.
const padCandidates = await Promise.all(
  Array.from({ length: 16 }, async (_, i) => {
    let signed: Event | undefined;
    const token = await getToken(
      "https://api.example.com/",
      "GET",
      (t) => {
        const event = sign(t);
        signed = event;
        return event;
      },
      { content: "x".repeat(i), now: NOW },
    );
    return { token, event: signed };
  }),
);
const padded = padCandidates.find((c) => c.token.endsWith("="));
if (padded?.event === undefined) {
  throw new Error("generator bug: could not produce a padded token");
}
const padToken = padded.token;

const goodToken = primary.token;
const goodEvent = primary.event;

unpackCases.push(
  { token: goodToken, event: goodEvent },
  { token: `Nostr ${goodToken}`, event: goodEvent },
  { token: `nostr\t${goodToken}`, event: goodEvent },
  { token: `NOSTR  ${goodToken}`, event: goodEvent },
  { token: `nOsTr\n${goodToken}`, event: goodEvent },
  // U+FEFF is JS regex `\s` → the scheme still strips.
  { token: `nostr\u{FEFF}${goodToken}`, event: goodEvent },
  // Missing `=` padding is accepted (the spec example is unpadded).
  { token: padToken.replace(/=+$/, ""), event: padded.event },
  { token: "", error: "missing token" },
  // "nostr" alone does not match /^nostr\s+/ → decoded as base64; length mod
  // 4 == 1 pads to `===`, which is non-canonical → encoding error.
  { token: "nostr", error: "invalid token encoding" },
  { token: "   ", error: "invalid token encoding" },
  // The scheme strips but leaves nothing to decode → not a "{" payload.
  { token: "nostr ", error: "invalid token" },
  { token: "!!!", error: "invalid token encoding" },
  // Single-char token: rem 1 → `A===` is rejected like @scure/base.
  { token: "A", error: "invalid token encoding" },
  // U+0085 NEL is NOT JS `\s` → no strip; non-base64 char → encoding error.
  { token: `nostr\u{0085}${goodToken}`, error: "invalid token encoding" },
  // Valid base64 that does not decode to a "{"-prefixed JSON object.
  { token: base64.encode(utf8Encoder.encode("hello")), error: "invalid token" },
  { token: base64.encode(utf8Encoder.encode("{x")), error: "invalid token JSON" },
  { token: base64.encode(utf8Encoder.encode("{}")), error: "token is not a signed event" },
  {
    token: base64.encode(utf8Encoder.encode('{"id":123}')),
    error: "token is not a signed event",
  },
);

// The unsigned form of a real event parses as JSON but is not signed.
{
  const unsigned = {
    pubkey: primary.event.pubkey,
    created_at: primary.event.created_at,
    kind: primary.event.kind,
    tags: primary.event.tags,
    content: primary.event.content,
  };
  unpackCases.push({
    token: base64.encode(utf8Encoder.encode(JSON.stringify(unsigned))),
    error: "token is not a signed event",
  });
}

function validateCase(
  event: Event,
  url: string,
  method: string,
  payload: unknown,
  now: number,
  maxSkewSecs: number,
  result: boolean,
  rust = true,
): void {
  validateCases.push({
    event,
    url,
    method,
    ...(payload === undefined ? {} : { payload_hex: bytesToHex(payloadBytes(payload)) }),
    ...(typeof payload === "object" && !(payload instanceof Uint8Array) && payload !== null
      ? { payload_json: payload }
      : {}),
    now,
    max_skew_secs: maxSkewSecs,
    result,
    ...(rust ? {} : { rust: false as const }),
  });
}

const URL = "https://api.example.com/upload?x=1";

validateCase(primary.event, URL, "POST", undefined, NOW, 60, true);
validateCase(primary.event, URL, "post", undefined, NOW, 60, true);
validateCase(primary.event, URL, "POST", undefined, NOW + 60, 60, true);
validateCase(primary.event, URL, "POST", undefined, NOW + 61, 60, false);
validateCase(primary.event, URL, "POST", undefined, NOW - 60, 60, true);
validateCase(primary.event, URL, "POST", undefined, NOW - 61, 60, false);
validateCase(primary.event, URL, "POST", undefined, NOW, 0, true);
validateCase(primary.event, URL, "POST", undefined, NOW + 5, 4, false);
validateCase(primary.event, "https://other.example.com/", "POST", undefined, NOW, 60, false);
validateCase(primary.event, URL, "GET", undefined, NOW, 60, false);
// Payload tag present but the caller does not check it → passes.
validateCase(payloadSigned.event, URL, "POST", undefined, NOW, 60, true);
validateCase(payloadSigned.event, URL, "POST", new Uint8Array([1, 2, 3, 0, 255]), NOW, 60, true);
validateCase(payloadSigned.event, URL, "POST", new Uint8Array([1, 2, 3]), NOW, 60, false);
// An event without a payload tag fails a required payload check.
validateCase(primary.event, URL, "POST", new Uint8Array([1]), NOW, 60, false);
// The object-payload path is TS-only.
validateCase(payloadSigned.event, URL, "POST", { whatever: true }, NOW, 60, false, false);

// The first `u`/`method` tag wins: hand-built tag orderings.
{
  const dupFirst = sign({
    kind: 27235,
    created_at: NOW,
    tags: [
      ["u", URL],
      ["u", "https://wrong.example/"],
      ["method", "POST"],
    ],
    content: "",
  });
  validateCase(dupFirst, URL, "POST", undefined, NOW, 60, true);
  validateCase(dupFirst, "https://wrong.example/", "POST", undefined, NOW, 60, false);

  const dupLast = sign({
    kind: 27235,
    created_at: NOW,
    tags: [
      ["u", "https://wrong.example/"],
      ["u", URL],
      ["method", "POST"],
    ],
    content: "",
  });
  validateCase(dupLast, URL, "POST", undefined, NOW, 60, false);
}

// Wrong kind, still correctly signed.
{
  const wrongKind = sign({
    kind: 1,
    created_at: NOW,
    tags: [
      ["u", URL],
      ["method", "POST"],
    ],
    content: "",
  });
  validateCase(wrongKind, URL, "POST", undefined, NOW, 60, false);
}

// Tampered content → the id/signature no longer verify.
validateCase({ ...primary.event, content: "tampered" }, URL, "POST", undefined, NOW, 60, false);

// Missing method tag.
{
  const noMethod = sign({
    kind: 27235,
    created_at: NOW,
    tags: [["u", URL]],
    content: "",
  });
  validateCase(noMethod, URL, "POST", undefined, NOW, 60, false);
}

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip98.http-auth",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    note: "signed with a fixed key and fixed BIP-340 aux (SigningBackend injection); tokens are base64 of the wire-order event JSON",
  },
  secret_key: SECRET_KEY,
  aux: AUX,
  auth: authCases,
  unpack: unpackCases,
  validate: validateCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip98 codec: ${authCases.length} auth + ${unpackCases.length} unpack + ${validateCases.length} validate cases written`,
);
