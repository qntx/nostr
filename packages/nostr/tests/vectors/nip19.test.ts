import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { HexError } from "../../src/core/error.ts";
import { bytesToHex, hexToBytes } from "../../src/core/util.ts";
import {
  Nip19Error,
  naddrEncode,
  neventEncode,
  nip19Decode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from "../../src/index.ts";
import type { DecodedResult } from "../../src/nips/nip19.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`. The runner executes both
// vectors/nip19/codec.json and vectors/nip19/official.json.
type EntityJson =
  | { type: "nprofile"; pubkey: string; relays: string[] }
  | { type: "nevent"; id: string; relays: string[]; author?: string; kind?: number }
  | { type: "naddr"; identifier: string; pubkey: string; kind: number; relays: string[] }
  | { type: "nsec"; secret: string }
  | { type: "npub"; pubkey: string }
  | { type: "note"; id: string };

type Case = {
  input?: string;
  encode?: EntityJson;
  decoded?: EntityJson;
  encoded?: string;
  error?: string;
};

function readVector(name: string): Case[] {
  const doc = JSON.parse(
    readFileSync(join(import.meta.dirname, "../../../../vectors/nip19", name), "utf8"),
  ) as { cases: Case[] };
  return doc.cases;
}

// Each arm assigns rather than returns so the lint sees a single exit.
function toJson(result: DecodedResult): EntityJson {
  let json: EntityJson;
  switch (result.type) {
    case "nprofile":
      json = {
        type: "nprofile",
        pubkey: result.data.pubkey,
        relays: [...(result.data.relays ?? [])],
      };
      break;
    case "nevent":
      json = {
        type: "nevent",
        id: result.data.id,
        relays: [...(result.data.relays ?? [])],
        ...(result.data.author === undefined ? {} : { author: result.data.author }),
        ...(result.data.kind === undefined ? {} : { kind: result.data.kind }),
      };
      break;
    case "naddr":
      json = {
        type: "naddr",
        identifier: result.data.identifier,
        pubkey: result.data.pubkey,
        kind: result.data.kind,
        relays: [...(result.data.relays ?? [])],
      };
      break;
    case "nsec":
      json = { type: "nsec", secret: bytesToHex(result.data) };
      break;
    case "npub":
      json = { type: "npub", pubkey: result.data };
      break;
    case "note":
      json = { type: "note", id: result.data };
      break;
  }
  return json;
}

function encodeEntity(entity: EntityJson): string {
  let encoded: string;
  switch (entity.type) {
    case "nprofile":
      encoded = nprofileEncode({ pubkey: entity.pubkey, relays: entity.relays });
      break;
    case "nevent":
      encoded = neventEncode({
        id: entity.id,
        relays: entity.relays,
        ...(entity.author === undefined ? {} : { author: entity.author }),
        ...(entity.kind === undefined ? {} : { kind: entity.kind }),
      });
      break;
    case "naddr":
      encoded = naddrEncode({
        identifier: entity.identifier,
        pubkey: entity.pubkey,
        kind: entity.kind,
        relays: entity.relays,
      });
      break;
    case "nsec":
      encoded = nsecEncode(hexToBytes(entity.secret));
      break;
    case "npub":
      encoded = npubEncode(entity.pubkey);
      break;
    case "note":
      encoded = noteEncode(entity.id);
      break;
  }
  return encoded;
}

const ENCODE_ERRORS: Record<string, typeof Nip19Error | typeof HexError> = {
  Nip19Error,
  HexError,
};

type DecodeValidCase = { input: string; decoded: EntityJson; encoded: string };
type DecodeInvalidCase = { input: string };
type EncodeValidCase = { encode: EntityJson; decoded: EntityJson; encoded: string };
type EncodeInvalidCase = { encode: EntityJson; error: typeof Nip19Error | typeof HexError };

// Case partitioning happens at describe scope: the no-conditional-in-test
// lint rejects conditionals (and multi-argument expects) in test bodies.
function partition(
  cases: Case[],
  file: string,
): {
  decodeValid: DecodeValidCase[];
  decodeInvalid: DecodeInvalidCase[];
  encodeValid: EncodeValidCase[];
  encodeInvalid: EncodeInvalidCase[];
} {
  const decodeValid: DecodeValidCase[] = [];
  const decodeInvalid: DecodeInvalidCase[] = [];
  const encodeValid: EncodeValidCase[] = [];
  const encodeInvalid: EncodeInvalidCase[] = [];
  for (const [i, c] of cases.entries()) {
    const label = `${file} case ${i}`;
    if (c.input !== undefined) {
      if (c.error === undefined) {
        if (c.decoded === undefined || c.encoded === undefined) {
          throw new Error(`malformed ${label}: decode case needs decoded+encoded`);
        }
        decodeValid.push({ input: c.input, decoded: c.decoded, encoded: c.encoded });
      } else {
        decodeInvalid.push({ input: c.input });
      }
      continue;
    }
    if (c.encode === undefined) {
      throw new Error(`malformed ${label}: needs input or encode`);
    }
    if (c.error === undefined) {
      if (c.decoded === undefined || c.encoded === undefined) {
        throw new Error(`malformed ${label}: encode case needs decoded+encoded`);
      }
      encodeValid.push({ encode: c.encode, decoded: c.decoded, encoded: c.encoded });
      continue;
    }
    const error = ENCODE_ERRORS[c.error];
    if (error === undefined) {
      throw new Error(`malformed ${label}: unknown error class ${c.error}`);
    }
    encodeInvalid.push({ encode: c.encode, error });
  }
  return { decodeValid, decodeInvalid, encodeValid, encodeInvalid };
}

describe.each(["codec.json", "official.json"])("vectors/nip19/%s", (file) => {
  const { decodeValid, decodeInvalid, encodeValid, encodeInvalid } = partition(
    readVector(file),
    file,
  );

  test("decode: valid inputs decode and re-encode canonically", () => {
    for (const c of decodeValid) {
      const decoded = toJson(nip19Decode(c.input));
      expect(decoded).toStrictEqual(c.decoded);
      expect(encodeEntity(decoded)).toBe(c.encoded);
    }
  });

  test("decode: invalid inputs throw Nip19Error", () => {
    for (const c of decodeInvalid) {
      expect(() => nip19Decode(c.input)).toThrow(Nip19Error);
    }
  });

  test("encode: valid entities encode and decode back", () => {
    for (const c of encodeValid) {
      const encoded = encodeEntity(c.encode);
      expect(encoded).toBe(c.encoded);
      expect(toJson(nip19Decode(encoded))).toStrictEqual(c.decoded);
    }
  });

  test("encode: invalid entities throw the recorded class", () => {
    for (const c of encodeInvalid) {
      expect(() => encodeEntity(c.encode)).toThrow(c.error);
    }
  });
});
