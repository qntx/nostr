import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/core/util.ts";
import { Nip21Error, isNostrURI, parseNostrURI } from "../../src/index.ts";
import type { DecodedResult } from "../../src/nips/nip19.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type EntityJson =
  | { type: "nprofile"; pubkey: string; relays: string[] }
  | { type: "nevent"; id: string; relays: string[]; author?: string; kind?: number }
  | { type: "naddr"; identifier: string; pubkey: string; kind: number; relays: string[] }
  | { type: "nsec"; secret: string }
  | { type: "npub"; pubkey: string }
  | { type: "note"; id: string };

type Case = {
  input: string;
  is_uri: boolean;
  value?: string;
  uri?: string;
  decoded?: EntityJson;
  error?: string;
};

const { cases } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip21/uri.json"), "utf8"),
) as { cases: Case[] };

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

const parseValid = cases.filter((c) => c.error === undefined);
const parseInvalid = cases.filter((c) => c.error !== undefined);

describe("vectors/nip21/uri.json", () => {
  test("isNostrURI records the shape check", () => {
    for (const c of cases) {
      expect(isNostrURI(c.input)).toBe(c.is_uri);
    }
  });

  test("parseNostrURI decodes valid URIs", () => {
    for (const c of parseValid) {
      const parsed = parseNostrURI(c.input);
      expect(parsed.value).toBe(c.value);
      expect(parsed.uri).toBe(c.uri);
      expect(toJson(parsed.decoded)).toStrictEqual(c.decoded);
    }
  });

  test("parseNostrURI rejects invalid URIs with Nip21Error", () => {
    for (const c of parseInvalid) {
      expect(() => parseNostrURI(c.input)).toThrow(Nip21Error);
    }
  });
});
