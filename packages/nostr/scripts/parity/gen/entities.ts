/// <reference types="node" />
// Shared NIP-19 entity helpers for the vector generators and the differential
// runner: the normalized `EntityJson` shape recorded in vector files, the
// `DecodedResult` → `EntityJson` normalizer, and the `EntityJson` → string
// encoder built on the public API.

import { bytesToHex, hexToBytes } from "../../../src/core/util.ts";
import {
  naddrEncode,
  neventEncode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from "../../../src/index.ts";
import type { DecodedResult } from "../../../src/nips/nip19.ts";

/** Normalized entity object recorded in `decoded`/`encode` fields. */
export type EntityJson =
  | { type: "nprofile"; pubkey: string; relays: string[] }
  | {
      type: "nevent";
      id: string;
      relays: string[];
      author?: string;
      kind?: number;
    }
  | { type: "naddr"; identifier: string; pubkey: string; kind: number; relays: string[] }
  | { type: "nsec"; secret: string }
  | { type: "npub"; pubkey: string }
  | { type: "note"; id: string };

/** Normalizes a `DecodedResult` into the vector's entity shape. */
export function toJson(result: DecodedResult): EntityJson {
  // Each arm assigns rather than returns so the lint sees a single exit.
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

/** Encodes a vector entity with the public TS API. */
export function encodeEntity(entity: EntityJson): string {
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
