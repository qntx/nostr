/// <reference types="node" />
// Generates vectors/nip21/uri.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-21 `nostr:` URI parser's behaviour as frozen vectors
// shared by the TS test suite (tests/vectors/nip21.test.ts) and the nk-* Rust
// crates.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { hexToBytes } from "../../../src/core/util.ts";
import {
  naddrEncode,
  neventEncode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from "../../../src/index.ts";
import { isNostrURI, parseNostrURI } from "../../../src/nips/nip21.ts";
import { encodeEntity, toJson } from "./entities.ts";
import type { EntityJson } from "./entities.ts";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";
const SK = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
const ID = "05bf4c8f85e9c7c58d4f5b5c5cd1a1552d4a1d9b8a4d78d9c4f5a95ba3c4f0a4";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip21");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

/**
 * Case shape: `input` is fed to both `isNostrURI` (`is_uri` records the result — true also holds
 * for well-shaped strings that fail to decode) and `parseNostrURI` (success records
 * `value`/`uri`/`decoded`, failure records the thrown class in `error`).
 */
type Case = {
  input: string;
  is_uri: boolean;
  value?: string;
  uri?: string;
  decoded?: EntityJson;
  error?: string;
};

const cases: Case[] = [];

function uriCase(input: string): void {
  const is_uri = isNostrURI(input);
  try {
    const parsed = parseNostrURI(input);
    cases.push({
      input,
      is_uri,
      value: parsed.value,
      uri: parsed.uri,
      decoded: toJson(parsed.decoded),
    });
  } catch (error) {
    cases.push({
      input,
      is_uri,
      error: error instanceof Error ? error.name : "Error",
    });
  }
}

const entity = (e: EntityJson): string => encodeEntity(e);

const npub = npubEncode(PK);
const nsec = nsecEncode(hexToBytes(SK));

// Valid entities of every supported prefix.
for (const e of [
  npub,
  noteEncode(ID),
  nprofileEncode({ pubkey: PK, relays: ["wss://relay.example.com", "wss://r.例え.jp"] }),
  neventEncode({ id: ID, relays: ["wss://relay.example.com"], author: PK2, kind: 1 }),
  naddrEncode({ identifier: "profile", pubkey: PK, kind: 0, relays: ["wss://r.例え.jp/パス"] }),
]) {
  uriCase(`nostr:${e}`);
}
// Case-insensitive scheme and entity.
uriCase(`NOSTR:${npub}`);
uriCase(`NoStR:${npub.toUpperCase()}`);
uriCase(`nostr:${npub.toUpperCase()}`);
// nsec is excluded by NIP-21 (both raw and uppercased).
uriCase(`nostr:${nsec}`);
uriCase(`nostr:${nsec.toUpperCase()}`);
// Missing scheme, missing separator, empty entity, wrong scheme.
uriCase(npub);
uriCase("nostr:");
uriCase("nostr:npub");
uriCase(`https:${npub}`);
// Bad charset: `!`, space, `b` in the data part, emoji.
uriCase(`nostr:${npub}!`);
uriCase(`nostr:${npub} `);
uriCase(`nostr:${entity({ type: "npub", pubkey: PK })}b`.replace("1", "1b"));
uriCase(`nostr:${npub}⚡`);
// Shape-valid but undecodable: mixed case, corrupted checksum, unknown prefix.
const mixed = `nostr:n${npub.slice(1, 2).toUpperCase()}${npub.slice(2)}`;
uriCase(mixed);
uriCase(`nostr:${npub.slice(0, -1)}x`);
uriCase(`nostr:${entity({ type: "note", id: ID }).replace("note", "nfoo")}`);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip21.uri",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  cases,
};
writeFileSync(join(vectors, "uri.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip21 uri: ${cases.length} cases written`);
