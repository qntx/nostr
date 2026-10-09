/// <reference types="node" />
// Generates vectors/nip44/shared-secret.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// For every official get_conversation_key case the ECDH x-coordinate is
// recorded so both implementations can prove
// `from_shared_secret(ecdh_x(sec1, pub2)) == conversation_key` —
// getConversationKeyFromSharedSecret on the TS side,
// ConversationKey::from_shared_secret on the Rust side.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { hexToBytes } from "../../../src/core/util.ts";
import { getConversationKeyFromSharedSecret } from "../../../src/nips/nip44.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip44");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

type ConversationCase = { sec1: string; pub2: string; conversation_key: string };
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the official vector file shape is fixed upstream
const official = JSON.parse(readFileSync(join(vectors, "official.json"), "utf8")) as {
  v2: { valid: { get_conversation_key: ConversationCase[] } };
};

const cases = official.v2.valid.get_conversation_key.map((row) => {
  const shared = secp256k1
    .getSharedSecret(hexToBytes(row.sec1), hexToBytes(`02${row.pub2}`))
    .subarray(1, 33);
  const conversationKey = getConversationKeyFromSharedSecret(shared);
  if (bytesToHex(conversationKey) !== row.conversation_key) {
    throw new Error(`getConversationKeyFromSharedSecret diverged from the vector for ${row.sec1}`);
  }
  return {
    sec1: row.sec1,
    pub2: row.pub2,
    shared_secret: bytesToHex(shared),
    conversation_key: row.conversation_key,
  };
});

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip44.v2",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  cases,
};
writeFileSync(join(vectors, "shared-secret.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip44 shared-secret: ${cases.length} cases written`);
