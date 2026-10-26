/// <reference types="node" />
// Generates vectors/ecdh.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Cases carry the raw x coordinate of the ECDH shared point — the input
// both NIP-04 (AES key) and NIP-44 (HKDF input) derive from. Every
// NIP-44 get_conversation_key case is cross-checked here by re-deriving
// the spec's conversation_key with HKDF-extract(salt="nip44-v2", shared_x).
// Expected values come from an independent reference: @noble/curves
// `getSharedSecret(sec, "02"||pub).slice(1)`.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const sharedX = (sec: string, pub: string): string =>
  bytesToHex(secp256k1.getSharedSecret(hexToBytes(sec), hexToBytes(`02${pub}`)).subarray(1, 33));

type ConversationCase = { sec1: string; pub2: string; conversation_key: string };
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the official vector file shape is fixed upstream
const official = JSON.parse(readFileSync(join(vectors, "nip44/official.json"), "utf8")) as {
  v2: { valid: { get_conversation_key: ConversationCase[] } };
};

type Case = { sec: string; pub: string; sharedX?: string; error?: string };
const cases: Case[] = [];

// NIP-44 spec get_conversation_key cases: assert the spec's
// conversation_key really is HKDF-extract(salt="nip44-v2", shared_x).
for (const row of official.v2.valid.get_conversation_key) {
  const x = hexToBytes(sharedX(row.sec1, row.pub2));
  const extracted = extract(sha256, x, utf8ToBytes("nip44-v2"));
  if (bytesToHex(extracted) !== row.conversation_key) {
    throw new Error(`hkdf_extract diverged from the spec conversation_key for ${row.sec1}`);
  }
  cases.push({ sec: row.sec1, pub: row.pub2, sharedX: bytesToHex(x) });
}

// Fixed-seed pairs: deterministic scalars hashed from fixed labels.
for (let i = 0; i < 8; i++) {
  const sec = sha256(utf8ToBytes(`qntx-ecdh-vector-${i}`));
  const peerSec = sha256(utf8ToBytes(`qntx-ecdh-peer-${i}`));
  const pub = secp256k1.getPublicKey(peerSec, true).subarray(1, 33);
  cases.push({
    sec: bytesToHex(sec),
    pub: bytesToHex(pub),
    sharedX: sharedX(bytesToHex(sec), bytesToHex(pub)),
  });
}

// An x coordinate that does not lift to a curve point: first small x where
// decompressing "02"||x fails — deterministic by construction.
// getSharedSecret throws on a public key that does not lift to a point.
const probeSecHex = "11".repeat(32);
const probeSec = hexToBytes(probeSecHex);
let badX: string | undefined;
for (let i = 0; i < 64; i++) {
  const candidate = i.toString(16).padStart(64, "0");
  try {
    secp256k1.getSharedSecret(probeSec, hexToBytes(`02${candidate}`));
  } catch {
    badX = candidate;
    break;
  }
}
if (badX === undefined) {
  throw new Error("no non-lifting x found in the first 64 candidates");
}

const goodPub = bytesToHex(secp256k1.getPublicKey(probeSec, true).subarray(1, 33));

// Invalid inputs: zero secret, secret = n, x not on curve.
cases.push(
  { sec: "00".repeat(32), pub: goodPub, error: "invalid" },
  {
    sec: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    pub: goodPub,
    error: "invalid",
  },
  { sec: probeSecHex, pub: badX, error: "invalid" },
);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "ecdh",
  source: { kind: "reference", name: "@noble/curves", version },
  cases: cases.map((c) => ({ ...c, sharedX: c.sharedX ?? null })),
};
writeFileSync(join(vectors, "ecdh.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`ecdh: ${cases.length} cases written`);
