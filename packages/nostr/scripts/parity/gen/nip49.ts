/// <reference types="node" />
// Generates vectors/nip49/max-logn.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the NIP-49 decrypt ceiling contract (maxLogN) and the key-security-byte
// ruling as frozen vectors; deterministic, driven by the NIP-49 spec payloads so a
// second run is byte-identical.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { bech32 } from "@scure/base";

import { Bech32MaxSize, encodeBytes } from "../../../src/nips/nip19.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip49");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "unknown";

// NIP-49 spec payloads (https://github.com/nostr-protocol/nips/blob/master/49.md):
// logn 4 / ksb 0x00 and the canonical logn 16 example.
const SPEC_LOGN4 = {
  ncryptsec:
    "ncryptsec1qgzv73a9ktnwmgyvv24x2xtr6grup2v6an96xgs64z3pmh5etg2k4yryachtlu3tpqwqphhm0pjnq9zmftr0qf4p5lmah4rlz02ucjkawr2s9quau67p3jq3d7yp3kreghs0wdcqpf6pkc8jcgsqrn5l",
  password: "",
  secret: "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
};
const SPEC_LOGN16 = {
  ncryptsec:
    "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p",
  password: "nostr",
  secret: "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
};

const KSB_OFFSET = 2 + 16 + 24;

// Re-encode a spec payload with a different key security byte; deterministic
// because only the ksb byte changes before bech32 re-encoding.
function withKeySecurityByte(ncryptsec: string, ksb: number): string {
  const { words } = bech32.decode(ncryptsec, Bech32MaxSize);
  const bytes = new Uint8Array(bech32.fromWords(words));
  bytes[KSB_OFFSET] = ksb;
  return encodeBytes("ncryptsec", bytes);
}

type Case = {
  input: string;
  password: string;
  maxLogN: number;
  secret?: string;
  error?: string;
};

const cases: Case[] = [
  // logn == maxLogN: the ceiling is inclusive, decryption succeeds.
  {
    input: SPEC_LOGN4.ncryptsec,
    password: SPEC_LOGN4.password,
    maxLogN: 4,
    secret: SPEC_LOGN4.secret,
  },
  {
    input: SPEC_LOGN16.ncryptsec,
    password: SPEC_LOGN16.password,
    maxLogN: 16,
    secret: SPEC_LOGN16.secret,
  },
  // logn > maxLogN: rejected with Nip49Error before scrypt runs.
  { input: SPEC_LOGN4.ncryptsec, password: SPEC_LOGN4.password, maxLogN: 3, error: "Nip49Error" },
  {
    input: SPEC_LOGN16.ncryptsec,
    password: SPEC_LOGN16.password,
    maxLogN: 15,
    error: "Nip49Error",
  },
  // maxLogN itself must be an integer in 1..=22.
  { input: SPEC_LOGN4.ncryptsec, password: SPEC_LOGN4.password, maxLogN: 0, error: "Nip49Error" },
  { input: SPEC_LOGN4.ncryptsec, password: SPEC_LOGN4.password, maxLogN: 23, error: "Nip49Error" },
  { input: SPEC_LOGN4.ncryptsec, password: SPEC_LOGN4.password, maxLogN: 1.5, error: "Nip49Error" },
  // NIP-49 defines only 0x00, 0x01, 0x02 as the key security byte.
  {
    input: withKeySecurityByte(SPEC_LOGN4.ncryptsec, 0x03),
    password: SPEC_LOGN4.password,
    maxLogN: 4,
    error: "Nip49Error",
  },
];

const doc = {
  schema: 1,
  capability: "nip49.ncryptsec",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    cross_check: null,
  },
  cases,
};

mkdirSync(vectors, { recursive: true });
writeFileSync(join(vectors, "max-logn.json"), `${JSON.stringify(doc, null, 2)}\n`);
