/// <reference types="node" />
// Generates vectors/nip49/{official,codec,max-logn}.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// codec.json payloads are built with noble scrypt + XChaCha20-Poly1305
// under FIXED salts/nonces and low log_n (1..4 keeps generation fast),
// so the nk-* Rust crates can replay `encrypt_with` byte-for-byte and
// `decrypt` on every case; TS `decrypt` runs each case here so the
// recorded `ncryptsec`/`error` always reflects the real behaviour.
// Deterministic: a second run is byte-identical.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

import { bytesToHex, hexToBytes, utf8Encoder } from "../../../src/core/util.ts";
import { Bech32MaxSize, encodeBytes } from "../../../src/nips/nip19.ts";
import { decrypt as nip49Decrypt } from "../../../src/nips/nip49.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip49");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "unknown";

const VERSION = 0x02;
const KSB_OFFSET = 2 + 16 + 24;

// The single worked example in the NIP-49 specification
// (https://github.com/nostr-protocol/nips/blob/master/49.md).
const SPEC_EXAMPLE = {
  ncryptsec:
    "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p",
  password: "nostr",
  secret: "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
};
// A second deterministic payload (logn 4, ksb 0x00, empty password) used by
// the max-logn vectors; generated, not spec-sourced.
const LOW_LOGN = {
  ncryptsec:
    "ncryptsec1qgzv73a9ktnwmgyvv24x2xtr6grup2v6an96xgs64z3pmh5etg2k4yryachtlu3tpqwqphhm0pjnq9zmftr0qf4p5lmah4rlz02ucjkawr2s9quau67p3jq3d7yp3kreghs0wdcqpf6pkc8jcgsqrn5l",
  password: "",
  secret: "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
};

/** Builds an ncryptsec exactly as the NIP-49 spec lays out the 91-byte record. */
function buildNcrypted(
  secret: Uint8Array,
  password: string,
  logn: number,
  ksb: number,
  salt: Uint8Array,
  nonce: Uint8Array,
): string {
  const key = scrypt(utf8Encoder.encode(password.normalize("NFKC")), salt, {
    N: 2 ** logn,
    r: 8,
    p: 1,
    dkLen: 32,
    maxmem: 128 * 8 * (2 ** logn + 2),
  });
  try {
    const ciphertext = xchacha20poly1305(key, nonce, Uint8Array.from([ksb])).encrypt(secret);
    return encodeBytes(
      "ncryptsec",
      concatBytes(
        Uint8Array.from([VERSION, logn]),
        salt,
        nonce,
        Uint8Array.from([ksb]),
        ciphertext,
      ),
    );
  } finally {
    key.fill(0);
  }
}

function payloadBytes(ncryptsec: string): Uint8Array {
  const { words } = bech32.decode(ncryptsec, Bech32MaxSize);
  return new Uint8Array(bech32.fromWords(words));
}

function reencode(ncryptsec: string, hrp: string, mutate?: (b: Uint8Array) => void): string {
  const bytes = payloadBytes(ncryptsec);
  if (mutate) {
    mutate(bytes);
  }
  return encodeBytes(hrp, bytes);
}

// ---------------------------------------------------------------------------
// codec.json — generated encrypt_with/decrypt cases at low log_n.
// ---------------------------------------------------------------------------

type Case = {
  secret: string;
  password: string;
  log_n: number;
  key_security: number;
  salt: string;
  nonce: string;
  ncryptsec: string;
};

type InvalidCase = {
  ncryptsec: string;
  password: string;
  max_log_n: number;
  error: string;
};

const cases: Case[] = [];
const invalid: InvalidCase[] = [];

const SECRET_A = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
const SECRET_B = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
const SALT_A = Uint8Array.from({ length: 16 }, (_, i) => i);
const SALT_B = Uint8Array.from({ length: 16 }, (_, i) => 0xf0 + i);
const NONCE_A = Uint8Array.from({ length: 24 }, (_, i) => 0xa0 + i);
const NONCE_B = Uint8Array.from({ length: 24 }, (_, i) => 0x50 + i);

async function valid(
  secret: string,
  password: string,
  logn: number,
  ksb: number,
  salt: Uint8Array,
  nonce: Uint8Array,
): Promise<void> {
  const ncryptsec = buildNcrypted(hexToBytes(secret), password, logn, ksb, salt, nonce);
  const decrypted = await nip49Decrypt(ncryptsec, password, { maxLogN: 22 });
  if (bytesToHex(decrypted) !== secret) {
    throw new Error(`nip49.decrypt diverged on logn=${logn} ksb=${ksb}`);
  }
  cases.push({
    secret,
    password,
    log_n: logn,
    key_security: ksb,
    salt: bytesToHex(salt),
    nonce: bytesToHex(nonce),
    ncryptsec,
  });
}

async function bad(
  reason: string,
  ncryptsec: string,
  password: string,
  maxLogN: number,
): Promise<void> {
  try {
    await nip49Decrypt(ncryptsec, password, { maxLogN });
  } catch (error) {
    invalid.push({
      ncryptsec,
      password,
      max_log_n: maxLogN,
      error: error instanceof Error ? error.name : "Error",
    });
    return;
  }
  throw new Error(`TS decrypt accepted ${reason}`);
}

// Every key-security byte on both secrets.
await valid(SECRET_A, "hunter2", 2, 0x00, SALT_A, NONCE_A);
await valid(SECRET_A, "hunter2", 3, 0x01, SALT_B, NONCE_B);
await valid(SECRET_A, "hunter2", 4, 0x02, SALT_A, NONCE_B);
await valid(SECRET_B, "correct horse battery staple", 1, 0x00, SALT_B, NONCE_A);
// NFKC pairs: the decomposed and composed forms of the same password must
// derive the same key and therefore produce identical payloads.
const NFKC_DECOMPOSED = "ÅΩẛ̣"; // U+212B U+2126 U+1E9B U+0323 (spec example)
const NFKC_COMPOSED = NFKC_DECOMPOSED.normalize("NFKC"); // U+00C5 U+03A9 U+1E69
if (NFKC_DECOMPOSED === NFKC_COMPOSED) {
  throw new Error("NFKC pair collapsed");
}
await valid(SECRET_A, NFKC_DECOMPOSED, 2, 0x02, SALT_A, NONCE_A);
await valid(SECRET_A, NFKC_COMPOSED, 2, 0x02, SALT_A, NONCE_A);
if (cases.at(-1)?.ncryptsec !== cases.at(-2)?.ncryptsec) {
  throw new Error("NFKC forms derived different keys");
}
// A long password spanning astral characters.
await valid(SECRET_B, "密碼🔐 ".repeat(8).trim(), 3, 0x02, SALT_B, NONCE_B);

const [victim] = cases;
if (victim === undefined) {
  throw new Error("missing victim case");
}

// Wrong password: scrypt derives a different key, AEAD rejects.
await bad("wrong password", victim.ncryptsec, `${victim.password} wrong`, 22);
// Bad version byte.
await bad(
  "bad version",
  reencode(victim.ncryptsec, "ncryptsec", (b) => {
    b[0] = 0x01;
  }),
  victim.password,
  22,
);
// A key-security byte other than 0x00/0x01/0x02 (ruling N7).
await bad(
  "bad ksb",
  reencode(victim.ncryptsec, "ncryptsec", (b) => {
    b[KSB_OFFSET] = 0x03;
  }),
  victim.password,
  22,
);
// Payload length other than 91 bytes.
await bad(
  "bad length",
  encodeBytes("ncryptsec", payloadBytes(victim.ncryptsec).subarray(0, 90)),
  victim.password,
  22,
);
// Right checksum, wrong hrp.
await bad("wrong prefix", reencode(victim.ncryptsec, "npub"), victim.password, 22);
// Corrupted ciphertext: flip a ciphertext byte, AEAD rejects.
await bad(
  "corrupted ciphertext",
  reencode(victim.ncryptsec, "ncryptsec", (b) => {
    b[b.length - 1] = 0xff;
  }),
  victim.password,
  22,
);
// A payload that decrypts to an invalid scalar (all zeros — ruling N3).
await bad(
  "invalid scalar",
  buildNcrypted(new Uint8Array(32), victim.password, 2, 0x02, SALT_A, NONCE_A),
  victim.password,
  22,
);
// log_n above the caller's ceiling is rejected before scrypt.
await bad("logn above ceiling", victim.ncryptsec, victim.password, victim.log_n - 1);

// ---------------------------------------------------------------------------
// official.json — the spec's worked example, transcribed.
// ---------------------------------------------------------------------------

const official = {
  schema: 1,
  capability: "nip49.ncryptsec",
  source: {
    kind: "official",
    generator: "https://github.com/nostr-protocol/nips/blob/master/49.md",
    version: null,
    cross_check: null,
    note: "The `ncryptsec` decryption example transcribed from the NIP-49 specification text (log_n=16, ksb=0x00, password 'nostr').",
  },
  cases: [
    {
      ncryptsec: SPEC_EXAMPLE.ncryptsec,
      password: SPEC_EXAMPLE.password,
      max_log_n: 22,
      secret: SPEC_EXAMPLE.secret,
      key_security: 0x00,
    },
  ],
};

// ---------------------------------------------------------------------------
// max-logn.json — the decrypt ceiling contract (unchanged file).
// ---------------------------------------------------------------------------

type MaxLognCase = {
  input: string;
  password: string;
  maxLogN: number;
  secret?: string;
  error?: string;
};

const maxLognCases: MaxLognCase[] = [
  // logn == maxLogN: the ceiling is inclusive, decryption succeeds.
  { input: LOW_LOGN.ncryptsec, password: LOW_LOGN.password, maxLogN: 4, secret: LOW_LOGN.secret },
  {
    input: SPEC_EXAMPLE.ncryptsec,
    password: SPEC_EXAMPLE.password,
    maxLogN: 16,
    secret: SPEC_EXAMPLE.secret,
  },
  // logn > maxLogN: rejected with Nip49Error before scrypt runs.
  { input: LOW_LOGN.ncryptsec, password: LOW_LOGN.password, maxLogN: 3, error: "Nip49Error" },
  {
    input: SPEC_EXAMPLE.ncryptsec,
    password: SPEC_EXAMPLE.password,
    maxLogN: 15,
    error: "Nip49Error",
  },
  // maxLogN itself must be an integer in 1..=22.
  { input: LOW_LOGN.ncryptsec, password: LOW_LOGN.password, maxLogN: 0, error: "Nip49Error" },
  { input: LOW_LOGN.ncryptsec, password: LOW_LOGN.password, maxLogN: 23, error: "Nip49Error" },
  { input: LOW_LOGN.ncryptsec, password: LOW_LOGN.password, maxLogN: 1.5, error: "Nip49Error" },
  // NIP-49 defines only 0x00, 0x01, 0x02 as the key security byte.
  {
    input: reencode(LOW_LOGN.ncryptsec, "ncryptsec", (b) => {
      b[KSB_OFFSET] = 0x03;
    }),
    password: LOW_LOGN.password,
    maxLogN: 4,
    error: "Nip49Error",
  },
];

const maxLognDoc = {
  schema: 1,
  capability: "nip49.ncryptsec",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    cross_check: null,
  },
  cases: maxLognCases,
};

const codecDoc = {
  schema: 1,
  capability: "nip49.ncryptsec",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    cross_check: null,
  },
  cases,
  invalid,
};

mkdirSync(vectors, { recursive: true });
writeFileSync(join(vectors, "official.json"), `${JSON.stringify(official, null, 2)}\n`);
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(codecDoc, null, 2)}\n`);
writeFileSync(join(vectors, "max-logn.json"), `${JSON.stringify(maxLognDoc, null, 2)}\n`);
console.log(
  `nip49: official 1 case, codec ${cases.length} cases / ${invalid.length} failures, max-logn ${maxLognCases.length} cases written`,
);
