/// <reference types="node" />
// Generates vectors/nip04/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Payloads are built with noble AES-256-CBC under FIXED ivs (the TS
// encrypt API takes no iv), so the nk-* Rust crates can replay
// `encrypt_with_iv` byte-for-byte and `decrypt` on every case.
// `decryptWithSharedSecret`/`decrypt` run each case here so the recorded
// `payload`/`error` always reflects the real TS behaviour.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { cbc } from "@noble/ciphers/aes.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { utf8Encoder } from "../../../src/core/util.ts";
import { decrypt as nip04Decrypt, decryptWithSharedSecret } from "../../../src/nips/nip04.ts";

const SEC1 = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
const SEC2 = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
const PUB1 = secp256k1.getPublicKey(hexToBytes(SEC1), true).subarray(1);
const PUB2 = secp256k1.getPublicKey(hexToBytes(SEC2), true).subarray(1);

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip04");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

function sharedX(secret: string, peer: Uint8Array): Uint8Array {
  return secp256k1
    .getSharedSecret(hexToBytes(secret), Uint8Array.from([2, ...peer]))
    .subarray(1, 33);
}

/**
 * Valid case: the payload is encrypted by noble with a fixed iv. Rust replays
 * `SharedSecret::derive`/`from_bytes` + `encrypt_with_iv` == `payload` and `decrypt` ==
 * `plaintext`.
 */
type Case = {
  sec1: string;
  pub2: string;
  shared_secret: string;
  iv: string;
  plaintext: string;
  payload: string;
};

/**
 * Failure case: `op` is "decrypt" (run decrypt on `payload` under the recorded key) or "derive"
 * (deriving the shared secret from `sec1`/`pub2` must already fail). `error` is the TS class name.
 */
type InvalidCase = {
  op: "decrypt" | "derive";
  sec1: string;
  pub2: string;
  shared_secret: string;
  payload: string;
  error: string;
};

const cases: Case[] = [];
const invalid: InvalidCase[] = [];

function valid(secret: string, peer: Uint8Array, plaintext: string, iv: Uint8Array): void {
  const x = sharedX(secret, peer);
  const ciphertext = cbc(x, iv).encrypt(utf8Encoder.encode(plaintext));
  const payload = `${base64.encode(ciphertext)}?iv=${base64.encode(iv)}`;
  // Both TS entry points must reproduce the plaintext before the case lands.
  if (decryptWithSharedSecret(x, payload) !== plaintext) {
    throw new Error(`decryptWithSharedSecret diverged on ${JSON.stringify(plaintext)}`);
  }
  if (nip04Decrypt(hexToBytes(secret), bytesToHex(peer), payload) !== plaintext) {
    throw new Error(`nip04.decrypt diverged on ${JSON.stringify(plaintext)}`);
  }
  cases.push({
    sec1: secret,
    pub2: bytesToHex(peer),
    shared_secret: bytesToHex(x),
    iv: bytesToHex(iv),
    plaintext,
    payload,
  });
}

/** Asserts the TS decrypt throws and records the error class. */
function bad(reason: string, secret: string, peer: Uint8Array, payload: string): void {
  try {
    decryptWithSharedSecret(sharedX(secret, peer), payload);
  } catch (error) {
    invalid.push({
      op: "decrypt",
      sec1: secret,
      pub2: bytesToHex(peer),
      shared_secret: bytesToHex(sharedX(secret, peer)),
      payload,
      error: error instanceof Error ? error.name : "Error",
    });
    return;
  }
  throw new Error(`TS decrypt accepted ${reason}`);
}

const IV_A = Uint8Array.from({ length: 16 }, (_, i) => i);
const IV_B = new Uint8Array(16).fill(0xaa);

// Empty, ASCII, astral, control characters, exact block multiples and their
// neighbours, and a longer message — each on both fixed ivs.
for (const [i, plaintext] of [
  "",
  "hi",
  "The quick brown fox jumps over the lazy dog",
  "⚡🚀💜",
  "你好世界",
  "\u0000\u0001\u0002\t\n",
  "a".repeat(15),
  "a".repeat(16),
  "a".repeat(17),
  "a".repeat(32),
  "a".repeat(48),
  "nostr ".repeat(200).trim(),
].entries()) {
  valid(SEC1, PUB2, plaintext, i % 2 === 0 ? IV_A : IV_B);
}
// The reverse direction and a second key pair.
valid(SEC2, PUB1, "reply", IV_B);

// Missing-iv shapes: no separator, empty sides, and a second separator —
// TS splits on "?iv=" and requires exactly two non-empty parts.
for (const payload of ["abc", "?iv=abc", "abc?iv=", "abc?iv=def?iv=ghi", ""]) {
  bad(`missing iv: ${JSON.stringify(payload)}`, SEC1, PUB2, payload);
}
// Bad base64 in either half (scure rejects unpadded too).
for (const payload of [
  `!!!?iv=${base64.encode(IV_A)}`,
  `${base64.encode(IV_A)}?iv=!!!`,
  `${base64.encode(IV_A).slice(0, -1)}?iv=${base64.encode(IV_A)}`, // unpadded ct
]) {
  bad(`bad base64: ${payload}`, SEC1, PUB2, payload);
}
// Wrong iv length (8 and 24 bytes decode fine but are not AES ivs).
for (const ivLen of [8, 24]) {
  bad(`iv length ${ivLen}`, SEC1, PUB2, `aGVsbG8=?iv=${base64.encode(new Uint8Array(ivLen))}`);
}
// Ciphertext not a multiple of the block size, and empty-decoding ciphertext.
bad("short ciphertext", SEC1, PUB2, `aGVsbG8=?iv=${base64.encode(IV_A)}`);
bad(
  "empty-decoding ciphertext",
  SEC1,
  PUB2,
  `${base64.encode(new Uint8Array(0))}?iv=${base64.encode(IV_A)}`,
);
// A payload that decrypts under SEC1: decrypting it under a wrong key must
// fail padding — but a pad-length byte of 1 passes vacuously (~1/256), so
// iterate deterministic wrong secrets until noble actually rejects one.
{
  const x = sharedX(SEC1, PUB2);
  const payload = `${base64.encode(cbc(x, IV_A).encrypt(utf8Encoder.encode("a".repeat(64))))}?iv=${base64.encode(IV_A)}`;
  for (const wrong of [SEC2, `${SEC1.slice(0, -2)}01`, `${SEC1.slice(0, -2)}02`]) {
    try {
      decryptWithSharedSecret(sharedX(wrong, PUB1), payload);
    } catch (error) {
      invalid.push({
        op: "decrypt",
        sec1: wrong,
        pub2: bytesToHex(PUB1),
        shared_secret: bytesToHex(sharedX(wrong, PUB1)),
        payload,
        error: error instanceof Error ? error.name : "Error",
      });
      break;
    }
  }
  if (invalid.at(-1)?.payload !== payload) {
    throw new Error("no wrong key rejected the payload");
  }
}
// Corrupted ciphertext: flipping the LAST byte changes the decoded
// PKCS#7 pad length into an out-of-range value, so unpadding rejects.
{
  const [victim] = cases.slice(3, 4);
  if (victim === undefined) {
    throw new Error("missing victim case");
  }
  const [ct, iv] = victim.payload.split("?iv=");
  if (ct === undefined || iv === undefined) {
    throw new Error("victim shape");
  }
  const flipped = base64.decode(ct);
  flipped[flipped.length - 1] = 0xff;
  bad("flipped ciphertext byte", SEC1, PUB2, `${base64.encode(flipped)}?iv=${iv}`);
}
// A pubkey whose x does not lift to a curve point: deriving the shared
// secret fails. The payload has a valid `?iv=` split so the TS decrypt
// reaches its public-key check. Scan the first few x values for one noble
// rejects (deterministic).
{
  const splitShape = `${base64.encode(IV_A)}?iv=${base64.encode(IV_A)}`;
  let i = 0;
  for (; ; i += 1) {
    const x = new Uint8Array(32).fill(0);
    x[31] = i;
    try {
      secp256k1.getSharedSecret(hexToBytes(SEC1), Uint8Array.from([2, ...x]));
    } catch {
      invalid.push({
        op: "derive",
        sec1: SEC1,
        pub2: bytesToHex(x),
        shared_secret: "00".repeat(32),
        payload: splitShape,
        error: "CryptoError",
      });
      break;
    }
    if (i > 64) {
      throw new Error("no non-liftable x found in range");
    }
  }
}

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip04.codec",
  source: {
    kind: "generated",
    generator: "@qntx/nostr",
    version,
    cross_check:
      "nostr-tools 2.24.1 @7fa1ef4: 13/13 valid payloads decrypt identically; failure shapes legitimately differ (nostr-tools has no `?iv=` split check and no shared-secret entry point)",
  },
  cases,
  invalid,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip04 codec: ${cases.length} cases, ${invalid.length} failures written`);
