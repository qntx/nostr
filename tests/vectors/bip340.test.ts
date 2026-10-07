import { readFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

// Official BIP-340 test vectors; nk-wasm asserts the same file in Rust
// (crates/nk-wasm/tests/bip340.rs).
const csv = readFileSync(join(import.meta.dirname, "../../vectors/bip340/official.csv"), "utf8");

type Row = {
  index: string;
  secretKey: string;
  publicKey: string;
  auxRand: string;
  message: string;
  signature: string;
  expected: boolean;
  comment: string;
};

const rows: Row[] = csv
  .trim()
  .split("\n")
  .slice(1)
  .filter((line) => line.length > 0)
  .map((line) => {
    const [
      index = "",
      secretKey = "",
      publicKey = "",
      auxRand = "",
      message = "",
      signature = "",
      result = "",
      comment = "",
    ] = line.split(",", 8);
    return {
      index,
      secretKey,
      publicKey,
      auxRand,
      message,
      signature,
      expected: result === "TRUE",
      comment,
    };
  });

function tryVerify(sig: string, msg: string, pk: string): boolean {
  try {
    return schnorr.verify(hexToBytes(sig), hexToBytes(msg), hexToBytes(pk));
  } catch {
    return false;
  }
}

describe("vectors/bip340", () => {
  test("verify matches the official result column", () => {
    for (const row of rows) {
      expect(tryVerify(row.signature, row.message, row.publicKey)).toBe(row.expected);
    }
  });
});

const signable = rows.filter((row) => row.secretKey !== "" && row.expected);

describe("vectors/bip340 sign", () => {
  test("public key derivation matches", () => {
    for (const row of signable) {
      expect(bytesToHex(schnorr.getPublicKey(hexToBytes(row.secretKey)))).toBe(
        row.publicKey.toLowerCase(),
      );
    }
  });

  test("aux-rand sign reproduces the official signature", () => {
    for (const row of signable) {
      const sig = schnorr.sign(
        hexToBytes(row.message),
        hexToBytes(row.secretKey),
        hexToBytes(row.auxRand),
      );
      expect(bytesToHex(sig)).toBe(row.signature.toLowerCase());
    }
  });
});
