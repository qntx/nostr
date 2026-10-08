import { readFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { Keys } from "../../src/core/key.ts";
import { bytesToHex, hexToBytes } from "../../src/core/util.ts";
import type { SerializedEventVerifier } from "../../src/core/verifier.ts";

// Official BIP-340 test vectors; nk-vectors asserts the same file in Rust
// (crates/nk-vectors/tests/bip340.rs). Rows sign/verify an arbitrary 32-byte
// "message" — the same (id, pubkey, sig) triple the library's
// SerializedEventVerifier byte path sees, minus the event-hash pre-check (the
// vector message plays the role of the event id).
const csv = readFileSync(
  join(import.meta.dirname, "../../../../vectors/bip340/official.csv"),
  "utf8",
);

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

const allRows: Row[] = csv
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

// Same row filter as the Rust runner (`is_event_id_sized`): only 32-byte
// messages exercise the schnorr byte path. Counts are pinned so the skip set
// cannot grow silently.
const rows = allRows.filter((row) => row.message.length === 64);
const skipped = allRows.length - rows.length;
const signable = rows.filter((row) => row.secretKey !== "");

const byteVerify: SerializedEventVerifier = (_serializedUtf8, id, pubkey, sig) => {
  try {
    return schnorr.verify(sig, id, pubkey);
  } catch {
    return false;
  }
};

describe("vectors/bip340", () => {
  test("row filter matches the Rust runner (15 executed, 4 skipped)", () => {
    expect(rows).toHaveLength(15);
    expect(skipped).toBe(4);
    expect(signable.length).toBeGreaterThan(0);
  });

  test("verify matches the official result column", () => {
    for (const row of rows) {
      const ok = byteVerify(
        new Uint8Array(0),
        hexToBytes(row.message),
        hexToBytes(row.publicKey),
        hexToBytes(row.signature),
      );
      expect(ok, `vector ${row.index}: ${row.comment}`).toBe(row.expected);
    }
  });

  test("Keys derives the vector public key", () => {
    for (const row of signable) {
      const keys = Keys.fromSecretKey(row.secretKey);
      expect(keys.publicKey, `vector ${row.index}`).toBe(row.publicKey.toLowerCase());
    }
  });

  test("aux-rand sign through the library backend reproduces the signature", () => {
    for (const row of signable) {
      const keys = Keys.fromSecretKey(row.secretKey);
      const sig = keys.backend.sign(
        hexToBytes(row.message),
        keys.secretKey.bytes,
        hexToBytes(row.auxRand),
      );
      expect(bytesToHex(sig), `vector ${row.index}`).toBe(row.signature.toLowerCase());
    }
  });
});
