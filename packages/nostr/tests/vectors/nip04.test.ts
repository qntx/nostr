import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { hexToBytes } from "../../src/core/util.ts";
import { CryptoError } from "../../src/index.ts";
import { decrypt, decryptFromPubkey } from "../../src/nips/nip04.ts";

// Shared vectors also replayed against rust-nostr by crates/interop; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type Case = {
  sec1: string;
  pub2: string;
  shared_secret: string;
  iv: string;
  plaintext: string;
  payload: string;
};

type InvalidCase = {
  op: "decrypt" | "derive";
  sec1: string;
  pub2: string;
  shared_secret: string;
  payload: string;
  error: string;
};

const { cases, invalid } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip04/codec.json"), "utf8"),
) as { cases: Case[]; invalid: InvalidCase[] };

describe("vectors/nip04/codec.json", () => {
  test("decrypt decrypts every valid payload with the shared secret", () => {
    for (const c of cases) {
      expect(decrypt(c.payload, hexToBytes(c.shared_secret))).toBe(c.plaintext);
    }
  });

  test("decryptFromPubkey decrypts every valid payload with key pairs", () => {
    for (const c of cases) {
      expect(decryptFromPubkey(c.payload, hexToBytes(c.sec1), c.pub2)).toBe(c.plaintext);
    }
  });

  test("decrypt rejects every invalid payload", () => {
    for (const c of invalid.filter((i) => i.op === "decrypt")) {
      expect(c.error).toBe("CryptoError");
      expect(() => decrypt(c.payload, hexToBytes(c.shared_secret))).toThrow(CryptoError);
    }
  });

  test("decryptFromPubkey rejects every invalid case with key pairs", () => {
    for (const c of invalid) {
      expect(c.error).toBe("CryptoError");
      expect(() => decryptFromPubkey(c.payload, hexToBytes(c.sec1), c.pub2)).toThrow(CryptoError);
    }
  });
});
