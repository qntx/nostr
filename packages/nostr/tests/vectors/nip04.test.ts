import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { hexToBytes } from "../../src/core/util.ts";
import { CryptoError } from "../../src/index.ts";
import { decrypt, decryptWithSharedSecret } from "../../src/nips/nip04.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
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
  test("decryptWithSharedSecret decrypts every valid payload", () => {
    for (const c of cases) {
      expect(decryptWithSharedSecret(hexToBytes(c.shared_secret), c.payload)).toBe(c.plaintext);
    }
  });

  test("decrypt decrypts every valid payload with key pairs", () => {
    for (const c of cases) {
      expect(decrypt(hexToBytes(c.sec1), c.pub2, c.payload)).toBe(c.plaintext);
    }
  });

  test("decryptWithSharedSecret rejects every invalid payload", () => {
    for (const c of invalid.filter((i) => i.op === "decrypt")) {
      expect(c.error).toBe("CryptoError");
      expect(() => decryptWithSharedSecret(hexToBytes(c.shared_secret), c.payload)).toThrow(
        CryptoError,
      );
    }
  });

  test("decrypt rejects every invalid case with key pairs", () => {
    for (const c of invalid) {
      expect(c.error).toBe("CryptoError");
      expect(() => decrypt(hexToBytes(c.sec1), c.pub2, c.payload)).toThrow(CryptoError);
    }
  });
});
