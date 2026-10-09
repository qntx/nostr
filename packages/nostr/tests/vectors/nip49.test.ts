import { readFileSync } from "node:fs";
import { join } from "node:path";

import { scryptAsync } from "@noble/hashes/scrypt.js";
import { describe, expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/core/util.ts";
import { decrypt, Nip49Error } from "../../src/nips/nip49.ts";
import type { Scrypt } from "../../src/nips/nip49.ts";

// Shared vectors regenerated with `bun packages/nostr/scripts/parity/gen/all.ts`.
// The runner asserts the NIP-49 decrypt ceiling contract: success cases return the
// secret, error cases reject with the recorded class before scrypt runs.
type Case = {
  input: string;
  password: string;
  maxLogN: number;
  secret?: string;
  error?: string;
};

const doc = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip49/max-logn.json"), "utf8"),
) as { cases: Case[] };

const valid = doc.cases.filter((c): c is Case & { secret: string } => c.secret !== undefined);
const invalid = doc.cases.filter((c): c is Case & { error: string } => c.error !== undefined);

function recording(calls: Array<{ password: Uint8Array; salt: Uint8Array }>): Scrypt {
  return async (password, salt, params) => {
    calls.push({ password, salt });
    return scryptAsync(password, salt, {
      ...params,
      maxmem: 128 * params.r * (params.N + params.p + 1),
    });
  };
}

describe("vectors/nip49/max-logn.json", () => {
  test("payloads at or below maxLogN decrypt", async () => {
    await Promise.all(
      valid.map(async (c) => {
        const calls: Array<{ password: Uint8Array; salt: Uint8Array }> = [];
        const result = await decrypt(c.input, c.password, {
          maxLogN: c.maxLogN,
          scrypt: recording(calls),
        });
        expect(bytesToHex(result)).toBe(c.secret);
        expect(calls).toHaveLength(1);
      }),
    );
  });

  test("invalid cases reject with the recorded error before scrypt runs", async () => {
    await Promise.all(
      invalid.map(async (c) => {
        const calls: Array<{ password: Uint8Array; salt: Uint8Array }> = [];
        const thrown = await decrypt(c.input, c.password, {
          maxLogN: c.maxLogN,
          scrypt: recording(calls),
        }).catch((error: unknown) => error);
        expect(thrown).toBeInstanceOf(Nip49Error);
        expect((thrown as Error).name).toBe(c.error);
        expect(calls).toHaveLength(0);
      }),
    );
  });
});
