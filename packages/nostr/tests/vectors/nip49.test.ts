import { readFileSync } from "node:fs";
import { join } from "node:path";

import { scryptAsync } from "@noble/hashes/scrypt.js";
import { describe, expect, test } from "vite-plus/test";

import { bytesToHex } from "../../src/core/util.ts";
import { decrypt, Nip49Error } from "../../src/nips/nip49.ts";
import type { Scrypt } from "../../src/nips/nip49.ts";

// Shared vectors regenerated with `bun packages/nostr/scripts/parity/gen/all.ts`.

type CodecCase = {
  secret: string;
  password: string;
  log_n: number;
  key_security: number;
  salt: string;
  nonce: string;
  ncryptsec: string;
};

type CodecInvalid = {
  ncryptsec: string;
  password: string;
  max_log_n: number;
  error: string;
};

type OfficialCase = {
  ncryptsec: string;
  password: string;
  max_log_n: number;
  secret: string;
  key_security: number;
};

type MaxLognCase = {
  input: string;
  password: string;
  maxLogN: number;
  secret?: string;
  error?: string;
};

function load(name: string): unknown {
  return JSON.parse(
    readFileSync(join(import.meta.dirname, `../../../../vectors/nip49/${name}`), "utf8"),
  );
}

const codec = load("codec.json") as { cases: CodecCase[]; invalid: CodecInvalid[] };
const official = load("official.json") as { cases: OfficialCase[] };
const maxLogn = load("max-logn.json") as { cases: MaxLognCase[] };

const maxValid = maxLogn.cases.filter(
  (c): c is MaxLognCase & { secret: string } => c.secret !== undefined,
);
const maxInvalid = maxLogn.cases.filter(
  (c): c is MaxLognCase & { error: string } => c.error !== undefined,
);

function recording(calls: Array<{ password: Uint8Array; salt: Uint8Array }>): Scrypt {
  return async (password, salt, params) => {
    calls.push({ password, salt });
    return scryptAsync(password, salt, {
      ...params,
      maxmem: 128 * params.r * (params.N + params.p + 1),
    });
  };
}

describe("vectors/nip49/official.json", () => {
  test("the spec example decrypts", async () => {
    await Promise.all(
      official.cases.map(async (c) => {
        const result = await decrypt(c.ncryptsec, c.password, { maxLogN: c.max_log_n });
        expect(bytesToHex(result)).toBe(c.secret);
      }),
    );
  });
});

describe("vectors/nip49/codec.json", () => {
  test("valid payloads decrypt to the recorded secret", async () => {
    await Promise.all(
      codec.cases.map(async (c) => {
        const result = await decrypt(c.ncryptsec, c.password, { maxLogN: 22 });
        expect(bytesToHex(result)).toBe(c.secret);
      }),
    );
  });

  test("decomposed and composed passwords derive the same key", () => {
    // One case carries a non-normalized password; its twin carries the NFKC
    // form. Identical ncryptsec outputs prove identical scrypt inputs.
    const decomposed = codec.cases.find((c) => c.password !== c.password.normalize("NFKC"));
    expect(decomposed).toBeDefined();
    const twins = codec.cases.filter((c) => c.ncryptsec === decomposed?.ncryptsec);
    expect(twins).toHaveLength(2);
    const composed = twins.find((c) => c.password === decomposed?.password.normalize("NFKC"));
    expect(composed).toBeDefined();
  });

  test("invalid cases reject with the recorded error", async () => {
    await Promise.all(
      codec.invalid.map(async (c) => {
        const thrown = await decrypt(c.ncryptsec, c.password, { maxLogN: c.max_log_n }).catch(
          (error: unknown) => error,
        );
        expect(thrown).toBeInstanceOf(Nip49Error);
        expect((thrown as Error).name).toBe(c.error);
      }),
    );
  });
});

describe("vectors/nip49/max-logn.json", () => {
  test("payloads at or below maxLogN decrypt", async () => {
    await Promise.all(
      maxValid.map(async (c) => {
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
      maxInvalid.map(async (c) => {
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
