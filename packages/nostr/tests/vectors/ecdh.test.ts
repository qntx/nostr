import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { nobleBackend } from "../../src/core/key.ts";
import { hexToBytes } from "../../src/core/util.ts";

type Case = { sec: string; pub: string; sharedX: string | null };

const doc = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/ecdh.json"), "utf8"),
) as { capability: string; cases: Case[] };

describe("vectors/ecdh", () => {
  test("valid cases match nobleBackend.ecdhX", () => {
    for (const c of doc.cases.filter((c) => c.sharedX !== null)) {
      expect(bytesToHex(nobleBackend.ecdhX(hexToBytes(c.sec), hexToBytes(c.pub)))).toBe(c.sharedX);
    }
  });

  test("invalid cases are rejected", () => {
    for (const c of doc.cases.filter((c) => c.sharedX === null)) {
      expect(() => nobleBackend.ecdhX(hexToBytes(c.sec), hexToBytes(c.pub))).toThrow(Error);
    }
  });
});
