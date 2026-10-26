import { readFileSync } from "node:fs";
import { join } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

type Case = { sec: string; pub: string; sharedX: string | null };

const doc = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/ecdh.json"), "utf8"),
) as { capability: string; cases: Case[] };

const sharedX = (c: Case) =>
  secp256k1.getSharedSecret(hexToBytes(c.sec), hexToBytes(`02${c.pub}`)).subarray(1, 33);

describe("vectors/ecdh", () => {
  test("valid cases match getSharedSecret(sec, 02||pub).slice(1)", () => {
    for (const c of doc.cases.filter((c) => c.sharedX !== null)) {
      expect(bytesToHex(sharedX(c))).toBe(c.sharedX);
    }
  });

  test("invalid cases are rejected", () => {
    for (const c of doc.cases.filter((c) => c.sharedX === null)) {
      expect(() => sharedX(c)).toThrow(Error);
    }
  });
});
