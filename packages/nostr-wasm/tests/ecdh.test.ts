import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { bytesToHex, CryptoError, hexToBytes, nobleBackend } from "@qntx/nostr/core";
import { KeysSigner } from "@qntx/nostr/signer";

import { loadNostrWasm } from "../src/load.ts";
import type { NostrWasm } from "../src/load.ts";
import { readBuiltWasm } from "./read-wasm.ts";

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const PEER_SK = "0000000000000000000000000000000000000000000000000000000000000002";

type Case = { sec: string; pub: string; sharedX: string | null };

const doc = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../vectors/ecdh.json"), "utf8"),
) as { capability: string; cases: Case[] };

const bytes = await readBuiltWasm();
const wasm: NostrWasm = await loadNostrWasm({ module: bytes });

describe("wasm ecdhX", () => {
  test("valid cases match the shared vectors", () => {
    for (const c of doc.cases.filter((c) => c.sharedX !== null)) {
      const x = wasm.ecdhX(hexToBytes(c.sec), hexToBytes(c.pub));
      expect(bytesToHex(x)).toBe(c.sharedX);
    }
  });

  test("invalid cases throw CryptoError", () => {
    for (const c of doc.cases.filter((c) => c.sharedX === null)) {
      expect(() => wasm.ecdhX(hexToBytes(c.sec), hexToBytes(c.pub))).toThrow(CryptoError);
    }
  });

  test("agrees with nobleBackend.ecdhX", () => {
    const sk = hexToBytes(SK_HEX);
    const peer = nobleBackend.publicKey(hexToBytes(PEER_SK));
    expect(wasm.ecdhX(sk, peer)).toStrictEqual(nobleBackend.ecdhX(sk, peer));
  });

  test("KeysSigner routes a nip44 round-trip through the wasm backend", async () => {
    const signer = new KeysSigner(SK_HEX, { backend: wasm });
    const peerPub = bytesToHex(nobleBackend.publicKey(hexToBytes(PEER_SK)));
    const ciphertext = await signer.nip44Encrypt(peerPub, "wasm conversation");
    const noblePeer = new KeysSigner(PEER_SK);
    await expect(noblePeer.nip44Decrypt(signer.keys.publicKey, ciphertext)).resolves.toBe(
      "wasm conversation",
    );
    signer.dispose();
    noblePeer.dispose();
  });
});
