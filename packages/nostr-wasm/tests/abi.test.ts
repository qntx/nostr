import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { serializeEvent, verifyEvent } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import { CryptoError, hexToBytes } from "@qntx/nostr/core";

import { instantiateCryptoWasm, wasmVerify, wasmVerifySerialized } from "../src/abi.ts";
import { createNostrWasmLoader } from "../src/instance.ts";
import { readBuiltWasm } from "./read-wasm.ts";

const utf8 = new TextEncoder();

const bytes = await readBuiltWasm();

// A minimal valid module that declares one function import — instantiation
// must refuse it: the byte ABI imports nothing.
const IMPORTING_MODULE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // type section: one () -> () type
  0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
  // import section: "a"."b" func of type 0
  0x02, 0x07, 0x01, 0x01, 0x61, 0x01, 0x62, 0x00, 0x00,
]);

// A minimal valid module exporting `nk_abi_version() -> 2` — the loader must
// refuse an ABI version it does not implement.
const WRONG_VERSION_MODULE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // type section: one () -> i32 type
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
  // function section: one function of type 0
  0x03, 0x02, 0x01, 0x00,
  // export section: func 0 as "nk_abi_version"
  0x07, 0x12, 0x01, 0x0e, 0x6e, 0x6b, 0x5f, 0x61, 0x62, 0x69, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
  0x6f, 0x6e, 0x00, 0x00,
  // code section: i32.const 2; end
  0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x02, 0x0b,
]);

const BIP340_V0_SK = hexToBytes("0000000000000000000000000000000000000000000000000000000000000003");
const BIP340_V0_PK = hexToBytes("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
const BIP340_V0_AUX = new Uint8Array(32);
const BIP340_V0_MSG = new Uint8Array(32);
const BIP340_V0_SIG = hexToBytes(
  "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
);

const wasmLoader = createNostrWasmLoader(async () => {
  await Promise.resolve();
  return bytes;
});
const wasm = await wasmLoader.loadNostrWasm();

describe("nk byte ABI contract", () => {
  test("module declares no imports", async () => {
    const mod = await WebAssembly.compile(new Uint8Array(bytes));
    expect(WebAssembly.Module.imports(mod)).toStrictEqual([]);
  });

  test("a module with imports fails to load", async () => {
    await expect(instantiateCryptoWasm(IMPORTING_MODULE)).rejects.toThrow(
      /must not import anything/,
    );
  });

  test("an ABI version mismatch fails to load", async () => {
    await expect(instantiateCryptoWasm(WRONG_VERSION_MODULE)).rejects.toThrow(CryptoError);
    await expect(instantiateCryptoWasm(WRONG_VERSION_MODULE)).rejects.toThrow(/ABI version/);
  });

  test("views refresh after scratch growth", async () => {
    const exports = await instantiateCryptoWasm(bytes);
    const before = exports.memory.buffer;
    // 4 MiB of serialized input forces the scratch region — and therefore the
    // linear memory — to grow past its initial size, detaching earlier views.
    const big = new Uint8Array(4 * 1024 * 1024);
    expect(wasmVerifySerialized(exports, big, BIP340_V0_MSG, BIP340_V0_PK, BIP340_V0_SIG)).toBe(
      false,
    );
    expect(exports.memory.buffer).not.toBe(before);
    // A normal call afterwards must still read the new buffer correctly.
    expect(wasmVerify(exports, BIP340_V0_MSG, BIP340_V0_PK, BIP340_V0_SIG)).toBe(true);
  });
});

const vectorsDir = join(import.meta.dirname, "../../../vectors");

describe("vectors/bip340/official.csv through the ABI", () => {
  const csv = readFileSync(join(vectorsDir, "bip340/official.csv"), "utf8");
  const columns = csv
    .trim()
    .split("\n")
    .slice(1)
    .filter((line) => line.length > 0)
    .map((line) => line.split(",", 8));
  // Same 32-byte-message filter as the Rust runners.
  const rows = columns
    .filter((cols) => cols.at(4)?.length === 64)
    .map((cols) => ({
      index: cols.at(0) ?? "?",
      secretKey: cols.at(1) ?? "",
      publicKey: cols.at(2) ?? "",
      auxRand: cols.at(3) ?? "",
      message: cols.at(4) ?? "",
      signature: cols.at(5) ?? "",
      expected: cols.at(6) === "TRUE",
    }));
  const signable = rows.filter((row) => row.secretKey !== "" && row.auxRand !== "");

  test("wasm matches noble and the expected column on every 32-byte row", () => {
    expect(rows).toHaveLength(15);
    expect(signable.length).toBeGreaterThan(0);
    for (const row of rows) {
      const msg = hexToBytes(row.message);
      const pk = hexToBytes(row.publicKey);
      const sig = hexToBytes(row.signature);
      let noble = false;
      try {
        noble = schnorr.verify(sig, msg, pk);
      } catch {
        noble = false;
      }
      expect(wasm.verify(msg, pk, sig), `vector ${row.index}`).toBe(row.expected);
      expect(wasm.verify(msg, pk, sig), `vector ${row.index} vs noble`).toBe(noble);
    }
  });

  test("signable rows reproduce their signatures and public keys", () => {
    for (const row of signable) {
      const msg = hexToBytes(row.message);
      const pk = hexToBytes(row.publicKey);
      const sig = hexToBytes(row.signature);
      const sk = hexToBytes(row.secretKey);
      const aux = hexToBytes(row.auxRand);
      expect(wasm.sign(msg, sk, aux), `vector ${row.index} sign`).toStrictEqual(sig);
      expect(wasm.publicKey(sk), `vector ${row.index} publicKey`).toStrictEqual(pk);
    }
  });
});

type SignCase = {
  unsigned: Record<string, unknown>;
  event: Event;
};

type SerializeCase = {
  serialized: string;
  id: string;
};

function readVector<T>(file: string): T[] {
  const doc = JSON.parse(readFileSync(join(vectorsDir, file), "utf8")) as { cases: T[] };
  return doc.cases;
}

describe("vectors/core through the ABI", () => {
  test("event-sign.json: wasm agrees with noble on every case", () => {
    for (const { event } of readVector<SignCase>("core/event-sign.json")) {
      const id = hexToBytes(event.id);
      const pk = hexToBytes(event.pubkey);
      const sig = hexToBytes(event.sig);
      const serialized = utf8.encode(serializeEvent(event));
      expect(wasm.verify(id, pk, sig)).toBe(true);
      expect(wasm.verifySerialized(serialized, id, pk, sig)).toBe(true);
      expect(wasm.verifyEvent({ ...event })).toBe(true);
      expect(verifyEvent({ ...event })).toBe(true);
    }
  });

  test("event-serialize.json: verifySerialized matches sha256 + schnorr semantics", () => {
    for (const { serialized, id } of readVector<SerializeCase>("core/event-serialize.json")) {
      const ser = utf8.encode(serialized);
      const idBytes = hexToBytes(id);
      // A real signature over this id made with our own key.
      const sig = wasm.sign(idBytes, BIP340_V0_SK, BIP340_V0_AUX);
      expect(sig).toHaveLength(64);
      expect(createHash("sha256").update(ser).digest().equals(idBytes)).toBe(true);
      expect(schnorr.verify(sig, idBytes, BIP340_V0_PK)).toBe(true);
      expect(wasm.verifySerialized(ser, idBytes, BIP340_V0_PK, sig)).toBe(true);
      // A mismatched id fails the hash pre-check on both sides.
      const wrong = Uint8Array.from(idBytes);
      wrong[0] = idBytes[0]! ^ 1;
      expect(wasm.verifySerialized(ser, wrong, BIP340_V0_PK, sig)).toBe(false);
    }
  });
});
