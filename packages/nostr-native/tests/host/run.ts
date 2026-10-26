#!/usr/bin/env bun
/**
 * Host test for the C verifier core — no simulator required. Generates `vectors.generated.h`
 * (gitignored) from the shared BIP-340 vectors in `vectors/bip340/official.csv`, NIST SHA-256
 * cases, and Nostr events signed with
 *
 * @qntx/nostr (expected results computed by `verifyEvent`), compiles the core with ASan+UBSan, and
 * runs it. Exits non-zero on any failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  bytesToHex,
  finalizeEvent,
  hexToBytes,
  serializeEvent,
  verifyEvent,
} from "@qntx/nostr/core";
import type { Event } from "@qntx/nostr/core";

const hostDir = import.meta.dirname;
const packageDir = join(hostDir, "..", "..");

const utf8Encoder = new TextEncoder();

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const OTHER_SK_HEX = "0000000000000000000000000000000000000000000000000000000000000001";

const EVENT_COUNT = 200;
const TAMPERED_COUNT = 50;

class Emit {
  blobs: string[] = [];
  private count = 0;

  blob(bytes: Uint8Array): string {
    const name = `blob_${this.count++}`;
    this.blobs.push(
      `static const unsigned char ${name}[] = {${[...bytes]
        .map((b) => `0x${b.toString(16).padStart(2, "0")}`)
        .join(",")}};`,
    );
    return name;
  }

  fixed(bytes: Uint8Array): string {
    return `{${[...bytes].map((b) => `0x${b.toString(16).padStart(2, "0")}`).join(",")}}`;
  }
}

function line(...values: string[]): string {
  return values.join("");
}

function* eventVectors(emit: Emit): Generator<string> {
  const events: Event[] = [];
  for (let i = 0; i < EVENT_COUNT; i += 1) {
    events.push(
      finalizeEvent(
        {
          kind: 1,
          content: `nostr-native vector ${i} — héllo 世界`,
          created_at: 1_800_000_000 + i,
          tags: [["t", `tag-${i % 7}`]],
        },
        SK_HEX,
      ),
    );
  }

  const emitEvent = (event: {
    serialized: Uint8Array;
    id: Uint8Array;
    pubkey: Uint8Array;
    sig: Uint8Array;
    expected: 0 | 1;
    name: string;
  }): string => {
    const serialized = emit.blob(event.serialized);
    return line(
      `{${serialized}, ${event.serialized.length}, ${emit.fixed(event.id)}, `,
      `${emit.fixed(event.pubkey)}, ${emit.fixed(event.sig)}, ${event.expected}, `,
      `"${event.name}"}`,
    );
  };

  for (const [i, event] of events.entries()) {
    const serialized = utf8Encoder.encode(serializeEvent(event));
    const id = hexToBytes(event.id);
    const pubkey = hexToBytes(event.pubkey);
    const sig = hexToBytes(event.sig);
    // Fresh copy — finalizeEvent pre-marks its output as verified in the object-identity cache.
    const expected = verifyEvent({ ...event }) ? 1 : 0;
    if (expected !== 1) {
      throw new Error(`generated event ${i} does not verify`);
    }
    yield emitEvent({ serialized, id, pubkey, sig, expected, name: `event-${i}` });

    if (i >= TAMPERED_COUNT) {
      continue;
    }
    // Tampered serialized bytes: id check must fail (same event shape via verifyEvent).
    const badContent = { ...event, content: `${event.content} tampered` };
    yield emitEvent({
      serialized: utf8Encoder.encode(serializeEvent(badContent)),
      id,
      pubkey,
      sig,
      expected: verifyEvent(badContent) ? 1 : 0,
      name: `event-${i}-tampered-content`,
    });
    // Tampered id: hash gate must reject.
    const badId = new Uint8Array(id);
    badId[0] = (badId[0]! + 1) % 256;
    yield emitEvent({
      serialized,
      id: badId,
      pubkey,
      sig,
      expected: verifyEvent({ ...event, id: bytesToHex(badId) }) ? 1 : 0,
      name: `event-${i}-tampered-id`,
    });
    // Tampered pubkey: a different valid x-only key — BIP-340 verify must fail.
    const otherPubkey = hexToBytes(
      finalizeEvent({ kind: 1, content: "x", created_at: 1, tags: [] }, OTHER_SK_HEX).pubkey,
    );
    yield emitEvent({
      serialized,
      id,
      pubkey: otherPubkey,
      sig,
      expected: verifyEvent({ ...event, pubkey: bytesToHex(otherPubkey) }) ? 1 : 0,
      name: `event-${i}-tampered-pubkey`,
    });
    // Tampered sig: flip one byte.
    const badSig = new Uint8Array(sig);
    badSig[7] = (badSig[7]! + 1) % 256;
    yield emitEvent({
      serialized,
      id,
      pubkey,
      sig: badSig,
      expected: verifyEvent({ ...event, sig: bytesToHex(badSig) }) ? 1 : 0,
      name: `event-${i}-tampered-sig`,
    });
  }
}

function* schnorrVectors(emit: Emit): Generator<string> {
  const csv = readFileSync(
    join(packageDir, "..", "..", "vectors", "bip340", "official.csv"),
    "utf8",
  );
  for (const row of csv.trim().split("\n").slice(1)) {
    const fields = row.split(",");
    const [index, , pubkeyHex, , messageHex, sigHex, result] = fields;
    if (pubkeyHex === undefined || sigHex === undefined || result === undefined) {
      throw new Error(`malformed BIP-340 row: ${row}`);
    }
    // Rows with arbitrary-length messages exercise schnorr verify directly — the full verifier
    // can only reach the signature check when sha256(serialized) equals id, so a fixed-size id.
    const msg = hexToBytes((messageHex ?? "").toLowerCase());
    const pubkey = hexToBytes(pubkeyHex.toLowerCase());
    const sig = hexToBytes(sigHex.toLowerCase());
    const expected = result === "TRUE" ? 1 : 0;
    const name = `bip340-${index ?? "?"}`;
    const expectedSanity = schnorr.verify(sig, msg, pubkey);
    if (expectedSanity !== (expected === 1)) {
      throw new Error(`BIP-340 vector ${index ?? "?"}: noble disagrees with the CSV result`);
    }
    const msgName = emit.blob(msg);
    yield line(
      `{${msgName}, ${msg.length}, ${emit.fixed(pubkey)}, ${emit.fixed(sig)}, `,
      `${expected}, "${name}"}`,
    );
  }
}

// BIP-340 rows carrying a secret key and a 32-byte message: the C signer must reproduce the CSV
// signature byte-for-byte, and public-key derivation must match the CSV pubkey column.
function* signVectors(emit: Emit): Generator<string> {
  const emitSign = (v: {
    seckey: Uint8Array;
    aux: Uint8Array;
    msg: Uint8Array;
    sig: Uint8Array;
    pubkey: Uint8Array;
    name: string;
  }): string =>
    line(
      `{${emit.fixed(v.seckey)}, ${emit.fixed(v.aux)}, ${emit.fixed(v.msg)}, `,
      `${emit.fixed(v.sig)}, ${emit.fixed(v.pubkey)}, "${v.name}"}`,
    );

  const csv = readFileSync(
    join(packageDir, "..", "..", "vectors", "bip340", "official.csv"),
    "utf8",
  );
  for (const row of csv.trim().split("\n").slice(1)) {
    const [index, skHex, pubkeyHex, auxHex, messageHex, sigHex, result] = row.split(",");
    if (
      skHex === undefined ||
      skHex === "" ||
      pubkeyHex === undefined ||
      auxHex === undefined ||
      sigHex === undefined ||
      result !== "TRUE"
    ) {
      continue;
    }
    const msg = hexToBytes((messageHex ?? "").toLowerCase());
    if (msg.length !== 32) {
      continue;
    }
    const seckey = hexToBytes(skHex.toLowerCase());
    const aux = hexToBytes(auxHex.toLowerCase());
    const sig = hexToBytes(sigHex.toLowerCase());
    const pubkey = hexToBytes(pubkeyHex.toLowerCase());
    const nobleSig = schnorr.sign(msg, seckey, aux);
    if (bytesToHex(nobleSig) !== bytesToHex(sig)) {
      throw new Error(`BIP-340 vector ${index ?? "?"}: noble sign disagrees with the CSV`);
    }
    yield emitSign({ seckey, aux, msg, sig, pubkey, name: `bip340-sign-${index ?? "?"}` });
  }

  // One deterministic aux per generated event: C must reproduce noble's signature exactly.
  const sk = hexToBytes(SK_HEX);
  for (let i = 0; i < EVENT_COUNT; i += 1) {
    const aux = sha256(utf8Encoder.encode(`nostr-native aux ${i}`));
    const msg = sha256(utf8Encoder.encode(`nostr-native sign id ${i}`));
    yield emitSign({
      seckey: sk,
      aux,
      msg,
      sig: schnorr.sign(msg, sk, aux),
      pubkey: schnorr.getPublicKey(sk),
      name: `event-sign-${i}`,
    });
  }
}

function badSeckeyRows(emit: Emit): string {
  const n = hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
  const nPlusOne = new Uint8Array(n);
  nPlusOne[31] = (nPlusOne[31]! + 1) % 256;
  const cases: Array<[string, Uint8Array]> = [
    ["sk-zero", new Uint8Array(32)],
    ["sk-n", n],
    ["sk-n-plus-1", nPlusOne],
    ["sk-ff", new Uint8Array(32).fill(0xff)],
  ];
  return cases.map(([name, bytes]) => `{${emit.fixed(bytes)}, "${name}"}`).join(",\n");
}

function* sha256Vectors(emit: Emit): Generator<string> {
  const inputs: Array<[string, Uint8Array]> = [
    ["sha256-empty", new Uint8Array(0)],
    ["sha256-abc", utf8Encoder.encode("abc")],
    [
      "sha256-448bit",
      utf8Encoder.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ],
    ["sha256-1m-a", new Uint8Array(1_000_000).fill(0x61)],
  ];
  for (const [name, data] of inputs) {
    const expected = sha256(data);
    const blob = emit.blob(data);
    yield line(`{${blob}, ${data.length}, ${emit.fixed(expected)}, "${name}"}`);
  }
}

function generateVectors(): string {
  const emit = new Emit();
  const shaRows = [...sha256Vectors(emit)];
  const schnorrRows = [...schnorrVectors(emit)];
  const eventRows = [...eventVectors(emit)];
  const signRows = [...signVectors(emit)];
  const badSkRows = badSeckeyRows(emit);

  return [
    "/* generated by tests/host/run.ts — do not edit */",
    "#include <stddef.h>",
    "",
    ...emit.blobs,
    "",
    `static const sha_case SHA256_CASES[] = {\n${shaRows.join(",\n")}\n};`,
    `static const schnorr_case SCHNORR_CASES[] = {\n${schnorrRows.join(",\n")}\n};`,
    `static const event_case EVENT_CASES[] = {\n${eventRows.join(",\n")}\n};`,
    `static const sign_case SIGN_CASES[] = {\n${signRows.join(",\n")}\n};`,
    `static const bad_seckey_case BAD_SECKEYS[] = {\n${badSkRows}\n};`,
    "",
  ].join("\n");
}

function basename(path: string): string {
  return path.split("/").pop() ?? path;
}

/**
 * Symbol guard: React Native pods are statically linked into one binary, so the module must not
 * export unprefixed `secp256k1_*` symbols — they would collide with any other pod embedding
 * libsecp256k1 (the vendor script namespaces every identifier to `nostr_native_secp256k1_`; the
 * shared core adds the `nostr_core_` prefix). Compiles the production configuration (no
 * NOSTR_NATIVE_TEST, same -D module flags) of every native translation unit and fails if a defined
 * external symbol lacks the `nostr_native_` prefix.
 */
function checkSymbolNamespace(buildDir: string): void {
  const sources = [
    join(packageDir, "cpp", "nostr_core.c"),
    join(packageDir, "cpp", "nostr_native.c"),
    join(packageDir, "vendor/secp256k1/src/precomputed_ecmult.c"),
    join(packageDir, "vendor/secp256k1/src/precomputed_ecmult_gen.c"),
  ];
  const offenders: string[] = [];
  let exported = 0;
  for (const source of sources) {
    const object = join(buildDir, `${basename(source)}.o`);
    execFileSync("cc", [
      "-std=c11",
      "-O1",
      "-c",
      "-D_DEFAULT_SOURCE",
      "-DENABLE_MODULE_ECDH",
      "-DENABLE_MODULE_EXTRAKEYS",
      "-DENABLE_MODULE_SCHNORRSIG",
      `-I${join(packageDir, "cpp")}`,
      `-I${join(packageDir, "vendor/secp256k1/include")}`,
      `-I${join(packageDir, "vendor/secp256k1/src")}`,
      source,
      "-o",
      object,
    ]);
    // nm -g -P prints "name type value" identically on GNU and macOS/llvm nm.
    const listing = execFileSync("nm", ["-g", "-P", object], { encoding: "utf8" });
    for (const row of listing.split("\n")) {
      const [raw, type] = row.split(/\s+/);
      if (raw === undefined || raw === "" || type === "U") {
        continue; // blank row or undefined symbol
      }
      // Mach-O prefixes C symbols with one leading underscore.
      const name = process.platform === "darwin" && raw.startsWith("_") ? raw.slice(1) : raw;
      exported += 1;
      if (!name.startsWith("nostr_native_") && !name.startsWith("nostr_core_")) {
        offenders.push(`${name} (${basename(source)})`);
      }
    }
  }
  if (offenders.length > 0) {
    throw new Error(
      `exported symbols missing the nostr_native_/nostr_core_ prefix: ${offenders.join(", ")}`,
    );
  }
  console.log(`symbol guard: ${exported} exported symbols checked, all nostr_*`);
}

function main(): void {
  const header = generateVectors();
  const headerPath = join(hostDir, "vectors.generated.h");
  writeFileSync(headerPath, header);
  console.log(
    `generated ${headerPath.split("/").pop() ?? "?"} (${(header.length / 1024).toFixed(0)} KiB)`,
  );

  const buildDir = mkdtempSync(join(tmpdir(), "nostr-native-host-"));
  checkSymbolNamespace(buildDir);
  const binary = join(buildDir, "host-test");
  execFileSync(
    "cc",
    [
      "-std=c11",
      "-O1",
      "-g",
      "-fsanitize=address,undefined",
      "-Wall",
      "-Wextra",
      "-Werror",
      // The vendored library legitimately leaves static helpers unused per config — keep -Werror
      // for everything else.
      "-Wno-unused-function",
      // glibc hides arc4random_buf and clock_gettime behind _DEFAULT_SOURCE
      // when compiling strict ISO C; both exist on every targeted glibc.
      "-D_DEFAULT_SOURCE",
      "-DENABLE_MODULE_ECDH",
      "-DENABLE_MODULE_EXTRAKEYS",
      "-DENABLE_MODULE_SCHNORRSIG",
      "-DNOSTR_NATIVE_TEST",
      `-I${join(packageDir, "cpp")}`,
      `-I${hostDir}`,
      join(packageDir, "cpp", "nostr_core.c"),
      join(packageDir, "cpp", "nostr_native.c"),
      join(packageDir, "vendor/secp256k1/src/precomputed_ecmult.c"),
      join(packageDir, "vendor/secp256k1/src/precomputed_ecmult_gen.c"),
      join(hostDir, "main.c"),
      "-o",
      binary,
    ],
    { stdio: "inherit" },
  );
  execFileSync(binary, [], { stdio: "inherit" });
}

main();
