/// <reference types="node" />
// Generates vectors/nip13/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-13 `getPow`/`minePow` semantics as frozen vectors shared
// by the TS test suite (tests/vectors/nip13.test.ts) and the nk-* Rust crates.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { getEventHash } from "../../../src/core/event.ts";
import type { UnsignedEvent } from "../../../src/core/event.ts";
import { bytesToHex, hexToBytes } from "../../../src/core/util.ts";
import { getPow } from "../../../src/nips/nip13.ts";

const PK = "79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6";
const PK2 = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip13");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

// ── getPow: leading zero bits ─────────────────────────────────────────────

/** A 32-byte id whose hex has exactly `bits` leading zero bits. */
function idWithPow(bits: number): string {
  const bytes = new Uint8Array(32).fill(0xff);
  let remaining = bits;
  for (let i = 0; i < 32 && remaining > 0; i++) {
    const take = Math.min(8, remaining);
    // `take` zero bits followed by a 1 (or a zero byte when take === 8).
    bytes[i] = take === 8 ? 0 : 2 ** (7 - take);
    remaining -= take;
  }
  return bytesToHex(bytes);
}

type PowCase =
  | { id: string; bits: number }
  | { input: string; bits?: number; error?: string; rust: false };

const powCases: PowCase[] = [];
// Every bit count through the first byte, then sparse coverage of the rest,
// including the 255/256 boundary.
for (const bits of [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 23, 24, 25, 31, 32, 33, 40, 63, 64, 65, 127, 128,
  129, 200, 255, 256,
]) {
  const id = idWithPow(bits);
  if (getPow(hexToBytes(id)) !== bits || getPow(id) !== bits) {
    throw new Error(`generator bug: idWithPow(${bits})`);
  }
  powCases.push({ id, bits });
}
// The NIP-13 spec example id.
powCases.push({ id: "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358", bits: 21 });

// String-input cases the Rust `pow(&EventId)` cannot express — getPow accepts
// any-case hex and throws Nip13Error otherwise.
const upperId = idWithPow(10).toUpperCase();
powCases.push({ input: upperId, bits: 10, rust: false });
const mixedId = idWithPow(12);
powCases.push({
  input: `${mixedId.slice(0, 8).toUpperCase()}${mixedId.slice(8)}`,
  bits: 12,
  rust: false,
});
for (const bad of ["not-hex", "zz".repeat(32), "ab".repeat(31), "", "0".repeat(65)]) {
  powCases.push({ input: bad, error: "Nip13Error", rust: false });
}

// ── minePow: the deterministic core ───────────────────────────────────────
// `minePow` itself is not vectorable (it reads the wall clock); what is
// deterministic is the search at a fixed `now`: nonce 1, 2, 3, … until the id
// has enough leading zeros. `nonce`/`id` record the first hit.

type MineCase = {
  unsigned: UnsignedEvent;
  difficulty: number;
  now: number;
  nonce: string;
  id: string;
};

function mineCase(unsigned: UnsignedEvent, difficulty: number, now: number): MineCase {
  for (let n = 1; ; n++) {
    const event: UnsignedEvent = {
      ...unsigned,
      created_at: now,
      tags: [...unsigned.tags, ["nonce", String(n), String(difficulty)]],
    };
    const id = getEventHash(event);
    if (getPow(id) >= difficulty) {
      return { unsigned, difficulty, now, nonce: String(n), id };
    }
    if (n > 20_000_000) {
      throw new Error("generator: no nonce found within cap");
    }
  }
}

const base: UnsignedEvent = {
  kind: 1,
  tags: [["t", "pow"]],
  content: "It's just me mining my own business",
  created_at: 0,
  pubkey: PK,
};

const mineCases: MineCase[] = [
  // Difficulty 0 always hits on the first attempt.
  mineCase(base, 0, 0),
  mineCase(base, 4, 1_700_000_000),
  mineCase(base, 8, 1_700_000_000),
  // `now` after the event's created_at: the result carries `now`.
  mineCase(base, 12, 1_700_000_042),
  // A different event: several existing tags, non-ASCII + escaped content.
  mineCase(
    {
      kind: 30023,
      tags: [
        ["d", "article-ñ"],
        ["t", "émoji ⚡"],
        ["e", "ab".repeat(32)],
      ],
      content: 'line\nbreak "quotes" \\ 控制字符 and emoji 🚀',
      created_at: 1_600_000_000,
      pubkey: PK2,
    },
    10,
    1_600_000_001,
  ),
  // Empty tags and empty content.
  mineCase({ kind: 0, tags: [], content: "", created_at: 42, pubkey: PK }, 8, 43),
];

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip13.pow",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  pow: powCases,
  mine: mineCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip13 codec: ${powCases.length} pow + ${mineCases.length} mine cases written`);
