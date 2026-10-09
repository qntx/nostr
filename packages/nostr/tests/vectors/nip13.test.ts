import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { getEventHash } from "../../src/core/event.ts";
import type { UnsignedEvent } from "../../src/core/event.ts";
import { hexToBytes } from "../../src/core/util.ts";
import { getPow, Nip13Error } from "../../src/nips/nip13.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type SharedPowCase = { id: string; bits: number };
type TsOnlyPowCase = { input: string; bits?: number; error?: string; rust: false };
type PowCase = SharedPowCase | TsOnlyPowCase;

type MineCase = {
  unsigned: UnsignedEvent;
  difficulty: number;
  now: number;
  nonce: string;
  id: string;
};

const { pow, mine } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip13/codec.json"), "utf8"),
) as { pow: PowCase[]; mine: MineCase[] };

const sharedPow = pow.filter((c): c is SharedPowCase => "id" in c);
const tsOnlyOk = pow.filter(
  (c): c is TsOnlyPowCase & { bits: number } => "input" in c && c.error === undefined,
);
const tsOnlyBad = pow.filter(
  (c): c is TsOnlyPowCase & { error: string } => "input" in c && c.error !== undefined,
);

describe("vectors/nip13 pow", () => {
  test.each(sharedPow)("case %#", (c) => {
    // The hex-string and raw-bytes forms agree.
    expect(getPow(c.id)).toBe(c.bits);
    expect(getPow(hexToBytes(c.id))).toBe(c.bits);
  });

  test.each(tsOnlyOk)("any-case hex case %#", (c) => {
    expect(getPow(c.input)).toBe(c.bits);
  });

  test.each(tsOnlyBad)("invalid string case %#", (c) => {
    expect(() => getPow(c.input)).toThrow(Nip13Error);
  });
});

describe("vectors/nip13 mine", () => {
  test.each(mine)("case %#", (c) => {
    // The recorded nonce/id is reproducible from the unsigned event: the
    // vector is the deterministic core of minePow (nonce 1, 2, … at a fixed
    // `now`). Rebuilding the event and hashing must give the recorded id.
    const event: UnsignedEvent = {
      ...c.unsigned,
      created_at: c.now,
      tags: [...c.unsigned.tags, ["nonce", c.nonce, String(c.difficulty)]],
    };
    expect(getEventHash(event)).toBe(c.id);
    expect(getPow(c.id)).toBeGreaterThanOrEqual(c.difficulty);
  });
});
