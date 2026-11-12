import { sha256 } from "@noble/hashes/sha2.js";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";

import { bytesToHex, utf8Encoder } from "../src/core/util.ts";
import { getEventHash, hexToBytes, serializeEvent } from "../src/index.ts";
import type { UnsignedEvent } from "../src/index.ts";
import type { PowProgress } from "../src/nips/nip13.ts";
import { getPow, minePow, Nip13Error } from "../src/nips/nip13.ts";
import { stubReportError } from "./helpers/report-error.ts";

const NIP13_EXAMPLE_ID = "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358";

const UNSIGNED: UnsignedEvent = {
  kind: 1,
  tags: [["t", "pow"]],
  content: "It's just me mining my own business",
  created_at: 0,
  pubkey: "79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6",
};

describe("nip13 getPow", () => {
  test("NIP-13 example id has at least 20 leading zero bits", () => {
    expect(getPow(NIP13_EXAMPLE_ID)).toBeGreaterThanOrEqual(20);
    expect(getPow(NIP13_EXAMPLE_ID)).toBe(21);
  });

  test("hex and raw bytes agree", () => {
    expect(getPow(hexToBytes(NIP13_EXAMPLE_ID))).toBe(getPow(NIP13_EXAMPLE_ID));
    expect(getPow("ac4f44bae06a45ebe88cfbd3c66358750159650a26c0d79e8ccaa92457fca4f6")).toBe(0);
    expect(getPow("0000000000000000006cfbd3c66358750159650a26c0d79e8ccaa92457fca4f6")).toBe(73);
  });

  test("non-hex or wrong-length string input throws Nip13Error", () => {
    expect(() => getPow("not-hex")).toThrow(Nip13Error);
    expect(() => getPow("zz".repeat(32))).toThrow(Nip13Error);
    expect(() => getPow("ab".repeat(31))).toThrow(Nip13Error);
    expect(() => getPow("")).toThrow(Nip13Error);
  });
});

describe("nip13 minePow", () => {
  test("mines difficulty 8 without mutating input", async () => {
    const tags = [...UNSIGNED.tags];
    const unsigned: UnsignedEvent = { ...UNSIGNED, tags };
    const mined = await minePow(unsigned, 8);

    expect(getPow(mined.id)).toBeGreaterThanOrEqual(8);
    expect(mined.id).toBe(getEventHash(mined));
    expect(mined.pubkey).toBe(unsigned.pubkey);
    expect(mined.content).toBe(unsigned.content);
    expect(mined.kind).toBe(unsigned.kind);
    expect("sig" in mined).toBe(false);

    const nonce = mined.tags.find((tag) => tag[0] === "nonce");
    expect(nonce?.[2]).toBe("8");
    expect(nonce?.[1]).toMatch(/^\d+$/);
    expect(mined.tags).toContainEqual(["t", "pow"]);

    expect(unsigned.tags).toBe(tags);
    expect(unsigned.tags).toStrictEqual([["t", "pow"]]);
    expect(unsigned.created_at).toBe(0);
  });

  test("mined id equals serializeEvent hashing at several difficulties", async () => {
    for (const difficulty of [4, 8, 12]) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- difficulties are mined one at a time
      const mined = await minePow({ ...UNSIGNED, tags: [...UNSIGNED.tags] }, difficulty);
      expect(getPow(mined.id)).toBeGreaterThanOrEqual(difficulty);
      expect(mined.id).toBe(getEventHash(mined));
      expect(mined.id).toBe(bytesToHex(sha256(utf8Encoder.encode(serializeEvent(mined)))));
      const nonce = mined.tags.find((tag) => tag[0] === "nonce");
      expect(nonce?.[2]).toBe(String(difficulty));
    }
  });

  test("abort rejects with signal.reason", async () => {
    const controller = new AbortController();
    const reason = new Error("user cancelled");
    controller.abort(reason);
    await expect(minePow(UNSIGNED, 32, { signal: controller.signal })).rejects.toBe(reason);
  });
});

describe("nip13 minePow onProgress", () => {
  // vectors/nip13/codec.json mine case: at `now` 1700000042 the UNSIGNED event
  // hits difficulty 12 at nonce 4431. Faking only Date keeps the yield's
  // setTimeout real while pinning the nonce sequence.
  const VECTOR_NOW = 1700000042;
  const VECTOR_ID = "000da6e4441d53ac600a03a7ddbd3fd83ef90df32038ce5d6f6dfa69b6147370";

  afterEach(() => {
    vi.useRealTimers();
  });

  const pinNow = (): void => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(VECTOR_NOW * 1000);
  };

  test("reports strictly increasing hash counts and non-decreasing best pow", async () => {
    pinNow();
    const calls: PowProgress[] = [];
    const mined = await minePow(UNSIGNED, 12, {
      yieldEvery: 50,
      onProgress: (p) => {
        calls.push(p);
      },
    });
    expect(mined.id).toBe(VECTOR_ID);
    // The winner lands at hash 4431; callbacks fire at every 50 losing hashes.
    expect(calls.map((p) => p.hashes)).toStrictEqual(
      Array.from({ length: 88 }, (_, i) => (i + 1) * 50),
    );
    for (const p of calls) {
      expect(p.bestPow).toBeLessThan(12);
    }
    for (let i = 1; i < calls.length; i++) {
      expect(calls[i]!.bestPow).toBeGreaterThanOrEqual(calls[i - 1]!.bestPow);
    }
  });

  test("the mined result is identical with and without onProgress", async () => {
    pinNow();
    const calls: PowProgress[] = [];
    const withProgress = await minePow(UNSIGNED, 12, {
      yieldEvery: 50,
      onProgress: (p) => {
        calls.push(p);
      },
    });
    const withoutProgress = await minePow(UNSIGNED, 12);
    expect(withProgress).toStrictEqual(withoutProgress);
    expect(calls.length).toBeGreaterThan(0);
  });

  test("a throwing onProgress is reported and does not change the result", async () => {
    pinNow();
    const { reported, restore } = stubReportError();
    const boom = new Error("boom");
    try {
      const mined = await minePow(UNSIGNED, 12, {
        yieldEvery: 50,
        onProgress: () => {
          throw boom;
        },
      });
      expect(mined.id).toBe(VECTOR_ID);
      expect(reported.length).toBeGreaterThan(0);
      expect(reported.every((e) => e === boom)).toBe(true);
    } finally {
      restore();
    }
  });

  test("aborting inside onProgress rejects with the abort reason", async () => {
    pinNow();
    const controller = new AbortController();
    const reason = new Error("stop mining");
    let calls = 0;
    await expect(
      minePow(UNSIGNED, 12, {
        yieldEvery: 50,
        signal: controller.signal,
        onProgress: () => {
          calls++;
          controller.abort(reason);
        },
      }),
    ).rejects.toBe(reason);
    expect(calls).toBe(1);
  });
});
