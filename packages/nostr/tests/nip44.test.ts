import { readFileSync } from "node:fs";
import { join } from "node:path";

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex as bytesToHexNoble, hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";

import { bytesToHex, utf8Encoder } from "../src/core/util.ts";
import { KeysSigner } from "../src/index.ts";
import * as nip44 from "../src/nips/nip44.ts";
import {
  DEFAULT_MAX_PAYLOAD_CHARS,
  calcPaddedLen,
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
  getConversationKey,
  getConversationKeyFromSharedSecret,
  getMessageKeys,
} from "../src/nips/nip44.ts";

const dir = import.meta.dirname;
const vectors = JSON.parse(
  readFileSync(join(dir, "../../../vectors/nip44/official.json"), "utf8"),
) as {
  v2: {
    valid: {
      get_conversation_key: Array<{ sec1: string; pub2: string; conversation_key: string }>;
      get_message_keys: {
        conversation_key: string;
        keys: Array<{
          nonce: string;
          chacha_key: string;
          chacha_nonce: string;
          hmac_key: string;
        }>;
      };
      calc_padded_len: Array<[number, number]>;
      encrypt_decrypt: Array<{
        sec1: string;
        sec2: string;
        conversation_key: string;
        nonce: string;
        plaintext: string;
        payload: string;
      }>;
      encrypt_decrypt_long_msg: Array<{
        conversation_key: string;
        nonce: string;
        pattern: string;
        repeat: number;
        plaintext_sha256: string;
        payload_sha256: string;
      }>;
    };
    invalid: {
      encrypt_msg_lengths: number[];
      get_conversation_key: Array<{ sec1: string; pub2: string; note: string }>;
      decrypt: Array<{
        conversation_key: string;
        nonce: string;
        plaintext: string;
        payload: string;
        note: string;
      }>;
    };
  };
};

// vectors/nip44/extended.json — NIP-44 spec-text boundary cases for the
// extended u32 length prefix (payloads recorded as SHA-256 checksums).
const extended = JSON.parse(
  readFileSync(join(dir, "../../../vectors/nip44/extended.json"), "utf8"),
) as {
  cases: Array<{
    pattern: string;
    repeat: number;
    conversation_key: string;
    nonce: string;
    plaintext_sha256: string;
    payload_sha256: string;
  }>;
};

// vectors/nip44/shared-secret.json — generated: the ECDH x-coordinate for
// every official get_conversation_key case.
const sharedSecret = JSON.parse(
  readFileSync(join(dir, "../../../vectors/nip44/shared-secret.json"), "utf8"),
) as {
  cases: Array<{
    sec1: string;
    pub2: string;
    shared_secret: string;
    conversation_key: string;
  }>;
};

describe("nip44", () => {
  test("get_conversation_key vectors", () => {
    for (const row of vectors.v2.valid.get_conversation_key) {
      const key = getConversationKey(hexToBytes(row.sec1), row.pub2);
      expect(bytesToHex(key)).toBe(row.conversation_key);
    }
  });

  // Proves the delegated-signer path: getConversationKeyFromSharedSecret on the
  // recorded ECDH x-coordinate yields the same conversation key.
  test("shared-secret vectors", () => {
    for (const row of sharedSecret.cases) {
      const key = getConversationKeyFromSharedSecret(hexToBytes(row.shared_secret));
      expect(bytesToHex(key)).toBe(row.conversation_key);
    }
  });

  test("get_message_keys vectors", () => {
    const { conversation_key, keys } = vectors.v2.valid.get_message_keys;
    const ck = hexToBytes(conversation_key);
    for (const row of keys) {
      const derived = getMessageKeys(ck, hexToBytes(row.nonce));
      expect(bytesToHex(derived.chacha_key)).toBe(row.chacha_key);
      expect(bytesToHex(derived.chacha_nonce)).toBe(row.chacha_nonce);
      expect(bytesToHex(derived.hmac_key)).toBe(row.hmac_key);
    }
  });

  test("calc_padded_len vectors", () => {
    for (const [input, expected] of vectors.v2.valid.calc_padded_len) {
      expect(calcPaddedLen(input)).toBe(expected);
    }
  });

  test("encrypt_decrypt vectors", () => {
    for (const row of vectors.v2.valid.encrypt_decrypt) {
      const ck = hexToBytes(row.conversation_key);
      const payload = nip44Encrypt(row.plaintext, ck, hexToBytes(row.nonce));
      expect(payload).toBe(row.payload);
      expect(nip44Decrypt(payload, ck)).toBe(row.plaintext);
    }
  });

  test("encrypt_decrypt_long_msg vectors (payload too large to inline)", () => {
    for (const row of vectors.v2.valid.encrypt_decrypt_long_msg) {
      const plaintext = row.pattern.repeat(row.repeat);
      expect(bytesToHexNoble(sha256(utf8Encoder.encode(plaintext)))).toBe(row.plaintext_sha256);
      const ck = hexToBytes(row.conversation_key);
      const payload = nip44Encrypt(plaintext, ck, hexToBytes(row.nonce));
      expect(bytesToHexNoble(sha256(utf8Encoder.encode(payload)))).toBe(row.payload_sha256);
      expect(nip44Decrypt(payload, ck)).toBe(plaintext);
    }
  });

  // NIP-44 extended-prefix boundary vectors from the spec text (44.md): the
  // u16/u32 prefix switch happens at a plaintext length of 65536.
  test("extended length prefix boundary vectors", () => {
    for (const row of extended.cases) {
      const plaintext = row.pattern.repeat(row.repeat);
      const ck = hexToBytes(row.conversation_key);
      const nonce = hexToBytes(row.nonce);
      expect(bytesToHexNoble(sha256(utf8Encoder.encode(plaintext)))).toBe(row.plaintext_sha256);
      const payload = nip44Encrypt(plaintext, ck, nonce);
      expect(bytesToHexNoble(sha256(utf8Encoder.encode(payload)))).toBe(row.payload_sha256);
      expect(nip44Decrypt(payload, ck)).toBe(plaintext);
    }
  });

  test("invalid.get_conversation_key vectors throw", () => {
    for (const row of vectors.v2.invalid.get_conversation_key) {
      expect(() => getConversationKey(hexToBytes(row.sec1), row.pub2)).toThrow(Error);
    }
  });

  test("invalid.decrypt vectors throw", () => {
    for (const row of vectors.v2.invalid.decrypt) {
      expect(() => nip44Decrypt(row.payload, hexToBytes(row.conversation_key))).toThrow(Error);
    }
  });

  test("invalid.encrypt_msg_lengths: 0 throws; >=65536 encrypt via u32 prefix", () => {
    const ck = hexToBytes("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
    const lengths = vectors.v2.invalid.encrypt_msg_lengths;
    // The vector list predates the extended u32 length prefix: under the
    // current spec only sub-minimum lengths are invalid; >=65536 is valid.
    // Decrypting these oversized payloads needs a raised maxPayloadChars.
    // Every length >= 65536 takes the same u32-prefixed path, so the boundary
    // plus one more entry covers it; the multi-megabyte entries made the test
    // exceed its timeout under suite load, and the 1 MiB default-cap test
    // below covers large payloads end to end.
    expect(lengths[0]).toBe(0);
    expect(() => nip44Encrypt("", ck)).toThrow(Error);
    for (const len of lengths.slice(1).filter((l) => l <= 100_000)) {
      const plaintext = "a".repeat(len);
      const payload = nip44Encrypt(plaintext, ck);
      expect(nip44Decrypt(payload, ck, { maxPayloadChars: payload.length })).toBe(plaintext);
    }
  });

  test("payload starting with # reports unknown version regardless of length", () => {
    const ck = hexToBytes("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
    // The '#' check runs before the length check (spec pseudocode order).
    expect(() => nip44Decrypt("#", ck)).toThrow(/unknown encryption version/);
    expect(() => nip44Decrypt(`#${"A".repeat(200)}`, ck)).toThrow(/unknown encryption version/);
    expect(() => nip44Decrypt("A".repeat(131), ck)).toThrow(/invalid payload length/);
  });

  test("DEFAULT_MAX_PAYLOAD_CHARS covers exactly a 1 MiB plaintext", () => {
    const ck = hexToBytes("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
    const oneMiB = "a".repeat(0x100000);
    const payload = nip44Encrypt(oneMiB, ck);
    // The cap is the base64 length of the payload for exactly 1 MiB of
    // plaintext, so a conforming 1 MiB payload decrypts with defaults.
    expect(payload).toHaveLength(DEFAULT_MAX_PAYLOAD_CHARS);
    expect(nip44Decrypt(payload, ck)).toBe(oneMiB);

    const over = nip44Encrypt(`${oneMiB}a`, ck);
    expect(over.length).toBeGreaterThan(DEFAULT_MAX_PAYLOAD_CHARS);
    expect(() => nip44Decrypt(over, ck)).toThrow(/invalid payload length/);
    expect(nip44Decrypt(over, ck, { maxPayloadChars: over.length })).toBe(`${oneMiB}a`);
  });

  test("KeysSigner nip44 round-trip", async () => {
    const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
    const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
    const pkB = await b.getPublicKey();
    const pkA = await a.getPublicKey();
    expect(a.nip44Encrypt).toBeTypeOf("function");
    expect(b.nip44Decrypt).toBeTypeOf("function");
    const cipher = await a.nip44Encrypt(pkB, "hello nip44");
    await expect(b.nip44Decrypt(pkA, cipher)).resolves.toBe("hello nip44");
  });

  describe("KeysSigner NIP-44 conversation-key cache", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    test("getConversationKey is derived once per peer and shared with decrypt", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
      const c = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000003");
      const peerA = await b.getPublicKey();
      const peerB = await c.getPublicKey();
      expect(peerA).not.toBe(peerB);

      const spy = vi.spyOn(nip44, "getConversationKey");
      const first = await a.nip44Encrypt(peerA, "one");
      const second = await a.nip44Encrypt(peerA, "two");
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]?.[0]).toStrictEqual(new Uint8Array(32));
      expect(spy.mock.calls[0]?.[1]).toBe(peerA);
      expect(first).not.toBe(second);
      await expect(a.nip44Decrypt(peerA, first)).resolves.toBe("one");
      await expect(a.nip44Decrypt(peerA, second)).resolves.toBe("two");

      const third = await a.nip44Encrypt(peerB, "three");
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.mock.calls[1]?.[0]).toStrictEqual(new Uint8Array(32));
      expect(spy.mock.calls[1]?.[1]).toBe(peerB);
      await expect(a.nip44Decrypt(peerB, third)).resolves.toBe("three");

      await expect(a.nip44Decrypt(peerA, first)).resolves.toBe("one");
      expect(spy).toHaveBeenCalledTimes(2);
    });

    test("low-level nip44.encrypt ciphertext decrypts via KeysSigner cache hit", async () => {
      const signer = new KeysSigner(
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const peerSigner = new KeysSigner(
        "0000000000000000000000000000000000000000000000000000000000000002",
      );
      const peer = await peerSigner.getPublicKey();
      const plaintext = "interop cache";
      const payload = nip44.encrypt(
        plaintext,
        nip44.getConversationKey(signer.keys.secretKey.bytes, peer),
      );
      const spy = vi.spyOn(nip44, "getConversationKey");
      expect(signer.nip44Encrypt).toBeTypeOf("function");
      expect(signer.nip44Decrypt).toBeTypeOf("function");
      const warm = await signer.nip44Encrypt(peer, "warm");
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]?.[0]).toStrictEqual(new Uint8Array(32));
      expect(spy.mock.calls[0]?.[1]).toBe(peer);
      await expect(signer.nip44Decrypt(peer, warm)).resolves.toBe("warm");
      await expect(signer.nip44Decrypt(peer, payload)).resolves.toBe(plaintext);
      expect(spy).toHaveBeenCalledTimes(1);
    });

    test("mixed-case peer hits the same cache entry", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
      const peer = await b.getPublicKey();
      const spy = vi.spyOn(nip44, "getConversationKey");
      const cipher = await a.nip44Encrypt(peer.toUpperCase(), "cased");
      await expect(a.nip44Decrypt(peer, cipher)).resolves.toBe("cased");
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]?.[0]).toStrictEqual(new Uint8Array(32));
      expect(spy.mock.calls[0]?.[1]).toBe(peer);
    });

    test("failed derivation is not cached", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const spy = vi.spyOn(nip44, "getConversationKey");
      await expect(a.nip44Encrypt("gg".repeat(32), "hi")).rejects.toThrow(/invalid public key/);
      await expect(a.nip44Encrypt("not-a-pubkey", "hi")).rejects.toThrow(/invalid public key/);
      expect(spy).toHaveBeenCalledTimes(2);
      await expect(a.nip44Encrypt("gg".repeat(32), "again")).rejects.toThrow(/invalid public key/);
      expect(spy).toHaveBeenCalledTimes(3);
    });

    test("decrypt errors reuse the cached key and still throw", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
      const c = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000003");
      const peerA = await b.getPublicKey();
      const peerB = await c.getPublicKey();
      const spy = vi.spyOn(nip44, "getConversationKey");
      const cipher = await a.nip44Encrypt(peerA, "ok");
      expect(spy).toHaveBeenCalledTimes(1);

      await expect(a.nip44Decrypt(peerA, "short")).rejects.toThrow(/invalid payload length/);
      expect(spy).toHaveBeenCalledTimes(1);

      await expect(a.nip44Encrypt(peerA, "")).rejects.toThrow(/invalid plaintext size/);
      expect(spy).toHaveBeenCalledTimes(1);

      await expect(a.nip44Decrypt(peerB, cipher)).rejects.toThrow(/invalid MAC/);
      expect(spy).toHaveBeenCalledTimes(2);
    });

    test("each KeysSigner instance keeps its own conversation-key cache", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
      const c = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000003");
      const peer = await c.getPublicKey();
      const spy = vi.spyOn(nip44, "getConversationKey");
      const fromA = await a.nip44Encrypt(peer, "from a");
      const fromB = await b.nip44Encrypt(peer, "from b");
      expect(spy).toHaveBeenCalledTimes(2);
      await expect(c.nip44Decrypt(await a.getPublicKey(), fromA)).resolves.toBe("from a");
      await expect(c.nip44Decrypt(await b.getPublicKey(), fromB)).resolves.toBe("from b");
    });

    test("encryptToPubkey is independent of KeysSigner conversation-key cache", async () => {
      const a = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000001");
      const b = new KeysSigner("0000000000000000000000000000000000000000000000000000000000000002");
      const peer = await b.getPublicKey();
      const signed = await a.nip44Encrypt(peer, "cached");
      const first = nip44.encryptToPubkey("gift wrap", a.keys.secretKey.bytes, peer);
      const second = nip44.encryptToPubkey("gift wrap 2", a.keys.secretKey.bytes, peer);
      expect(first).not.toBe(second);
      expect(first).not.toBe(signed);
      expect(nip44.decryptFromPubkey(first, a.keys.secretKey.bytes, peer)).toBe("gift wrap");
      expect(nip44.decryptFromPubkey(second, a.keys.secretKey.bytes, peer)).toBe("gift wrap 2");
      await expect(a.nip44Decrypt(peer, signed)).resolves.toBe("cached");
    });
  });

  test("rejects conversation_key and nonce that are not 32 bytes", () => {
    const key = new Uint8Array(32);
    expect(() => nip44Encrypt("hi", key, new Uint8Array(16))).toThrow(/nonce must be 32 bytes/);
    expect(() => nip44Encrypt("hi", new Uint8Array(16))).toThrow(
      /conversation_key must be 32 bytes/,
    );
    expect(() => getConversationKey(new Uint8Array(16), "aa".repeat(32))).toThrow(
      /secret key length/,
    );
  });
});
