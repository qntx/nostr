import { schnorr } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { CryptoError } from "../src/core/error.ts";
import type { EventTemplate } from "../src/core/event.ts";
import type { SigningBackend } from "../src/core/key.ts";
import { bytesToHex, hexToBytes } from "../src/core/util.ts";
import {
  EventBuilder,
  finalizeEvent,
  Keys,
  KeysSigner,
  Kind,
  SecretKey,
  verifyEvent,
} from "../src/index.ts";

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

const TEMPLATE: EventTemplate = {
  kind: Kind.TextNote,
  tags: [["t", "backend"]],
  content: "Hello, backend!",
  created_at: 1617932115,
};

// A recording backend wrapping noble: counts calls and captures arguments verbatim.
function recordingBackend() {
  const calls = {
    publicKey: [] as Uint8Array[],
    sign: [] as Array<{
      id: Uint8Array;
      secretKey: Uint8Array;
      auxRand: Uint8Array;
    }>,
  };
  const backend: SigningBackend = {
    publicKey: (secretKey) => {
      calls.publicKey.push(secretKey);
      return schnorr.getPublicKey(secretKey);
    },
    sign: (id, secretKey, auxRand) => {
      calls.sign.push({ id, secretKey, auxRand });
      return schnorr.sign(id, secretKey, auxRand);
    },
  };
  return { backend, calls };
}

describe("SigningBackend", () => {
  test("Keys.fromSecretKey derives the public key through the backend once", () => {
    const { backend, calls } = recordingBackend();
    const sk = hexToBytes(SK_HEX);
    const keys = Keys.fromSecretKey(sk, backend);
    expect(calls.publicKey).toHaveLength(1);
    expect(calls.publicKey[0]).toStrictEqual(sk);
    expect(keys.publicKey).toBe(bytesToHex(schnorr.getPublicKey(sk)));
  });

  test("finalizeEvent signs through the backend with the event id and fresh aux", () => {
    const { backend, calls } = recordingBackend();
    const keys = Keys.fromSecretKey(SK_HEX, backend);
    const event = finalizeEvent(TEMPLATE, keys);
    expect(calls.sign).toHaveLength(1);
    const call = calls.sign[0]!;
    expect(call.id).toStrictEqual(hexToBytes(event.id));
    expect(call.secretKey).toStrictEqual(hexToBytes(SK_HEX));
    expect(call.auxRand).toHaveLength(32);
    expect(event.sig).toBe(bytesToHex(schnorr.sign(call.id, call.secretKey, call.auxRand)));

    const again = finalizeEvent(TEMPLATE, keys);
    expect(calls.sign).toHaveLength(2);
    expect(calls.sign[1]!.auxRand).not.toStrictEqual(call.auxRand);
    expect(again.sig).not.toBe(event.sig);

    expect(verifyEvent({ ...event })).toBe(true);
    expect(verifyEvent({ ...again })).toBe(true);
  });

  test("KeysSigner.signEvent routes through the backend", async () => {
    const { backend, calls } = recordingBackend();
    const keys = Keys.fromSecretKey(SK_HEX, backend);
    const signer = new KeysSigner(keys);
    const unsigned = {
      ...TEMPLATE,
      pubkey: keys.publicKey,
    };
    const event = await signer.signEvent(unsigned);
    expect(calls.sign).toHaveLength(1);
    expect(calls.sign[0]!.id).toStrictEqual(hexToBytes(event.id));
    expect(verifyEvent({ ...event })).toBe(true);
  });

  test("EventBuilder.signWithKeys routes through the backend", () => {
    const { backend, calls } = recordingBackend();
    const keys = Keys.fromSecretKey(SK_HEX, backend);
    const event = EventBuilder.textNote("hello").createdAt(1617932115).signWithKeys(keys);
    expect(calls.sign).toHaveLength(1);
    expect(calls.sign[0]!.id).toStrictEqual(hexToBytes(event.id));
    expect(verifyEvent({ ...event })).toBe(true);
  });

  test("a backend returning a wrong-length public key throws CryptoError", () => {
    const backend: SigningBackend = {
      publicKey: () => new Uint8Array(31),
      sign: () => new Uint8Array(64),
    };
    expect(() => Keys.fromSecretKey(SK_HEX, backend)).toThrow(CryptoError);
    expect(() => Keys.generate(backend)).toThrow(CryptoError);
  });

  test("a backend returning a wrong-length signature throws CryptoError", () => {
    const backend: SigningBackend = {
      publicKey: (sk) => schnorr.getPublicKey(sk),
      sign: () => new Uint8Array(63),
    };
    const keys = Keys.fromSecretKey(SK_HEX, backend);
    expect(() => finalizeEvent(TEMPLATE, keys)).toThrow(CryptoError);
  });

  test("a throwing backend propagates the error", () => {
    const boom = new Error("backend exploded");
    const backend: SigningBackend = {
      publicKey: () => {
        throw boom;
      },
      sign: () => {
        throw boom;
      },
    };
    expect(() => Keys.fromSecretKey(SK_HEX, backend)).toThrow(boom);

    const signingOnly: SigningBackend = {
      publicKey: (sk) => schnorr.getPublicKey(sk),
      sign: () => {
        throw boom;
      },
    };
    const keys = Keys.fromSecretKey(SK_HEX, signingOnly);
    expect(() => finalizeEvent(TEMPLATE, keys)).toThrow(boom);
  });

  test("the default backend is unchanged for bytes, hex, and SecretKey", () => {
    for (const sk of [hexToBytes(SK_HEX), SK_HEX, SecretKey.fromHex(SK_HEX)]) {
      const event = finalizeEvent(TEMPLATE, sk);
      expect(verifyEvent({ ...event })).toBe(true);
      expect(event.pubkey).toBe(bytesToHex(schnorr.getPublicKey(hexToBytes(SK_HEX))));
    }
  });
});
