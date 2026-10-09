import { schnorr } from "@noble/curves/secp256k1.js";
import { describe, expect, test, vi } from "vite-plus/test";

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
  SignerDisposedError,
  verifyEvent,
} from "../src/index.ts";
import * as nip04 from "../src/nips/nip04.ts";
import * as nip44 from "../src/nips/nip44.ts";

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

describe("KeysSigner.dispose", () => {
  const PEER_SK = "0000000000000000000000000000000000000000000000000000000000000002";
  const peer = bytesToHex(schnorr.getPublicKey(hexToBytes(PEER_SK)));

  test("every method rejects with SignerDisposedError after dispose", async () => {
    const signer = new KeysSigner(SK_HEX);
    signer.dispose();
    await expect(signer.getPublicKey()).rejects.toBeInstanceOf(SignerDisposedError);
    await expect(signer.signEvent({ ...TEMPLATE, pubkey: peer })).rejects.toBeInstanceOf(
      SignerDisposedError,
    );
    await expect(signer.nip04Encrypt(peer, "x")).rejects.toBeInstanceOf(SignerDisposedError);
    await expect(signer.nip04Decrypt(peer, "x")).rejects.toBeInstanceOf(SignerDisposedError);
    await expect(signer.nip44Encrypt(peer, "x")).rejects.toBeInstanceOf(SignerDisposedError);
    await expect(signer.nip44Decrypt(peer, "x")).rejects.toBeInstanceOf(SignerDisposedError);
  });

  test("dispose is idempotent", async () => {
    const signer = new KeysSigner(SK_HEX);
    signer.dispose();
    signer.dispose();
    await expect(signer.getPublicKey()).rejects.toBeInstanceOf(SignerDisposedError);
  });

  test("dispose zeroizes the secret and every cached conversation key", async () => {
    const signer = new KeysSigner(SK_HEX);
    const { keys } = signer;
    const convSpy = vi.spyOn(nip44, "getConversationKey");
    await signer.nip44Encrypt(peer, "hi");
    const convKey = convSpy.mock.results[0]?.value as Uint8Array;
    const derivationCopy = convSpy.mock.calls[0]?.[0];
    expect(derivationCopy).toStrictEqual(new Uint8Array(32));

    signer.dispose();
    expect(convKey).toStrictEqual(new Uint8Array(32));
    expect(() => keys.secretKey.bytes).toThrow(CryptoError);
  });

  test("the per-call secret copies are wiped", async () => {
    const signer = new KeysSigner(SK_HEX);
    const encSpy = vi.spyOn(nip04, "encrypt");
    const decSpy = vi.spyOn(nip04, "decrypt");
    const ciphertext = await signer.nip04Encrypt(peer, "secret-copy");
    await signer.nip04Decrypt(peer, ciphertext);
    expect(encSpy.mock.calls[0]?.[0]).toStrictEqual(new Uint8Array(32));
    expect(decSpy.mock.calls[0]?.[0]).toStrictEqual(new Uint8Array(32));
    signer.dispose();
  });
});
