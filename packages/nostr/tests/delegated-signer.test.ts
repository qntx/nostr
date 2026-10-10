import { readFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";

import { CryptoError } from "../src/core/error.ts";
import type { UnsignedEvent } from "../src/core/event.ts";
import { bytesToHex, hexToBytes } from "../src/core/util.ts";
import {
  DelegatedSigner,
  getEventHash,
  KeysSigner,
  SignerDisposedError,
  verifyEvent,
} from "../src/index.ts";
import * as nip44 from "../src/nips/nip44.ts";
import type { NostrKeyOperations } from "../src/signer/index.ts";

const SK1 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
const SK2 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000002");
const PK2 = bytesToHex(schnorr.getPublicKey(SK2));

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../vectors/nip44/official.json"), "utf8"),
) as {
  v2: {
    valid: {
      get_conversation_key: Array<{ sec1: string; pub2: string; conversation_key: string }>;
      encrypt_decrypt: Array<{
        sec1: string;
        sec2: string;
        conversation_key: string;
        nonce: string;
        plaintext: string;
        payload: string;
      }>;
    };
  };
};

type HolderCalls = {
  getPublicKey: number;
  signEventId: number;
  sharedSecret: number;
  secrets: Uint8Array[];
};

// A test key holder owning `secretKey`: the NostrKeyOperations contract with call
// counting and shared-secret capture so tests can assert wipe behavior.
function testHolder(secretKey: Uint8Array): { ops: NostrKeyOperations; calls: HolderCalls } {
  const pubkey = bytesToHex(schnorr.getPublicKey(secretKey));
  const calls: HolderCalls = {
    getPublicKey: 0,
    signEventId: 0,
    sharedSecret: 0,
    secrets: [],
  };
  const ops: NostrKeyOperations = {
    getPublicKey: async () => {
      calls.getPublicKey += 1;
      return Promise.resolve(pubkey);
    },
    signEventId: async (id) => {
      calls.signEventId += 1;
      return Promise.resolve(schnorr.sign(id, secretKey, randomBytes(32)));
    },
    sharedSecret: async (peer) => {
      calls.sharedSecret += 1;
      const shared = secp256k1.getSharedSecret(secretKey, hexToBytes(`02${peer}`)).slice(1, 33);
      calls.secrets.push(shared);
      return Promise.resolve(shared);
    },
  };
  return { ops, calls };
}

function unsignedFor(pubkey: string): UnsignedEvent {
  return {
    kind: 1,
    tags: [["t", "delegated"]],
    content: "delegated signing",
    created_at: 1_700_000_000,
    pubkey,
  };
}

describe("DelegatedSigner", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("getPublicKey validates the holder value and caches it", async () => {
    const { ops, calls } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    await expect(signer.getPublicKey()).resolves.toBe(bytesToHex(schnorr.getPublicKey(SK1)));
    await signer.getPublicKey();
    expect(calls.getPublicKey).toBe(1);

    const bad = new DelegatedSigner({ ...ops, getPublicKey: async () => Promise.resolve("UPPER") });
    await expect(bad.getPublicKey()).rejects.toThrow(CryptoError);
    const short = new DelegatedSigner({ ...ops, getPublicKey: async () => Promise.resolve("ab") });
    await expect(short.getPublicKey()).rejects.toThrow(CryptoError);
  });

  test("signEvent verifies and marks the event", async () => {
    const { ops } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    const pubkey = await signer.getPublicKey();
    const unsigned = unsignedFor(pubkey);
    const event = await signer.signEvent(unsigned);
    expect(event.id).toBe(getEventHash(unsigned));
    expect(event.sig).toHaveLength(128);
    expect(verifyEvent({ ...event })).toBe(true);
  });

  test("signEvent rejects a pubkey mismatch", async () => {
    const signer = new DelegatedSigner(testHolder(SK1).ops);
    await expect(signer.signEvent(unsignedFor(PK2))).rejects.toThrow(/pubkey does not match/);
  });

  test("signEvent rejects invalid unsigned events", async () => {
    const signer = new DelegatedSigner(testHolder(SK1).ops);
    const unsigned = { ...unsignedFor(await signer.getPublicKey()), kind: -1 };
    await expect(signer.signEvent(unsigned)).rejects.toThrow(Error);
  });

  test("signEvent rejects misbehaving holders", async () => {
    const { ops } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    const unsigned = unsignedFor(await signer.getPublicKey());

    const short = new DelegatedSigner({
      ...ops,
      signEventId: async () => Promise.resolve(new Uint8Array(63)),
    });
    await expect(short.signEvent(unsigned)).rejects.toThrow(CryptoError);

    const wrong = new DelegatedSigner({
      ...ops,
      // A well-formed 64-byte signature over the wrong message still fails BIP-340.
      signEventId: async () =>
        Promise.resolve(schnorr.sign(new Uint8Array(32), SK1, randomBytes(32))),
    });
    await expect(wrong.signEvent(unsigned)).rejects.toThrow(/fails verification/);
  });

  test("official get_conversation_key vectors via the shared-secret entry point", () => {
    for (const row of vectors.v2.valid.get_conversation_key) {
      const sharedX = secp256k1
        .getSharedSecret(hexToBytes(row.sec1), hexToBytes(`02${row.pub2}`))
        .slice(1, 33);
      expect(bytesToHex(nip44.getConversationKeyFromSharedSecret(sharedX))).toBe(
        row.conversation_key,
      );
    }
  });

  test("official encrypt_decrypt vectors through DelegatedSigner", async () => {
    await Promise.all(
      vectors.v2.valid.encrypt_decrypt.map(async (row) => {
        const { ops } = testHolder(hexToBytes(row.sec1));
        const signer = new DelegatedSigner(ops);
        const peer = bytesToHex(schnorr.getPublicKey(hexToBytes(row.sec2)));
        await expect(signer.nip44Decrypt(peer, row.payload)).resolves.toBe(row.plaintext);
        const own = await signer.nip44Encrypt(peer, row.plaintext);
        expect(nip44.decrypt(own, hexToBytes(row.conversation_key))).toBe(row.plaintext);
      }),
    );
  });

  test("the NIP-44 shared secret is wiped right after derivation and the key is cached", async () => {
    const { ops, calls } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    await signer.nip44Encrypt(PK2, "one");
    await signer.nip44Encrypt(PK2, "two");
    expect(calls.sharedSecret).toBe(1);
    const { secrets } = calls;
    for (const shared of secrets) {
      expect(shared).toStrictEqual(new Uint8Array(32));
    }
  });

  test("NIP-04 cross-decrypts with KeysSigner in both directions", async () => {
    const delegated = new DelegatedSigner(testHolder(SK1).ops);
    const keys = new KeysSigner(SK2);
    const pk1 = await delegated.getPublicKey();

    const toKeys = await delegated.nip04Encrypt(PK2, "hello keys");
    await expect(keys.nip04Decrypt(pk1, toKeys)).resolves.toBe("hello keys");

    const toDelegated = await keys.nip04Encrypt(pk1, "hello delegated");
    await expect(delegated.nip04Decrypt(PK2, toDelegated)).resolves.toBe("hello delegated");
  });

  test("the NIP-04 shared secret is wiped after every call with no caching", async () => {
    const { ops, calls } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    await signer.nip04Encrypt(PK2, "x");
    await signer.nip04Encrypt(PK2, "y");
    expect(calls.sharedSecret).toBe(2);
    const { secrets } = calls;
    for (const shared of secrets) {
      expect(shared).toStrictEqual(new Uint8Array(32));
    }
  });

  test("without sharedSecret the four encryption methods reject with CryptoError", async () => {
    const { ops } = testHolder(SK1);
    const { sharedSecret: _, ...noEcdh } = ops;
    const signer = new DelegatedSigner(noEcdh);
    // Thunks, not eager promises: each rejection must have its handler
    // attached in the same tick the promise is created.
    await Promise.all(
      [
        async () => signer.nip04Encrypt(PK2, "x"),
        async () => signer.nip04Decrypt(PK2, "x"),
        async () => signer.nip44Encrypt(PK2, "x"),
        async () => signer.nip44Decrypt(PK2, "x"),
      ].map(async (call) => {
        const rejected = call();
        await expect(rejected).rejects.toThrow(CryptoError);
        await expect(rejected).rejects.toThrow(/does not support/);
      }),
    );
  });

  test("dispose wipes the cache, rejects afterwards, and never calls the holder", async () => {
    const { ops, calls } = testHolder(SK1);
    const signer = new DelegatedSigner(ops);
    const pubkey = await signer.getPublicKey();
    const unsigned = unsignedFor(pubkey);

    const spy = vi.spyOn(nip44, "getConversationKeyFromSharedSecret");
    await signer.nip44Encrypt(PK2, "hi");
    const convKey = spy.mock.results[0]?.value as Uint8Array;

    signer.dispose();
    signer.dispose();
    expect(convKey).toStrictEqual(new Uint8Array(32));

    const totalCalls = calls.getPublicKey + calls.signEventId + calls.sharedSecret;
    await Promise.all(
      [
        async () => signer.getPublicKey(),
        async () => signer.signEvent(unsigned),
        async () => signer.nip04Encrypt(PK2, "x"),
        async () => signer.nip04Decrypt(PK2, "x"),
        async () => signer.nip44Encrypt(PK2, "x"),
        async () => signer.nip44Decrypt(PK2, "x"),
      ].map(async (call) => expect(call()).rejects.toBeInstanceOf(SignerDisposedError)),
    );
    expect(calls.getPublicKey + calls.signEventId + calls.sharedSecret).toBe(totalCalls);
  });

  test("dispose during a pending sharedSecret call wipes the secret and caches nothing", async () => {
    const { ops } = testHolder(SK1);
    let resolveShared: ((v: Uint8Array) => void) | undefined;
    let entered: () => void = () => {};
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const signer = new DelegatedSigner({
      ...ops,
      sharedSecret: async () => {
        entered();
        return new Promise((resolve) => {
          resolveShared = resolve;
        });
      },
    });
    const spy = vi.spyOn(nip44, "getConversationKeyFromSharedSecret");

    // `.catch` attaches the rejection handler before the promise can reject.
    const pending = signer.nip44Encrypt(PK2, "hi").catch((error: unknown) => error);
    await enteredPromise; // the holder's op is now in flight
    signer.dispose();
    const shared = secp256k1.getSharedSecret(SK1, hexToBytes(`02${PK2}`)).slice(1, 33);
    resolveShared?.(shared);

    await expect(pending).resolves.toBeInstanceOf(SignerDisposedError);
    expect(shared).toStrictEqual(new Uint8Array(32));
    // The reply never reached derivation, so the cache never saw a key.
    expect(spy).not.toHaveBeenCalled();
  });

  test("dispose during a pending signEventId call rejects without an event", async () => {
    const { ops } = testHolder(SK1);
    let resolveSig: ((v: Uint8Array) => void) | undefined;
    let entered: () => void = () => {};
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const signer = new DelegatedSigner({
      ...ops,
      signEventId: async () => {
        entered();
        return new Promise((resolve) => {
          resolveSig = resolve;
        });
      },
    });
    const pubkey = await signer.getPublicKey();
    // `.catch` attaches the rejection handler before the promise can reject.
    const pending = signer.signEvent(unsignedFor(pubkey)).catch((error: unknown) => error);
    await enteredPromise; // signEventId is now in flight
    signer.dispose();
    resolveSig?.(schnorr.sign(new Uint8Array(32), SK1, randomBytes(32)));

    await expect(pending).resolves.toBeInstanceOf(SignerDisposedError);
  });
});
