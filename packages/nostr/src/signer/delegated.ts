import { schnorr } from "@noble/curves/secp256k1.js";

import { CryptoError, EventValidationError } from "../core/error.ts";
import type { Event, UnsignedEvent } from "../core/event.ts";
import { getEventHash, markVerified, validateEvent } from "../core/event.ts";
import { assertHex32, bytesToHex, hexToBytes, isHex32 } from "../core/util.ts";
import * as nip04 from "../nips/nip04.ts";
import * as nip44 from "../nips/nip44.ts";
import { SignerDisposedError } from "./error.ts";
import type { NostrSigner } from "./types.ts";

/**
 * The three operations an external key holder (wallet keyring, NFC card, platform secure store)
 * provides. The secret itself never enters this process.
 */
export type NostrKeyOperations = {
  /** Lowercase 64-char hex x-only public key. */
  getPublicKey: () => Promise<string>;
  /** 64-byte BIP-340 signature over the 32-byte event id. */
  signEventId: (id: Uint8Array) => Promise<Uint8Array>;
  /**
   * Optional. 32-byte x-coordinate of `ECDH(secret, lift_x(peer))`, unhashed. Enables NIP-04 and
   * NIP-44.
   */
  sharedSecret?: (peer: string) => Promise<Uint8Array>;
};

/**
 * {@link NostrSigner} backed by a {@link NostrKeyOperations} key holder. The signer verifies
 * everything the holder returns: the public key shape, the signature length, and the BIP-340
 * signature itself — a misbehaving holder never produces an event relays would reject.
 */
export class DelegatedSigner implements NostrSigner {
  readonly #operations: NostrKeyOperations;
  readonly #convKeys = new Map<string, Uint8Array>();
  #pubkey: string | undefined;
  #disposed = false;

  constructor(operations: NostrKeyOperations) {
    this.#operations = operations;
  }

  #assertUsable(): void {
    if (this.#disposed) {
      throw new SignerDisposedError("signer has been disposed");
    }
  }

  async #publicKey(): Promise<string> {
    let pubkey = this.#pubkey;
    if (pubkey === undefined) {
      pubkey = await this.#operations.getPublicKey();
      this.#assertUsable();
      if (!isHex32(pubkey)) {
        throw new CryptoError("key holder returned an invalid public key");
      }
      this.#pubkey = pubkey;
    }
    return pubkey;
  }

  async getPublicKey(): Promise<string> {
    this.#assertUsable();
    return this.#publicKey();
  }

  async signEvent(unsigned: UnsignedEvent): Promise<Event> {
    this.#assertUsable();
    if (!validateEvent(unsigned)) {
      throw new EventValidationError("cannot sign invalid unsigned event");
    }
    const pubkey = await this.#publicKey();
    if (unsigned.pubkey !== pubkey) {
      throw new CryptoError("unsigned event pubkey does not match the key holder's public key");
    }
    const id = getEventHash(unsigned);
    const sig = await this.#operations.signEventId(hexToBytes(id));
    this.#assertUsable();
    if (sig.length !== 64) {
      throw new CryptoError("key holder returned an invalid signature length");
    }
    if (!schnorr.verify(sig, hexToBytes(id), hexToBytes(pubkey))) {
      throw new CryptoError("key holder returned a signature that fails verification");
    }
    const event: Event = { ...unsigned, id, sig: bytesToHex(sig) };
    markVerified(event);
    return event;
  }

  /**
   * The normalized lowercase peer pubkey is handed to the holder; the returned 32-byte shared
   * secret is the caller's to wipe.
   */
  async #sharedSecret(peer: string): Promise<Uint8Array> {
    const { sharedSecret } = this.#operations;
    if (!sharedSecret) {
      throw new CryptoError("key holder does not support ECDH shared secrets");
    }
    const shared = await sharedSecret(assertHex32(peer, "peer public key"));
    if (this.#disposed) {
      shared.fill(0);
      throw new SignerDisposedError("signer has been disposed");
    }
    if (shared.length !== 32) {
      shared.fill(0);
      throw new CryptoError("key holder returned an invalid shared secret");
    }
    return shared;
  }

  async #conversationKey(peer: string): Promise<Uint8Array> {
    const pk = assertHex32(peer, "peer public key");
    let key = this.#convKeys.get(pk);
    if (!key) {
      const shared = await this.#sharedSecret(pk);
      try {
        key = nip44.getConversationKeyFromSharedSecret(shared);
      } finally {
        shared.fill(0);
      }
      this.#convKeys.set(pk, key);
    }
    return key;
  }

  async nip44Encrypt(peer: string, plaintext: string): Promise<string> {
    this.#assertUsable();
    return nip44.encrypt(plaintext, await this.#conversationKey(peer));
  }

  async nip44Decrypt(peer: string, payload: string): Promise<string> {
    this.#assertUsable();
    return nip44.decrypt(payload, await this.#conversationKey(peer));
  }

  async nip04Encrypt(peer: string, plaintext: string): Promise<string> {
    this.#assertUsable();
    const shared = await this.#sharedSecret(peer);
    try {
      return nip04.encryptWithSharedSecret(shared, plaintext);
    } finally {
      shared.fill(0);
    }
  }

  async nip04Decrypt(peer: string, ciphertext: string): Promise<string> {
    this.#assertUsable();
    const shared = await this.#sharedSecret(peer);
    try {
      return nip04.decryptWithSharedSecret(shared, ciphertext);
    } finally {
      shared.fill(0);
    }
  }

  /**
   * Zero-fill and clear every cached NIP-44 conversation key. All later calls reject with
   * {@link SignerDisposedError} and never reach the key holder. Idempotent.
   */
  dispose(): void {
    for (const key of this.#convKeys.values()) {
      key.fill(0);
    }
    this.#convKeys.clear();
    this.#disposed = true;
  }
}
