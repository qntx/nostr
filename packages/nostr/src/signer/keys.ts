import type { Event, UnsignedEvent } from "../core/event.ts";
import type { SecretKeyInput } from "../core/key.ts";
import { Keys, signEvent } from "../core/key.ts";
import * as nip04 from "../nips/nip04.ts";
import * as nip44 from "../nips/nip44.ts";
import { SignerDisposedError } from "./error.ts";
import type { NostrSigner } from "./types.ts";

/** Local secret-key signer with NIP-04 (legacy) and NIP-44 support. */
export class KeysSigner implements NostrSigner {
  readonly #keys: Keys;
  readonly #convKeys = new Map<string, Uint8Array>();
  #disposed = false;

  constructor(secretKey: SecretKeyInput | Keys) {
    this.#keys = secretKey instanceof Keys ? secretKey : Keys.fromSecretKey(secretKey);
  }

  /**
   * The live {@link Keys} instance holding the secret material. {@link KeysSigner.dispose} zeroizes
   * it, so a reference obtained earlier reports a zeroized secret afterwards.
   */
  get keys(): Keys {
    return this.#keys;
  }

  #assertUsable(): void {
    if (this.#disposed) {
      throw new SignerDisposedError("signer has been disposed");
    }
  }

  async getPublicKey(): Promise<string> {
    this.#assertUsable();
    return this.#keys.publicKey;
  }

  async signEvent(unsigned: UnsignedEvent): Promise<Event> {
    this.#assertUsable();
    return signEvent(unsigned, this.#keys);
  }

  async nip04Encrypt(peer: string, plaintext: string): Promise<string> {
    this.#assertUsable();
    const secret = this.#keys.secretKey.bytes;
    try {
      return nip04.encrypt(secret, peer, plaintext);
    } finally {
      secret.fill(0);
    }
  }

  async nip04Decrypt(peer: string, ciphertext: string): Promise<string> {
    this.#assertUsable();
    const secret = this.#keys.secretKey.bytes;
    try {
      return nip04.decrypt(secret, peer, ciphertext);
    } finally {
      secret.fill(0);
    }
  }

  #conversationKey(peer: string): Uint8Array {
    const pk = peer.toLowerCase();
    let key = this.#convKeys.get(pk);
    if (!key) {
      const secret = this.#keys.secretKey.bytes;
      try {
        key = nip44.getConversationKey(secret, pk);
      } finally {
        secret.fill(0);
      }
      this.#convKeys.set(pk, key);
    }
    return key;
  }

  async nip44Encrypt(peer: string, plaintext: string): Promise<string> {
    this.#assertUsable();
    return nip44.encrypt(plaintext, this.#conversationKey(peer));
  }

  async nip44Decrypt(peer: string, payload: string): Promise<string> {
    this.#assertUsable();
    return nip44.decrypt(payload, this.#conversationKey(peer));
  }

  /**
   * Zeroize the wrapped secret key and every cached NIP-44 conversation key. All later calls reject
   * with {@link SignerDisposedError}. Idempotent.
   */
  dispose(): void {
    this.#keys.secretKey.zeroize();
    for (const key of this.#convKeys.values()) {
      key.fill(0);
    }
    this.#convKeys.clear();
    this.#disposed = true;
  }
}
