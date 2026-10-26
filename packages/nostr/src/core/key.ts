import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

import { CryptoError, EventValidationError } from "./error.ts";
import { markVerified, serializeValidatedEvent, validateEvent } from "./event.ts";
import type { Event, EventTemplate, UnsignedEvent } from "./event.ts";
import {
  assertByteLength,
  assertHex32,
  assertSecretKeyBytes,
  bytesToHex,
  hexToBytes,
  utf8Encoder,
} from "./util.ts";

/** 32-byte secret key held as bytes; prefer zeroize when done. */
export class SecretKey {
  #bytes: Uint8Array | undefined;

  private constructor(bytes: Uint8Array) {
    assertSecretKeyBytes(bytes);
    this.#bytes = new Uint8Array(bytes);
  }

  static generate(): SecretKey {
    return new SecretKey(schnorr.utils.randomSecretKey());
  }

  static fromBytes(bytes: Uint8Array): SecretKey {
    return new SecretKey(bytes);
  }

  static fromHex(hex: string): SecretKey {
    return new SecretKey(hexToBytes(assertHex32(hex, "secret key")));
  }

  get bytes(): Uint8Array {
    if (!this.#bytes) {
      throw new CryptoError("secret key has been zeroized");
    }
    return new Uint8Array(this.#bytes);
  }

  toHex(): string {
    return bytesToHex(this.bytes);
  }

  /** Best-effort wipe of the internal buffer. */
  zeroize(): void {
    if (this.#bytes) {
      this.#bytes.fill(0);
      this.#bytes = undefined;
    }
  }
}

/** Anything a secret key can be given as: instance, raw bytes, or hex. */
export type SecretKeyInput = SecretKey | Uint8Array | string;

/** Coerce a {@link SecretKeyInput} to {@link SecretKey}. */
export function toSecretKey(input: SecretKeyInput): SecretKey {
  if (input instanceof SecretKey) {
    return input;
  }
  if (typeof input === "string") {
    return SecretKey.fromHex(input);
  }
  return SecretKey.fromBytes(input);
}

/** Lowercase hex-encoded secp256k1 public key (x-only, 64 chars). */
export type PublicKey = string;

/** Validate and normalize a hex public key; throws {@link HexError} on bad input. */
export function publicKeyFromHex(hex: string): PublicKey {
  return assertHex32(hex, "public key");
}

/**
 * The crypto primitives every secret-key operation routes through. `publicKey` returns the 32-byte
 * x-only public key of a 32-byte secret key; `sign` returns the 64-byte BIP-340 signature of a
 * 32-byte `id` using 32 bytes of auxiliary randomness; `verifySerialized` returns true iff
 * `sha256(serializedUtf8)` equals `id` and `sig` is a valid BIP-340 signature of `id` by the x-only
 * `pubkey`; `ecdhX` returns the 32-byte x coordinate of the ECDH shared point between `secretKey`
 * and the even-Y lift of `publicKeyX` (the shared secret both NIP-04 and NIP-44 derive from). All
 * throw on invalid input (for example an out-of-range secret key or a non-lifting public key).
 */
export type NostrBackend = {
  publicKey: (secretKey: Uint8Array) => Uint8Array;
  sign: (id: Uint8Array, secretKey: Uint8Array, auxRand: Uint8Array) => Uint8Array;
  verifySerialized: (
    serializedUtf8: Uint8Array,
    id: Uint8Array,
    pubkey: Uint8Array,
    sig: Uint8Array,
  ) => boolean;
  ecdhX: (secretKey: Uint8Array, publicKeyX: Uint8Array) => Uint8Array;
};

/** The @noble/curves backend — the default everywhere a backend is optional. */
export const nobleBackend: NostrBackend = {
  publicKey: (secretKey) => schnorr.getPublicKey(secretKey),
  sign: (id, secretKey, auxRand) => schnorr.sign(id, secretKey, auxRand),
  verifySerialized: (serializedUtf8, id, pubkey, sig) => {
    try {
      const digest = sha256(serializedUtf8);
      if (!digest.every((byte, i) => byte === id[i])) {
        return false;
      }
      return schnorr.verify(sig, id, pubkey);
    } catch {
      return false;
    }
  },
  ecdhX: (secretKey, publicKeyX) => {
    assertSecretKeyBytes(secretKey);
    assertByteLength(publicKeyX, 32, "public key");
    let shared: Uint8Array;
    try {
      shared = secp256k1.getSharedSecret(secretKey, new Uint8Array([0x02, ...publicKeyX]));
    } catch (error) {
      throw new CryptoError("invalid ECDH input", { cause: error });
    }
    const x = shared.slice(1, 33);
    shared.fill(0);
    return x;
  },
};

/** Derive the public key for a secret key given as SecretKey, bytes, or hex. */
export function getPublicKey(secretKey: SecretKeyInput): PublicKey {
  return bytesToHex(schnorr.getPublicKey(toSecretKey(secretKey).bytes));
}

/** Keypair convenience wrapper. */
export class Keys {
  readonly secretKey: SecretKey;
  readonly publicKey: PublicKey;
  /**
   * Crypto backend that derived {@link publicKey} and signs in {@link finalizeEvent}/
   * {@link signEvent}. Defaults to noble; pass a loaded `NostrWasm` module or a native backend to
   * delegate the work.
   */
  readonly backend: NostrBackend;

  private constructor(secretKey: SecretKey, backend: NostrBackend) {
    this.secretKey = secretKey;
    this.backend = backend;
    const secretBytes = secretKey.bytes;
    let pubkey: Uint8Array;
    try {
      pubkey = backend.publicKey(secretBytes);
    } finally {
      secretBytes.fill(0);
    }
    if (pubkey.length !== 32) {
      throw new CryptoError("signing backend returned an invalid public key");
    }
    this.publicKey = bytesToHex(pubkey);
  }

  static generate(backend: NostrBackend = nobleBackend): Keys {
    return new Keys(SecretKey.generate(), backend);
  }

  static fromSecretKey(secretKey: SecretKeyInput, backend: NostrBackend = nobleBackend): Keys {
    return new Keys(toSecretKey(secretKey), backend);
  }
}

function resolveKeys(secretKey: SecretKeyInput | Keys): Keys {
  return secretKey instanceof Keys ? secretKey : Keys.fromSecretKey(secretKey);
}

/**
 * Fill pubkey/id/sig on a template and return a signed event.
 *
 * `auxRand` is the 32-byte BIP-340 auxiliary randomness. It defaults to a fresh `randomBytes(32)`
 * draw; an explicit value makes the signature reproducible, which is required for vectors and
 * tests. Never reuse aux randomness in production.
 */
export function finalizeEvent(
  template: EventTemplate,
  secretKey: SecretKeyInput | Keys,
  auxRand?: Uint8Array,
): Event {
  const keys = resolveKeys(secretKey);
  const unsigned: UnsignedEvent = {
    kind: template.kind,
    tags: template.tags,
    content: template.content,
    created_at: template.created_at,
    pubkey: keys.publicKey,
  };
  return signEvent(unsigned, keys, auxRand);
}

/**
 * Sign an already-assembled unsigned event. Rejects when `unsigned.pubkey` does not match the
 * secret key.
 *
 * `auxRand` is the 32-byte BIP-340 auxiliary randomness. It defaults to a fresh `randomBytes(32)`
 * draw; an explicit value makes the signature reproducible, which is required for vectors and
 * tests. Never reuse aux randomness in production.
 */
export function signEvent(
  unsigned: UnsignedEvent,
  secretKey: SecretKeyInput | Keys,
  auxRand?: Uint8Array,
): Event {
  const keys = resolveKeys(secretKey);
  if (auxRand !== undefined && auxRand.length !== 32) {
    throw new CryptoError("auxRand must be 32 bytes");
  }
  if (!validateEvent(unsigned)) {
    throw new EventValidationError("cannot sign invalid unsigned event");
  }

  if (unsigned.pubkey !== keys.publicKey) {
    throw new CryptoError("unsigned event pubkey does not match secret key");
  }

  const normalized: UnsignedEvent = {
    kind: unsigned.kind,
    tags: unsigned.tags,
    content: unsigned.content,
    created_at: unsigned.created_at,
    pubkey: keys.publicKey,
  };

  const id = bytesToHex(sha256(utf8Encoder.encode(serializeValidatedEvent(normalized))));
  const secretBytes = keys.secretKey.bytes;
  let sig: Uint8Array;
  try {
    sig = keys.backend.sign(hexToBytes(id), secretBytes, auxRand ?? randomBytes(32));
  } finally {
    secretBytes.fill(0);
  }
  if (sig.length !== 64) {
    throw new CryptoError("signing backend returned an invalid signature");
  }
  const event: Event = { ...normalized, id, sig: bytesToHex(sig) };
  markVerified(event);
  return event;
}
