import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

import { CryptoError, EventValidationError } from "./error.ts";
import { markVerified, serializeValidatedEvent, validateEvent } from "./event.ts";
import type { Event, EventTemplate, UnsignedEvent } from "./event.ts";
import { assertHex32, assertSecretKeyBytes, bytesToHex, hexToBytes, utf8Encoder } from "./util.ts";

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
 * BIP-340 signing backend. `publicKey` returns the 32-byte x-only public key of a 32-byte secret
 * key; `sign` returns the 64-byte BIP-340 signature of a 32-byte `id` using 32 bytes of auxiliary
 * randomness. Both throw on invalid input (for example an out-of-range secret key).
 */
export type SigningBackend = {
  publicKey: (secretKey: Uint8Array) => Uint8Array;
  sign: (id: Uint8Array, secretKey: Uint8Array, auxRand: Uint8Array) => Uint8Array;
};

const nobleSigning: SigningBackend = {
  publicKey: (secretKey) => schnorr.getPublicKey(secretKey),
  sign: (id, secretKey, auxRand) => schnorr.sign(id, secretKey, auxRand),
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
   * BIP-340 backend that derived {@link publicKey} and signs in {@link finalizeEvent}/
   * {@link signEvent}. Defaults to noble; pass a loaded `NostrWasm` module or a native backend to
   * delegate signing.
   */
  readonly backend: SigningBackend;

  private constructor(secretKey: SecretKey, backend: SigningBackend) {
    this.secretKey = secretKey;
    this.backend = backend;
    const pubkey = backend.publicKey(secretKey.bytes);
    if (pubkey.length !== 32) {
      throw new CryptoError("signing backend returned an invalid public key");
    }
    this.publicKey = bytesToHex(pubkey);
  }

  static generate(backend: SigningBackend = nobleSigning): Keys {
    return new Keys(SecretKey.generate(), backend);
  }

  static fromSecretKey(secretKey: SecretKeyInput, backend: SigningBackend = nobleSigning): Keys {
    return new Keys(toSecretKey(secretKey), backend);
  }
}

function resolveKeys(secretKey: SecretKeyInput | Keys): Keys {
  return secretKey instanceof Keys ? secretKey : Keys.fromSecretKey(secretKey);
}

/** Fill pubkey/id/sig on a template and return a signed event. */
export function finalizeEvent(template: EventTemplate, secretKey: SecretKeyInput | Keys): Event {
  const keys = resolveKeys(secretKey);
  const unsigned: UnsignedEvent = {
    kind: template.kind,
    tags: template.tags,
    content: template.content,
    created_at: template.created_at,
    pubkey: keys.publicKey,
  };
  return signEvent(unsigned, keys);
}

/**
 * Sign an already-assembled unsigned event. Rejects when `unsigned.pubkey` does not match the
 * secret key.
 */
export function signEvent(unsigned: UnsignedEvent, secretKey: SecretKeyInput | Keys): Event {
  const keys = resolveKeys(secretKey);
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
  const sig = keys.backend.sign(hexToBytes(id), keys.secretKey.bytes, randomBytes(32));
  if (sig.length !== 64) {
    throw new CryptoError("signing backend returned an invalid signature");
  }
  const event: Event = { ...normalized, id, sig: bytesToHex(sig) };
  markVerified(event);
  return event;
}
