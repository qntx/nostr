/** NIP-04 legacy encrypted direct messages. Prefer NIP-44 for new applications. */
import { cbc } from "@noble/ciphers/aes.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { CryptoError } from "../core/error.ts";
import {
  assertByteLength,
  assertHex32,
  assertSecretKeyBytes,
  hexToBytes,
  utf8Decoder,
  utf8Encoder,
} from "../core/util.ts";

function normalizeSharedSecret(privkey: Uint8Array, pubkey: string): Uint8Array {
  assertHex32(pubkey, "public key");
  try {
    const key = secp256k1.getSharedSecret(privkey, hexToBytes(`02${pubkey.toLowerCase()}`));
    return key.slice(1, 33);
  } catch (error) {
    throw new CryptoError("invalid NIP-04 public key", { cause: error });
  }
}

function resolveSecret(secretKey: string | Uint8Array): Uint8Array {
  if (typeof secretKey === "string") {
    return hexToBytes(assertHex32(secretKey, "secret key"));
  }
  assertSecretKeyBytes(secretKey);
  return secretKey;
}

/** Encrypt plaintext to a peer pubkey (NIP-04). */
export function encrypt(secretKey: string | Uint8Array, pubkey: string, text: string): string {
  const privkey = resolveSecret(secretKey);
  const normalizedKey = normalizeSharedSecret(privkey, pubkey);
  try {
    return encryptWithSharedSecret(normalizedKey, text);
  } finally {
    normalizedKey.fill(0);
  }
}

/**
 * Encrypt with the raw 32-byte ECDH x-coordinate instead of a secret key, for key holders that only
 * expose ECDH ({@link NostrKeyOperations}).
 */
export function encryptWithSharedSecret(sharedX: Uint8Array, text: string): string {
  assertByteLength(sharedX, 32, "shared secret");
  const iv = randomBytes(16);
  const plaintext = utf8Encoder.encode(text);
  const ciphertext = cbc(sharedX, iv).encrypt(plaintext);
  return `${base64.encode(ciphertext)}?iv=${base64.encode(iv)}`;
}

/** Decrypt a NIP-04 payload from a peer pubkey. */
export function decrypt(secretKey: string | Uint8Array, pubkey: string, data: string): string {
  const privkey = resolveSecret(secretKey);
  splitPayload(data);
  const normalizedKey = normalizeSharedSecret(privkey, pubkey);
  try {
    return decryptWithSharedSecret(normalizedKey, data);
  } finally {
    normalizedKey.fill(0);
  }
}

function splitPayload(data: string): [ciphertext: string, iv: string] {
  const parts = data.split("?iv=");
  const [ciphertext, iv] = parts;
  if (
    parts.length !== 2 ||
    ciphertext === undefined ||
    ciphertext === "" ||
    iv === undefined ||
    iv === ""
  ) {
    throw new CryptoError("invalid NIP-04 payload: missing iv");
  }
  return [ciphertext, iv];
}

/**
 * Decrypt a NIP-04 payload with the raw 32-byte ECDH x-coordinate instead of a secret key, for key
 * holders that only expose ECDH ({@link NostrKeyOperations}).
 */
export function decryptWithSharedSecret(sharedX: Uint8Array, data: string): string {
  assertByteLength(sharedX, 32, "shared secret");
  const [ciphertextPart, ivPart] = splitPayload(data);
  try {
    const iv = base64.decode(ivPart);
    const ciphertext = base64.decode(ciphertextPart);
    const plaintext = cbc(sharedX, iv).decrypt(ciphertext);
    return utf8Decoder.decode(plaintext);
  } catch (error) {
    throw new CryptoError("invalid NIP-04 payload", { cause: error });
  }
}
