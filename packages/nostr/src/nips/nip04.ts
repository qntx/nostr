/** NIP-04 legacy encrypted direct messages. Prefer NIP-44 for new applications. */
import { cbc } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { CryptoError } from "../core/error.ts";
import { nobleBackend } from "../core/key.ts";
import type { NostrBackend } from "../core/key.ts";
import {
  assertByteLength,
  assertHex32,
  assertSecretKeyBytes,
  hexToBytes,
  utf8Decoder,
  utf8Encoder,
  lowerAscii,
} from "../core/util.ts";

function normalizeSharedSecret(
  privkey: Uint8Array,
  pubkey: string,
  backend: NostrBackend,
): Uint8Array {
  assertHex32(pubkey, "public key");
  const sharedX = backend.ecdhX(privkey, hexToBytes(lowerAscii(pubkey)));
  if (sharedX.length !== 32) {
    throw new CryptoError("invalid NIP-04 shared secret");
  }
  return sharedX;
}

/**
 * Encrypt plaintext with the raw 32-byte ECDH x-coordinate (NIP-04's key material, like NIP-44's
 * conversation key), for key holders that only expose ECDH ({@link NostrKeyOperations}).
 */
export function encrypt(plaintext: string, sharedSecret: Uint8Array): string {
  assertByteLength(sharedSecret, 32, "shared secret");
  const iv = randomBytes(16);
  const plaintextBytes = utf8Encoder.encode(plaintext);
  const ciphertext = cbc(sharedSecret, iv).encrypt(plaintextBytes);
  return `${base64.encode(ciphertext)}?iv=${base64.encode(iv)}`;
}

/** Decrypt a NIP-04 payload with the raw 32-byte ECDH x-coordinate. */
export function decrypt(payload: string, sharedSecret: Uint8Array): string {
  assertByteLength(sharedSecret, 32, "shared secret");
  const [ciphertextPart, ivPart] = splitPayload(payload);
  try {
    const iv = base64.decode(ivPart);
    const ciphertext = base64.decode(ciphertextPart);
    const plaintext = cbc(sharedSecret, iv).decrypt(ciphertext);
    return utf8Decoder.decode(plaintext);
  } catch (error) {
    throw new CryptoError("invalid NIP-04 payload", { cause: error });
  }
}

/** Encrypt plaintext to a peer pubkey, deriving the shared secret from `secretKey`. */
export function encryptToPubkey(
  plaintext: string,
  secretKey: Uint8Array,
  peerPubkey: string,
  backend: NostrBackend = nobleBackend,
): string {
  assertSecretKeyBytes(secretKey);
  const sharedSecret = normalizeSharedSecret(secretKey, peerPubkey, backend);
  try {
    return encrypt(plaintext, sharedSecret);
  } finally {
    sharedSecret.fill(0);
  }
}

/** Decrypt a NIP-04 payload from a peer pubkey, deriving the shared secret from `secretKey`. */
export function decryptFromPubkey(
  payload: string,
  secretKey: Uint8Array,
  peerPubkey: string,
  backend: NostrBackend = nobleBackend,
): string {
  assertSecretKeyBytes(secretKey);
  splitPayload(payload);
  const sharedSecret = normalizeSharedSecret(secretKey, peerPubkey, backend);
  try {
    return decrypt(payload, sharedSecret);
  } finally {
    sharedSecret.fill(0);
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
