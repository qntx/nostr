import { NitroModules } from "react-native-nitro-modules";

import type { SerializedEventVerifier, SigningBackend } from "@qntx/nostr/core";

import type { NostrNative } from "./specs/nostr-native.nitro.ts";

const nostrNative = NitroModules.createHybridObject<NostrNative>("NostrNative");

function asArrayBuffer(view: Uint8Array): ArrayBuffer {
  const { buffer, byteOffset, byteLength } = view;
  if (buffer instanceof ArrayBuffer && byteOffset === 0 && byteLength === buffer.byteLength) {
    return buffer;
  }
  return new Uint8Array(view).buffer;
}

/**
 * `SerializedEventVerifier` backed by native libsecp256k1 — plug into `createEventVerifier` from
 * `@qntx/nostr/core`. The Nitro hybrid object is created once at module load.
 */
export const verifySerialized: SerializedEventVerifier = (serializedUtf8, id, pubkey, sig) =>
  nostrNative.verifySerialized(
    asArrayBuffer(serializedUtf8),
    asArrayBuffer(id),
    asArrayBuffer(pubkey),
    asArrayBuffer(sig),
  );

/**
 * `SigningBackend` backed by native libsecp256k1 — plug into `Keys.fromSecretKey(secretKey,
 * signing)` or `Keys.generate(signing)` so signing runs on the same randomized context as
 * verification. Throws on an invalid secret key or wrong-length input.
 */
export const signing: SigningBackend = {
  publicKey: (secretKey) => new Uint8Array(nostrNative.publicKey(asArrayBuffer(secretKey))),
  sign: (id, secretKey, auxRand) =>
    new Uint8Array(
      nostrNative.sign(asArrayBuffer(id), asArrayBuffer(secretKey), asArrayBuffer(auxRand)),
    ),
};
