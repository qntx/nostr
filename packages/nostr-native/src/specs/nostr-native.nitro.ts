import type { HybridObject } from "react-native-nitro-modules";

/**
 * Native BIP-340 backend backed by libsecp256k1 (C) via a shared C++ HybridObject.
 * `verifySerialized` takes the canonical NIP-01 serialization as UTF-8 bytes plus the event
 * `id`/`pubkey`/`sig` as raw bytes, and returns true iff `sha256(serializedUtf8)` equals `id` and
 * `sig` is a valid BIP-340 signature of `id` by the x-only `pubkey`. It never throws — malformed
 * input (including wrong buffer lengths) returns false. `publicKey` and `sign` implement the
 * `@qntx/nostr` `SigningBackend` contract and throw on bad input: wrong buffer lengths or an
 * invalid secret key (zero or >= group order).
 */
export interface NostrNative extends HybridObject<{ ios: "c++"; android: "c++" }> {
  verifySerialized(
    serializedUtf8: ArrayBuffer,
    id: ArrayBuffer,
    pubkey: ArrayBuffer,
    sig: ArrayBuffer,
  ): boolean;
  publicKey(secretKey: ArrayBuffer): ArrayBuffer;
  sign(id: ArrayBuffer, secretKey: ArrayBuffer, auxRand: ArrayBuffer): ArrayBuffer;
}
