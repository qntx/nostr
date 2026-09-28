import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  isMarkedFailed,
  isMarkedVerified,
  markUnverified,
  markVerified,
  serializeEvent,
  validateSignedEvent,
} from "./event.ts";
import type { Event } from "./event.ts";
import { hexToBytes, utf8Encoder } from "./util.ts";

/**
 * Verification backend: return true iff `sha256(serializedUtf8)` equals `id` and `sig` is a valid
 * BIP-340 signature of `id` by the x-only `pubkey`. Inputs are raw bytes (`id`/`pubkey` 32, `sig`
 * 64). Exceptions propagate through the built verifier unmarked — a throwing backend is broken and
 * must surface.
 */
export type SerializedEventVerifier = (
  serializedUtf8: Uint8Array,
  id: Uint8Array,
  pubkey: Uint8Array,
  sig: Uint8Array,
) => boolean;

/**
 * Build an event verifier with exactly the semantics of {@link verifyEvent}, delegating the hash and
 * signature check to `backend`. Verified/failed results share `verifyEvent`'s WeakSet caches, so
 * verifiers built this way and `verifyEvent` agree on (and reuse) each other's results.
 */
export function createEventVerifier(backend: SerializedEventVerifier): (event: Event) => boolean {
  return (event) => {
    if (isMarkedVerified(event)) {
      return true;
    }
    if (isMarkedFailed(event)) {
      return false;
    }
    if (!validateSignedEvent(event)) {
      markUnverified(event);
      return false;
    }
    const ok = backend(
      utf8Encoder.encode(serializeEvent(event)),
      hexToBytes(event.id),
      hexToBytes(event.pubkey),
      hexToBytes(event.sig),
    );
    if (ok) {
      markVerified(event);
    } else {
      markUnverified(event);
    }
    return ok;
  };
}

const nobleSerializedVerify: SerializedEventVerifier = (serializedUtf8, id, pubkey, sig) => {
  try {
    const digest = sha256(serializedUtf8);
    if (!digest.every((byte, i) => byte === id[i])) {
      return false;
    }
    return schnorr.verify(sig, id, pubkey);
  } catch {
    return false;
  }
};

/** Verify event id and BIP-340 signature. Uses WeakSet cache (does not mutate the event). */
export const verifyEvent: (event: Event) => boolean = createEventVerifier(nobleSerializedVerify);
