import {
  isMarkedFailed,
  isMarkedVerified,
  markUnverified,
  markVerified,
  serializeValidatedEvent,
  validateSignedEvent,
} from "./event.ts";
import type { Event } from "./event.ts";
import { nobleBackend } from "./key.ts";
import type { NostrBackend } from "./key.ts";
import { hexToBytes, utf8Encoder } from "./util.ts";

/** Whole-event verifier: return true iff the event's id and BIP-340 signature verify. */
export type EventVerifier = (event: Event) => boolean;

/**
 * Build an event verifier with exactly the semantics of {@link verifyEvent}, delegating the hash and
 * signature check to `backend`. Verified/failed results share `verifyEvent`'s WeakSet caches, so
 * verifiers built this way and `verifyEvent` agree on (and reuse) each other's results.
 */
export function createEventVerifier(backend: NostrBackend): EventVerifier {
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
    const ok = backend.verifySerialized(
      utf8Encoder.encode(serializeValidatedEvent(event)),
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

/** Verify event id and BIP-340 signature. Uses WeakSet cache (does not mutate the event). */
export const verifyEvent: EventVerifier = createEventVerifier(nobleBackend);
