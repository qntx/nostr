import { NostrError, createEventVerifier } from "@qntx/nostr/core";
import type { EventVerifier, NostrBackend } from "@qntx/nostr/core";

/** Wasm instance aborted; later calls on that instance fail. */
export class WasmPoisonedError extends NostrError {
  override name = "WasmPoisonedError";
}

/**
 * Run `fn` unless the instance is already poisoned; a `WebAssembly.RuntimeError` aborts the
 * instance, so it is converted to {@link WasmPoisonedError} and rethrown on every later call.
 */
export function runPoisoned<T>(poison: { error?: Error }, fn: () => T): T {
  if (poison.error !== undefined) {
    throw poison.error;
  }
  try {
    return fn();
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) {
      poison.error = new WasmPoisonedError("wasm instance aborted", {
        cause: error,
      });
      throw poison.error;
    }
    throw error;
  }
}

/**
 * Build the WASM event verifier on {@link createEventVerifier}. A `WebAssembly.RuntimeError` from
 * the module means the instance aborted — it poisons every later call with the same
 * `WasmPoisonedError`; any other backend error verifies `false` (the event is marked failed).
 */
export function createWasmEventVerifier(
  verifySerialized: NostrBackend["verifySerialized"],
  poison: { error?: Error },
): EventVerifier {
  const raw: NostrBackend["verifySerialized"] = (serializedUtf8, id, pubkey, sig) => {
    try {
      return runPoisoned(poison, () => verifySerialized(serializedUtf8, id, pubkey, sig));
    } catch (error) {
      if (error instanceof WasmPoisonedError) {
        throw error;
      }
      return false;
    }
  };
  const backend: NostrBackend = {
    verifySerialized: raw,
    // createEventVerifier only calls verifySerialized; the rest of the shape is
    // required by NostrBackend and never invoked.
    publicKey: () => {
      throw new NostrError("wasm verifier backend: publicKey is unsupported");
    },
    sign: () => {
      throw new NostrError("wasm verifier backend: sign is unsupported");
    },
    ecdhX: () => {
      throw new NostrError("wasm verifier backend: ecdhX is unsupported");
    },
  };
  return createEventVerifier(backend);
}
