import { WasmPoisonedError } from "../core/error.ts";
import { createEventVerifier } from "../core/verifier.ts";
import type { EventVerifier, SerializedEventVerifier } from "../core/verifier.ts";

export { WasmPoisonedError } from "../core/error.ts";

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
  verifySerialized: SerializedEventVerifier,
  poison: { error?: Error },
): EventVerifier {
  const backend: SerializedEventVerifier = (serializedUtf8, id, pubkey, sig) => {
    try {
      return runPoisoned(poison, () => verifySerialized(serializedUtf8, id, pubkey, sig));
    } catch (error) {
      if (error instanceof WasmPoisonedError) {
        throw error;
      }
      return false;
    }
  };
  return createEventVerifier(backend);
}
