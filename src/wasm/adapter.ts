import { WasmVerifyPoisonedError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import { createEventVerifier } from "../core/verifier.ts";
import type { SerializedEventVerifier } from "../core/verifier.ts";

export { WasmVerifyPoisonedError } from "../core/error.ts";

/**
 * Build the WASM event verifier on {@link createEventVerifier}. A `WebAssembly.RuntimeError` from
 * the module means the instance aborted — it poisons every later call with the same
 * `WasmVerifyPoisonedError`; any other backend error verifies `false` (the event is marked
 * failed).
 */
export function createWasmEventVerifier(
  verifySerialized: SerializedEventVerifier,
  poison: { error?: Error },
): (event: Event) => boolean {
  const backend: SerializedEventVerifier = (serializedUtf8, id, pubkey, sig) => {
    if (poison.error !== undefined) {
      throw poison.error;
    }
    try {
      return verifySerialized(serializedUtf8, id, pubkey, sig);
    } catch (error) {
      if (error instanceof WebAssembly.RuntimeError) {
        poison.error = new WasmVerifyPoisonedError("wasm verify aborted the instance", {
          cause: error,
        });
        throw poison.error;
      }
      return false;
    }
  };
  return createEventVerifier(backend);
}
