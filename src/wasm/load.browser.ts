import { CryptoError } from "../core/error.ts";
import { createNostrWasmLoader, fetchWasmUrl, isWasmBytes } from "./instance.ts";
import type { LoadNostrWasmOptions, NostrWasm } from "./instance.ts";

export type { LoadNostrWasmOptions, NostrWasm } from "./instance.ts";

async function wasmBytes(opts?: LoadNostrWasmOptions): Promise<ArrayBuffer | ArrayBufferView> {
  const source = opts?.module;
  if (source !== undefined && isWasmBytes(source)) {
    return source;
  }
  if (source instanceof URL && source.protocol !== "file:") {
    return fetchWasmUrl(source);
  }
  if (source instanceof URL) {
    throw new CryptoError(`cannot fetch wasm from ${source.href}`);
  }
  return fetchWasmUrl(new URL("nostr_crypto_wasm_bg.wasm", import.meta.url));
}

const loader = createNostrWasmLoader(wasmBytes);

/** Instantiate once. Repeats reuse the same module. Failure throws; no noble fallback. */
export async function loadNostrWasm(opts?: LoadNostrWasmOptions): Promise<NostrWasm> {
  return loader.loadNostrWasm(opts);
}
