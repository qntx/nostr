import { createNostrWasmLoader, fetchWasmUrl, isWasmBytes } from "./instance.ts";
import type { LoadNostrWasmOptions, NostrWasm } from "./instance.ts";

export { WasmVerifyPoisonedError } from "./adapter.ts";
export type { LoadNostrWasmOptions, NostrWasm } from "./instance.ts";

async function defaultWasmHref(): Promise<string> {
  const mod = await import("./nostr_crypto_wasm_bg.wasm?url");
  return mod.default;
}

async function readWasmUrl(url: URL): Promise<Uint8Array> {
  if (url.protocol === "file:") {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    return new Uint8Array(await readFile(fileURLToPath(url)));
  }
  return fetchWasmUrl(url);
}

async function wasmBytes(opts?: LoadNostrWasmOptions): Promise<ArrayBuffer | ArrayBufferView> {
  const source = opts?.module;
  if (source !== undefined && isWasmBytes(source)) {
    return source;
  }
  const href = source instanceof URL ? source : new URL(await defaultWasmHref(), import.meta.url);
  return readWasmUrl(href);
}

const loader = createNostrWasmLoader(wasmBytes);

/** Instantiate once. Repeats reuse the same module. Failure throws; no noble fallback. */
export async function loadNostrWasm(opts?: LoadNostrWasmOptions): Promise<NostrWasm> {
  return loader.loadNostrWasm(opts);
}

/** Clears intern so tests can re-instantiate. Not exported from the wasm subpath. */
export function resetNostrWasmForTests(): void {
  loader.resetNostrWasm();
}
