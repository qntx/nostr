/*
 * Subresource Integrity hash (`sha256-<base64>`) of the shipped `nostr_wasm.wasm`, regenerated
 * whenever build:wasm runs. Pass it to `fetch(url, { integrity })` so the browser refuses to
 * execute a tampered module:
 *
 *   const res = await fetch(wasmUrl, { integrity: NOSTR_WASM_INTEGRITY });
 *   const wasm = await loadNostrWasm({ module: await res.arrayBuffer() });
 *
 * The constant only guards fetch-time delivery — callers that want SRI enforcement must fetch
 * with `integrity` and pass `module`.
 */
export const NOSTR_WASM_INTEGRITY = "sha256-U35sfOfQiY3cwnVyhStF4kNI7uMn9FBRRJbXn7DbpPg=";
