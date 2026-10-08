/**
 * Types for the packed `dist/index.mjs` entry, which exists only after `build:wasm`. The wildcard
 * ambient module keeps node-load.ts fully typed without the artifact on disk.
 */
// oxlint-disable consistent-type-imports -- ambient module bodies cannot use import statements
declare module "*.mjs" {
  export function loadNostrWasm(
    opts?: import("@qntx/nostr").LoadNostrWasmOptions,
  ): Promise<import("@qntx/nostr").NostrWasm>;
}
