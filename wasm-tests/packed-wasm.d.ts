/**
 * Types for the packed `dist/wasm.mjs` entry, which exists only after `build:wasm`. The wildcard
 * ambient module keeps node-load.ts fully typed without the artifact on disk.
 */
// oxlint-disable consistent-type-imports -- ambient module bodies cannot use import statements
declare module "*.mjs" {
  export function loadNostrWasm(
    opts?: import("../src/wasm/index.ts").LoadNostrWasmOptions,
  ): Promise<import("../src/wasm/index.ts").NostrWasm>;
}
