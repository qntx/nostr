import { defineConfig } from "bumpp";

// npm packages and Cargo workspace versions are lockstep; bumpp rewrites every
// `0.x.y` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and the `nk-core = "=x.y.z"` dep.
// Internal @qntx/* ranges (peer ^<v>, dev <v>) are synced by sync-versions.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["packages/nostr/package.json", "packages/nostr-wasm/package.json", "Cargo.toml"],
  execute: "bun scripts/sync-versions.ts && cargo update --workspace",
  // execute rewrites Cargo.lock and the internal ranges; commit them too.
  all: true,
  commit: true,
  tag: true,
  push: true,
});

export default config;
