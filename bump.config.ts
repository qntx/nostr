import { defineConfig } from "bumpp";

// npm package and Cargo workspace versions are lockstep; bumpp rewrites every
// `0.x.y` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and the `nk-core = "=x.y.z"` dep.
export default defineConfig({
  files: ["package.json", "Cargo.toml"],
  execute: "cargo update --workspace",
  commit: true,
  tag: true,
  push: true,
});
