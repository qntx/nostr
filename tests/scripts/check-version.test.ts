import { describe, expect, test } from "vite-plus/test";

import { checkVersion } from "../../scripts/check-version.ts";

const CARGO_TOML = `[workspace]
members = ["crates/*"]

[workspace.package]
version = "0.9.0"

[workspace.dependencies]
nk-core = { version = "=0.9.0", path = "crates/nk-core", default-features = false }
sha2 = "0.11"
`;

const PARSED = {
  workspace: {
    package: { version: "0.9.0" },
    dependencies: {
      "nk-core": { version: "=0.9.0", path: "crates/nk-core", "default-features": false },
      sha2: "0.11",
    },
  },
};

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion({ version: "0.9.0" }, PARSED, CARGO_TOML)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion({ version: "0.9.1" }, PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      "version mismatch: package.json has 0.9.1, Cargo.toml has 0.9.0",
    ]);
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies["nk-core"].version = "=0.8.0";
    const errors = checkVersion({ version: "0.9.0" }, parsed, CARGO_TOML);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("nk-core");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('sha2 = "0.11"', 'sha2 = "0.9.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.sha2 = "0.9.0";
    const errors = checkVersion({ version: "0.9.0" }, parsed, toml);
    expect(errors).toStrictEqual([
      'Cargo.toml: "0.9.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });
});
