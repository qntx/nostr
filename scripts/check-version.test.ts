import { describe, expect, test } from "vite-plus/test";

import { checkVersion } from "./check-version.ts";

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

const NOSTR = {
  path: "packages/nostr/package.json",
  pkg: { name: "@qntx/nostr", version: "0.9.0" },
};

const NOSTR_WASM = {
  path: "packages/nostr-wasm/package.json",
  pkg: {
    name: "@qntx/nostr-wasm",
    version: "0.9.0",
    peerDependencies: { "@qntx/nostr": "^0.9.0" } as Record<string, string>,
    devDependencies: { "@qntx/nostr": "0.9.0" } as Record<string, string>,
  },
};

const PACKAGES = [NOSTR, NOSTR_WASM];

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion(
      [NOSTR, { ...NOSTR_WASM, pkg: { ...NOSTR_WASM.pkg, version: "0.9.1" } }],
      PARSED,
      CARGO_TOML,
    );
    expect(errors).toStrictEqual([
      "version mismatch: packages/nostr-wasm/package.json has 0.9.1, Cargo.toml has 0.9.0",
    ]);
  });

  test("rejects a peer range without a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.peerDependencies["@qntx/nostr"] = "0.9.0";
    const errors = checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: peerDependencies["@qntx/nostr"] must be "^0.9.0", got "0.9.0"',
    ]);
  });

  test("rejects a dev range with a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["@qntx/nostr"] = "^0.9.0";
    const errors = checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], PARSED, CARGO_TOML);
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: devDependencies["@qntx/nostr"] must be "0.9.0", got "^0.9.0"',
    ]);
  });

  test("ignores ranges on external packages", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["typescript"] = "^7.0.2";
    expect(checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], PARSED, CARGO_TOML)).toStrictEqual([]);
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies["nk-core"].version = "=0.8.0";
    const errors = checkVersion(PACKAGES, parsed, CARGO_TOML);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("nk-core");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('sha2 = "0.11"', 'sha2 = "0.9.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.sha2 = "0.9.0";
    const errors = checkVersion(PACKAGES, parsed, toml);
    expect(errors).toStrictEqual([
      'Cargo.toml: "0.9.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });
});
