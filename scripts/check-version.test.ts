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

// Cargo.lock shape: workspace members are [[package]] entries with no
// `source`; everything from crates.io carries a registry source.
const LOCK = {
  package: [
    { name: "nk-core", version: "0.9.0" },
    { name: "nk-vectors", version: "0.9.0" },
    {
      name: "sha2",
      version: "0.9.0",
      source: "registry+https://github.com/rust-lang/crates.io-index",
    },
  ],
};

// The 0.10.1 → 0.11.0 bump that motivated the lockfile check: manifests at
// 0.11.0 while the members' lock entries still record 0.10.1.
const CARGO_TOML_11 = CARGO_TOML.replaceAll("0.9.0", "0.11.0");
const PARSED_11 = {
  workspace: {
    package: { version: "0.11.0" },
    dependencies: {
      "nk-core": { version: "=0.11.0", path: "crates/nk-core", "default-features": false },
      sha2: "0.11",
    },
  },
};
const STALE_LOCK = {
  package: [
    { name: "nk-core", version: "0.10.1" },
    { name: "nk-vectors", version: "0.10.1" },
    {
      name: "sha2",
      version: "0.9.0",
      source: "registry+https://github.com/rust-lang/crates.io-index",
    },
  ],
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

// bun.lock mirrors the workspace manifests under `workspaces` keyed by
// directory; the root entry ("") has no version and is skipped.
const BUN_LOCK = {
  workspaces: {
    "": { name: "@qntx/nostr-monorepo" },
    "packages/nostr": { name: "@qntx/nostr", version: "0.9.0" },
    "packages/nostr-wasm": { name: "@qntx/nostr-wasm", version: "0.9.0" },
  },
};

const LOCK_11 = {
  package: [
    { name: "nk-core", version: "0.11.0" },
    { name: "nk-vectors", version: "0.11.0" },
    {
      name: "sha2",
      version: "0.9.0",
      source: "registry+https://github.com/rust-lang/crates.io-index",
    },
  ],
};

const BUN_LOCK_11 = {
  workspaces: {
    "packages/nostr": { name: "@qntx/nostr", version: "0.11.0" },
    "packages/nostr-wasm": { name: "@qntx/nostr-wasm", version: "0.11.0" },
  },
};

const STALE_BUN_LOCK = {
  workspaces: {
    "packages/nostr": { name: "@qntx/nostr", version: "0.10.1" },
    "packages/nostr-wasm": { name: "@qntx/nostr-wasm", version: "0.10.1" },
  },
};

const PACKAGES_11 = [
  { path: "packages/nostr/package.json", pkg: { name: "@qntx/nostr", version: "0.11.0" } },
  {
    path: "packages/nostr-wasm/package.json",
    pkg: {
      name: "@qntx/nostr-wasm",
      version: "0.11.0",
      peerDependencies: { "@qntx/nostr": "^0.11.0" },
      devDependencies: { "@qntx/nostr": "0.11.0" },
    },
  },
];

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML, LOCK, BUN_LOCK)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion(
      [NOSTR, { ...NOSTR_WASM, pkg: { ...NOSTR_WASM.pkg, version: "0.9.1" } }],
      PARSED,
      CARGO_TOML,
      LOCK,
      BUN_LOCK,
    );
    expect(errors).toStrictEqual([
      "version mismatch: packages/nostr-wasm/package.json has 0.9.1, Cargo.toml has 0.9.0",
      'bun.lock: workspaces["packages/nostr-wasm"] has version "0.9.0", expected "0.9.1"',
    ]);
  });

  test("rejects a peer range without a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.peerDependencies["@qntx/nostr"] = "0.9.0";
    const errors = checkVersion(
      [NOSTR, { ...NOSTR_WASM, pkg }],
      PARSED,
      CARGO_TOML,
      LOCK,
      BUN_LOCK,
    );
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: peerDependencies["@qntx/nostr"] must be "^0.9.0", got "0.9.0"',
    ]);
  });

  test("rejects a dev range with a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["@qntx/nostr"] = "^0.9.0";
    const errors = checkVersion(
      [NOSTR, { ...NOSTR_WASM, pkg }],
      PARSED,
      CARGO_TOML,
      LOCK,
      BUN_LOCK,
    );
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: devDependencies["@qntx/nostr"] must be "0.9.0", got "^0.9.0"',
    ]);
  });

  test("ignores ranges on external packages", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["typescript"] = "^7.0.2";
    expect(
      checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], PARSED, CARGO_TOML, LOCK, BUN_LOCK),
    ).toStrictEqual([]);
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies["nk-core"].version = "=0.8.0";
    const errors = checkVersion(PACKAGES, parsed, CARGO_TOML, LOCK, BUN_LOCK);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("nk-core");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('sha2 = "0.11"', 'sha2 = "0.9.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.sha2 = "0.9.0";
    const errors = checkVersion(PACKAGES, parsed, toml, LOCK, BUN_LOCK);
    expect(errors).toStrictEqual([
      'Cargo.toml: "0.9.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });

  test("rejects a stale Cargo.lock member version", () => {
    const errors = checkVersion(PACKAGES_11, PARSED_11, CARGO_TOML_11, STALE_LOCK, BUN_LOCK_11);
    expect(errors).toStrictEqual([
      'Cargo.lock: workspace member "nk-core" has version "0.10.1", expected "0.11.0"',
      'Cargo.lock: workspace member "nk-vectors" has version "0.10.1", expected "0.11.0"',
    ]);
  });

  test("does not flag a registry crate on the same version number", () => {
    // sha2 sits at "0.9.0" in LOCK — equal to the workspace version but
    // registry-sourced, so it is not a member and must pass.
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML, LOCK, BUN_LOCK)).toStrictEqual([]);
  });

  test("rejects a stale bun.lock workspace version", () => {
    // The 0.9.0 → 0.12.1 drift this check guards: manifests moved on while
    // bun.lock still records the old workspace versions.
    const errors = checkVersion(PACKAGES_11, PARSED_11, CARGO_TOML_11, LOCK_11, STALE_BUN_LOCK);
    expect(errors).toStrictEqual([
      'bun.lock: workspaces["packages/nostr"] has version "0.10.1", expected "0.11.0"',
      'bun.lock: workspaces["packages/nostr-wasm"] has version "0.10.1", expected "0.11.0"',
    ]);
  });

  test("rejects a bun.lock workspace entry that is missing", () => {
    const errors = checkVersion(PACKAGES, PARSED, CARGO_TOML, LOCK, { workspaces: {} });
    expect(errors).toStrictEqual([
      'bun.lock: missing workspaces["packages/nostr"] entry',
      'bun.lock: missing workspaces["packages/nostr-wasm"] entry',
    ]);
  });
});
