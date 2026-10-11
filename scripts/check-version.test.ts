import { describe, expect, test } from "vite-plus/test";

import { checkVersion } from "./check-version.ts";

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
    expect(checkVersion(PACKAGES, BUN_LOCK)).toStrictEqual([]);
  });

  test("rejects a missing version", () => {
    const errors = checkVersion(
      [NOSTR, { ...NOSTR_WASM, pkg: { name: "@qntx/nostr-wasm" } }],
      BUN_LOCK,
    );
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: missing string "version"',
      'bun.lock: workspaces["packages/nostr-wasm"] has version "0.9.0", expected undefined',
    ]);
  });

  test("rejects a peer range without a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.peerDependencies["@qntx/nostr"] = "0.9.0";
    const errors = checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], BUN_LOCK);
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: peerDependencies["@qntx/nostr"] must be "^0.9.0", got "0.9.0"',
    ]);
  });

  test("rejects a dev range with a caret", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["@qntx/nostr"] = "^0.9.0";
    const errors = checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], BUN_LOCK);
    expect(errors).toStrictEqual([
      'packages/nostr-wasm/package.json: devDependencies["@qntx/nostr"] must be "0.9.0", got "^0.9.0"',
    ]);
  });

  test("ignores ranges on external packages", () => {
    const pkg = structuredClone(NOSTR_WASM.pkg);
    pkg.devDependencies["typescript"] = "^7.0.2";
    expect(checkVersion([NOSTR, { ...NOSTR_WASM, pkg }], BUN_LOCK)).toStrictEqual([]);
  });

  test("rejects a stale bun.lock workspace version", () => {
    // The drift this check guards: manifests moved on while bun.lock still
    // records the old workspace versions.
    const errors = checkVersion(PACKAGES_11, STALE_BUN_LOCK);
    expect(errors).toStrictEqual([
      'bun.lock: workspaces["packages/nostr"] has version "0.10.1", expected "0.11.0"',
      'bun.lock: workspaces["packages/nostr-wasm"] has version "0.10.1", expected "0.11.0"',
    ]);
  });

  test("rejects a bun.lock workspace entry that is missing", () => {
    const errors = checkVersion(PACKAGES, { workspaces: {} });
    expect(errors).toStrictEqual([
      'bun.lock: missing workspaces["packages/nostr"] entry',
      'bun.lock: missing workspaces["packages/nostr-wasm"] entry',
    ]);
  });

  test("accepts a bumped pair with a synced lock", () => {
    expect(checkVersion(PACKAGES_11, BUN_LOCK_11)).toStrictEqual([]);
  });
});
