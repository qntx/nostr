import { describe, expect, test } from "vite-plus/test";

import { syncInternalDeps } from "./sync-versions.ts";

const INTERNAL = new Set(["@qntx/nostr", "@qntx/nostr-wasm"]);

describe("syncInternalDeps", () => {
  test("rewrites peer ranges to ^<version> and dev ranges to <version>", () => {
    const pkg = {
      name: "@qntx/nostr-wasm",
      peerDependencies: { "@qntx/nostr": "^0.9.0" },
      devDependencies: { "@qntx/nostr": "0.9.0", typescript: "7.0.2" },
    };
    expect(syncInternalDeps(pkg, "0.9.1", INTERNAL)).toStrictEqual({
      name: "@qntx/nostr-wasm",
      peerDependencies: { "@qntx/nostr": "^0.9.1" },
      devDependencies: { "@qntx/nostr": "0.9.1", typescript: "7.0.2" },
    });
  });

  test("leaves manifests without internal deps untouched", () => {
    const pkg = { name: "@qntx/nostr", dependencies: { "@noble/curves": "^2.4.0" } };
    expect(syncInternalDeps(pkg, "0.9.1", INTERNAL)).toStrictEqual(pkg);
  });
});
