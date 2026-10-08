import { builtinModules } from "node:module";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintConfig, merge } from "@qntx/oxlint";

// The library runs on Node, browsers, and Hermes: Node builtins must not be
// imported from src (platform shims exempted by override below).
const platformNeutralImports = {
  paths: builtinModules.map((name) => ({
    name,
    message: "Node builtin — the library must stay platform-neutral",
  })),
  patterns: [
    {
      group: ["node:*"],
      message: "Node builtin — the library must stay platform-neutral",
    },
  ],
};

// The wasm package may reach into @qntx/nostr only through the core leaf.
const nostrCoreOnlyImports = {
  paths: [
    {
      name: "@qntx/nostr",
      message: "the wasm package may only import @qntx/nostr/core",
    },
  ],
  patterns: [
    {
      group: ["@qntx/nostr/**", "!@qntx/nostr/core"],
      message: "the wasm package may only import @qntx/nostr/core",
    },
  ],
};

const config: UserConfig = defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
  lint: merge(lintConfig, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    ignorePatterns: [
      "3rdparty/**",
      "target/**",
      "packages/nostr-wasm/src/generated/**",
      "packages/nostr/.hermes-smoke.iife.js",
    ],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        files: [
          "packages/nostr/src/nips/nip77.ts",
          "packages/nostr-wasm/src/abi.ts",
          "packages/nostr/tests/hermes/globals.ts",
          "packages/nostr-wasm/tests/**",
        ],
        rules: {
          // Bitwise ops are the binary format in these files (negentropy
          // varints/fingerprints, the u32 wasm ABI, the Hermes xorshift/UTF-8
          // test shims, and the wasm benches driving that ABI).
          "eslint/no-bitwise": "off",
        },
      },
      {
        files: [
          "packages/nostr/bench/**",
          "packages/nostr/scripts/**",
          "scripts/**",
          "packages/nostr-wasm/tests/**",
        ],
        rules: {
          // Bench and maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        files: ["packages/*/src/**"],
        rules: {
          // Hermes V1 (what React Native ships) has no ES2023 immutable array
          // methods, so the library must sort/reverse copies in place.
          "unicorn/no-array-sort": "off",
          "unicorn/no-array-reverse": "off",
          // @types/node leaks into the src program via the two platform files
          // exempted below, so Node-only globals would typecheck silently;
          // browser-only globals are equally absent on Hermes. Both sets are
          // banned — library code must use globalThis lookups instead.
          "eslint/no-restricted-globals": [
            "error",
            { name: "Buffer", message: "Node-only global — use Uint8Array" },
            { name: "process", message: "Node-only global — not available in browsers or Hermes" },
            { name: "global", message: "Node-only global — use globalThis" },
            { name: "require", message: "CJS-only — use import" },
            { name: "module", message: "CJS-only global" },
            { name: "__dirname", message: "CJS-only global" },
            { name: "__filename", message: "CJS-only global" },
            { name: "setImmediate", message: "Node-only global — use setTimeout" },
            { name: "clearImmediate", message: "Node-only global — use clearTimeout" },
            { name: "window", message: "browser-only global — use globalThis" },
            { name: "document", message: "browser-only global — use globalThis" },
            { name: "navigator", message: "browser-only global — use globalThis" },
            { name: "location", message: "browser-only global — use globalThis" },
            { name: "localStorage", message: "browser-only global — inject a store" },
            { name: "sessionStorage", message: "browser-only global — inject a store" },
          ],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      {
        files: ["packages/nostr-wasm/src/**"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: [...platformNeutralImports.paths, ...nostrCoreOnlyImports.paths],
              patterns: [...platformNeutralImports.patterns, ...nostrCoreOnlyImports.patterns],
            },
          ],
        },
      },
      {
        // Platform shims: wasm loading under Node legitimately needs builtins
        // (still bound to the @qntx/nostr/core boundary).
        files: ["packages/nostr-wasm/src/load.ts"],
        rules: {
          "eslint/no-restricted-imports": ["error", nostrCoreOnlyImports],
        },
      },
      {
        // The fake-relay test server legitimately needs builtins (and `ws`).
        files: ["packages/nostr/src/testing/serve.ts"],
        rules: {
          "eslint/no-restricted-imports": "off",
        },
      },
      {
        // Synchronous implementations of async contracts (EventStore,
        // NostrSigner, AsyncIterator.return) must keep the async signature
        // without an await in the body.
        files: [
          "packages/nostr/src/storage/memory.ts",
          "packages/nostr/src/signer/keys.ts",
          "packages/nostr/src/signer/nip46.ts",
          "packages/nostr/src/relay/subscription.ts",
        ],
        rules: {
          "typescript/require-await": "off",
        },
      },
    ],
  }),
  fmt: {
    ...fmt,
    ignorePatterns: [
      ...fmt.ignorePatterns,
      "3rdparty/**",
      "target/**",
      "packages/nostr-wasm/src/generated/**",
      "bun.lock",
      // TOML is owned by taplo (.taplo.toml, align_entries); generated vectors
      // stay byte-frozen.
      "**/*.toml",
      "vectors/**",
    ],
  },
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
});

export default config;
