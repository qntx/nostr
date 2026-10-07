import { existsSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintConfig, merge } from "@qntx/oxlint";

const packWasm = process.env["WASM_PACK"] === "1";
const wasmTest = process.env["WASM_TEST"] === "1";
const bench = process.env["BENCH"] === "1";

/** Always declare ./wasm so `vp pack` without WASM_PACK does not strip the export. */
export function applyPackExports(pkgExports: Record<string, unknown>): Record<string, unknown> {
  for (const [key, value] of Object.entries(pkgExports)) {
    if (typeof value !== "string" || !value.endsWith(".mjs")) {
      continue;
    }
    pkgExports[key] = {
      types: value.replace(/\.mjs$/, ".d.mts"),
      import: value,
      default: value,
    };
  }
  // Re-append after the generated "./package.json" so the export order is
  // identical whether or not the wasm entry was part of this build.
  delete pkgExports["./wasm.browser"];
  pkgExports["./wasm.browser"] = {
    types: "./dist/wasm.browser.d.mts",
    import: "./dist/wasm.browser.mjs",
    default: "./dist/wasm.browser.mjs",
  };
  delete pkgExports["./wasm"];
  pkgExports["./wasm"] = {
    types: "./dist/wasm.d.mts",
    browser: "./dist/wasm.browser.mjs",
    import: "./dist/wasm.mjs",
    default: "./dist/wasm.mjs",
  };
  return pkgExports;
}

/** Asset-URL for `*.wasm?url`. Does not instantiate the module. */
function wasmUrlAsset() {
  return {
    name: "wasm-url-asset",
    resolveId(id: string, importer: string | undefined) {
      if (!id.endsWith(".wasm?url")) {
        return undefined;
      }
      const bare = id.slice(0, -"?url".length);
      const imported = importer === undefined ? importer : importer.split("?")[0];
      const from =
        imported === undefined || imported === "" ? process.cwd() : path.dirname(imported);
      const file = path.resolve(from, bare);
      if (!existsSync(file)) {
        throw new Error(`missing wasm asset ${file}`);
      }
      return `\0wasm-url:${file}`;
    },
    load(
      this: {
        emitFile: (asset: { type: "asset"; fileName: string; source: Uint8Array }) => string;
      },
      id: string,
    ) {
      if (!id.startsWith("\0wasm-url:")) {
        return undefined;
      }
      const file = id.slice("\0wasm-url:".length);
      const ref = this.emitFile({
        type: "asset",
        fileName: "nk_wasm_bg.wasm",
        source: new Uint8Array(readFileSync(file)),
      });
      return `export default import.meta.ROLLUP_FILE_URL_${ref};`;
    },
  };
}

const config: UserConfig = defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  pack: {
    deps: { resolveDepSubpath: true },
    plugins: packWasm ? [wasmUrlAsset()] : [],
    entry: {
      index: "src/index.ts",
      core: "src/core/index.ts",
      signer: "src/signer/index.ts",
      relay: "src/relay/index.ts",
      client: "src/client/index.ts",
      storage: "src/storage/index.ts",
      store: "src/store/index.ts",
      loaders: "src/loaders/index.ts",
      gossip: "src/gossip/index.ts",
      "nips/blossom": "src/nips/blossom.ts",
      "nips/nip04": "src/nips/nip04.ts",
      "nips/nip05": "src/nips/nip05.ts",
      "nips/nip10": "src/nips/nip10.ts",
      "nips/nip11": "src/nips/nip11.ts",
      "nips/nip13": "src/nips/nip13.ts",
      "nips/nip17": "src/nips/nip17.ts",
      "nips/nip19": "src/nips/nip19.ts",
      "nips/nip21": "src/nips/nip21.ts",
      "nips/nip27": "src/nips/nip27.ts",
      "nips/nip42": "src/nips/nip42.ts",
      "nips/nip44": "src/nips/nip44.ts",
      "nips/nip46": "src/nips/nip46.ts",
      "nips/nip49": "src/nips/nip49.ts",
      "nips/nip51": "src/nips/nip51.ts",
      "nips/nip57": "src/nips/nip57.ts",
      "nips/nip59": "src/nips/nip59.ts",
      "nips/nip65": "src/nips/nip65.ts",
      "nips/nip77": "src/nips/nip77.ts",
      "nips/nip98": "src/nips/nip98.ts",
      testing: "src/testing/index.ts",
      // bun CI is Rust-free; wasm entry is publish / build:wasm only
      ...(packWasm
        ? { wasm: "src/wasm/index.ts", "wasm.browser": "src/wasm/index.browser.ts" }
        : {}),
    },
    dts: {
      generator: "tsgo",
    },
    sourcemap: true,
    exports: {
      customExports: applyPackExports,
    },
  },
  test: {
    include: wasmTest
      ? ["wasm-tests/**/*.ts"]
      : bench
        ? ["bench/**/*.ts"]
        : ["tests/**/*.{test,spec}.ts"],
    exclude: ["3rdparty/**", "node_modules/**", "dist/**"],
  },
  lint: merge(lintConfig, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    ignorePatterns: ["3rdparty/**", "target/**", "src/wasm/generated/**", ".hermes-smoke.iife.js"],
    overrides: [
      {
        files: ["src/nips/nip77.ts", "src/wasm/abi.ts", "tests/hermes/globals.ts", "wasm-tests/**"],
        rules: {
          // Bitwise ops are the binary format in these files (negentropy
          // varints/fingerprints, the u32 wasm ABI, the Hermes xorshift/UTF-8
          // test shims, and the wasm benches driving that ABI).
          "eslint/no-bitwise": "off",
        },
      },
      {
        files: ["bench/**", "scripts/**", "wasm-tests/**"],
        rules: {
          // Bench and maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        files: ["src/**"],
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
          // The library runs on Node, browsers, and Hermes: Node builtins must
          // not be imported from src (platform shims exempted below).
          "eslint/no-restricted-imports": [
            "error",
            {
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
            },
          ],
        },
      },
      {
        // Platform shims: wasm loading under Node and the fake-relay test server
        // legitimately need builtins (and `ws`).
        files: ["src/wasm/load.ts", "src/testing/serve.ts"],
        rules: {
          "eslint/no-restricted-imports": "off",
        },
      },
      {
        // Synchronous implementations of async contracts (EventStore,
        // NostrSigner, AsyncIterator.return) must keep the async signature
        // without an await in the body.
        files: [
          "src/storage/memory.ts",
          "src/signer/keys.ts",
          "src/signer/nip46.ts",
          "src/relay/subscription.ts",
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
      "src/wasm/generated/**",
      "bun.lock",
      // TOML is owned by taplo (.taplo.toml, align_entries); generated vectors
      // stay byte-frozen.
      "**/*.toml",
      "vectors/**",
    ],
  },
});

export default config;
