import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const bench = process.env["BENCH"] === "1";

/**
 * The `.` export carries a `browser` condition (the fetch-only loader); every other generated entry
 * is a plain string expanded to types/import/default.
 */
export function applyPackExports(pkgExports: Record<string, unknown>): Record<string, unknown> {
  for (const [key, value] of Object.entries(pkgExports)) {
    if (typeof value !== "string" || !value.endsWith(".mjs")) {
      continue;
    }
    const types = value.replace(/\.mjs$/, ".d.mts");
    pkgExports[key] =
      key === "."
        ? { types, browser: "./dist/browser.mjs", import: value, default: value }
        : { types, import: value, default: value };
  }
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
        fileName: "nk_wasm.wasm",
        source: new Uint8Array(readFileSync(file)),
      });
      return `export default import.meta.ROLLUP_FILE_URL_${ref};`;
    },
  };
}

const config: UserConfig = defineConfig({
  pack: {
    plugins: [wasmUrlAsset()],
    entry: {
      index: "src/index.ts",
      browser: "src/index.browser.ts",
    },
    dts: {
      generator: "tsgo",
      // Without the dev `paths` mapping: @qntx/nostr/* resolves to the built
      // package, not ../nostr/src — otherwise tsgo emits stray .d.ts there.
      tsconfig: "tsconfig.pack.json",
    },
    deps: {
      neverBundle: ["@qntx/nostr"],
    },
    sourcemap: true,
    exports: {
      customExports: applyPackExports,
    },
  },
  test: {
    // Development resolution for the workspace sibling: tests resolve
    // @qntx/nostr subpaths against sources without a prior pack build. The
    // specifier stays external in the pack output via deps.neverBundle.
    alias: [
      { find: /^@qntx\/nostr\/core$/, replacement: path.resolve("../nostr/src/core/index.ts") },
      { find: /^@qntx\/nostr$/, replacement: path.resolve("../nostr/src/index.ts") },
    ],
    include: bench ? ["tests/**/*.ts"] : ["tests/**/*.test.ts"],
  },
});

export default config;
