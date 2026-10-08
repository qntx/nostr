import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const bench = process.env["BENCH"] === "1";

/** ESM-only sugar flattens to a string; keep types/import/default for pack entries. */
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
  return pkgExports;
}

const config: UserConfig = defineConfig({
  pack: {
    deps: { resolveDepSubpath: true },
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
    include: bench ? ["bench/**/*.ts"] : ["tests/**/*.{test,spec}.ts"],
  },
});

export default config;
