import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
    },
    dts: {
      generator: "tsgo",
      // Without the dev `paths` mapping: @qntx/nostr/* resolves to the built
      // package, not ../nostr/src — otherwise tsgo emits stray .d.ts there.
      tsconfig: "tsconfig.pack.json",
    },
    deps: {
      neverBundle: ["@qntx/nostr", "react-native-nitro-modules"],
    },
    sourcemap: true,
  },
});

export default config;
