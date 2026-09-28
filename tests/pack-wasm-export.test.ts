import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { applyPackExports } from "../vite.config.ts";

const root = join(import.meta.dirname, "..");

const WASM_EXPORT = {
  types: "./dist/wasm.d.mts",
  import: "./dist/wasm.mjs",
  default: "./dist/wasm.mjs",
} as const;

type Pkg = {
  version: string;
  scripts: Record<string, string>;
  exports: Record<string, unknown>;
};

function readPkg(): Pkg {
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Pkg;
}

describe("package.json wasm publish", () => {
  test("exports ./wasm with types and import paths", () => {
    const wasm = readPkg().exports["./wasm"];
    expect(wasm).toStrictEqual(WASM_EXPORT);
    expect(Object.hasOwn(wasm as object, "types")).toBe(true);
    expect(Object.hasOwn(wasm as object, "import")).toBe(true);
    expect((wasm as { types: string }).types).toBe("./dist/wasm.d.mts");
    expect((wasm as { import: string }).import).toBe("./dist/wasm.mjs");
  });

  test("prepublishOnly packs wasm", () => {
    // The setup-wasm reusable workflow requires this exact string;
    // package checks run at the end of build:wasm instead.
    expect(readPkg().scripts["prepublishOnly"]).toBe("bun run build:wasm");
  });

  test("wasm subpath does not export resetNostrWasmForTests", () => {
    const src = readFileSync(join(root, "src/wasm/index.ts"), "utf8");
    expect(src).not.toMatch(/resetNostrWasmForTests/);
    expect(src).toMatch(/export \{ loadNostrWasm/);
  });

  test("build:wasm fails closed when dist/*.wasm is missing", () => {
    const script = readPkg().scripts["build:wasm"]!;
    expect(script).toBe(
      "bash scripts/build-wasm.sh && WASM_PACK=1 vp pack && ls dist/*.wasm >/dev/null && publint && attw --pack . --profile esm-only",
    );
    expect(script).not.toMatch(/(^|[\s;|&])cp(\s|$)/);
    expect(script).not.toContain("then cp ");
    expect(script.endsWith("attw --pack . --profile esm-only")).toBe(true);
  });

  test("bun run build does not set WASM_PACK", () => {
    const build = readPkg().scripts["build"]!;
    expect(build).toBe("vp pack");
    expect(build).not.toContain("WASM_PACK");
    expect(build).not.toContain("build:wasm");
  });
});

describe("applyPackExports", () => {
  test("writes ./wasm when the pack map has no wasm key", () => {
    const out = applyPackExports({
      ".": "./dist/index.mjs",
      "./core": "./dist/core.mjs",
    });
    expect(out["./wasm"]).toStrictEqual(WASM_EXPORT);
    expect(out["."]).toStrictEqual({
      types: "./dist/index.d.mts",
      import: "./dist/index.mjs",
      default: "./dist/index.mjs",
    });
    expect(out["./core"]).toStrictEqual({
      types: "./dist/core.d.mts",
      import: "./dist/core.mjs",
      default: "./dist/core.mjs",
    });
  });

  test("writes ./wasm for an empty pack map", () => {
    expect(applyPackExports({})["./wasm"]).toStrictEqual(WASM_EXPORT);
  });

  test("overwrites a string ./wasm export", () => {
    expect(applyPackExports({ "./wasm": "./dist/other.mjs" })["./wasm"]).toStrictEqual(WASM_EXPORT);
  });

  test("overwrites a wrong object ./wasm export", () => {
    expect(
      applyPackExports({
        "./wasm": { types: "./dist/wrong.d.mts", import: "./dist/wrong.mjs" },
      })["./wasm"],
    ).toStrictEqual(WASM_EXPORT);
  });

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const client = { types: "./dist/client.d.mts", import: "./dist/client.mjs" };
    const out = applyPackExports({
      "./package.json": pkgJson,
      "./client": client,
    });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["./client"]).toBe(client);
    expect(out["./wasm"]).toStrictEqual(WASM_EXPORT);
  });

  test("writes ./wasm when WASM_PACK is unset", () => {
    const prev = process.env["WASM_PACK"];
    delete process.env["WASM_PACK"];
    try {
      expect(applyPackExports({ "./relay": "./dist/relay.mjs" })["./wasm"]).toStrictEqual(
        WASM_EXPORT,
      );
    } finally {
      restoreEnv("WASM_PACK", prev);
    }
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    Reflect.deleteProperty(process.env, name);
  } else {
    process.env[name] = value;
  }
}

describe("vite pack.entry.wasm gate", () => {
  test("wasm entry stays WASM_PACK-gated", () => {
    const src = readFileSync(join(root, "vite.config.ts"), "utf8");
    expect(src).toContain('const packWasm = process.env["WASM_PACK"] === "1"');
    expect(src).toContain('...(packWasm ? { wasm: "src/wasm/index.ts" } : {})');
    expect(src).toContain("customExports: applyPackExports");
    expect(src.match(/wasm: "src\/wasm\/index\.ts"/g)).toStrictEqual(['wasm: "src/wasm/index.ts"']);
  });
});

describe("package.json testing publish", () => {
  test("exports ./testing with types and import paths", () => {
    const testing = readPkg().exports["./testing"];
    expect(testing).toStrictEqual({
      types: "./dist/testing.d.mts",
      import: "./dist/testing.mjs",
      default: "./dist/testing.mjs",
    });
  });

  test("applyPackExports maps ./testing mjs to types/import", () => {
    const out = applyPackExports({ "./testing": "./dist/testing.mjs" });
    expect(out["./testing"]).toStrictEqual({
      types: "./dist/testing.d.mts",
      import: "./dist/testing.mjs",
      default: "./dist/testing.mjs",
    });
  });

  test("vite pack entries include src/testing/index.ts", () => {
    const src = readFileSync(join(root, "vite.config.ts"), "utf8");
    expect(src).toContain('testing: "src/testing/index.ts"');
  });

  test("testing entry keeps ws behind a dynamic import", () => {
    const serve = readFileSync(join(root, "src/testing/serve.ts"), "utf8");
    const index = readFileSync(join(root, "src/testing/index.ts"), "utf8");
    expect(serve).toContain('await import("ws")');
    expect(serve).not.toMatch(/^import .*from "ws"/m);
    expect(index).not.toMatch(/from "ws"/);
  });
});
