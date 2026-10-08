import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { applyPackExports } from "../vite.config.ts";

const root = join(import.meta.dirname, "..");

type Pkg = {
  exports: Record<string, unknown>;
};

function readPkg(): Pkg {
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Pkg;
}

describe("applyPackExports", () => {
  test("maps a .mjs string export to types/import/default", () => {
    const out = applyPackExports({ ".": "./dist/index.mjs", "./core": "./dist/core.mjs" });
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

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const client = { types: "./dist/client.d.mts", import: "./dist/client.mjs" };
    const out = applyPackExports({ "./package.json": pkgJson, "./client": client });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["./client"]).toBe(client);
  });
});

describe("package.json testing publish", () => {
  test("exports ./testing with types and import paths", () => {
    expect(readPkg().exports["./testing"]).toStrictEqual({
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
