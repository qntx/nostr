import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { applyPackExports } from "../vite.config.ts";

const root = join(import.meta.dirname, "..");

const INDEX_EXPORT = {
  types: "./dist/index.d.mts",
  browser: "./dist/browser.mjs",
  import: "./dist/index.mjs",
  default: "./dist/index.mjs",
} as const;

const BROWSER_EXPORT = {
  types: "./dist/browser.d.mts",
  import: "./dist/browser.mjs",
  default: "./dist/browser.mjs",
} as const;

type Pkg = {
  version: string;
  exports: Record<string, unknown>;
};

function readPkg(): Pkg {
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Pkg;
}

describe("package.json publish", () => {
  test("exports . with types, browser and import paths", () => {
    expect(readPkg().exports["."]).toStrictEqual(INDEX_EXPORT);
  });

  test("exports ./browser with types and import paths", () => {
    expect(readPkg().exports["./browser"]).toStrictEqual(BROWSER_EXPORT);
  });
});

describe("applyPackExports", () => {
  test("maps . to types/browser/import/default", () => {
    const out = applyPackExports({ ".": "./dist/index.mjs" });
    expect(out["."]).toStrictEqual(INDEX_EXPORT);
  });

  test("maps ./browser to types/import/default", () => {
    const out = applyPackExports({ "./browser": "./dist/browser.mjs" });
    expect(out["./browser"]).toStrictEqual(BROWSER_EXPORT);
  });

  test("leaves non-mjs strings and object exports unchanged", () => {
    const pkgJson = "./package.json";
    const other = { types: "./dist/x.d.mts", import: "./dist/x.mjs" };
    const out = applyPackExports({ "./package.json": pkgJson, "./x": other });
    expect(out["./package.json"]).toBe(pkgJson);
    expect(out["./x"]).toBe(other);
  });
});
