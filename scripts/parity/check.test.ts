import { describe, expect, test } from "vite-plus/test";

import { checkParity } from "./check.ts";

const TRUE = (): boolean => true;
const EMPTY = (): string => "";
const mapReader =
  (files: Map<string, string>) =>
  (p: string): string =>
    files.get(p) ?? "";

function cap(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const c: Record<string, unknown> = {
    id: "core.example",
    tier: "B",
    status: "ts-only",
    milestone: "NK1",
    ts: { module: "src/x.ts", tests: ["tests/x.test.ts"] },
    rust: null,
    rustNote: "no rust-nostr counterpart",
    vectors: [],
    ...overrides,
  };
  // rustNote is only valid with rust: null; an explicit rust object drops
  // the default note unless the override sets one on purpose.
  if (overrides["rust"] !== null && overrides["rust"] !== undefined && !("rustNote" in overrides)) {
    delete c["rustNote"];
  }
  return c;
}

function parity(caps: Array<Record<string, unknown>>): unknown {
  return { schema: 1, capabilities: caps };
}

describe("parity check", () => {
  test("accepts a minimal valid document", () => {
    expect(checkParity(parity([cap()]), [], TRUE, EMPTY)).toStrictEqual([]);
  });

  test("rejects duplicate ids", () => {
    const errors = checkParity(parity([cap(), cap()]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": duplicate id']);
  });

  test("rejects an invalid tier", () => {
    const errors = checkParity(parity([cap({ tier: "D" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": tier must be one of A|B|C']);
  });

  test("rejects n/a outside tier C", () => {
    const errors = checkParity(parity([cap({ status: "n/a" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": status "n/a" is only allowed for tier C',
    ]);
  });

  test("requires tier C to be n/a", () => {
    const errors = checkParity(parity([cap({ tier: "C" })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual(['capability "core.example": tier C must have status "n/a"']);
  });

  test("rejects missing referenced paths", () => {
    const errors = checkParity(parity([cap()]), [], () => false, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": referenced path does not exist: src/x.ts',
      'capability "core.example": referenced path does not exist: tests/x.test.ts',
    ]);
  });

  test("rejects stable without ts tests", () => {
    const errors = checkParity(
      parity([cap({ status: "stable", ts: { module: "src/x.ts", tests: [] } })]),
      [],
      TRUE,
      EMPTY,
    );
    expect(errors).toStrictEqual([
      'capability "core.example": "stable" requires non-empty ts.tests',
    ]);
  });

  test("rejects rust null without rustNote", () => {
    const c = cap();
    delete c["rustNote"];
    const errors = checkParity(parity([c]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": rust is null but rustNote is missing or empty',
    ]);
  });

  test("rejects a rust object without an api", () => {
    const errors = checkParity(parity([cap({ rust: { tests: ["tests/x.rs"] } })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": rust.api must be a non-empty string naming the rust-nostr path',
    ]);
  });

  test("rejects a rust object without tests", () => {
    const errors = checkParity(parity([cap({ rust: { api: "nostr::Event" } })]), [], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      'capability "core.example": rust.tests must list at least one runner file',
    ]);
  });

  test("rejects rustNote alongside a rust object", () => {
    const errors = checkParity(
      parity([cap({ rust: { api: "nostr::Event", tests: ["tests/x.rs"] }, rustNote: "kept" })]),
      [],
      TRUE,
      EMPTY,
    );
    expect(errors).toStrictEqual([
      'capability "core.example": rustNote is only allowed when rust is null',
    ]);
  });

  test("requires a vector for stable tier A", () => {
    const errors = checkParity(
      parity([
        cap({ tier: "A", status: "stable", rust: { api: "nostr::x", tests: ["rust/x.rs"] } }),
      ]),
      [],
      TRUE,
      EMPTY,
    );
    expect(errors).toStrictEqual([
      'capability "core.example": tier A "stable" requires at least one vector file',
    ]);
  });

  test("rejects unreferenced vector files", () => {
    const errors = checkParity(parity([cap()]), ["vectors/core/orphan.json"], TRUE, EMPTY);
    expect(errors).toStrictEqual([
      "vector file is not referenced by any capability: vectors/core/orphan.json",
    ]);
  });

  test("requires each vector to be cited in a test file", () => {
    const c = cap({ vectors: ["vectors/core/x.json"] });
    const files = new Map([
      ["src/x.ts", ""],
      ["tests/x.test.ts", "reads nothing relevant"],
      ["vectors/core/x.json", "{}"],
    ]);
    const errors = checkParity(
      parity([c]),
      ["vectors/core/x.json"],
      (p) => files.has(p),
      mapReader(files),
    );
    expect(errors).toStrictEqual([
      'capability "core.example": vector vectors/core/x.json is not referenced by any of its test files',
    ]);
  });

  test("accepts a vector cited by test file contents", () => {
    const c = cap({ vectors: ["vectors/core/x.json"] });
    const files = new Map([
      ["src/x.ts", ""],
      ["tests/x.test.ts", 'readFileSync("vectors/core/x.json")'],
      ["vectors/core/x.json", "{}"],
    ]);
    const errors = checkParity(
      parity([c]),
      ["vectors/core/x.json"],
      (p) => files.has(p),
      mapReader(files),
    );
    expect(errors).toStrictEqual([]);
  });

  test("accepts a vector cited only by rust tests (rust: null capability keeps ts vectors)", () => {
    const c = cap({
      status: "stable",
      rust: { api: "nostr::x", tests: ["tests/x.rs"] },
      vectors: ["vectors/core/x.json"],
    });
    const files = new Map([
      ["src/x.ts", ""],
      ["tests/x.test.ts", "no citation"],
      ["tests/x.rs", "x.json"],
      ["vectors/core/x.json", "{}"],
    ]);
    const errors = checkParity(
      parity([c]),
      ["vectors/core/x.json"],
      (p) => files.has(p),
      mapReader(files),
    );
    expect(errors).toStrictEqual([]);
  });
});
