import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { blocksJson } from "../../scripts/parity/content-json.ts";
import type { BlockJson } from "../../scripts/parity/content-json.ts";
import { parseContent } from "../../src/nips/nip27.ts";
import type { ParseContentOptions } from "../../src/nips/nip27.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type TokenizeCase = {
  name: string;
  content: string;
  tags?: string[][];
  legacy?: boolean;
  imeta?: Record<string, string>;
  out: BlockJson[];
};

const { cases } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip27/codec.json"), "utf8"),
) as { cases: TokenizeCase[] };

function replay(c: TokenizeCase): BlockJson[] {
  const options: ParseContentOptions = {};
  if (c.legacy === true) {
    options.legacyBech32 = true;
  }
  if (c.imeta !== undefined) {
    options.imeta = new Map(Object.entries(c.imeta));
  }
  const input = c.tags === undefined ? c.content : { content: c.content, tags: c.tags };
  return blocksJson(parseContent(input, options));
}

describe("vectors/nip27/codec.json", () => {
  test("parseContent blocks match", () => {
    for (const c of cases) {
      expect(replay(c)).toStrictEqual(c.out);
    }
  });
});
