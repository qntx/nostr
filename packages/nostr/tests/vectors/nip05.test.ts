import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import {
  Nip05Error,
  lookupFromDocument,
  parseNip05,
  parseNip05Document,
  wellKnownUrl,
} from "../../src/nips/nip05.ts";
import type { Nip05Address, Nip05Document } from "../../src/nips/nip05.ts";

// Shared vectors replayed by crates/nk-core/tests/it/nip05.rs; regenerate
// with `bun packages/nostr/scripts/parity/gen/all.ts`.
type ParseCase = { name: string; input: string; out: Nip05Address | null };
type WellKnownCase = { name: string; local: string; domain: string; out: string };
type DocumentCase = { name: string; json: string; out: Nip05Document | { err: true } };
type LookupCase = {
  name: string;
  json: string;
  identifier: string;
  out: { pubkey: string; relays?: string[] } | null;
};

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip05/codec.json"), "utf8"),
) as {
  parse: ParseCase[];
  well_known: WellKnownCase[];
  document: DocumentCase[];
  lookup: LookupCase[];
};

const parseOk = codec.parse.filter((c) => c.out !== null);
const parseErr = codec.parse.filter((c) => c.out === null);
const documentOk = codec.document.filter((c) => !("err" in c.out));
const documentErr = codec.document.filter((c) => "err" in c.out);
const lookupOk = codec.lookup.filter((c) => c.out !== null);
const lookupErr = codec.lookup.filter((c) => c.out === null);

describe("vectors/nip05/codec.json", () => {
  test.each(parseOk)("parseNip05: $name", (c) => {
    expect(parseNip05(c.input)).toStrictEqual(c.out);
  });

  test.each(parseErr)("parseNip05 invalid: $name", (c) => {
    expect(() => parseNip05(c.input)).toThrow(Nip05Error);
  });

  test.each(codec.well_known)("wellKnownUrl: $name", (c) => {
    expect(wellKnownUrl({ local: c.local, domain: c.domain })).toBe(c.out);
  });

  test.each(documentOk)("parseNip05Document: $name", (c) => {
    expect(parseNip05Document(JSON.parse(c.json))).toStrictEqual(c.out);
  });

  test.each(documentErr)("parseNip05Document invalid: $name", (c) => {
    expect(() => parseNip05Document(JSON.parse(c.json))).toThrow(Nip05Error);
  });

  test.each(lookupOk)("lookupFromDocument: $name", (c) => {
    const doc = parseNip05Document(JSON.parse(c.json));
    expect(lookupFromDocument(doc, parseNip05(c.identifier))).toStrictEqual(c.out);
  });

  test.each(lookupErr)("lookupFromDocument no match: $name", (c) => {
    const doc = parseNip05Document(JSON.parse(c.json));
    expect(lookupFromDocument(doc, parseNip05(c.identifier))).toBeUndefined();
  });
});
