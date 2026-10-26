import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { Nip11Error, parseRelayInformation, relayInfoHttpUrl } from "../../src/nips/nip11.ts";
import type { RelayInformation } from "../../src/nips/nip11.ts";

// Shared vectors replayed by crates/nk-core/tests/it/nip11.rs; regenerate
// with `bun packages/nostr/scripts/parity/gen/all.ts`.
type UrlCase = { name: string; input: string; out: string };
type DocumentCase = { name: string; json: string; out: RelayInformation | { err: true } };

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip11/codec.json"), "utf8"),
) as { url: UrlCase[]; document: DocumentCase[] };

const documentOk = codec.document.filter((c) => !("err" in c.out));
const documentErr = codec.document.filter((c) => "err" in c.out);

describe("vectors/nip11/codec.json", () => {
  test.each(codec.url)("relayInfoHttpUrl: $name", (c) => {
    expect(relayInfoHttpUrl(c.input)).toBe(c.out);
  });

  test.each(documentOk)("parseRelayInformation: $name", (c) => {
    expect(parseRelayInformation(JSON.parse(c.json))).toStrictEqual(c.out);
  });

  test.each(documentErr)("parseRelayInformation invalid: $name", (c) => {
    expect(() => parseRelayInformation(JSON.parse(c.json))).toThrow(Nip11Error);
  });
});
