import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { isAuthRequired, makeAuthEvent } from "../../src/nips/nip42.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type AuthCase = {
  relay: string;
  challenge: string;
  tags: Array<[string, string]>;
  content: string;
  rust?: false;
};

type AuthRequiredCase = { reason: string; result: boolean };

const { auth, auth_required } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip42/codec.json"), "utf8"),
) as { auth: AuthCase[]; auth_required: AuthRequiredCase[] };

describe("vectors/nip42 auth event", () => {
  test.each(auth)("case %#", (c) => {
    const template = makeAuthEvent(c.relay, c.challenge);
    expect(template.kind).toBe(22242);
    // `makeAuthEvent` stores the relay string verbatim; for shared cases the
    // vector records the normalized form (identical to the raw input there).
    expect(template.tags).toStrictEqual(c.tags);
    expect(template.content).toBe(c.content);
  });
});

describe("vectors/nip42 is_auth_required", () => {
  test.each(auth_required)("case %#", (c) => {
    expect(isAuthRequired(c.reason)).toBe(c.result);
  });
});
