/// <reference types="node" />
// Generates vectors/nip42/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-42 `makeAuthEvent`/`isAuthRequired` semantics as frozen
// vectors shared by the TS test suite (tests/vectors/nip42.test.ts) and the
// nk-* Rust crates.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { normalizeURL } from "../../../src/core/util.ts";
import { makeAuthEvent } from "../../../src/nips/nip42.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip42");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

type AuthCase = {
  relay: string;
  challenge: string;
  tags: Array<[string, string]>;
  content: string;
  rust?: false;
};

const authCases: AuthCase[] = [];

function authCase(relay: string, challenge: string, rust = true): void {
  const template = makeAuthEvent(relay, challenge);
  // Shared cases carry the *normalized* relay the Rust `RelayUrl` produces;
  // `rust: false` cases record the raw TS tag value instead.
  const relayTag = rust ? normalizeURL(relay) : relay;
  if (template.kind !== 22242) {
    throw new Error("generator bug: wrong kind");
  }
  authCases.push({
    relay,
    challenge,
    tags: [
      ["relay", relayTag],
      ["challenge", challenge],
    ],
    content: template.content,
    ...(rust ? {} : { rust: false as const }),
  });
}

// Already-normalized relays: TS stores the string verbatim and Rust stores
// the identical normalized form.
for (const relay of [
  "wss://relay.example/",
  "wss://relay.example/path",
  "ws://localhost:7777/",
  "wss://nostr.example.com:444/sub?x=1&y=2",
]) {
  authCase(relay, "challenge-string");
}
authCase("wss://relay.example/", "");
authCase("wss://relay.example/", "émoji ⚡ challenge");
// Long challenge.
authCase("wss://relay.example/", "ab".repeat(128));

// Inputs the Rust `RelayUrl` cannot express (unparsed strings are TS-only)
// or whose raw form differs from the normalized tag value.
authCase("RELAY.EXAMPLE", "upper", false);
authCase("relay.example/path?q=2&q=1", "query reorder", false);
authCase("wss://relay.example/#frag", "fragment dropped", false);
authCase("not a url", "invalid", false);
authCase("", "empty relay", false);

const authRequired = [
  { reason: "auth-required: take a ticket", result: true },
  { reason: "auth-required:", result: true },
  { reason: "auth-required: ", result: true },
  { reason: "auth-required", result: false },
  { reason: " auth-required: leading space", result: false },
  { reason: "AUTH-REQUIRED: upper", result: false },
  { reason: "restricted: nope", result: false },
  { reason: "", result: false },
];

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip42.auth-event",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  auth: authCases,
  auth_required: authRequired,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip42 codec: ${authCases.length} auth + ${authRequired.length} auth_required cases written`,
);
