/// <reference types="node" />
// Generates vectors/nip11/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-11 `relayInfoHttpUrl`/`parseRelayInformation`
// semantics as frozen vectors shared by the TS test suite
// (tests/vectors/nip11.test.ts) and crates/nk-core.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { parseRelayInformation, relayInfoHttpUrl } from "../../../src/nips/nip11.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip11");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc";

type UrlCase = { name: string; input: string; out: string };
type DocumentCase = { name: string; json: string; out: unknown };

const urlCases: UrlCase[] = [];
const documentCases: DocumentCase[] = [];

function urlCase(name: string, input: string): void {
  urlCases.push({ name, input, out: relayInfoHttpUrl(input) });
}

function documentCase(name: string, doc: unknown): void {
  const json = JSON.stringify(doc);
  let out: unknown;
  try {
    out = parseRelayInformation(JSON.parse(json));
  } catch {
    out = { err: true };
  }
  documentCases.push({ name, json, out });
}

urlCase("wss to https", "wss://a.example/");
urlCase("ws to http", "ws://a.example/");
urlCase("ws port and path with query", "ws://a.example:8080/x?y=1");
urlCase("wss nested path", "wss://a.example/relay/v2?x=1");

documentCase("non-object", 42);
documentCase("array is not an object", [1, 2]);
documentCase("all string fields", {
  name: "Test Relay",
  description: "a relay",
  banner: "https://x.example/b.png",
  icon: "https://x.example/i.png",
  contact: "admin@x.example",
  software: "https://x.example/sw",
  version: "1.0.0",
  payments_url: "https://x.example/pay",
  terms_of_service: "https://x.example/tos",
});
documentCase("wrong-typed strings dropped", {
  name: 42,
  description: true,
  banner: ["x"],
  icon: { url: "x" },
  contact: null,
  software: 1.5,
  version: ["1"],
  payments_url: 7,
  terms_of_service: false,
});
documentCase("supported_nips filters non-integers and negatives", {
  supported_nips: [1, "2", 2.5, -3, 4, null, true],
});
documentCase("supported_nips not an array dropped", { supported_nips: 11 });
documentCase("supported_nips empty kept", { supported_nips: [] });
documentCase("limitation: every number and boolean", {
  limitation: {
    max_message_length: 65536,
    max_subscriptions: 20,
    max_limit: 5000,
    max_subid_length: 64,
    max_event_tags: 2000,
    max_content_length: 70000,
    min_pow_difficulty: 30,
    created_at_lower_limit: 31536000,
    created_at_upper_limit: 3,
    default_limit: 500,
    auth_required: true,
    payment_required: false,
    restricted_writes: true,
  },
});
documentCase("limitation: wrong-typed entries dropped", {
  limitation: {
    max_message_length: "65536",
    max_subscriptions: -1,
    max_limit: 2.5,
    max_subid_length: null,
    max_event_tags: true,
    max_content_length: 70000,
    min_pow_difficulty: "30",
    created_at_lower_limit: [],
    created_at_upper_limit: 3,
    default_limit: {},
    auth_required: "yes",
    payment_required: false,
    restricted_writes: 1,
  },
});
documentCase("all-invalid limitation dropped", {
  limitation: { max_limit: "x", auth_required: "y", bogus: 1 },
});
documentCase("empty limitation dropped", { limitation: {} });
documentCase("non-object limitation dropped", { limitation: 7 });
documentCase("pubkey and self kept when 64-hex", { pubkey: PK, self: PK2 });
documentCase("uppercase pubkey folds to lowercase", { pubkey: PK.toUpperCase() });
documentCase("non-hex pubkey dropped", { pubkey: "not-hex", self: PK2.slice(0, 60) });
documentCase("non-string pubkey dropped", { pubkey: 42, self: null });
documentCase("unknown keys ignored", { names: { a: 1 }, posting_policy: "x" });

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip11.codec",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  url: urlCases,
  document: documentCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip11 codec: ${urlCases.length} url + ${documentCases.length} document cases written`);
