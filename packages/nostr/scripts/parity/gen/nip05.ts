/// <reference types="node" />
// Generates vectors/nip05/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-05 `parseNip05`/`wellKnownUrl`/
// `parseNip05Document`/`lookupFromDocument` semantics as frozen vectors
// shared by the TS test suite (tests/vectors/nip05.test.ts) and
// crates/nk-core.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  lookupFromDocument,
  parseNip05,
  parseNip05Document,
  wellKnownUrl,
} from "../../../src/nips/nip05.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip05");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc";
const PK3 = "82341f883b6eabd2f7c4e5ad0a4e0d0b0c0d0e0f1234567890abcdef12345678";

type ParseCase = { name: string; input: string; out: unknown };
type WellKnownCase = { name: string; local: string; domain: string; out: string };
type DocumentCase = { name: string; json: string; out: unknown };
type LookupCase = { name: string; json: string; identifier: string; out: unknown };

const parseCases: ParseCase[] = [];
const wellKnownCases: WellKnownCase[] = [];
const documentCases: DocumentCase[] = [];
const lookupCases: LookupCase[] = [];

function parseCase(name: string, input: string): void {
  let out: unknown;
  try {
    out = parseNip05(input);
  } catch {
    out = null;
  }
  parseCases.push({ name, input, out });
}

function wellKnownCase(name: string, local: string, domain: string): void {
  wellKnownCases.push({ name, local, domain, out: wellKnownUrl({ local, domain }) });
}

function documentCase(name: string, doc: unknown): void {
  const json = JSON.stringify(doc);
  let out: unknown;
  try {
    out = parseNip05Document(JSON.parse(json));
  } catch {
    out = { err: true };
  }
  documentCases.push({ name, json, out });
}

function documentCaseRaw(name: string, json: string): void {
  let out: unknown;
  try {
    out = parseNip05Document(JSON.parse(json));
  } catch {
    out = { err: true };
  }
  documentCases.push({ name, json, out });
}

function lookupCase(name: string, doc: unknown, identifier: string): void {
  const json = JSON.stringify(doc);
  const parsed = parseNip05Document(JSON.parse(json));
  const address = parseNip05(identifier);
  lookupCases.push({
    name,
    json,
    identifier,
    out: lookupFromDocument(parsed, address) ?? null,
  });
}

parseCase("whitespace trims", "  bob@Example.COM  ");
parseCase("uppercase folds", "Bob.Smith-99@EXAMPLE.com");
parseCase("bare domain becomes root", "example.com");
parseCase("explicit root local", "_@example.com");
parseCase("no dot is invalid", "alice@localhost");
parseCase("empty is invalid", "");
parseCase("inner space is invalid", "a b@x.com");
parseCase("bare at-sign is invalid", "@");
parseCase("kelvin sign is not ASCII", "K@x.com");
parseCase("trailing dot is invalid", "a@x.com.");
parseCase("empty local is invalid", "@x.com");
parseCase("local dots and dashes", "a.b-c_d@x-y.example.com");

wellKnownCase("named address", "bob", "example.com");
wellKnownCase("root address", "_", "sub.example.com");

documentCase("non-object", 42);
documentCaseRaw("array is not an object", "[]");
documentCase("missing names", {});
documentCase("names not an object", { names: [] });
documentCase("empty names is fine", { names: {} });
documentCase("names: non-hex and non-string skipped", {
  names: {
    alice: PK,
    bob: 42,
    carol: "not-hex",
    dave: null,
    eve: {},
  },
});
documentCase("keys and values lowercase", {
  names: { Alice: PK.toUpperCase(), BOB: PK2 },
});
documentCaseRaw(
  "case-folding collision: document order wins",
  `{"names":{"Alice":"${PK}","alice":"${PK2}"}}`,
);
documentCase("relays: full filtering", {
  names: { alice: PK },
  relays: {
    [PK]: ["wss://a.example", "wss://b.example", 42, ""],
    "not-a-key": ["wss://x.example"],
    [PK2]: "not-an-array",
    [PK3]: [],
  },
});
documentCase("relays not an object is ignored", { names: { alice: PK }, relays: [] });
documentCase("nip46 full", {
  names: { alice: PK },
  nip46: {
    relays: ["wss://a.example", 42, ""],
    nostrconnect_url: "nostrconnect://abc?relay=wss://a",
  },
});
documentCase("nip46 empty relays array kept", {
  names: { alice: PK },
  nip46: { relays: [] },
});
documentCase("nip46 nothing valid is absent", {
  names: { alice: PK },
  nip46: { relays: "not-array", nostrconnect_url: 5 },
});
documentCase("nip46 non-object is absent", { names: { alice: PK }, nip46: "x" });
documentCase("nip46 empty url dropped", {
  names: { alice: PK },
  nip46: { nostrconnect_url: "" },
});

const lookupDoc = {
  names: { alice: PK, bob: PK2 },
  relays: { [PK]: ["wss://a.example"] },
};
lookupCase("match with relays", lookupDoc, "alice@example.com");
lookupCase("match without relays", lookupDoc, "bob@example.com");
lookupCase("no match", lookupDoc, "carol@example.com");
lookupCase("root lookup", { names: { _: PK3 } }, "example.com");
lookupCase("case-folded identifier", lookupDoc, "ALICE@EXAMPLE.COM");

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip05.codec",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  parse: parseCases,
  well_known: wellKnownCases,
  document: documentCases,
  lookup: lookupCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip05 codec: ${parseCases.length} parse + ${wellKnownCases.length} well_known + ${documentCases.length} document + ${lookupCases.length} lookup cases written`,
);
