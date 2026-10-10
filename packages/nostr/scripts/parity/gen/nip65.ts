/// <reference types="node" />
// Generates vectors/nip65/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-65 `parseRelayList`/`relayListToTags`/
// `relayListEventBuilder`/`readRelays`/`writeRelays` semantics as frozen
// vectors shared by the TS test suite (tests/vectors/nip65.test.ts) and the
// nk-* Rust crates.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { hexToBytes } from "../../../src/core/util.ts";
import type { RelayListItem } from "../../../src/nips/nip65.ts";
import {
  parseRelayList,
  relayListEventBuilder,
  relayListToTags,
  readRelays,
  writeRelays,
} from "../../../src/nips/nip65.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip65");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const ALICE = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const AUX = hexToBytes("07".repeat(32));

function signed(tags: Tag[], kind = 10002, secretKey = ALICE): Event {
  const keys = Keys.fromSecretKey(secretKey);
  return signEvent(
    { pubkey: keys.publicKey, created_at: 1_700_000_000, kind, tags, content: "" },
    keys,
    AUX,
  );
}

type ParseCase = {
  name: string;
  event: Event;
  out?: RelayListItem[];
  err?: string;
};

type BuildCase = {
  name: string;
  rust?: false;
  items: Array<{ url: string; marker: string }>;
  relay_list?: { kind: number; content: string };
  out_tags: Tag[];
  read: string[];
  write: string[];
};

const parseCases: ParseCase[] = [];
const buildCases: BuildCase[] = [];

function parseCase(name: string, event: Event): void {
  let out: RelayListItem[] | undefined;
  let err: string | undefined;
  try {
    out = [...parseRelayList(event)];
  } catch (error) {
    err = error instanceof Error ? error.constructor.name : "Error";
  }
  parseCases.push({
    name,
    event,
    ...(out === undefined ? {} : { out }),
    ...(err === undefined ? {} : { err }),
  });
}

function buildCase(name: string, items: Array<{ url: string; marker: string }>, rust = true): void {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- TS-only cases carry non-enum markers verbatim
  const typed = items as RelayListItem[];
  const builder = relayListEventBuilder(typed);
  buildCases.push({
    name,
    items,
    relay_list: { kind: builder.currentKind, content: builder.currentContent },
    out_tags: relayListToTags(typed),
    read: readRelays(typed),
    write: writeRelays(typed),
    ...(rust ? {} : { rust: false as const }),
  });
}

// Normalization, markers, dedup by normalized URL, skipping.
parseCase(
  "mixed markers with dedup and skips",
  signed([
    ["r", "wss://a.example", "read"],
    ["r", "wss://a.example/", "write"], // same normalized URL: first wins
    ["r", "https://b.example/", "write"], // https normalizes to wss
    ["r", "wss://c.example//path", ""],
    ["r", "relay.example", "read"], // bare host gets wss:// + slash
    ["r", "not a url"],
    ["r", ""],
    ["r"],
    ["r", "wss://d.example", "bogus"], // unknown marker -> both
    ["x", "wss://e.example"],
    ["t", "wss://f.example"],
  ]),
);
parseCase("empty list", signed([]));
parseCase("uppercase marker is not a marker", signed([["r", "wss://a.example", "READ"]]));
parseCase(
  "marker slot extra positions ignored",
  signed([["r", "wss://a.example", "write", "extra", "more"]]),
);
parseCase("wrong kind 3 rejected", signed([["r", "wss://a.example"]], 3));
parseCase("wrong kind 0 rejected", signed([], 0));
parseCase("kind 1 rejected", signed([["r", "wss://a.example"]], 1));

buildCase("all three markers", [
  { url: "wss://a.example/", marker: "read" },
  { url: "wss://b.example/", marker: "write" },
  { url: "wss://c.example/", marker: "both" },
]);
buildCase("read and write filter views", [
  { url: "wss://ro.example/", marker: "read" },
  { url: "wss://wo.example/", marker: "write" },
  { url: "wss://rw.example/", marker: "both" },
  { url: "wss://rw2.example/", marker: "both" },
]);
buildCase("empty items", []);
// TS writes item fields verbatim; unnormalizable urls and non-enum markers
// cannot exist inside the Rust types.
buildCase("unnormalizable item url is TS-only", [{ url: "not a url", marker: "read" }], false);
buildCase(
  "non-enum marker written verbatim is TS-only",
  [{ url: "wss://a.example/", marker: "bogus" }],
  false,
);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip65.relay-list",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  parse: parseCases,
  build: buildCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip65 codec: ${parseCases.length} parse + ${buildCases.length} build cases written`);
