/// <reference types="node" />
// Generates vectors/nip10/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-10 `parseThreadTags`/`buildReplyTags`/`replyTo`
// semantics as frozen vectors shared by the TS test suite
// (tests/vectors/nip10.test.ts) and the nk-* Rust crates. The canonical
// `ThreadReferences` JSON encoding lives in ../thread-json.ts and is shared
// with the seeded `nip10.thread` differential stream (diff.ts).

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { hexToBytes, normalizeURL } from "../../../src/core/util.ts";
import { buildReplyTags, parseThreadTags, replyTo } from "../../../src/nips/nip10.ts";
import type { ReplyTagsOptions } from "../../../src/nips/nip10.ts";
import { threadJson } from "../thread-json.ts";
import type { ThreadJson } from "../thread-json.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip10");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const ALICE = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const BOB = "97a988d6151d344dd477a8953a71a47266a800a840acdf8d0e0f1e4df0ff14ab";
const CAROL = "c14e56a75582d7c0e8d21f8ec8d424d7cd33a1e02919ee2e8f5635e6a7a24afe";
const alicePk = Keys.fromSecretKey(ALICE).publicKey;
const bobPk = Keys.fromSecretKey(BOB).publicKey;
const carolPk = Keys.fromSecretKey(CAROL).publicKey;

const ID1 = "aa".repeat(32);
const ID2 = "bb".repeat(32);
const ID3 = "cc".repeat(32);
const ID4 = "dd".repeat(32);
const ID5 = "ee".repeat(32);

const AUX = hexToBytes("07".repeat(32));

function signed(tags: Tag[], kind = 1, secretKey = ALICE): Event {
  const keys = Keys.fromSecretKey(secretKey);
  return signEvent(
    { pubkey: keys.publicKey, created_at: 1_700_000_000, kind, tags, content: "n" },
    keys,
    AUX,
  );
}

// The vector inputs deliberately include malformed elements; the cast narrows
// `unknown` to the API's input shape.
// oxlint-disable-next-line no-unsafe-type-assertion
const asTags = (tags: unknown): Tag[] => tags as Tag[];

type ParseCase = {
  name: string;
  tags: unknown[];
  out?: ThreadJson;
  err?: string;
  rust?: false;
};

const parseCases: ParseCase[] = [];

function parseCase(name: string, tags: unknown[], rust = true): void {
  let out: ThreadJson | undefined;
  let err: string | undefined;
  try {
    out = threadJson(parseThreadTags({ tags: asTags(tags) }));
  } catch (error) {
    err = error instanceof Error ? error.constructor.name : "Error";
  }
  parseCases.push({
    name,
    tags,
    ...(out === undefined ? {} : { out }),
    ...(err === undefined ? {} : { err }),
    ...(rust ? {} : { rust: false as const }),
  });
}

parseCase("marked root/reply with profiles and quotes", [
  ["e", ID1, "wss://root.example", "root", alicePk],
  ["e", ID2, "wss://reply.example", "reply", alicePk],
  ["e", ID3, "", "mention"],
  ["q", ID4, "wss://quote.example"],
  ["q", `30023:${bobPk}:article`, "wss://addr.example"],
  ["p", alicePk, "wss://author.example"],
  ["p", bobPk],
]);
parseCase("positional two unmarked e tags", [
  ["e", ID1],
  ["e", ID2],
]);
parseCase("positional single unmarked e is both", [["e", ID1]]);
parseCase("empty marker is positional unmarked", [
  ["e", ID1, "", ""],
  ["e", ID2, "", ""],
]);
parseCase("NIP-01 four-tuple author at index 3 is positional", [
  ["e", ID1, "wss://relay.example", alicePk],
]);
parseCase("five-tuple author at index 4 with markers", [
  ["e", ID1, "wss://relay.example", "", alicePk],
  ["e", ID2, "", "reply", bobPk],
]);
parseCase("author scanned index 4 then 3", [["e", ID1, "", "nonhex-marker", alicePk]]);
parseCase("uppercase hex id and author are lowercased", [
  ["e", ID1.toUpperCase(), "wss://relay.example", "root", alicePk.toUpperCase()],
  ["p", alicePk.toUpperCase(), "wss://author.example"],
]);
parseCase("unknown marker is a mention only", [["e", ID1, "", "fork"]]);
parseCase("mention marker leaves positional unset", [
  ["e", ID1, "", "mention"],
  ["e", ID2],
]);
parseCase("marked reply back-fills root", [["e", ID2, "", "reply"]]);
parseCase("marked root back-fills reply", [["e", ID1, "", "root"]]);
parseCase("mention with root id is dropped", [
  ["e", ID1, "", "root"],
  ["e", ID1, "", "mention"],
  ["e", ID2, "", "mention"],
]);
parseCase("author inherits p-tag relay hints", [
  ["e", ID1, "wss://direct.example", "root", alicePk],
  ["e", ID2, "", "reply", bobPk],
  ["p", alicePk, "wss://author.example"],
  ["p", bobPk],
  ["p", alicePk, "wss://author.example"],
]);
parseCase("q hex with author and relay", [["q", ID4, "wss://q.example", carolPk]]);
parseCase("q address ignores index 3", [["q", `30023:${bobPk}:post`, "wss://a.example", ID5]]);
parseCase("invalid q tags skipped", [
  ["q"],
  ["q", ""],
  ["q", "not-a-quote"],
  ["q", "30023:short:d"],
  ["q", ID4, "wss://ok.example", "not-a-pubkey"],
]);
parseCase("q mixed-case id and author", [["q", ID4.toUpperCase(), "", carolPk.toUpperCase()]]);
parseCase("uppercase marker is not a marker", [["e", ID1, "", "ROOT"]]);
parseCase("noise tags skipped", [
  ["t", "nostr"],
  ["x", "1"],
  ["a", "30023:pk:d"],
  ["e", "nothex"],
]);
parseCase("empty tag array skipped", [[], ["e", ID1]]);
parseCase("p tag validation", [
  ["p", "nothex"],
  ["p"],
  ["p", bobPk, ""],
  ["e", ID1, "", "root", bobPk],
]);
parseCase("null tag throws", [null, ["e", ID1]], false);
parseCase("numeric e value throws", [["e", 42]], false);

type ReplyCase = {
  name: string;
  parent: unknown;
  // oxlint-disable-next-line no-restricted-types -- the vector encodes "no hint" as null
  relay_hint: string | null;
  quotes: ReplyTagsOptions["quotes"];
  // Present only for reply_to cases: the wrapped EventBuilder's kind/content.
  reply_to?: { content: string; kind: number };
  out_tags?: Tag[];
  err?: string;
  rust?: false;
};

const replyCases: ReplyCase[] = [];

/** TS writes relay hints verbatim; Rust stores a normalized `RelayUrl`. */
function isNormalized(hint: string): boolean {
  try {
    // A hint equal to its own normalization survives the Rust type unchanged.
    return hint === normalizeURL(hint);
  } catch {
    return false;
  }
}

function replyCase(
  name: string,
  parent: Event,
  // oxlint-disable-next-line no-restricted-types -- the vector encodes "no hint" as null
  relayHint: string | null,
  quotes: ReplyTagsOptions["quotes"],
  rust?: boolean,
): void {
  let out_tags: Tag[] | undefined;
  let err: string | undefined;
  try {
    out_tags = buildReplyTags({
      parent,
      relayHint: relayHint ?? undefined,
      quotes,
    });
  } catch (error) {
    err = error instanceof Error ? error.constructor.name : "Error";
  }
  const shared = rust ?? (relayHint === null || isNormalized(relayHint));
  replyCases.push({
    name,
    parent,
    relay_hint: relayHint,
    quotes,
    ...(out_tags === undefined ? {} : { out_tags }),
    ...(err === undefined ? {} : { err }),
    ...(shared ? {} : { rust: false as const }),
  });
}

function replyToCase(name: string, parent: Event, content: string): void {
  try {
    const builder = replyTo(parent, content);
    replyCases.push({
      name,
      parent,
      relay_hint: null,
      quotes: [],
      reply_to: { content: builder.currentContent, kind: builder.currentKind },
      out_tags: [...builder.currentTags],
    });
  } catch (error) {
    replyCases.push({
      name,
      parent,
      relay_hint: null,
      quotes: [],
      reply_to: { content, kind: 1 },
      err: error instanceof Error ? error.constructor.name : "Error",
    });
  }
}

const rootNote = signed([]);
const childNote = signed(
  [["e", rootNote.id, "wss://root.example", "root", rootNote.pubkey]],
  1,
  BOB,
);
const grandChildNote = signed(
  [
    ["e", rootNote.id, "wss://root.example", "root"],
    ["e", childNote.id, "", "reply"],
    ["p", childNote.pubkey, "wss://parent.example"],
  ],
  1,
  CAROL,
);

replyCase("root parent with relay hint", rootNote, "wss://hint.example/", []);
replyCase("root parent without hint", rootNote, null, []);
replyCase("unnormalized caller hint is TS-only", rootNote, "hint.example", []);
replyCase("nested reply parent", childNote, "wss://parent.example/", []);
replyCase("deep thread parent", grandChildNote, null, []);
replyCase("quotes emit q tags and author p tags", rootNote, null, [
  { id: ID4, relays: ["wss://quote.example"], author: carolPk },
  { id: ID5, relays: [] },
  { identifier: "article", pubkey: bobPk, kind: 30023, relays: ["wss://addr.example"] },
]);
replyCase("quote with author but no relay writes empty slot", rootNote, null, [
  { id: ID5, author: alicePk },
]);
replyCase(
  "string quotes are a TS convenience",
  rootNote,
  null,
  [ID4, `30023:${bobPk}:slug`, "garbage"],
  false,
);
replyCase("non-kind-1 parent rejected", signed([], 6), null, []);
replyCase("kind-0 parent rejected", signed([], 0), null, []);
replyToCase("reply_to wraps buildReplyTags in a kind-1 builder", childNote, "reply body");

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip10.thread",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  parse: parseCases,
  reply: replyCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip10 codec: ${parseCases.length} parse + ${replyCases.length} reply cases written`);
