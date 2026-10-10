/// <reference types="node" />
// Generates vectors/nip51/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-51 list parsers/builders plus the private-tag
// encrypt/decrypt flow as frozen vectors shared by the TS test suite
// (tests/vectors/nip51.test.ts) and the nk-* Rust crates.
//
// Private-tag ciphertexts are deterministic: the `Nip51Crypto` wrapper calls
// the real `nip44.encrypt`/`decrypt` with a recorded fixed nonce.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { hexToBytes } from "../../../src/core/util.ts";
import {
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
  getConversationKey,
} from "../../../src/nips/nip44.ts";
import {
  bookmarkListEventBuilder,
  decryptPrivateTags,
  encryptPrivateTags,
  muteListEventBuilder,
  parseBookmarkList,
  parseEmojiSet,
  parseFavoriteRelays,
  parseFollowPack,
  parseMuteList,
  parsePinList,
  parseRelaySet,
  parseUserEmojiList,
  pinListEventBuilder,
} from "../../../src/nips/nip51.ts";
import type { MuteItem, Nip51Crypto } from "../../../src/nips/nip51.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip51");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const AUTHOR_SK = "000000000000000000000000000000000000000000000000000000000000a1ce";
const FOREIGN_SK = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const AUX = hexToBytes("07".repeat(32));
const NONCE = hexToBytes("c1".repeat(32));
const NONCE2 = hexToBytes("d2".repeat(32));

const PK = "aa".repeat(32);
const PK2 = "cc".repeat(32);
const ID = "bb".repeat(32);
const ID2 = "dd".repeat(32);
const ARTICLE = `30023:${PK}:post-1`;
const ARTICLE_D_COLON = `30023:${PK}:post:with:colons`;
const RELAY_SET = `30002:${PK}:home`;
const RELAY_SET_D_COLON = `30002:${PK}:home:extra`;
const EMOJI_SET = `30030:${PK}:cats`;
const PEOPLE_SET = `30000:${PK}:friends`;

const authorKeys = Keys.fromSecretKey(AUTHOR_SK);
const author = authorKeys.publicKey;

function signed(tags: Tag[], kind: number, content = ""): Event {
  return signEvent(
    { pubkey: author, created_at: 1_700_000_000, kind, tags, content },
    authorKeys,
    AUX,
  );
}

/** Real `nip44` under `Nip51Crypto`, nonce drawn from a recorded stream. */
function fixedNonceCrypto(secretKey: string, nonce: Uint8Array): Nip51Crypto {
  const keys = Keys.fromSecretKey(secretKey);
  const sk = hexToBytes(secretKey);
  return {
    getPublicKey: async () => {
      await Promise.resolve();
      return keys.publicKey;
    },
    nip44Encrypt: async (peer, plaintext) => {
      await Promise.resolve();
      return nip44Encrypt(plaintext, getConversationKey(sk, peer), nonce);
    },
    nip44Decrypt: async (peer, payload) => {
      await Promise.resolve();
      return nip44Decrypt(payload, getConversationKey(sk, peer));
    },
  };
}

const errName = (error: unknown): string =>
  error instanceof Error ? error.constructor.name : "Error";

type ParseCase = { name: string; op: string; event: Event; out?: unknown; err?: string };
type BuildCase = {
  name: string;
  op: string;
  rust?: false;
  input: unknown;
  builder?: { kind: number; content: string; tags: Tag[] };
  err?: string;
};
type EncryptCase = {
  name: string;
  rust?: false;
  secret_key: string;
  nonce: string;
  tags: Tag[];
  content: string;
};
type DecryptCase = {
  name: string;
  secret_key: string;
  pubkey: string;
  content: string;
  out?: Tag[];
  items?: MuteItem[];
  err?: string;
};

const parseCases: ParseCase[] = [];
const buildCases: BuildCase[] = [];
const encryptCases: EncryptCase[] = [];
const decryptCases: DecryptCase[] = [];

type ParseOp =
  | "mute"
  | "pin"
  | "bookmark"
  | "user_emoji"
  | "relay_set"
  | "favorite_relays"
  | "emoji_set"
  | "follow_pack";

const PARSERS: Record<ParseOp, (event: Pick<Event, "kind" | "tags">) => unknown> = {
  mute: parseMuteList,
  pin: parsePinList,
  bookmark: parseBookmarkList,
  user_emoji: parseUserEmojiList,
  relay_set: parseRelaySet,
  favorite_relays: parseFavoriteRelays,
  emoji_set: parseEmojiSet,
  follow_pack: parseFollowPack,
};

function parseCase(name: string, op: ParseOp, event: Event): void {
  let out: unknown;
  let err: string | undefined;
  try {
    out = PARSERS[op](event);
  } catch (error) {
    err = errName(error);
  }
  parseCases.push({
    name,
    op,
    event,
    ...(out === undefined ? {} : { out }),
    ...(err === undefined ? {} : { err }),
  });
}

type BuildInput =
  | { op: "mute"; items: MuteItem[] }
  | { op: "pin"; ids: string[] }
  | { op: "bookmark"; items: { e?: string[]; a?: string[] } };

function buildCase(name: string, input: BuildInput, rust = true): void {
  let built: { kind: number; content: string; tags: Tag[] } | undefined;
  let err: string | undefined;
  try {
    const builder =
      input.op === "mute"
        ? muteListEventBuilder(input.items)
        : input.op === "pin"
          ? pinListEventBuilder(input.ids)
          : bookmarkListEventBuilder(input.items);
    built = {
      kind: builder.currentKind,
      content: builder.currentContent,
      tags: [...builder.currentTags],
    };
  } catch (error) {
    err = errName(error);
  }
  buildCases.push({
    name,
    op: input.op,
    input: input.op === "pin" ? input.ids : input.items,
    ...(rust ? {} : { rust: false as const }),
    ...(built === undefined ? {} : { builder: built }),
    ...(err === undefined ? {} : { err }),
  });
}

async function encryptCase(
  name: string,
  tags: ReadonlyArray<Tag>,
  nonce: Uint8Array = NONCE,
  rust = true,
  secretKey = AUTHOR_SK,
): Promise<string> {
  const content = await encryptPrivateTags(fixedNonceCrypto(secretKey, nonce), tags);
  encryptCases.push({
    name,
    ...(rust ? {} : { rust: false as const }),
    secret_key: secretKey,
    nonce: [...nonce].map((b) => b.toString(16).padStart(2, "0")).join(""),
    tags: tags.map((tag) => [...tag]),
    content,
  });
  return content;
}

async function decryptCase(
  name: string,
  pubkey: string,
  content: string,
  secretKey = AUTHOR_SK,
): Promise<void> {
  let out: ReadonlyArray<Tag> | undefined;
  let err: string | undefined;
  try {
    out = await decryptPrivateTags(fixedNonceCrypto(secretKey, NONCE), { pubkey, content });
  } catch (error) {
    err = errName(error);
  }
  decryptCases.push({
    name,
    secret_key: secretKey,
    pubkey,
    content,
    ...(out === undefined ? {} : { out: out.map((tag) => [...tag]) }),
    ...(out === undefined ? {} : { items: parseMuteList({ kind: 10000, tags: out }) }),
    ...(err === undefined ? {} : { err }),
  });
}

// ---------------------------------------------------------------- parse ---

parseCase(
  "mute: public items and ignores",
  "mute",
  signed(
    [
      ["p", PK.toUpperCase(), "wss://hint.example"],
      ["e", ID],
      ["t", "spam"],
      ["word", "Scam"],
      ["emoji", "ignored", "https://x.example/x.png"],
      ["p", "not-hex"],
      ["e", ""],
      ["t", ""],
      ["word", ""],
    ],
    10000,
  ),
);
parseCase("mute: empty list", "mute", signed([], 10000));
parseCase("mute: wrong kind", "mute", signed([["p", PK]], 1));

parseCase(
  "pin: ids and ignores",
  "pin",
  signed(
    [["e", ID, "wss://r.example", PK], ["p", PK], ["e", ID2.toUpperCase()], ["e", "nope"], ["e"]],
    10001,
  ),
);
parseCase("pin: wrong kind", "pin", signed([["e", ID]], 10000));

parseCase(
  "bookmark: events and verbatim addresses",
  "bookmark",
  signed(
    [
      ["e", ID],
      ["a", ARTICLE],
      ["a", ARTICLE_D_COLON],
      ["t", "ignored"],
      ["e", ID2],
      ["a", ""],
      ["e", "nope"],
    ],
    10003,
  ),
);
parseCase("bookmark: wrong kind", "bookmark", signed([["e", ID]], 1));

parseCase(
  "user emoji: sets and complete emoji only",
  "user_emoji",
  signed(
    [
      ["emoji", "cat", "https://cdn.example/cat.png", EMOJI_SET],
      ["a", EMOJI_SET],
      ["a", "not a coord, kept verbatim"],
      ["emoji", "incomplete"],
      ["emoji", "", "https://cdn.example/none.png"],
      ["p", PK],
      ["emoji", "dog", "https://cdn.example/dog.png"],
    ],
    10030,
  ),
);
parseCase("user emoji: wrong kind", "user_emoji", signed([], 30030));

parseCase(
  "relay set: d, normalization, dedup, skips",
  "relay_set",
  signed(
    [
      ["d", "home"],
      ["title", "Home"],
      ["relay", "wss://a.example"],
      ["relay", "not a url"],
      ["relay", "wss://a.example/"],
      ["r", "wss://wrong.example"],
      ["relay", "wss://b.example"],
      ["relay", ""],
      ["relay"],
    ],
    30002,
  ),
);
parseCase("relay set: missing d is empty", "relay_set", signed([], 30002));
parseCase("relay set: wrong kind", "relay_set", signed([["d", "x"]], 10012));

parseCase(
  "favorite relays: relay urls and 30002 coordinates only",
  "favorite_relays",
  signed(
    [
      ["relay", "wss://a.example"],
      ["a", RELAY_SET],
      ["a", RELAY_SET_D_COLON],
      ["a", "30002"],
      ["a", `30002:${PK}`],
      ["a", `30002:${PK}:`],
      ["a", PEOPLE_SET],
      ["a", EMOJI_SET],
      ["a", `30002:${PK2.toUpperCase()}:upper`],
      ["p", PK],
      ["relay", "://bad"],
    ],
    10012,
  ),
);
parseCase("favorite relays: wrong kind", "favorite_relays", signed([], 30002));

parseCase(
  "emoji set: d title emoji",
  "emoji_set",
  signed(
    [
      ["d", "cats"],
      ["title", "Cats"],
      ["image", "https://cdn.example/cover.png"],
      ["emoji", "cat", "https://cdn.example/cat.png"],
      ["emoji", "short-only"],
      ["a", EMOJI_SET],
    ],
    30030,
  ),
);
parseCase(
  "emoji set: empty title is absent",
  "emoji_set",
  signed(
    [
      ["d", "cats"],
      ["title", ""],
      ["emoji", "cat", "https://cdn.example/cat.png"],
    ],
    30030,
  ),
);
parseCase("emoji set: wrong kind", "emoji_set", signed([], 10030));

parseCase(
  "follow pack: d and pubkeys",
  "follow_pack",
  signed(
    [
      ["d", "dev"],
      ["title", "Devs"],
      ["p", PK2.toUpperCase(), "wss://hint.example"],
      ["p", "short"],
      ["p", PK],
      ["e", ID],
    ],
    39089,
  ),
);
parseCase("follow pack: wrong kind", "follow_pack", signed([["p", PK]], 30002));

// ---------------------------------------------------------------- build ---

buildCase("mute: all item kinds", {
  op: "mute",
  items: [
    { type: "pubkey", value: PK },
    { type: "event", value: ID },
    { type: "hashtag", value: "spam" },
    { type: "word", value: "Scam" },
    { type: "hashtag", value: "" },
    { type: "word", value: "" },
  ],
});
// Typed Rust `MuteItem`/`EventId` cannot carry non-hex values — TS-only (N9).
buildCase(
  "mute: non-hex pubkey is TS-only",
  { op: "mute", items: [{ type: "pubkey", value: "nope" }] },
  false,
);
buildCase("pin: ids", { op: "pin", ids: [ID.toUpperCase(), ID2] });
buildCase("pin: non-hex id is TS-only", { op: "pin", ids: ["nope"] }, false);
buildCase("bookmark: events then addresses", {
  op: "bookmark",
  items: { e: [ID.toUpperCase()], a: [ARTICLE, ARTICLE_D_COLON] },
});
// `EventAddress` cannot carry a malformed coordinate — TS-only.
buildCase(
  "bookmark: verbatim a is TS-only",
  { op: "bookmark", items: { a: ["not a coord", ""] } },
  false,
);

// --------------------------------------------------------------- private ---

async function buildPrivate(): Promise<void> {
  await encryptCase("empty tag list", []);
  const mixed = await encryptCase("mixed tags", [
    ["p", PK],
    ["e", ID],
    ["t", "spam"],
    ["word", "Lower"],
    ["emoji", "cat", "https://cdn.example/cat.png"],
    ["relay", "wss://a.example"],
    ["d", ""],
  ]);
  await encryptCase("second key second nonce", [["p", PK2]], NONCE2, true, FOREIGN_SK);
  // `Tags` cannot carry an empty inner array — TS-only.
  await encryptCase("empty inner tag is TS-only", [[], ["p", PK]], NONCE, false);

  await decryptCase("round trip", author, mixed);
  await decryptCase("empty content is no private tags", author, "");
  await decryptCase("foreign author rejects", PK2, mixed);

  // Decryptable ciphertext whose plaintext is not a tag array.
  const bad = fixedNonceCrypto(AUTHOR_SK, NONCE);
  const notJson = await bad.nip44Encrypt(author, "not-json");
  const wrongShape = await bad.nip44Encrypt(author, "{}");
  const emptyInner = await bad.nip44Encrypt(author, "[[]]");
  const nonString = await bad.nip44Encrypt(author, '[["p", 1]]');
  // `JSON.parse` accepts the \ud800 escape; serde_json rejects it (N10) and TS
  // now rejects the parsed string the same way.
  const surrogate = await bad.nip44Encrypt(author, String.raw`[["word","\ud800"]]`);
  await decryptCase("decrypts to non-JSON", author, notJson);
  await decryptCase("decrypts to wrong shape", author, wrongShape);
  await decryptCase("decrypts to empty inner tag", author, emptyInner);
  await decryptCase("decrypts to non-string item", author, nonString);
  await decryptCase("decrypts to lone surrogate", author, surrogate);

  // A NIP-04-shaped payload is not a NIP-44 ciphertext (deterministic string).
  const nip04Shape = `${Buffer.from(new Uint8Array(32)).toString("base64")}?iv=${Buffer.from(new Uint8Array(16)).toString("base64")}`;
  await decryptCase("NIP-04-shaped content is a crypto error", author, nip04Shape);

  // Tampered MAC — flip the last non-padding base64 character.
  const at = mixed.length - (mixed.endsWith("=") ? 3 : 1);
  const tampered = `${mixed.slice(0, at)}${mixed.at(at) === "A" ? "B" : "A"}${mixed.slice(at + 1)}`;
  await decryptCase("tampered payload is a crypto error", author, tampered);
}

await buildPrivate();

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip51.lists",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  parse: parseCases,
  build: buildCases,
  private: { encrypt: encryptCases, decrypt: decryptCases },
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip51 codec: ${parseCases.length} parse + ${buildCases.length} build + ${encryptCases.length} encrypt + ${decryptCases.length} decrypt cases written`,
);
