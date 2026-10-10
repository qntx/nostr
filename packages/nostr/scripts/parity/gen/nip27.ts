/// <reference types="node" />
// Generates vectors/nip27/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-27 `parseContent` tokenizer semantics as frozen
// vectors shared by the TS test suite (tests/vectors/nip27.test.ts) and the
// nk-* Rust crates. The canonical `ContentBlock` JSON encoding lives in
// ../content-json.ts and is shared with the seeded `nip27.tokenize`
// differential stream (diff.ts).

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Tag } from "../../../src/core/tag.ts";
import { hexToBytes } from "../../../src/core/util.ts";
import {
  naddrEncode,
  neventEncode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from "../../../src/nips/nip19.ts";
import { parseContent } from "../../../src/nips/nip27.ts";
import type { ParseContentOptions } from "../../../src/nips/nip27.ts";
import { blocksJson } from "../content-json.ts";
import type { BlockJson } from "../content-json.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip27");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const PK = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
const ID = "aa".repeat(32);
const SECRET = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";

const NPUB = npubEncode(PK);
const NPROFILE = nprofileEncode({ pubkey: PK, relays: ["wss://r1.example", "wss://r2.example"] });
const NPROFILE_BARE = nprofileEncode({ pubkey: PK });
const NOTE = noteEncode(ID);
const NEVENT = neventEncode({ id: ID, relays: ["wss://r.example"], author: PK, kind: 1 });
const NEVENT_BARE = neventEncode({ id: ID });
const NADDR = naddrEncode({ identifier: "article-1", pubkey: PK, kind: 30_023, relays: [] });
const NSEC = nsecEncode(hexToBytes(SECRET));

const KELVIN = "K";
const LONG_S = "ſ";

type TokenizeCase = {
  name: string;
  content: string;
  tags?: Tag[];
  legacy?: boolean;
  imeta?: Record<string, string>;
  out: BlockJson[];
};

const cases: TokenizeCase[] = [];

function tokenize(
  name: string,
  content: string,
  opts?: { tags?: Tag[]; legacy?: boolean; imeta?: Record<string, string> },
): void {
  const options: ParseContentOptions = {};
  if (opts?.legacy === true) {
    options.legacyBech32 = true;
  }
  if (opts?.imeta !== undefined) {
    options.imeta = new Map(Object.entries(opts.imeta));
  }
  const input = opts?.tags === undefined ? content : { content, tags: opts.tags };
  cases.push({
    name,
    content,
    ...(opts?.tags === undefined ? {} : { tags: opts.tags }),
    ...(opts?.legacy === true ? { legacy: true } : {}),
    ...(opts?.imeta === undefined ? {} : { imeta: opts.imeta }),
    out: blocksJson(parseContent(input, options)),
  });
}

// ── text ─────────────────────────────────────────────────────────────
tokenize("empty content", "");
tokenize("plain text merges", "hello nostr world");
tokenize("unmatched fragments stay text", ":: :a nostr: lnbc # !");

// ── nostr: references ────────────────────────────────────────────────
tokenize("nostr npub", `nostr:${NPUB}`);
tokenize("nostr glued to preceding text", `xnostr:${NPUB}`);
tokenize("nostr uppercase scheme and prefix", `NOSTR:${NPUB.toUpperCase()}`);
tokenize("nostr long-s scheme", `no${LONG_S}tr:${NPUB}`);
tokenize("nostr nprofile with relays", `nostr:${NPROFILE}`);
tokenize("nostr nprofile without relays", `nostr:${NPROFILE_BARE}`);
tokenize("nostr note", `nostr:${NOTE}`);
tokenize("nostr nevent with hints", `nostr:${NEVENT}`);
tokenize("nostr nevent without hints", `nostr:${NEVENT_BARE}`);
tokenize("nostr naddr", `nostr:${NADDR}`);
tokenize("nostr nsec ignored", `nostr:${NSEC}`);
tokenize(
  "nostr invalid bech32",
  "nostr:npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
);
tokenize("nostr empty data", "nostr:npub1");
tokenize("adjacent references merge no text", `nostr:${NPUB}nostr:${NOTE}`);

// ── urls ─────────────────────────────────────────────────────────────
tokenize("https url", "see https://example.com/x now");
tokenize("http url", "http://a.b");
tokenize("uppercase scheme", "HTTPS://a.b/x");
tokenize("long-s scheme candidate fails URL parse", `HTT${LONG_S}://a.b/x`);
tokenize("kelvin in host stays text-adjacent", `https://a.${KELVIN}/x`);
tokenize("host without dot", "https://localhost/x");
tokenize("ipv6 host has no dot", "https://[::1]/x");
tokenize("ipv4 host", "https://1.2.3.4/x");
tokenize("ws relay", "ws://a.b/socket");
tokenize("wss relay", "wss://relay.example");
tokenize("relay ignores imeta", "wss://a.b/f", {
  imeta: { "wss://a.b/f": "image/png" },
});
tokenize("relay host without dot", "wss://localhost");

// URL tail trimming — every punctuation class plus balanced/unbalanced closers.
tokenize("url trailing period", "https://a.b/x.");
tokenize("url trailing comma and bang", "https://a.b/x,!");
tokenize("url trailing semicolon colon quote", "https://a.b/x;:'");
tokenize("url trailing question", "https://a.b/x?");
tokenize("url unbalanced closer", "https://a.b/x)");
tokenize("url double closer", "https://a.b/x))");
tokenize("url balanced parens kept", "https://a.b/(x)");
tokenize("url nested unbalanced", "https://a.b/(x))");
tokenize("url unbalanced bracket", "https://a.b/x]");
tokenize("url balanced bracket kept", "https://a.b/[x]");
tokenize("url opener only", "https://a.b/(x");

// URL run stop characters.
tokenize("url stops at angle bracket", "https://a.b/x<y");
tokenize("url stops at quote", 'https://a.b/x"y');
tokenize("url stops at cjk period", "https://a.b/x。tail");
tokenize("url stops at fullwidth bang", "https://a.b/x！tail");
tokenize("url stops at bom whitespace", "https://a.b/x﻿y");
tokenize("url stops at space", "https://a.b/x y");

// Media classification — imeta first, then extension.
tokenize("image by extension", "https://a.b/pic.png");
tokenize("image uppercase extension", "https://a.b/PIC.PNG");
tokenize("video extension", "https://a.b/v.webm");
tokenize("audio extension", "https://a.b/song.FLAC");
tokenize("image extension before query", "https://a.b/f.png?w=100");
tokenize("unknown extension stays url", "https://a.b/f.txt");
tokenize("no extension stays url", "https://a.b/path");
tokenize("dot-only tail trims to url", "https://a.b/path.");
tokenize("imeta mime wins over extension", "https://a.b/f.png", {
  imeta: { "https://a.b/f.png": "video/mp4" },
});
tokenize("imeta mime without slash", "https://a.b/f", {
  imeta: { "https://a.b/f": "audio" },
});
tokenize("imeta uppercase base falls to extension", "https://a.b/f.png", {
  imeta: { "https://a.b/f.png": "IMAGE/png" },
});
tokenize("imeta non-media mime falls to extension", "https://a.b/f.png", {
  imeta: { "https://a.b/f.png": "application/pdf" },
});
tokenize("imeta key must equal trimmed url", "https://a.b/f.png.", {
  imeta: { "https://a.b/f.png.": "image/png", "https://a.b/f.png": "video/webm" },
});

// ── invoices ─────────────────────────────────────────────────────────
tokenize("invoice plain", "lnbc1xyz");
tokenize("invoice amount", "lnbc2100n1xyz");
tokenize("invoice amount multiplier", "lnbc10m1xyz");
tokenize("invoice backtracks separator", "lnbc101xyz");
tokenize("invoice digit-1 splits amount", "lnbc21xyz");
tokenize("invoice no-amount with multiplier-shaped data", "lnbc1uxyz");
tokenize("invoice multiplier", "lnbc1m1xyz");
tokenize("invoice currencies", "lntbs1xyz lnbcrt1xyz lntb1xyz");
tokenize("invoice uppercase", "LNBC1XYZ");
tokenize("invoice lightning prefix stripped", "LIGHTNING:lnbc1xyz");
tokenize("invoice prefix and body folded", `light${LONG_S}ghtning:LNBC1XYZ`); // ſ not in lightning — text
tokenize("invoice kelvin in data", `lnbc1${KELVIN}yz`);
tokenize("invoice word char before", "xlnbc1xyz");
tokenize("invoice word char after", "lnbc1xyzb");
tokenize("invoice cjk after", "lnbc1xyz中");
tokenize("invoice astral after ok", "lnbc1xyz😀");
tokenize("invoice no separator", "lnbcxyz");
tokenize("invoice separator without data", "lnbc1");
tokenize("invoice zero amount run no separator", "lnbc000xyz");

// ── hashtags ─────────────────────────────────────────────────────────
tokenize("hashtag plain", "#nostr");
tokenize("hashtag digit leading", "#1abc");
tokenize("hashtag underscore", "#_x_");
tokenize("hashtag unicode letters", "#日本語 #café");
tokenize("hashtag combining mark", "#é");
tokenize("hashtag trailing punctuation", "#tag.#next");
tokenize("hashtag preceded by letter", "x#tag");
tokenize("hashtag preceded by hash", "##tag");
tokenize("hashtag after astral", "😀#tag");
tokenize("hashtag before astral", "#tag😀");
tokenize("hashtag at 42 cap", `#${"a".repeat(42)}`);
tokenize("hashtag beyond 42 is text", `#${"b".repeat(43)}`);
tokenize("hash alone", "# #!");

// ── emoji ────────────────────────────────────────────────────────────
const EMOJI_TAGS: Tag[] = [
  ["emoji", "wave", "https://a.b/w.gif"],
  ["emoji", "dup", "u1"],
  ["emoji", "dup", "u2"],
  ["emoji", "", "ignored"],
  ["emoji", "novalue", ""],
  ["emoji", "single"],
  ["notemoji", "wave", "x"],
  ["emoji", KELVIN, "https://a.b/k.gif"],
];
tokenize("emoji hit and miss", "hi :wave: and :wave2:", { tags: EMOJI_TAGS });
tokenize("emoji later duplicate wins", ":dup:", { tags: EMOJI_TAGS });
tokenize("emoji kelvin shortcode", `:${KELVIN}:`, { tags: EMOJI_TAGS });
tokenize("emoji ascii-k misses kelvin tag", ":k:", { tags: EMOJI_TAGS });
tokenize("emoji shortcode shape only", ":a-b_c9:", { tags: EMOJI_TAGS });
tokenize("emoji no tags never match", ":wave:");
tokenize("emoji unclosed", ":wave");
tokenize("emoji empty", "::");

// ── legacy bare bech32 ───────────────────────────────────────────────
tokenize("bare npub legacy", NPUB, { legacy: true });
tokenize("bare note legacy", `at ${NOTE} end`, { legacy: true });
tokenize("bare nevent legacy", NEVENT, { legacy: true });
tokenize("bare naddr legacy", NADDR, { legacy: true });
tokenize("bare nprofile legacy", NPROFILE, { legacy: true });
tokenize("bare uppercase prefix legacy", NPUB.toUpperCase(), { legacy: true });
tokenize("bare without legacy is text", NPUB);
tokenize("bare word char before", `x${NPUB}`, { legacy: true });
tokenize("bare word char after", `${NPUB}b`, { legacy: true });
tokenize("bare cjk after", `${NPUB}中`, { legacy: true });
tokenize("bare astral after ok", `${NPUB}😀`, { legacy: true });
tokenize("bare nsec never", NSEC, { legacy: true });
tokenize(
  "bare invalid checksum",
  "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
  {
    legacy: true,
  },
);
tokenize("bare glued inside nostr scheme", `nostr:${NPUB}`, { legacy: true });

// ── mixed / resume behaviour ─────────────────────────────────────────
tokenize("failed candidate resumes inside its span", "see https://x/wss://a.b now");
tokenize(
  "mixed stream",
  `gm nostr:${NPUB} check https://a.b/pic.png and wss://r.x pay lnbc10u1xyz #nostr :wave: end`,
  { tags: [["emoji", "wave", "https://a.b/w.gif"]] },
);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip27.tokenize",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  cases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`nip27 codec: ${cases.length} tokenize cases written`);
