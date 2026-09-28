import { describe, expect, test } from "vite-plus/test";

import {
  Keys,
  naddrEncode,
  neventEncode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from "../src/index.ts";
import type { Event } from "../src/index.ts";
import { parseContent } from "../src/nips/nip27.ts";
import type { ContentBlock, ParseContentOptions } from "../src/nips/nip27.ts";

const keys = Keys.generate();
const NPUB = npubEncode(keys.publicKey);
const NOTE = noteEncode("77".repeat(32));
const NSEC = nsecEncode(keys.secretKey.bytes);
const NPROFILE = nprofileEncode({ pubkey: keys.publicKey, relays: ["wss://r.example"] });
const NEVENT = neventEncode({ id: "ab".repeat(32) });
const NADDR = naddrEncode({ kind: 30023, pubkey: keys.publicKey, identifier: "post" });

const text = (t: string): ContentBlock => ({ type: "text", text: t });

type Case = {
  name: string;
  content: string | Pick<Event, "content" | "tags">;
  opts?: ParseContentOptions;
  want: ContentBlock[];
};

const cases: Case[] = [
  {
    name: "plain text is one block",
    content: "hello world",
    want: [text("hello world")],
  },
  {
    name: "empty content yields no blocks",
    content: "",
    want: [],
  },
  {
    name: "nostr: npub decodes to a reference",
    content: `hi nostr:${NPUB} yo`,
    want: [
      text("hi "),
      { type: "reference", pointer: { pubkey: keys.publicKey }, bare: false },
      text(" yo"),
    ],
  },
  {
    name: "nostr: note, nprofile, nevent, naddr decode to pointers",
    content: `nostr:${NOTE} nostr:${NPROFILE} nostr:${NEVENT} nostr:${NADDR}`,
    want: [
      { type: "reference", pointer: { id: "77".repeat(32) }, bare: false },
      text(" "),
      {
        type: "reference",
        pointer: { pubkey: keys.publicKey, relays: ["wss://r.example"] },
        bare: false,
      },
      text(" "),
      { type: "reference", pointer: { id: "ab".repeat(32), relays: [] }, bare: false },
      text(" "),
      {
        type: "reference",
        pointer: { kind: 30023, pubkey: keys.publicKey, identifier: "post", relays: [] },
        bare: false,
      },
    ],
  },
  {
    name: "nostr: nsec stays text",
    content: `key nostr:${NSEC} end`,
    want: [text(`key nostr:${NSEC} end`)],
  },
  {
    name: "undecodable bech32 stays text",
    content: "bad nostr:npub1qqqqqqqqqq tail",
    want: [text("bad nostr:npub1qqqqqqqqqq tail")],
  },
  {
    name: "nostr: followed by a non-entity stays text",
    content: "nostr:zzz1qqq is not a reference",
    want: [text("nostr:zzz1qqq is not a reference")],
  },
  {
    name: "https url keeps the original substring",
    content: "see https://Example.COM/A B",
    want: [text("see "), { type: "url", url: "https://Example.COM/A" }, text(" B")],
  },
  {
    name: "http url works too",
    content: "http://a.example/x",
    want: [{ type: "url", url: "http://a.example/x" }],
  },
  {
    name: "url without a dotted hostname stays text",
    content: "hit https://localhost/x now",
    want: [text("hit https://localhost/x now")],
  },
  {
    name: "trailing sentence punctuation is excluded from the url",
    content: "go https://x.example/a!?;:'",
    want: [text("go "), { type: "url", url: "https://x.example/a" }, text("!?;:'")],
  },
  {
    name: "CJK and full-width punctuation delimit urls",
    content: "看https://x.example/a。还有https://y.example/b，明天",
    want: [
      text("看"),
      { type: "url", url: "https://x.example/a" },
      text("。还有"),
      { type: "url", url: "https://y.example/b" },
      text("，明天"),
    ],
  },
  {
    name: "parenthesized url drops the unmatched closer",
    content: "(https://x.example/a) nice",
    want: [text("("), { type: "url", url: "https://x.example/a" }, text(") nice")],
  },
  {
    name: "wikipedia-style balanced parens stay in the url",
    content: "https://en.wikipedia.org/wiki/Foo_(bar) done",
    want: [{ type: "url", url: "https://en.wikipedia.org/wiki/Foo_(bar)" }, text(" done")],
  },
  {
    name: "media extensions classify image, video, audio",
    content:
      "https://i.example/a.PNG https://v.example/b.m3u8 https://s.example/c.flac https://x.example/d.txt",
    want: [
      { type: "image", url: "https://i.example/a.PNG" },
      text(" "),
      { type: "video", url: "https://v.example/b.m3u8" },
      text(" "),
      { type: "audio", url: "https://s.example/c.flac" },
      text(" "),
      { type: "url", url: "https://x.example/d.txt" },
    ],
  },
  {
    name: "imeta mime wins over the path extension",
    content: "https://x.example/a.mp4 https://x.example/b.png",
    opts: {
      imeta: new Map([
        ["https://x.example/a.mp4", "image/png"],
        ["https://x.example/b.png", "video/mp4"],
      ]),
    },
    want: [
      { type: "image", url: "https://x.example/a.mp4" },
      text(" "),
      { type: "video", url: "https://x.example/b.png" },
    ],
  },
  {
    name: "ws/wss urls become relay blocks",
    content: "ws://r1.example wss://r2.example/p",
    want: [
      { type: "relay", url: "ws://r1.example" },
      text(" "),
      { type: "relay", url: "wss://r2.example/p" },
    ],
  },
  {
    name: "bolt11 invoice emits lowercase",
    content: "pay LNBC1PVJLUEZSP5QQQ now",
    want: [text("pay "), { type: "invoice", bolt11: "lnbc1pvjluezsp5qqq" }, text(" now")],
  },
  {
    name: "lightning: prefix is stripped from the invoice",
    content: "zap lightning:lnbc1pvjluezsp5qqq ok",
    want: [text("zap "), { type: "invoice", bolt11: "lnbc1pvjluezsp5qqq" }, text(" ok")],
  },
  {
    name: "lntbs invoice prefix is recognized",
    content: "lntbs1qqqxyz",
    want: [{ type: "invoice", bolt11: "lntbs1qqqxyz" }],
  },
  {
    name: "invoice glued to a letter or digit stays text",
    content: "alnbc1qqq lnbc1qqqb 9lnbc1qqq",
    want: [text("alnbc1qqq lnbc1qqqb 9lnbc1qqq")],
  },
  {
    name: "ascii hashtag",
    content: "love #nostr today",
    want: [text("love "), { type: "hashtag", value: "nostr" }, text(" today")],
  },
  {
    name: "unicode hashtags: CJK and Japanese",
    content: "#中文 #日本語",
    want: [{ type: "hashtag", value: "中文" }, text(" "), { type: "hashtag", value: "日本語" }],
  },
  {
    name: "hashtag with combining marks and underscore",
    content: "#éclair #a_b1",
    want: [{ type: "hashtag", value: "éclair" }, text(" "), { type: "hashtag", value: "a_b1" }],
  },
  {
    name: "hashtag after CJK punctuation still parses",
    content: "好。#tag",
    want: [text("好。"), { type: "hashtag", value: "tag" }],
  },
  {
    name: "mid-word # is not a hashtag",
    content: "foo#bar",
    want: [text("foo#bar")],
  },
  {
    name: "hashtag caps at 42 code points",
    content: `#${"a".repeat(42)} ok`,
    want: [{ type: "hashtag", value: "a".repeat(42) }, text(" ok")],
  },
  {
    name: "a longer hashtag run truncates at 42",
    content: `#${"b".repeat(50)}`,
    want: [{ type: "hashtag", value: "b".repeat(42) }, text("b".repeat(8))],
  },
  {
    name: "emoji shortcode resolves against the event's tags",
    content: {
      content: "ship it :shipit: now",
      tags: [["emoji", "shipit", "https://cdn.example/shipit.png"]],
    },
    want: [
      text("ship it "),
      { type: "emoji", shortcode: "shipit", url: "https://cdn.example/shipit.png" },
      text(" now"),
    ],
  },
  {
    name: "shortcode missing from emoji tags stays text",
    content: { content: "hello :wave: bye", tags: [] },
    want: [text("hello :wave: bye")],
  },
  {
    name: "string input never resolves emoji",
    content: "hello :shipit: bye",
    want: [text("hello :shipit: bye")],
  },
  {
    name: "bare bech32 stays text without the option",
    content: `dm ${NPUB} pls`,
    want: [text(`dm ${NPUB} pls`)],
  },
  {
    name: "bare bech32 decodes with legacyBech32",
    content: `dm ${NPUB} and ${NOTE}`,
    opts: { legacyBech32: true },
    want: [
      text("dm "),
      { type: "reference", pointer: { pubkey: keys.publicKey }, bare: true },
      text(" and "),
      { type: "reference", pointer: { id: "77".repeat(32) }, bare: true },
    ],
  },
  {
    name: "bare bech32 glued to letters stays text",
    content: `x${NPUB} tail`,
    opts: { legacyBech32: true },
    want: [text(`x${NPUB} tail`)],
  },
  {
    name: "bare nsec is never a reference",
    content: `x ${NSEC} y`,
    opts: { legacyBech32: true },
    want: [text(`x ${NSEC} y`)],
  },
  {
    name: "mixed content parses in order",
    content: `gm #中文 nostr:${NPUB} https://i.example/p.webp wss://r.example :ok:`,
    want: [
      text("gm "),
      { type: "hashtag", value: "中文" },
      text(" "),
      { type: "reference", pointer: { pubkey: keys.publicKey }, bare: false },
      text(" "),
      { type: "image", url: "https://i.example/p.webp" },
      text(" "),
      { type: "relay", url: "wss://r.example" },
      text(" :ok:"),
    ],
  },
];

describe("nip27 parseContent", () => {
  test.each(cases)("$name", (c) => {
    expect(parseContent(c.content, c.opts)).toStrictEqual(c.want);
  });

  test("1000 mixed notes tokenize within 50ms", () => {
    const fixture =
      `gm #中文 #nostr nostr:${NPUB} https://i.example/p.png ` +
      `https://en.wikipedia.org/wiki/Foo_(bar) wss://r.example ` +
      `lightning:lnbc1pvjluezsp5qqq :wave: 你好世界`;
    const event = {
      content: fixture,
      tags: [["emoji", "wave", "https://cdn.example/wave.png"]],
    };
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) {
      parseContent(event);
    }
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(50);
  });
});
