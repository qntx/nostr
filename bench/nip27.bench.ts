import { describe, expect, test } from "vite-plus/test";

import { Keys, npubEncode } from "../src/index.ts";
import { parseContent } from "../src/nips/nip27.ts";

const N = 1000;
const NPUB = npubEncode(Keys.generate().publicKey);

describe("nip27 bench", () => {
  test(`${N} mixed notes tokenize`, () => {
    const fixture =
      `gm #中文 #nostr nostr:${NPUB} https://i.example/p.png ` +
      `https://en.wikipedia.org/wiki/Foo_(bar) wss://r.example ` +
      `lightning:lnbc1pvjluezsp5qqq :wave: 你好世界`;
    const event = {
      content: fixture,
      tags: [["emoji", "wave", "https://cdn.example/wave.png"]],
    };

    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
      parseContent(event);
    }
    const ms = performance.now() - t0;

    console.log(`[nip27 bench] ${N} mixed notes tokenized: ${ms.toFixed(1)}ms total`);
    expect(Number.isFinite(ms)).toBe(true);
  }, 60_000);
});
