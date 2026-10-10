import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { CryptoError, EventValidationError, HexError } from "../../src/core/error.ts";
import type { Event } from "../../src/core/event.ts";
import { Keys } from "../../src/core/key.ts";
import type { Tag } from "../../src/core/tag.ts";
import { hexToBytes } from "../../src/core/util.ts";
import {
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
  getConversationKey,
} from "../../src/nips/nip44.ts";
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
} from "../../src/nips/nip51.ts";
import type { MuteItem, Nip51Crypto } from "../../src/nips/nip51.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type ParseCase = {
  name: string;
  op: string;
  event: Event;
  out?: unknown;
  err?: string;
};

type BuildCase = {
  name: string;
  op: string;
  rust?: boolean;
  input: unknown;
  builder?: { kind: number; content: string; tags: Tag[] };
  err?: string;
};

type EncryptCase = {
  name: string;
  rust?: boolean;
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

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip51/codec.json"), "utf8"),
) as {
  parse: ParseCase[];
  build: BuildCase[];
  private: { encrypt: EncryptCase[]; decrypt: DecryptCase[] };
};

const ERRORS = { CryptoError, EventValidationError, HexError } as const;

const PARSERS: Record<string, (event: Event) => unknown> = {
  mute: (event) => parseMuteList(event),
  pin: (event) => parsePinList(event),
  bookmark: (event) => parseBookmarkList(event),
  user_emoji: (event) => parseUserEmojiList(event),
  relay_set: (event) => parseRelaySet(event),
  favorite_relays: (event) => parseFavoriteRelays(event),
  emoji_set: (event) => parseEmojiSet(event),
  follow_pack: (event) => parseFollowPack(event),
};

function parserOf(op: string): (event: Event) => unknown {
  const parse = PARSERS[op];
  if (parse === undefined) {
    throw new Error(`unknown vector op ${op}`);
  }
  return parse;
}

function builderOf(c: BuildCase): { kind: number; content: string; tags: Tag[] } {
  const builder =
    c.op === "mute"
      ? muteListEventBuilder(c.input as MuteItem[])
      : c.op === "pin"
        ? pinListEventBuilder(c.input as string[])
        : bookmarkListEventBuilder(c.input as { e?: string[]; a?: string[] });
  return {
    kind: builder.currentKind,
    content: builder.currentContent,
    tags: [...builder.currentTags],
  };
}

/** Real `nip44` under `Nip51Crypto` with the recorded nonce — same wiring as the generator. */
function cryptoWithNonce(secretKey: string, nonceHex: string): Nip51Crypto {
  const keys = Keys.fromSecretKey(secretKey);
  const sk = hexToBytes(secretKey);
  const nonce = nonceHex === "" ? undefined : hexToBytes(nonceHex);
  return {
    getPublicKey: async () => Promise.resolve(keys.publicKey),
    nip44Encrypt: async (peer, plaintext) =>
      Promise.resolve(nip44Encrypt(plaintext, getConversationKey(sk, peer), nonce)),
    nip44Decrypt: async (peer, payload) =>
      Promise.resolve(nip44Decrypt(payload, getConversationKey(sk, peer))),
  };
}

describe("vectors/nip51/codec.json", () => {
  test.each(codec.parse.filter((c) => c.err === undefined))("parse %s", (c) => {
    expect(parserOf(c.op)(c.event)).toStrictEqual(c.out);
  });

  test.each(codec.parse.filter((c) => c.err !== undefined))("parse err %s", (c) => {
    expect(() => parserOf(c.op)(c.event)).toThrow(ERRORS[c.err as keyof typeof ERRORS]);
  });

  test.each(codec.build.filter((c) => c.err === undefined))("build %s", (c) => {
    expect(builderOf(c)).toStrictEqual(c.builder);
  });

  test.each(codec.build.filter((c) => c.err !== undefined))("build err %s", (c) => {
    expect(() => builderOf(c)).toThrow(ERRORS[c.err as keyof typeof ERRORS]);
  });

  test.each(codec.private.encrypt)("encrypt %s", async (c) => {
    const crypto = cryptoWithNonce(c.secret_key, c.nonce);
    await expect(encryptPrivateTags(crypto, c.tags)).resolves.toBe(c.content);
  });

  test.each(codec.private.decrypt.filter((c) => c.err === undefined))("decrypt %s", async (c) => {
    const crypto = cryptoWithNonce(c.secret_key, "");
    const event = { pubkey: c.pubkey, content: c.content } as Event;
    const tags = await decryptPrivateTags(crypto, event);
    expect([...tags]).toStrictEqual(c.out);
    expect(parseMuteList({ kind: 10_000, tags })).toStrictEqual(c.items);
  });

  test.each(codec.private.decrypt.filter((c) => c.err !== undefined))(
    "decrypt err %s",
    async (c) => {
      const crypto = cryptoWithNonce(c.secret_key, "");
      const event = { pubkey: c.pubkey, content: c.content } as Event;
      await expect(decryptPrivateTags(crypto, event)).rejects.toThrow(
        ERRORS[c.err as keyof typeof ERRORS],
      );
    },
  );
});
