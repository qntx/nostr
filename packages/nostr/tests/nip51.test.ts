import { describe, expect, test } from "vite-plus/test";

import {
  CryptoError,
  EventValidationError,
  HexError,
  KeysSigner,
  Kind,
  normalizeURL,
} from "../src/index.ts";
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
  parseMuteListPrivate,
  parsePinList,
  parseRelaySet,
  parseUserEmojiList,
  pinListEventBuilder,
} from "../src/nips/nip51.ts";
import type { MuteItem, Nip51Crypto } from "../src/nips/nip51.ts";

const PK = "aa".repeat(32);
const PK2 = "cc".repeat(32);
const ID = "bb".repeat(32);
const ID2 = "dd".repeat(32);
const ARTICLE = `30023:${PK}:post-1`;
const RELAY_SET = `30002:${PK}:home`;
const EMOJI_SET = `30030:${PK}:cats`;
const PEOPLE_SET = `30000:${PK}:friends`;
const AUTHOR_SK = "000000000000000000000000000000000000000000000000000000000000a1ce";

async function unusedEncrypt(): Promise<string> {
  await Promise.resolve();
  throw new Error("nip44Encrypt should not be invoked");
}

const catchError = async (p: Promise<unknown>): Promise<unknown> => {
  try {
    await p;
  } catch (error) {
    return error;
  }
  throw new Error("expected rejection");
};

function trackingCrypto(opts: {
  pubkey: string;
  decrypt?: ((peer: string, payload: string) => string | Promise<string>) | undefined;
}): Nip51Crypto & { decryptInvocations: number } {
  const stub = {
    decryptInvocations: 0,
    async getPublicKey() {
      await Promise.resolve();
      return opts.pubkey;
    },
    nip44Encrypt: unusedEncrypt,
    async nip44Decrypt(peer: string, payload: string) {
      stub.decryptInvocations += 1;
      if (!opts.decrypt) {
        throw new Error("nip44Decrypt should not be invoked");
      }
      return opts.decrypt(peer, payload);
    },
  };
  return stub;
}

describe("nip51 mute list", () => {
  test("parses public p/e/t/word tags and ignores unknown tags", () => {
    const items = parseMuteList({
      kind: Kind.MuteList,
      tags: [
        ["p", PK.toUpperCase(), "wss://hint.example"],
        ["e", ID],
        ["t", "spam"],
        ["word", "Scam"],
        ["emoji", "ignored", "https://x.example/x.png"],
        ["p", "not-hex"],
        ["e", ""],
      ],
    });
    expect(items).toStrictEqual<MuteItem[]>([
      { type: "pubkey", value: PK },
      { type: "event", value: ID },
      { type: "hashtag", value: "spam" },
      { type: "word", value: "scam" },
    ]);
  });

  test("muteListEventBuilder round-trips public items", () => {
    const items: MuteItem[] = [
      { type: "pubkey", value: PK },
      { type: "event", value: ID },
      { type: "hashtag", value: "spam" },
      { type: "word", value: "scam" },
    ];
    const built = muteListEventBuilder(items);
    expect(built.currentKind).toBe(Kind.MuteList);
    expect(built.currentContent).toBe("");
    expect(built.currentTags).toStrictEqual([
      ["p", PK],
      ["e", ID],
      ["t", "spam"],
      ["word", "scam"],
    ]);
    expect(parseMuteList({ kind: built.currentKind, tags: built.currentTags })).toStrictEqual(
      items,
    );
  });

  test("muteListEventBuilder lowercases hex and words; skips empty t/word", () => {
    const built = muteListEventBuilder([
      { type: "pubkey", value: PK.toUpperCase() },
      { type: "event", value: ID.toUpperCase() },
      { type: "hashtag", value: "" },
      { type: "word", value: "" },
      { type: "word", value: "Scam" },
    ]);
    expect(built.currentTags).toStrictEqual([
      ["p", PK],
      ["e", ID],
      ["word", "scam"],
    ]);
  });

  test("muteListEventBuilder rejects non-hex pubkey", () => {
    expect(() => muteListEventBuilder([{ type: "pubkey", value: "nope" }])).toThrow(HexError);
  });
});

describe("nip51 pin list", () => {
  test("parses e tags and ignores unknown tags", () => {
    expect(
      parsePinList({
        kind: Kind.PinList,
        tags: [
          ["e", ID, "wss://r.example", PK],
          ["p", PK],
          ["e", ID2],
          ["e", "nope"],
        ],
      }),
    ).toStrictEqual([ID, ID2]);
  });

  test("pinListEventBuilder emits e tags", () => {
    const built = pinListEventBuilder([ID.toUpperCase(), ID2]);
    expect(built.currentKind).toBe(Kind.PinList);
    expect(built.currentContent).toBe("");
    expect(built.currentTags).toStrictEqual([
      ["e", ID],
      ["e", ID2],
    ]);
    expect(parsePinList({ kind: built.currentKind, tags: built.currentTags })).toStrictEqual([
      ID,
      ID2,
    ]);
  });

  test("pinListEventBuilder rejects non-hex ids", () => {
    expect(() => pinListEventBuilder(["nope"])).toThrow(HexError);
  });
});

describe("nip51 bookmark list", () => {
  test("parses e and a tags and ignores unknown tags", () => {
    expect(
      parseBookmarkList({
        kind: Kind.BookmarkList,
        tags: [
          ["e", ID],
          ["a", ARTICLE],
          ["t", "ignored"],
          ["e", ID2],
          ["a", ""],
        ],
      }),
    ).toStrictEqual({ e: [ID, ID2], a: [ARTICLE] });
  });

  test("bookmarkListEventBuilder emits e then a", () => {
    const built = bookmarkListEventBuilder({ e: [ID.toUpperCase()], a: [ARTICLE, ""] });
    expect(built.currentKind).toBe(Kind.BookmarkList);
    expect(built.currentContent).toBe("");
    expect(built.currentTags).toStrictEqual([
      ["e", ID],
      ["a", ARTICLE],
    ]);
    expect(parseBookmarkList({ kind: built.currentKind, tags: built.currentTags })).toStrictEqual({
      e: [ID],
      a: [ARTICLE],
    });
  });
});

describe("nip51 user emoji list", () => {
  test("parses emoji and a tags; skips incomplete emoji", () => {
    expect(
      parseUserEmojiList({
        kind: Kind.UserEmojiList,
        tags: [
          ["emoji", "cat", "https://cdn.example/cat.png", EMOJI_SET],
          ["a", EMOJI_SET],
          ["emoji", "incomplete"],
          ["p", PK],
          ["emoji", "dog", "https://cdn.example/dog.png"],
        ],
      }),
    ).toStrictEqual({
      emoji: [
        { shortcode: "cat", url: "https://cdn.example/cat.png" },
        { shortcode: "dog", url: "https://cdn.example/dog.png" },
      ],
      sets: [EMOJI_SET],
    });
  });
});

describe("nip51 relay set", () => {
  test("parses d and relay tags; skips invalid urls and unknown tags", () => {
    expect(
      parseRelaySet({
        kind: Kind.RelaySets,
        tags: [
          ["d", "home"],
          ["title", "Home"],
          ["relay", "wss://a.example"],
          ["relay", "not a url"],
          ["relay", "wss://a.example/"],
          ["r", "wss://wrong.example"],
          ["relay", "wss://b.example"],
        ],
      }),
    ).toStrictEqual({
      d: "home",
      relays: [normalizeURL("wss://a.example"), normalizeURL("wss://b.example")],
    });
  });

  test("missing d is empty string", () => {
    expect(parseRelaySet({ kind: Kind.RelaySets, tags: [] })).toStrictEqual({ d: "", relays: [] });
  });
});

describe("nip51 favorite relays", () => {
  test("parses relay urls and kind 30002 a tags only", () => {
    const withColonD = `30002:${PK}:home:extra`;
    expect(
      parseFavoriteRelays({
        kind: Kind.FavoriteRelays,
        tags: [
          ["relay", "wss://a.example"],
          ["a", RELAY_SET],
          ["a", withColonD],
          ["a", "30002"],
          ["a", `30002:${PK}`],
          ["a", `30002:${PK}:`],
          ["a", PEOPLE_SET],
          ["a", EMOJI_SET],
          ["p", PK],
          ["relay", "://bad"],
        ],
      }),
    ).toStrictEqual({
      relays: [normalizeURL("wss://a.example")],
      sets: [RELAY_SET, withColonD],
    });
  });
});

describe("nip51 emoji set", () => {
  test("parses d, title, and emoji tags", () => {
    expect(
      parseEmojiSet({
        kind: Kind.EmojiSet,
        tags: [
          ["d", "cats"],
          ["title", "Cats"],
          ["image", "https://cdn.example/cover.png"],
          ["emoji", "cat", "https://cdn.example/cat.png"],
          ["a", EMOJI_SET],
        ],
      }),
    ).toStrictEqual({
      d: "cats",
      title: "Cats",
      emoji: [{ shortcode: "cat", url: "https://cdn.example/cat.png" }],
    });
  });

  test("omits title when absent", () => {
    const parsed = parseEmojiSet({
      kind: Kind.EmojiSet,
      tags: [
        ["d", "cats"],
        ["emoji", "cat", "https://cdn.example/cat.png"],
      ],
    });
    expect(parsed.d).toBe("cats");
    expect(parsed.title).toBeUndefined();
    expect(parsed.emoji).toStrictEqual([{ shortcode: "cat", url: "https://cdn.example/cat.png" }]);
  });
});

describe("nip51 follow pack", () => {
  test("parses d and p tags; ignores unknown tags", () => {
    expect(
      parseFollowPack({
        kind: Kind.StarterPack,
        tags: [
          ["d", "dev"],
          ["title", "Devs"],
          ["p", PK2.toUpperCase(), "wss://hint.example"],
          ["p", "short"],
          ["p", PK],
          ["e", ID],
        ],
      }),
    ).toStrictEqual({ d: "dev", pubkeys: [PK2, PK] });
  });
});

describe("nip51 kind mismatch", () => {
  const wrong = { kind: Kind.TextNote, tags: [] as const };

  test("throws EventValidationError", () => {
    expect(() => parseMuteList(wrong)).toThrow(EventValidationError);
    expect(() => parseMuteList(wrong)).toThrow(
      `expected kind ${Kind.MuteList}, got ${Kind.TextNote}`,
    );
    expect(() => parsePinList(wrong)).toThrow(EventValidationError);
    expect(() => parseBookmarkList(wrong)).toThrow(EventValidationError);
    expect(() => parseUserEmojiList(wrong)).toThrow(EventValidationError);
    expect(() => parseRelaySet(wrong)).toThrow(EventValidationError);
    expect(() => parseFavoriteRelays(wrong)).toThrow(EventValidationError);
    expect(() => parseEmojiSet(wrong)).toThrow(EventValidationError);
    expect(() => parseFollowPack(wrong)).toThrow(EventValidationError);
  });
});

describe("nip51 private tags", () => {
  test('encrypt [["p", PK]] round-trips through decrypt', async () => {
    const signer = new KeysSigner(AUTHOR_SK);
    const author = await signer.getPublicKey();
    const peers: string[] = [];
    const crypto: Nip51Crypto = {
      getPublicKey: async () => signer.getPublicKey(),
      nip44Encrypt: async (peer, plaintext) => {
        peers.push(peer);
        return signer.nip44Encrypt(peer, plaintext);
      },
      nip44Decrypt: async (peer, payload) => {
        peers.push(peer);
        return signer.nip44Decrypt(peer, payload);
      },
    };
    const tags = [["p", PK]] as const;
    const content = await encryptPrivateTags(crypto, tags);
    expect(content.length).toBeGreaterThan(0);
    expect(content).not.toBe(JSON.stringify(tags));
    const decrypted = await decryptPrivateTags(crypto, { pubkey: author, content });
    expect(decrypted).toStrictEqual([["p", PK]]);
    expect(peers).toStrictEqual([author, author]);
  });

  test("parseMuteListPrivate splits public tags and private content; parseMuteList ignores content", async () => {
    const signer = new KeysSigner(AUTHOR_SK);
    const author = await signer.getPublicKey();
    const privateTags = [
      ["e", ID.toUpperCase()],
      ["word", "Secret"],
    ] as const;
    const content = await encryptPrivateTags(signer, privateTags);
    const event = {
      kind: Kind.MuteList,
      pubkey: author,
      tags: [
        ["p", PK],
        ["t", "spam"],
      ] as const,
      content,
    };
    const parsed = await parseMuteListPrivate(signer, event);
    expect(parsed.public).toStrictEqual<MuteItem[]>([
      { type: "pubkey", value: PK },
      { type: "hashtag", value: "spam" },
    ]);
    expect(parsed.private).toStrictEqual<MuteItem[]>([
      { type: "event", value: ID },
      { type: "word", value: "secret" },
    ]);
    expect(parseMuteList(event)).toStrictEqual(parsed.public);
    expect(event.content).toBe(content);
    expect(event.content.length).toBeGreaterThan(0);
  });

  test("empty content yields private [] without invoking nip44Decrypt", async () => {
    const crypto = trackingCrypto({ pubkey: PK });
    const parsed = await parseMuteListPrivate(crypto, {
      kind: Kind.MuteList,
      pubkey: PK2,
      tags: [["p", PK2]],
      content: "",
    });
    expect(parsed.public).toStrictEqual<MuteItem[]>([{ type: "pubkey", value: PK2 }]);
    expect(parsed.private).toStrictEqual<MuteItem[]>([]);
    expect(crypto.decryptInvocations).toBe(0);
    await expect(decryptPrivateTags(crypto, { pubkey: PK2, content: "" })).resolves.toStrictEqual(
      [],
    );
    expect(crypto.decryptInvocations).toBe(0);
  });

  test("foreign pubkey throws before decrypt", async () => {
    const crypto = trackingCrypto({ pubkey: PK });
    await expect(
      decryptPrivateTags(crypto, { pubkey: PK2, content: "ciphertext" }),
    ).rejects.toThrow(EventValidationError);
    await expect(
      decryptPrivateTags(crypto, { pubkey: PK2, content: "ciphertext" }),
    ).rejects.toThrow("NIP-51 private content is only for the author");
    expect(crypto.decryptInvocations).toBe(0);
  });

  test("mixed-case author pubkey is accepted", async () => {
    const crypto = trackingCrypto({
      pubkey: PK,
      decrypt: () => JSON.stringify([["p", PK2]]),
    });
    const tags = await decryptPrivateTags(crypto, {
      pubkey: PK.toUpperCase(),
      content: "ciphertext",
    });
    expect(tags).toStrictEqual([["p", PK2]]);
    expect(crypto.decryptInvocations).toBe(1);
  });

  test("NIP-04-shaped content throws CryptoError and must not succeed", async () => {
    const signer = new KeysSigner(AUTHOR_SK);
    const author = await signer.getPublicKey();
    const tags = [["p", PK]] as const;
    const nip04Content = await signer.nip04Encrypt(author, JSON.stringify(tags));
    expect(nip04Content).toContain("?iv=");
    await expect(
      decryptPrivateTags(signer, { pubkey: author, content: nip04Content }),
    ).rejects.toThrow(CryptoError);
    const error = await catchError(
      decryptPrivateTags(signer, { pubkey: author, content: nip04Content }),
    );
    expect(error).toBeInstanceOf(CryptoError);
    expect(error).not.toBeInstanceOf(EventValidationError);
  });

  test("plaintext JSON in content is not a parse-first fallback", async () => {
    const signer = new KeysSigner(AUTHOR_SK);
    const author = await signer.getPublicKey();
    const tags = [["p", PK]] as const;
    const plaintextJson = JSON.stringify(tags);
    expect(() => JSON.parse(plaintextJson)).not.toThrow();
    const crypto = trackingCrypto({
      pubkey: author,
      decrypt: async (peer, payload) => {
        await Promise.resolve();
        return signer.nip44Decrypt(peer, payload);
      },
    });
    const error = await catchError(
      decryptPrivateTags(crypto, { pubkey: author, content: plaintextJson }),
    );
    expect(error).toBeInstanceOf(CryptoError);
    expect(error).not.toBeInstanceOf(EventValidationError);
    expect(crypto.decryptInvocations).toBe(1);
  });

  test("NIP-44 decrypt of not-json throws EventValidationError not SyntaxError", async () => {
    const crypto = trackingCrypto({
      pubkey: PK,
      decrypt: () => "not-json",
    });
    const error = await catchError(decryptPrivateTags(crypto, { pubkey: PK, content: "payload" }));
    expect(error).toBeInstanceOf(EventValidationError);
    expect(error).not.toBeInstanceOf(SyntaxError);
    const validationError = error as EventValidationError;
    expect(validationError.message).toBe("invalid NIP-51 private tags");
    expect(validationError.cause).toBeInstanceOf(SyntaxError);
    expect(crypto.decryptInvocations).toBe(1);
  });

  test.each(["{}", "null", "1", '"x"', "[[]]", '[["p", 1]]', "[1]"])(
    "decrypted JSON %s that is not a tag array throws EventValidationError",
    async (plaintext) => {
      const crypto = trackingCrypto({
        pubkey: PK,
        decrypt: () => plaintext,
      });
      const error = await catchError(
        decryptPrivateTags(crypto, { pubkey: PK, content: "payload" }),
      );
      expect(error).toBeInstanceOf(EventValidationError);
      const validationError = error as EventValidationError;
      expect(validationError.message).toBe("invalid NIP-51 private tags");
      expect(validationError.cause).toBeUndefined();
      expect(crypto.decryptInvocations).toBe(1);
    },
  );

  test("muteListEventBuilder still emits empty content; caller sets encrypted content", async () => {
    const signer = new KeysSigner(AUTHOR_SK);
    const built = muteListEventBuilder([{ type: "pubkey", value: PK }]);
    expect(built.currentContent).toBe("");
    const cipher = await encryptPrivateTags(signer, [["word", "secret"]]);
    built.content(cipher);
    expect(built.currentContent).toBe(cipher);
    expect(built.currentContent).not.toBe("");
    expect(built.currentTags).toStrictEqual([["p", PK]]);
  });

  test("parseMuteListPrivate kind !== 10000 throws via requireKind", async () => {
    const crypto = trackingCrypto({ pubkey: PK });
    await expect(
      parseMuteListPrivate(crypto, {
        kind: Kind.TextNote,
        pubkey: PK,
        tags: [],
        content: "",
      }),
    ).rejects.toThrow(EventValidationError);
    await expect(
      parseMuteListPrivate(crypto, {
        kind: Kind.TextNote,
        pubkey: PK,
        tags: [],
        content: "ciphertext",
      }),
    ).rejects.toThrow(`expected kind ${Kind.MuteList}, got ${Kind.TextNote}`);
    expect(crypto.decryptInvocations).toBe(0);
  });
});
