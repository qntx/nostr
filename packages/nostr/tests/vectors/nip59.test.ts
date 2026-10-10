import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../../src/core/event.ts";
import { Keys, signEvent } from "../../src/core/key.ts";
import type { Tag } from "../../src/core/tag.ts";
import { hexToBytes } from "../../src/core/util.ts";
import * as nip44 from "../../src/nips/nip44.ts";
import type { Nip59Crypto, Rumor, WrapOptions } from "../../src/nips/nip59.ts";
import { createGiftWrap, createRumor, createSeal, unwrap, wrap } from "../../src/nips/nip59.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type VectorOptions = {
  timestamps?: { seal: number; wrap: number };
  now?: number;
  randomize?: "wrap" | "seal+wrap";
  relay_hint?: string;
  extra_tags?: Tag[];
  expiration?: number;
  ephemeral?: boolean;
};

type RumorInput = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: Tag[];
  content: string;
};

type WrapCase = {
  name: string;
  secret_key: string;
  recipient_secret_key: string;
  rumor: RumorInput;
  options: VectorOptions;
  entropy: string;
  wrap: Event;
};

type SealCase = Omit<WrapCase, "wrap"> & { seal: Event };

type GiftCase = {
  name: string;
  recipient_secret_key: string;
  seal: Event;
  options: VectorOptions;
  entropy: string;
  wrap: Event;
};

type UnwrapOk = {
  name: string;
  gift_wrap: Event;
  recipient_secret_key: string;
  rumor: RumorInput & { id: string };
};

type UnwrapErr = {
  name: string;
  gift_wrap: Event;
  recipient_secret_key: string;
  error: string;
};

const vector = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip59/codec.json"), "utf8"),
) as {
  wrap: WrapCase[];
  seal: SealCase[];
  gift: GiftCase[];
  unwrap: Array<UnwrapOk | UnwrapErr>;
};

/** Sequential reads over the recorded `entropy` hex — the same bytes nk-nips replays. */
class Stream {
  private readonly bytes: Uint8Array;
  private pos = 0;

  constructor(hex: string) {
    this.bytes = hexToBytes(hex);
  }

  take(n: number): Uint8Array {
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

function cryptoOf(secretKey: string, stream: Stream): Nip59Crypto {
  const secretBytes = hexToBytes(secretKey);
  const keys = Keys.fromSecretKey(secretKey);
  return {
    getPublicKey: async () => Promise.resolve(keys.publicKey),
    signEvent: async (unsigned) => Promise.resolve(signEvent(unsigned, keys, stream.take(32))),
    nip44Encrypt: async (peer, plaintext) =>
      Promise.resolve(
        nip44.encrypt(plaintext, nip44.getConversationKey(secretBytes, peer), stream.take(32)),
      ),
    nip44Decrypt: async (peer, payload) =>
      Promise.resolve(nip44.decrypt(payload, nip44.getConversationKey(secretBytes, peer))),
  };
}

function optionsOf(options: VectorOptions, stream: Stream): WrapOptions {
  return {
    timestamps: options.timestamps,
    now: options.now,
    randomize: options.randomize,
    relayHint: options.relay_hint,
    extraTags: options.extra_tags,
    expiration: options.expiration,
    ephemeral: options.ephemeral,
    randomBytes: (n) => stream.take(n),
  };
}

function rumorOf(input: RumorInput): Rumor {
  return createRumor(input.pubkey, {
    kind: input.kind,
    content: input.content,
    tags: input.tags,
    created_at: input.created_at,
  });
}

describe("nip59 codec vectors", () => {
  test.each(vector.wrap)("wrap %s", async (c) => {
    const stream = new Stream(c.entropy);
    const recipient = Keys.fromSecretKey(c.recipient_secret_key).publicKey;
    const gift = await wrap(
      cryptoOf(c.secret_key, stream),
      recipient,
      rumorOf(c.rumor),
      optionsOf(c.options, stream),
    );
    expect(gift).toStrictEqual(c.wrap);
  });

  test.each(vector.seal)("seal %s", async (c) => {
    const stream = new Stream(c.entropy);
    const recipient = Keys.fromSecretKey(c.recipient_secret_key).publicKey;
    const seal = await createSeal(
      cryptoOf(c.secret_key, stream),
      recipient,
      rumorOf(c.rumor),
      optionsOf(c.options, stream),
    );
    expect(seal).toStrictEqual(c.seal);
  });

  test.each(vector.gift)("gift_wrap %s", (c) => {
    const stream = new Stream(c.entropy);
    const recipient = Keys.fromSecretKey(c.recipient_secret_key).publicKey;
    const gift = createGiftWrap(c.seal, recipient, optionsOf(c.options, stream));
    expect(gift).toStrictEqual(c.wrap);
  });
});

const unwrapOk = vector.unwrap.filter((c): c is UnwrapOk => "rumor" in c);
const unwrapErr = vector.unwrap.filter((c): c is UnwrapErr => "error" in c);

function decryptorOf(secretKey: string): Nip59Crypto {
  const recipient = Keys.fromSecretKey(secretKey);
  return {
    getPublicKey: async () => Promise.resolve(recipient.publicKey),
    signEvent: async () => Promise.reject(new Error("unused")),
    nip44Encrypt: async () => Promise.reject(new Error("unused")),
    nip44Decrypt: async (peer, payload) =>
      Promise.resolve(
        nip44.decrypt(payload, nip44.getConversationKey(recipient.secretKey.bytes, peer)),
      ),
  };
}

describe("nip59 unwrap vectors", () => {
  test.each(unwrapOk)("ok %s", async (c) => {
    const rumor = await unwrap(decryptorOf(c.recipient_secret_key), c.gift_wrap);
    expect(rumor).toStrictEqual(c.rumor);
  });

  test.each(unwrapErr)("err %s", async (c) => {
    await expect(unwrap(decryptorOf(c.recipient_secret_key), c.gift_wrap)).rejects.toThrow(c.error);
  });
});
