import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../../src/core/event.ts";
import { Keys, signEvent } from "../../src/core/key.ts";
import type { Tag } from "../../src/core/tag.ts";
import { hexToBytes } from "../../src/core/util.ts";
import type { ChatMessageOptions, Recipient } from "../../src/nips/nip17.ts";
import {
  buildChatMessageRumor,
  dmRelayListEventBuilder,
  dmRelayListToTags,
  normalizeRecipients,
  parseDmRelayList,
  wrapDirectMessage,
} from "../../src/nips/nip17.ts";
import * as nip44 from "../../src/nips/nip44.ts";
import type { Nip59Crypto, Rumor, WrapOptions } from "../../src/nips/nip59.ts";
import { createRumor } from "../../src/nips/nip59.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type VectorRecipient = { pubkey: string; relay_hint?: string };

type VectorOptions = {
  timestamps?: { seal: number; wrap: number };
  now?: number;
  randomize?: "wrap" | "seal+wrap";
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
  rust: boolean;
  sender_secret_key: string;
  recipients: VectorRecipient[];
  rumor: RumorInput;
  options: VectorOptions;
  entropy: string;
  output: Array<{ recipient: string; wrap: Event }>;
};

type WrapErr = Omit<WrapCase, "rust" | "entropy" | "output"> & { error: string };

type ChatCase = {
  name: string;
  rust: boolean;
  sender: string;
  recipients: VectorRecipient[];
  content: string;
  created_at: number;
  options: {
    subject?: string;
    reply_to?: { id: string; relay_hint?: string };
  };
  rumor?: Rumor;
  error?: string;
};

type NormalizeCase = {
  name: string;
  input: Array<string | VectorRecipient>;
  output: VectorRecipient[];
};

type RelayBuildCase = { name: string; relays: string[]; tags?: Tag[]; error?: string };
type RelayParseCase = { name: string; event: Event; relays?: string[]; error?: string };

const vector = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip17/codec.json"), "utf8"),
) as {
  wrap: Array<WrapCase | WrapErr>;
  chat: ChatCase[];
  normalize: NormalizeCase[];
  relay_list: { build: RelayBuildCase[]; parse: RelayParseCase[] };
};

/** Sequential reads over the recorded `entropy` hex — the same bytes `nk` replays. */
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

function wrapOptionsOf(options: VectorOptions, stream: Stream): WrapOptions {
  return {
    timestamps: options.timestamps,
    now: options.now,
    randomize: options.randomize,
    expiration: options.expiration,
    ephemeral: options.ephemeral,
    randomBytes: (n) => stream.take(n),
  };
}

function recipientOf(r: VectorRecipient): Recipient {
  return { pubkey: r.pubkey, relayHint: r.relay_hint };
}

function normalizeInputOf(item: string | VectorRecipient): string | Recipient {
  return typeof item === "string" ? item : recipientOf(item);
}

function rumorOf(input: RumorInput): Rumor {
  return createRumor(input.pubkey, {
    kind: input.kind,
    content: input.content,
    tags: input.tags,
    created_at: input.created_at,
  });
}

function chatOptionsOf(options: ChatCase["options"], created_at: number): ChatMessageOptions {
  return {
    subject: options.subject,
    replyTo: options.reply_to
      ? { id: options.reply_to.id, relayHint: options.reply_to.relay_hint }
      : undefined,
    created_at,
  };
}

const wrapOk = vector.wrap.filter((c): c is WrapCase => "entropy" in c);
const wrapErr = vector.wrap.filter((c): c is WrapErr => "error" in c);
const chatOk = vector.chat.filter((c): c is ChatCase & { rumor: Rumor } => c.rumor !== undefined);
const chatErr = vector.chat.filter((c): c is ChatCase & { error: string } => c.error !== undefined);

describe("nip17 codec vectors", () => {
  test.each(wrapOk)("wrap %s", async (c) => {
    const stream = new Stream(c.entropy);
    const output = await wrapDirectMessage(
      cryptoOf(c.sender_secret_key, stream),
      c.recipients.map(recipientOf),
      rumorOf(c.rumor),
      wrapOptionsOf(c.options, stream),
    );
    expect(output).toStrictEqual(c.output);
  });

  test.each(wrapErr)("wrap err %s", async (c) => {
    const stream = new Stream("");
    await expect(
      wrapDirectMessage(
        cryptoOf(c.sender_secret_key, stream),
        c.recipients.map(recipientOf),
        rumorOf(c.rumor),
        wrapOptionsOf(c.options, stream),
      ),
    ).rejects.toThrow(c.error);
  });

  test.each(chatOk)("chat %s", (c) => {
    const rumor = buildChatMessageRumor(
      c.sender,
      c.recipients.map(recipientOf),
      c.content,
      chatOptionsOf(c.options, c.created_at),
    );
    expect(rumor).toStrictEqual(c.rumor);
  });

  test.each(chatErr)("chat err %s", (c) => {
    expect(() =>
      buildChatMessageRumor(
        c.sender,
        c.recipients.map(recipientOf),
        c.content,
        chatOptionsOf(c.options, c.created_at),
      ),
    ).toThrow(c.error);
  });

  test.each(vector.normalize)("normalize %s", (c) => {
    const out = normalizeRecipients(c.input.map(normalizeInputOf));
    expect(out).toStrictEqual(c.output.map((r) => ({ pubkey: r.pubkey, relayHint: r.relay_hint })));
  });

  const buildOk = vector.relay_list.build.filter(
    (c): c is RelayBuildCase & { tags: Tag[] } => c.tags !== undefined,
  );
  const buildErr = vector.relay_list.build.filter(
    (c): c is RelayBuildCase & { error: string } => c.error !== undefined,
  );

  test.each(buildOk)("relay build %s", (c) => {
    expect(dmRelayListToTags(c.relays)).toStrictEqual(c.tags);
    expect(() => dmRelayListEventBuilder(c.relays)).not.toThrow();
  });

  test.each(buildErr)("relay build err %s", (c) => {
    expect(() => dmRelayListEventBuilder(c.relays)).toThrow(c.error);
  });

  const parseOk = vector.relay_list.parse.filter(
    (c): c is RelayParseCase & { relays: string[] } => c.relays !== undefined,
  );
  const parseErr = vector.relay_list.parse.filter(
    (c): c is RelayParseCase & { error: string } => c.error !== undefined,
  );

  test.each(parseOk)("relay parse %s", (c) => {
    expect(parseDmRelayList(c.event)).toStrictEqual(c.relays);
  });

  test.each(parseErr)("relay parse err %s", (c) => {
    expect(() => parseDmRelayList(c.event)).toThrow(c.error);
  });
});
