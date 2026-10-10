/// <reference types="node" />
// Generates vectors/nip17/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-17 `wrapDirectMessage`/`buildChatMessageRumor`/
// `normalizeRecipients`/relay-list semantics as frozen vectors shared by the
// TS test suite (tests/vectors/nip17.test.ts) and the nk-* Rust crates.
//
// Every wrap is produced by the real TS API under a deterministic entropy
// stream, exactly like gen/nip59.ts: `WrapOptions.randomBytes` feeds each
// gift wrap's ephemeral key, timestamp offset, NIP-44 nonce and BIP-340 aux,
// and the injected `Nip59Crypto` wrapper draws each seal's nonce/aux from the
// same stream — matching `nk`'s draw order per copy (seal: [offset] → nonce
// → aux; gift wrap: key → [offset] → nonce → aux), self copy first. The
// consumed prefix is recorded per case as `entropy`, which the Rust runner
// replays through a scripted `CryptoRng`.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { bytesToHex, hexToBytes } from "../../../src/core/util.ts";
import type { ChatMessageOptions, Recipient } from "../../../src/nips/nip17.ts";
import {
  buildChatMessageRumor,
  dmRelayListEventBuilder,
  dmRelayListToTags,
  normalizeRecipients,
  parseDmRelayList,
  wrapDirectMessage,
} from "../../../src/nips/nip17.ts";
import * as nip44 from "../../../src/nips/nip44.ts";
import type { Nip59Crypto, Rumor, WrapOptions } from "../../../src/nips/nip59.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip17");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const SENDER = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const ALICE = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const BOB = "97a988d6151d344dd477a8953a71a47266a800a840acdf8d0e0f1e4df0ff14ab";
const CAROL = "5e4f2c2eac02f0c28d0a3a6f6ed1a3c5c1a2b3d4e5f60718293a4b5c6d7e8f90";
const senderPk = Keys.fromSecretKey(SENDER).publicKey;
const alicePk = Keys.fromSecretKey(ALICE).publicKey;
const bobPk = Keys.fromSecretKey(BOB).publicKey;
const carolPk = Keys.fromSecretKey(CAROL).publicKey;

/** Deterministic entropy: `seed + i` bytes — distinct, nonzero, valid scalars. */
function entropy(seed: number): Uint8Array {
  const bytes = new Uint8Array(2048);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = (seed + i) % 256;
  }
  return bytes;
}

/** Sequential reads over a fixed byte string, recording consumption. */
class Stream {
  private readonly bytes: Uint8Array;
  private pos = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  take(n: number): Uint8Array {
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  get consumedHex(): string {
    return bytesToHex(this.bytes.slice(0, this.pos));
  }
}

/** `Nip59Crypto` backed by `secretKey` whose nonce/aux draws come from `stream`. */
function cryptoOf(secretKey: string, stream: Stream): Nip59Crypto {
  const secretBytes = hexToBytes(secretKey);
  const keys = Keys.fromSecretKey(secretKey);
  return {
    getPublicKey: async () => {
      await Promise.resolve();
      return keys.publicKey;
    },
    signEvent: async (unsigned) => {
      await Promise.resolve();
      return signEvent(unsigned, keys, stream.take(32));
    },
    nip44Encrypt: async (peer, plaintext) => {
      await Promise.resolve();
      return nip44.encrypt(plaintext, nip44.getConversationKey(secretBytes, peer), stream.take(32));
    },
    nip44Decrypt: async (peer, payload) => {
      await Promise.resolve();
      return nip44.decrypt(payload, nip44.getConversationKey(secretBytes, peer));
    },
  };
}

type VectorRecipient = { pubkey: string; relay_hint?: string | undefined };

function toRecipient(r: VectorRecipient): Recipient {
  return { pubkey: r.pubkey, relayHint: r.relay_hint };
}

type VectorOptions = {
  timestamps?: { seal: number; wrap: number } | undefined;
  now?: number | undefined;
  randomize?: "wrap" | "seal+wrap" | undefined;
  expiration?: number | undefined;
  ephemeral?: boolean | undefined;
};

function wrapOptions(options: VectorOptions, stream: Stream): WrapOptions {
  return {
    timestamps: options.timestamps,
    now: options.now,
    randomize: options.randomize,
    expiration: options.expiration,
    ephemeral: options.ephemeral,
    randomBytes: (n) => stream.take(n),
  };
}

type ChatOptionsVector = {
  subject?: string | undefined;
  reply_to?: { id: string; relay_hint?: string | undefined } | undefined;
};

function toChatOptions(options: ChatOptionsVector): ChatMessageOptions {
  return {
    subject: options.subject,
    replyTo: options.reply_to
      ? { id: options.reply_to.id, relayHint: options.reply_to.relay_hint }
      : undefined,
  };
}

type WrapCase = {
  name: string;
  rust: boolean;
  sender_secret_key: string;
  recipients: VectorRecipient[];
  rumor: { pubkey: string; created_at: number; kind: number; tags: Tag[]; content: string };
  options: VectorOptions;
  entropy: string;
  output: Array<{ recipient: string; wrap: Event }>;
};

type WrapErr = {
  name: string;
  sender_secret_key: string;
  recipients: VectorRecipient[];
  rumor: { pubkey: string; created_at: number; kind: number; tags: Tag[]; content: string };
  options: VectorOptions;
  error: string;
};

async function wrapCase(
  name: string,
  seed: number,
  sender: string,
  recipients: VectorRecipient[],
  rumor: Rumor,
  options: VectorOptions,
): Promise<WrapCase> {
  const stream = new Stream(entropy(seed));
  const output = await wrapDirectMessage(
    cryptoOf(sender, stream),
    recipients.map(toRecipient),
    rumor,
    wrapOptions(options, stream),
  );
  return {
    name,
    rust: recipients.every((r) => r.relay_hint === undefined || isNormalized(r.relay_hint)),
    sender_secret_key: sender,
    recipients,
    rumor: rumorInput(rumor),
    options,
    entropy: stream.consumedHex,
    output: output.map(({ recipient, wrap }) => ({ recipient, wrap })),
  };
}

/** TS writes relay hints verbatim; Rust stores a normalized `RelayUrl`. */
function isNormalized(hint: string): boolean {
  try {
    // A hint equal to its own normalization survives the Rust type unchanged.
    return hint === normalizeRelay(hint);
  } catch {
    return false;
  }
}

function normalizeRelay(url: string): string {
  const [r] = dmRelayListToTags([url]);
  const value = r?.at(1);
  if (value === undefined) {
    throw new Error(`unreachable: ${url} normalizes to nothing`);
  }
  return value;
}

function rumorInput(rumor: Rumor): WrapCase["rumor"] {
  return {
    pubkey: rumor.pubkey,
    created_at: rumor.created_at,
    kind: rumor.kind,
    tags: [...rumor.tags],
    content: rumor.content,
  };
}

type ChatCase = {
  name: string;
  rust: boolean;
  sender: string;
  recipients: VectorRecipient[];
  content: string;
  created_at: number;
  options: ChatOptionsVector;
  rumor?: Rumor;
  error?: string;
};

function chatCase(
  name: string,
  sender: string,
  recipients: VectorRecipient[],
  content: string,
  created_at: number,
  options: ChatOptionsVector,
): ChatCase {
  const hints = [...recipients.map((r) => r.relay_hint), options.reply_to?.relay_hint];
  const rust = hints.every((h) => h === undefined || isNormalized(h));
  try {
    const rumor = buildChatMessageRumor(sender, recipients.map(toRecipient), content, {
      ...toChatOptions(options),
      created_at,
    });
    return { name, rust, sender, recipients, content, created_at, options, rumor };
  } catch (error) {
    return {
      name,
      rust,
      sender,
      recipients,
      content,
      created_at,
      options,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

type RelayBuildCase = {
  name: string;
  relays: string[];
  tags?: ReadonlyArray<Tag>;
  error?: string;
};

type NormalizeCase = {
  name: string;
  input: Array<string | VectorRecipient>;
  output: VectorRecipient[];
};

function normalizeCase(name: string, input: Array<string | VectorRecipient>): NormalizeCase {
  return {
    name,
    input,
    output: normalizeRecipients(
      input.map((item) => (typeof item === "string" ? item : toRecipient(item))),
    ).map((r) => ({ pubkey: r.pubkey, relay_hint: r.relayHint })),
  };
}

type RelayParseCase = {
  name: string;
  event: Event;
  relays?: string[];
  error?: string;
};

function buildCase(name: string, relays: string[]): RelayBuildCase {
  try {
    dmRelayListEventBuilder(relays);
    return { name, relays, tags: dmRelayListToTags(relays) };
  } catch (error) {
    return { name, relays, error: error instanceof Error ? error.message : String(error) };
  }
}

async function parseCase(name: string, event: Event): Promise<RelayParseCase> {
  try {
    return { name, event, relays: await Promise.resolve(parseDmRelayList(event)) };
  } catch (error) {
    return { name, event, error: error instanceof Error ? error.message : String(error) };
  }
}

function signNow(template: { kind: number; content: string; tags: Tag[] }, key: string): Event {
  const keys = Keys.fromSecretKey(key);
  return signEvent(
    { ...template, created_at: 1_700_000_000, pubkey: keys.publicKey },
    keys,
    hexToBytes("42".repeat(32)),
  );
}

async function main(): Promise<void> {
  const chatRumor = (recipients: VectorRecipient[], options: ChatOptionsVector = {}): Rumor =>
    buildChatMessageRumor(senderPk, recipients.map(toRecipient), "hello there", {
      ...toChatOptions(options),
      created_at: 1_700_000_000,
    });

  const wrapCases: Array<WrapCase | WrapErr> = [
    await wrapCase(
      "two-recipients-fixed",
      0x07,
      SENDER,
      [{ pubkey: alicePk, relay_hint: "wss://alice.example.com/" }, { pubkey: bobPk }],
      chatRumor([{ pubkey: alicePk }, { pubkey: bobPk }]),
      { timestamps: { seal: 1_700_000_100, wrap: 1_700_000_200 } },
    ),
    await wrapCase(
      "duplicate-and-sender-in-list",
      0x11,
      SENDER,
      [
        { pubkey: alicePk },
        { pubkey: senderPk, relay_hint: "wss://self.example.com/" },
        { pubkey: alicePk, relay_hint: "wss://dup.example.com/" },
        { pubkey: bobPk },
      ],
      chatRumor([{ pubkey: alicePk }, { pubkey: bobPk }]),
      { timestamps: { seal: 1_700_000_101, wrap: 1_700_000_201 } },
    ),
    await wrapCase(
      "random-timestamps-ephemeral",
      0x23,
      SENDER,
      [{ pubkey: alicePk }, { pubkey: bobPk }, { pubkey: carolPk }],
      chatRumor([{ pubkey: alicePk }, { pubkey: bobPk }, { pubkey: carolPk }], {
        subject: "group",
      }),
      { now: 1_710_000_000, ephemeral: true },
    ),
    await wrapCase(
      "wrap-only-expiration",
      0x35,
      SENDER,
      [{ pubkey: bobPk, relay_hint: "wss://bob.example.com/" }],
      chatRumor([{ pubkey: bobPk }]),
      { now: 1_710_000_000, randomize: "wrap", expiration: 1_800_000_000 },
    ),
    await wrapCase(
      "unnormalized-relay-hint",
      0x47,
      SENDER,
      [{ pubkey: alicePk, relay_hint: "alice.example.com" }],
      chatRumor([{ pubkey: alicePk }]),
      { timestamps: { seal: 1_700_000_102, wrap: 1_700_000_202 } },
    ),
  ];
  {
    const stream = new Stream(entropy(0x59));
    try {
      await wrapDirectMessage(
        cryptoOf(SENDER, stream),
        [],
        chatRumor([{ pubkey: alicePk }]),
        wrapOptions({ timestamps: { seal: 1_700_000_103, wrap: 1_700_000_203 } }, stream),
      );
      throw new Error("unreachable: empty recipients accepted");
    } catch (error) {
      wrapCases.push({
        name: "empty-recipients",
        sender_secret_key: SENDER,
        recipients: [],
        rumor: rumorInput(chatRumor([{ pubkey: alicePk }])),
        options: { timestamps: { seal: 1_700_000_103, wrap: 1_700_000_203 } },
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const chatCases: ChatCase[] = [
    chatCase(
      "basic",
      senderPk,
      [{ pubkey: alicePk }, { pubkey: bobPk, relay_hint: "wss://bob.example.com/" }],
      "hi",
      1_700_000_000,
      {},
    ),
    chatCase("reply-and-subject", senderPk, [{ pubkey: alicePk }], "re: earlier", 1_700_000_005, {
      subject: "catch up",
      reply_to: {
        id: "11".repeat(32),
        relay_hint: "wss://relay.example.com/",
      },
    }),
    chatCase(
      "reply-no-relay",
      senderPk,
      [{ pubkey: alicePk, relay_hint: "wss://alice.example.com/" }],
      "ack",
      1_700_000_006,
      { reply_to: { id: "22".repeat(32) } },
    ),
    chatCase("empty-recipients", senderPk, [], "hi", 1_700_000_007, {}),
    chatCase(
      "unnormalized-hint",
      senderPk,
      [{ pubkey: alicePk, relay_hint: "alice.example.com" }],
      "hi",
      1_700_000_008,
      {},
    ),
  ];

  const relayBuild: RelayBuildCase[] = [
    buildCase("two-relays", ["wss://a.example.com/", "wss://b.example.com/path"]),
    buildCase("dedup-and-skip-invalid", [
      "wss://a.example.com/",
      "wss://a.example.com",
      "not a url",
      "",
      "wss://b.example.com/",
    ]),
    buildCase("unnormalized-inputs", ["alice.example.com", "https://b.example.com"]),
    buildCase("empty-after-normalize", ["not a url", ""]),
  ];

  const relayParse: RelayParseCase[] = [
    await parseCase(
      "parse-basic",
      signNow(
        {
          kind: 10050,
          content: "",
          tags: [
            ["relay", "wss://a.example.com"],
            ["relay", "not a url"],
            ["relay", "wss://a.example.com/"],
            ["x", "ignored"],
            ["relay"],
          ],
        },
        SENDER,
      ),
    ),
    await parseCase("parse-empty-list", signNow({ kind: 10050, content: "", tags: [] }, SENDER)),
    await parseCase(
      "parse-wrong-kind",
      signNow({ kind: 1, content: "", tags: [["relay", "wss://a.example.com/"]] }, SENDER),
    ),
  ];

  mkdirSync(vectors, { recursive: true });
  writeFileSync(
    join(vectors, "codec.json"),
    `${JSON.stringify(
      {
        schema: 1,
        capability: "nip17.dm",
        source: {
          kind: "generated",
          generator: "@qntx/nostr",
          version,
          note: "real `wrapDirectMessage` under an injected `randomBytes` entropy stream (same draw order as nip59 vectors: per copy seal [offset u32] → nonce → aux, then wrap key → [offset u32] → nonce → aux, self copy first); `entropy` records the consumed bytes; `rust: false` marks inputs TS accepts that Rust's typed API cannot express (unnormalized relay hints)",
        },
        wrap: wrapCases,
        chat: chatCases,
        normalize: [
          normalizeCase("strings-and-objects-dedup", [
            alicePk,
            { pubkey: bobPk, relay_hint: "wss://bob.example.com/" },
            { pubkey: alicePk, relay_hint: "wss://first-wins.example.com/" },
            alicePk.toUpperCase(),
            bobPk,
          ]),
          normalizeCase("single-string", [alicePk]),
        ],
        relay_list: { build: relayBuild, parse: relayParse },
      },
      null,
      2,
    )}\n`,
  );
}

await main();
