/// <reference types="node" />
// Generates vectors/nip59/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-59 `createSeal`/`createGiftWrap`/`wrap`/`unwrap`
// semantics as frozen vectors shared by the TS test suite
// (tests/vectors/nip59.test.ts) and the nk-* Rust crates.
//
// Every event is produced by the real TS API under a deterministic entropy
// stream: `WrapOptions.randomBytes` feeds the gift wrap's ephemeral key,
// timestamp offset, NIP-44 nonce and BIP-340 aux, and the injected
// `Nip59Crypto` wrapper draws its seal nonce/aux from the same stream — the
// byte order matches nk-nips `*_with_rng` (seal: [offset] → nonce → aux;
// gift wrap: key → [offset] → nonce → aux). The consumed prefix is recorded
// per case as `entropy`, which the Rust runner replays through a scripted
// `CryptoRng`.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";

import type { Event } from "../../../src/core/event.ts";
import type { Keys as KeysType, SigningBackend } from "../../../src/core/key.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import { Kind } from "../../../src/core/kind.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { bytesToHex, hexToBytes } from "../../../src/core/util.ts";
import * as nip44 from "../../../src/nips/nip44.ts";
import type { Nip59Crypto, Rumor, WrapOptions } from "../../../src/nips/nip59.ts";
import { createGiftWrap, createRumor, createSeal, wrap } from "../../../src/nips/nip59.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip59");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const AUTHOR = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const RECIPIENT = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const OTHER = "97a988d6151d344dd477a8953a71a47266a800a840acdf8d0e0f1e4df0ff14ab";
const recipientPk = Keys.fromSecretKey(RECIPIENT).publicKey;
const otherPk = Keys.fromSecretKey(OTHER).publicKey;

/** Deterministic entropy: `seed + i` bytes — distinct, nonzero, valid scalars. */
function entropy(seed: number): Uint8Array {
  const bytes = new Uint8Array(256);
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
  const keys = Keys.fromSecretKey(secretKey, {
    publicKey: (sk) => schnorr.getPublicKey(sk),
    sign: (id, sk) => schnorr.sign(id, sk, stream.take(32)),
  });
  return {
    getPublicKey: async () => {
      await Promise.resolve();
      return keys.publicKey;
    },
    signEvent: async (unsigned) => {
      await Promise.resolve();
      return signEvent(unsigned, keys);
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

/** Signing `Keys` whose aux draws come from `stream`. */
function keysOf(secretKey: string, stream: Stream): KeysType {
  return Keys.fromSecretKey(secretKey, {
    publicKey: (sk) => schnorr.getPublicKey(sk),
    sign: (id, sk) => schnorr.sign(id, sk, stream.take(32)),
  });
}

type VectorOptions = {
  timestamps?: { seal: number; wrap: number } | undefined;
  now?: number | undefined;
  randomize?: "wrap" | "seal+wrap" | undefined;
  relay_hint?: string | undefined;
  extra_tags?: ReadonlyArray<Tag> | undefined;
  expiration?: number | undefined;
  ephemeral?: boolean | undefined;
};

function wrapOptions(options: VectorOptions, stream: Stream): WrapOptions {
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

type RumorInput = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: ReadonlyArray<Tag>;
  content: string;
};

function rumorOf(input: RumorInput): Rumor {
  return createRumor(input.pubkey, {
    kind: input.kind,
    content: input.content,
    tags: input.tags,
    created_at: input.created_at,
  });
}

const rumorBase: RumorInput = {
  pubkey: Keys.fromSecretKey(AUTHOR).publicKey,
  created_at: 1_700_000_000,
  kind: 1,
  tags: [["t", "nostr"]],
  content: "hello nostr",
};

const rumorUnicode: RumorInput = {
  pubkey: Keys.fromSecretKey(AUTHOR).publicKey,
  created_at: 1_700_000_123,
  kind: 14,
  tags: [["p", recipientPk]],
  content: "hello 🌍 café — 你好",
};

const rumorEmpty: RumorInput = {
  pubkey: Keys.fromSecretKey(AUTHOR).publicKey,
  created_at: 1_699_999_999,
  kind: 14,
  tags: [],
  content: "",
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

async function wrapCase(
  name: string,
  seed: number,
  rumor: RumorInput,
  options: VectorOptions,
): Promise<WrapCase> {
  const stream = new Stream(entropy(seed));
  const gift = await wrap(
    cryptoOf(AUTHOR, stream),
    recipientPk,
    rumorOf(rumor),
    wrapOptions(options, stream),
  );
  return {
    name,
    secret_key: AUTHOR,
    recipient_secret_key: RECIPIENT,
    rumor,
    options,
    entropy: stream.consumedHex,
    wrap: gift,
  };
}

type SealCase = {
  name: string;
  secret_key: string;
  recipient_secret_key: string;
  rumor: RumorInput;
  options: VectorOptions;
  entropy: string;
  seal: Event;
};

async function sealCase(
  name: string,
  seed: number,
  rumor: RumorInput,
  options: VectorOptions,
): Promise<SealCase> {
  const stream = new Stream(entropy(seed));
  const seal = await createSeal(
    cryptoOf(AUTHOR, stream),
    recipientPk,
    rumorOf(rumor),
    wrapOptions(options, stream),
  );
  return {
    name,
    secret_key: AUTHOR,
    recipient_secret_key: RECIPIENT,
    rumor,
    options,
    entropy: stream.consumedHex,
    seal,
  };
}

type GiftCase = {
  name: string;
  recipient_secret_key: string;
  seal: Event;
  options: VectorOptions;
  entropy: string;
  wrap: Event;
};

function giftCase(name: string, seed: number, seal: Event, options: VectorOptions): GiftCase {
  const stream = new Stream(entropy(seed));
  const gift = createGiftWrap(seal, recipientPk, wrapOptions(options, stream));
  return {
    name,
    recipient_secret_key: RECIPIENT,
    seal,
    options,
    entropy: stream.consumedHex,
    wrap: gift,
  };
}

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

/**
 * A seal carrying arbitrary `content` to `recipientPk`, signed by `author` via the real
 * `nip44.encrypt` + `signEvent` primitives — needed for inner-layer fixtures the API cannot produce
 * (non-rumor plaintext, foreign-key ciphertext).
 */
function manualSeal(
  author: string,
  recipientPk2: string,
  contentPlaintext: string,
  createdAt: number,
  tags: Tag[],
  stream: Stream,
  encryptToPk = recipientPk2,
): Event {
  const content = nip44.encrypt(
    contentPlaintext,
    nip44.getConversationKey(hexToBytes(author), encryptToPk),
    stream.take(32),
  );
  return signEvent(
    {
      kind: Kind.Seal,
      content,
      created_at: createdAt,
      tags,
      pubkey: Keys.fromSecretKey(author).publicKey,
    },
    keysOf(author, stream),
  );
}

const rumorJson = (rumor: Record<string, unknown>): string => JSON.stringify(rumor);

const err = (name: string, gift: Event, error: string, recipient = RECIPIENT): UnwrapErr => ({
  name,
  gift_wrap: gift,
  recipient_secret_key: recipient,
  error,
});

async function main(): Promise<void> {
  const authorPk = Keys.fromSecretKey(AUTHOR).publicKey;

  const wrapFixedBasic = await wrapCase("fixed-basic", 0x07, rumorBase, {
    timestamps: { seal: 1_700_000_100, wrap: 1_700_000_200 },
  });
  const wrapFixedFull = await wrapCase("fixed-full", 0x11, rumorUnicode, {
    timestamps: { seal: 1_700_000_101, wrap: 1_700_000_201 },
    relay_hint: "wss://relay.example.com/",
    extra_tags: [
      ["t", "dm"],
      ["subject", "hi"],
    ],
    expiration: 1_800_000_000,
  });
  const wrapFixedEphemeral = await wrapCase("fixed-ephemeral", 0x23, rumorBase, {
    timestamps: { seal: 1_700_000_102, wrap: 1_700_000_202 },
    ephemeral: true,
  });
  const wrapRandomBoth = await wrapCase("random-seal-and-wrap", 0x35, rumorEmpty, {
    now: 1_710_000_000,
    randomize: "seal+wrap",
  });
  const wrapRandomWrapOnly = await wrapCase("random-wrap-only", 0x47, rumorBase, {
    now: 1_710_000_000,
    randomize: "wrap",
    expiration: 1_800_000_000,
  });
  const wrapCases: WrapCase[] = [
    wrapFixedBasic,
    wrapFixedFull,
    wrapFixedEphemeral,
    wrapRandomBoth,
    wrapRandomWrapOnly,
  ];

  const sealFixed = await sealCase("seal-fixed", 0x59, rumorBase, {
    timestamps: { seal: 1_700_000_103, wrap: 1_700_000_203 },
  });
  const sealRandom = await sealCase("seal-random", 0x6b, rumorUnicode, {
    now: 1_710_000_000,
    expiration: 1_800_000_000,
  });
  const sealWrapOnly = await sealCase("seal-wrap-only", 0x7d, rumorBase, {
    now: 1_710_000_000,
    randomize: "wrap",
  });
  const sealCases: SealCase[] = [sealFixed, sealRandom, sealWrapOnly];

  const giftCases: GiftCase[] = [
    giftCase("wrap-fixed", 0x89, sealFixed.seal, {
      timestamps: { seal: 0, wrap: 1_700_000_204 },
    }),
    giftCase("wrap-random-ephemeral", 0x9b, sealRandom.seal, {
      now: 1_710_000_000,
      ephemeral: true,
      relay_hint: "wss://relay.example.com/",
    }),
  ];

  // Unwrap fixtures. Successful cases reuse the wrap outputs above; failures
  // are mutations of real outputs or carriers built from the public
  // `nip44.encrypt`/`signEvent` primitives where the API cannot be driven to
  // produce them.
  const unwrap: Array<UnwrapOk | UnwrapErr> = [];

  const ok = (name: string, gift: Event, rumor: RumorInput): UnwrapOk => ({
    name,
    gift_wrap: gift,
    recipient_secret_key: RECIPIENT,
    rumor: { ...rumor, id: rumorOf(rumor).id },
  });

  unwrap.push(
    ok("wrap-fixed-basic", wrapFixedBasic.wrap, rumorBase),
    ok("wrap-fixed-full", wrapFixedFull.wrap, rumorUnicode),
    ok("wrap-fixed-ephemeral", wrapFixedEphemeral.wrap, rumorBase),
    ok("wrap-random-seal-and-wrap", wrapRandomBoth.wrap, rumorEmpty),
    ok("wrap-random-wrap-only", wrapRandomWrapOnly.wrap, rumorBase),
  );

  // A fixture stream for seal carriers and their wraps.
  const carrierStream = new Stream(entropy(0xad));

  const wrapSeal = (seal: Event, seed: number): Event =>
    createGiftWrap(
      seal,
      recipientPk,
      wrapOptions({ timestamps: { seal: 0, wrap: 1_700_000_300 } }, new Stream(entropy(seed))),
    );

  /**
   * Gift wrap whose content is an arbitrary NIP-44 payload to `recipientPk` — built from the public
   * `encrypt` + `signEvent` primitives, since `createGiftWrap` only serializes seals.
   */
  const manualWrap = (plaintext: string, seed: number): Event => {
    const s = new Stream(entropy(seed));
    const backend: SigningBackend = {
      publicKey: (sk) => schnorr.getPublicKey(sk),
      sign: (id, sk) => schnorr.sign(id, sk, s.take(32)),
    };
    const ephemeral = Keys.fromSecretKey(s.take(32), backend);
    return signEvent(
      {
        kind: Kind.GiftWrap,
        tags: [["p", recipientPk]],
        content: nip44.encrypt(
          plaintext,
          nip44.getConversationKey(ephemeral.secretKey.bytes, recipientPk),
          s.take(32),
        ),
        created_at: 1_700_000_300,
        pubkey: ephemeral.publicKey,
      },
      ephemeral,
    );
  };

  const signedNote = signEvent(
    {
      kind: 1,
      tags: [],
      content: "not a gift wrap",
      created_at: 1_700_000_000,
      pubkey: authorPk,
    },
    keysOf(AUTHOR, carrierStream),
  );
  unwrap.push(err("wrong-kind", signedNote, "expected gift wrap"));

  const badWrapSig: Event = {
    ...wrapFixedBasic.wrap,
    sig: wrapFixedBasic.wrap.sig.replace(/.$/, wrapFixedBasic.wrap.sig.endsWith("0") ? "1" : "0"),
  };
  unwrap.push(err("bad-wrap-signature", badWrapSig, "gift wrap signature"));

  // Gift wrap addressed to a different recipient — outer NIP-44 MAC fails.
  {
    const seal = manualSeal(
      AUTHOR,
      otherPk,
      rumorJson({ ...rumorBase, pubkey: authorPk }),
      1_700_000_100,
      [],
      carrierStream,
      otherPk,
    );
    const s = new Stream(entropy(0xbf));
    const gift = createGiftWrap(
      seal,
      otherPk,
      wrapOptions({ timestamps: { seal: 0, wrap: 1_700_000_300 } }, s),
    );
    unwrap.push(err("outer-decrypt-fails", gift, "failed to decrypt"));
  }

  // Outer ciphertext decrypts to non-JSON — the API only wraps serialized
  // seals, so the carrier is built from `encrypt` + `signEvent` directly.
  // Then the seal layer.
  unwrap.push(
    err("outer-invalid-json", manualWrap("not json", 0xc1), "invalid JSON"),
    err("seal-not-object", manualWrap("5", 0xd3), "expected seal"),
    err(
      "seal-not-object-inner",
      wrapSeal(
        manualSeal(AUTHOR, recipientPk, "5", 1_700_000_100, [], new Stream(entropy(0xd5))),
        0xd5,
      ),
      "invalid rumor",
    ),
    err("seal-wrong-kind", wrapSeal(signedNote, 0xd7), "expected seal"),
    err(
      "seal-bad-tag",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          JSON.stringify({}),
          1_700_000_100,
          [["x", "y"]],
          new Stream(entropy(0xd9)),
        ),
        0xdb,
      ),
      "seal tags must be empty",
    ),
    err(
      "seal-bad-expiration",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          JSON.stringify({}),
          1_700_000_100,
          [["expiration", "abc"]],
          new Stream(entropy(0xdd)),
        ),
        0xdf,
      ),
      "seal tags must be empty",
    ),
  );
  {
    const seal = manualSeal(
      AUTHOR,
      recipientPk,
      rumorJson({ ...rumorBase }),
      1_700_000_100,
      [],
      new Stream(entropy(0xe1)),
    );
    const tampered: Event = { ...seal, sig: wrapFixedBasic.wrap.sig };
    unwrap.push(err("seal-bad-signature", wrapSeal(tampered, 0xe3), "seal signature"));
  }

  // Inner rumor layer.
  unwrap.push(
    err(
      "inner-decrypt-fails",
      wrapSeal(
        manualSeal(
          AUTHOR,
          otherPk,
          rumorJson({ ...rumorBase }),
          1_700_000_100,
          [],
          new Stream(entropy(0xe5)),
        ),
        0xe7,
      ),
      "failed to decrypt",
    ),
    err(
      "inner-invalid-json",
      wrapSeal(
        manualSeal(AUTHOR, recipientPk, "{oops", 1_700_000_100, [], new Stream(entropy(0xe9))),
        0xeb,
      ),
      "invalid JSON",
    ),
    err(
      "rumor-not-object",
      wrapSeal(
        manualSeal(AUTHOR, recipientPk, "[]", 1_700_000_100, [], new Stream(entropy(0xed))),
        0xef,
      ),
      "invalid rumor",
    ),
    err(
      "rumor-with-sig",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          rumorJson({ ...rumorOf(rumorBase), sig: "ab".repeat(64) }),
          1_700_000_100,
          [],
          new Stream(entropy(0xf1)),
        ),
        0xf3,
      ),
      "rumor must be unsigned",
    ),
    err(
      "rumor-invalid",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          JSON.stringify({ kind: 1 }),
          1_700_000_100,
          [],
          new Stream(entropy(0xf5)),
        ),
        0xf7,
      ),
      "invalid rumor",
    ),
    err(
      "rumor-id-mismatch",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          rumorJson({ ...rumorOf(rumorBase), id: "f".repeat(64) }),
          1_700_000_100,
          [],
          new Stream(entropy(0xf9)),
        ),
        0xfb,
      ),
      "invalid rumor",
    ),
    err(
      "seal-pubkey-mismatch",
      wrapSeal(
        manualSeal(
          AUTHOR,
          recipientPk,
          rumorJson({ ...rumorOf({ ...rumorBase, pubkey: otherPk }) }),
          1_700_000_100,
          [],
          new Stream(entropy(0xfd)),
        ),
        0xff,
      ),
      "seal pubkey does not match rumor pubkey",
    ),
  );

  // Accepted rumor variants: missing id and uppercase id.
  {
    const noId = { ...rumorOf(rumorBase) } as Record<string, unknown>;
    delete noId["id"];
    const seal = manualSeal(
      AUTHOR,
      recipientPk,
      JSON.stringify(noId),
      1_700_000_100,
      [],
      new Stream(entropy(0xa1)),
    );
    unwrap.push({
      name: "rumor-no-id",
      gift_wrap: wrapSeal(seal, 0xa3),
      recipient_secret_key: RECIPIENT,
      rumor: { ...rumorBase, id: rumorOf(rumorBase).id },
    });
  }
  {
    const upper = { ...rumorOf(rumorBase), id: rumorOf(rumorBase).id.toUpperCase() };
    const seal = manualSeal(
      AUTHOR,
      recipientPk,
      JSON.stringify(upper),
      1_700_000_100,
      [],
      new Stream(entropy(0xa5)),
    );
    unwrap.push({
      name: "rumor-uppercase-id",
      gift_wrap: wrapSeal(seal, 0xa7),
      recipient_secret_key: RECIPIENT,
      rumor: { ...rumorBase, id: rumorOf(rumorBase).id },
    });
  }

  mkdirSync(vectors, { recursive: true });
  writeFileSync(
    join(vectors, "codec.json"),
    `${JSON.stringify(
      {
        schema: 1,
        capability: "nip59.wrap",
        source: {
          kind: "generated",
          generator: "@qntx/nostr",
          version,
          note: "real `wrap`/`createSeal`/`createGiftWrap` under an injected `randomBytes` entropy stream; `entropy` records the consumed bytes in draw order (seal: [offset u32] → nonce → aux; wrap: ephemeral key → [offset u32] → nonce → aux)",
        },
        wrap: wrapCases,
        seal: sealCases,
        gift: giftCases,
        unwrap,
      },
      null,
      2,
    )}\n`,
  );
}

await main();
