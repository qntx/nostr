/// <reference types="node" />
// Generates vectors/nip57/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-57 `makeZapRequest`/`parseBolt11`/`validateZapReceipt`
// semantics as frozen vectors shared by the TS test suite
// (tests/vectors/nip57.test.ts) and the nk-* Rust crates. Every case output
// is produced by the real TS API.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import { Kind } from "../../../src/core/kind.ts";
import type { Tag } from "../../../src/core/tag.ts";
import { bytesToHex, hexToBytes, utf8Encoder } from "../../../src/core/util.ts";
import { makeZapRequest, parseBolt11, validateZapReceipt } from "../../../src/nips/nip57.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip57");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const SENDER = "a1".repeat(32);
const PROVIDER = "b2".repeat(32);
const RECIPIENT = "c3".repeat(32);
const OTHER = "d4".repeat(32);
const AUX = hexToBytes("07".repeat(32));
const CREATED_AT = 1_700_000_000;

const senderKeys = Keys.fromSecretKey(SENDER);
const providerKeys = Keys.fromSecretKey(PROVIDER);
const recipientPub = Keys.fromSecretKey(RECIPIENT).publicKey;
const otherPub = Keys.fromSecretKey(OTHER).publicKey;

function signed(tags: ReadonlyArray<Tag>, kind: number, keys: Keys): Event {
  return signEvent(
    { pubkey: keys.publicKey, created_at: CREATED_AT, kind, tags, content: "" },
    keys,
    AUX,
  );
}

// BOLT11 construction helpers — the invoice strings are inputs; the
// expected parse output comes from the real `parseBolt11`.
function intWords(value: bigint, count: number): number[] {
  const words: number[] = [];
  let v = value;
  for (let i = 0; i < count; i++) {
    words.push(Number(v % 32n));
    v /= 32n;
  }
  return words.toReversed();
}

function wordsField(type: number, data: number[]): number[] {
  return [type, Math.floor(data.length / 32), data.length % 32, ...data];
}

function bytesField(type: number, bytes: Uint8Array): number[] {
  return wordsField(type, [...bech32.toWords(bytes)]);
}

const SIG_WORDS = [...bech32.toWords(new Uint8Array(65).fill(0xab))];

function invoice(hrp: string, timestamp: number, fields: number[][]): string {
  return bech32.encode(
    hrp,
    [...intWords(BigInt(timestamp), 7), ...fields.flat(), ...SIG_WORDS],
    false,
  );
}

type Bolt11Out = {
  amountMsats?: number;
  description?: string;
  descriptionHash?: string;
  paymentHash?: string;
  timestamp: number;
  expiry: number;
};

function bolt11Out(pr: string): Bolt11Out | undefined {
  const f = parseBolt11(pr);
  if (f === undefined) {
    return undefined;
  }
  return {
    ...(f.amountMsats === undefined ? {} : { amountMsats: f.amountMsats }),
    ...(f.description === undefined ? {} : { description: f.description }),
    ...(f.descriptionHash === undefined ? {} : { descriptionHash: bytesToHex(f.descriptionHash) }),
    ...(f.paymentHash === undefined ? {} : { paymentHash: bytesToHex(f.paymentHash) }),
    timestamp: f.timestamp,
    expiry: f.expiry,
  };
}

const bolt11Cases: Array<{ name: string; invoice: string; out?: Bolt11Out }> = [];

function bolt11Case(name: string, pr: string): void {
  const out = bolt11Out(pr);
  bolt11Cases.push({ name, invoice: pr, ...(out === undefined ? {} : { out }) });
}

const PAYMENT = hexToBytes("ab".repeat(32));
const DESCHASH = hexToBytes("cd".repeat(32));

const fullInvoice = invoice("lnbc210n", CREATED_AT, [
  bytesField(1, PAYMENT),
  bytesField(13, utf8Encoder.encode("test zap")),
  bytesField(23, DESCHASH),
  wordsField(6, intWords(86_400n, 4)),
]);
bolt11Case("full fields with amount and expiry", fullInvoice);
bolt11Case("no amount in hrp", invoice("lnbc", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case("multiplier milli", invoice("lnbc10m", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case("multiplier micro", invoice("lnbc10u", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case("multiplier nano", invoice("lnbc10n", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case("multiplier pico whole msats", invoice("lnbc10p", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case(
  "multiplier pico fractional dropped",
  invoice("lnbc11p", CREATED_AT, [bytesField(1, PAYMENT)]),
);
bolt11Case("no multiplier whole btc", invoice("lnbc25", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case(
  "amount product beyond safe integer omitted",
  invoice("lnbc90071992547410n", CREATED_AT, [bytesField(1, PAYMENT)]),
);
bolt11Case(
  "amount digits beyond safe integer omitted",
  invoice("lnbc9007199254740992", CREATED_AT, [bytesField(1, PAYMENT)]),
);
bolt11Case("uppercase invoice decodes", fullInvoice.toUpperCase());
bolt11Case(
  "duplicate fields keep the first",
  invoice("lnbc", CREATED_AT, [
    wordsField(6, intWords(7200n, 3)),
    wordsField(6, intWords(86_400n, 4)),
    bytesField(1, PAYMENT),
    bytesField(1, DESCHASH),
  ]),
);
bolt11Case(
  "expiry beyond safe integer keeps 3600 (N8)",
  invoice("lnbc", CREATED_AT, [bytesField(1, PAYMENT), wordsField(6, intWords(2n ** 54n, 11))]),
);
bolt11Case(
  "explicit zero expiry",
  invoice("lnbc", CREATED_AT, [bytesField(1, PAYMENT), wordsField(6, intWords(0n, 1))]),
);
bolt11Case(
  "description with invalid utf-8 dropped",
  invoice("lnbc", CREATED_AT, [
    bytesField(1, PAYMENT),
    bytesField(13, new Uint8Array([0xff, 0xfe, 0xfd])),
  ]),
);
bolt11Case(
  "description longer than 5000-char invoice",
  // A single TLV field is capped at 1023 words — pad with unknown fields
  // (type 30) to push the whole invoice past 5000 characters.
  invoice("lnbc", CREATED_AT, [
    bytesField(1, PAYMENT),
    bytesField(13, utf8Encoder.encode("padding")),
    ...Array.from({ length: 6 }, () => bytesField(30, utf8Encoder.encode("x".repeat(600)))),
  ]),
);
bolt11Case(
  "tlv overrun truncates remaining fields",
  invoice("lnbc", CREATED_AT, [bytesField(1, PAYMENT), [6, 0, 10]]),
);
bolt11Case(
  "missing payment hash is not an invoice",
  invoice("lnbc", CREATED_AT, [bytesField(13, utf8Encoder.encode("no hash"))]),
);
bolt11Case("non-ln hrp rejected", invoice("xyz", CREATED_AT, [bytesField(1, PAYMENT)]));
bolt11Case("too few words rejected", bech32.encode("lnbc", intWords(1700000000n, 7), false));
bolt11Case("bad checksum rejected", `${fullInvoice.slice(0, -2)}qq`);
bolt11Case("not bech32 at all", "lnbc1not a real invoice!!");

const zapRequestCases: Array<{
  name: string;
  rust?: false;
  input: { pubkey?: string; event?: Event };
  amount: number;
  relays: string[];
  comment?: string;
  lnurl?: string;
  out?: { kind: number; created_at: number; content: string; tags: ReadonlyArray<Tag> };
  err?: string;
}> = [];

function zapRequestCase(
  name: string,
  input: { pubkey?: string; event?: Event },
  params: { amount: number; relays: string[]; comment?: string; lnurl?: string },
  rust = true,
): void {
  let out:
    | { kind: number; created_at: number; content: string; tags: ReadonlyArray<Tag> }
    | undefined;
  let err: string | undefined;
  try {
    const template =
      input.event === undefined
        ? makeZapRequest({ pubkey: input.pubkey ?? "", ...params })
        : makeZapRequest({ event: input.event, ...params });
    out = {
      kind: template.kind,
      created_at: CREATED_AT,
      content: template.content,
      tags: template.tags,
    };
  } catch (error) {
    err = error instanceof Error ? error.constructor.name : "Error";
  }
  zapRequestCases.push({
    name,
    ...(rust ? {} : { rust: false as const }),
    input,
    ...params,
    ...(out === undefined ? {} : { out }),
    ...(err === undefined ? {} : { err }),
  });
}

const kind1Target = signed([["t", "nostr"]], Kind.TextNote, senderKeys);
const addrTarget = signed(
  [
    ["d", "article-1"],
    ["title", "hello"],
  ],
  30_023,
  senderKeys,
);
const addrNoD = signed([["title", "hello"]], 30_023, senderKeys);

zapRequestCase(
  "profile zap with comment and lnurl",
  { pubkey: recipientPub },
  {
    amount: 21_000,
    relays: ["wss://relay-a.example/", "wss://relay-b.example/"],
    comment: "great post",
    lnurl: "lnurl1provider0",
  },
);
zapRequestCase(
  "profile zap minimal",
  { pubkey: recipientPub },
  { amount: 1, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "profile zap empty lnurl string emits no tag",
  { pubkey: recipientPub },
  { amount: 500, relays: ["wss://relay-a.example/"], lnurl: "" },
);
zapRequestCase(
  "event zap kind 1",
  { event: kind1Target },
  { amount: 21_000, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "event zap addressable emits a and k",
  { event: addrTarget },
  { amount: 21_000, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "addressable event without d rejected",
  { event: addrNoD },
  { amount: 21_000, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "zero amount rejected",
  { pubkey: recipientPub },
  { amount: 0, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "amount beyond safe integer rejected",
  { pubkey: recipientPub },
  { amount: 9_007_199_254_740_992, relays: ["wss://relay-a.example/"] },
);
zapRequestCase(
  "non-integer amount rejected (ts only)",
  { pubkey: recipientPub },
  { amount: 1.5, relays: ["wss://relay-a.example/"] },
  false,
);
zapRequestCase(
  "negative amount rejected (ts only)",
  { pubkey: recipientPub },
  { amount: -5, relays: ["wss://relay-a.example/"] },
  false,
);
zapRequestCase("empty relays rejected", { pubkey: recipientPub }, { amount: 1, relays: [] });
zapRequestCase(
  "non-hex pubkey kept verbatim (ts only)",
  { pubkey: "not-hex" },
  { amount: 1, relays: ["wss://relay-a.example/"] },
  false,
);
zapRequestCase(
  "raw relay strings kept verbatim (ts only)",
  { pubkey: recipientPub },
  { amount: 1, relays: ["RELAY.EXAMPLE", "not a url"] },
  false,
);

// Receipt cases — every ZapRejection reason from real validateZapReceipt
// output.
const preimage = hexToBytes("42".repeat(32));

function requestWith(tags: ReadonlyArray<Tag>): Event {
  return signed(tags, Kind.ZapRequest, senderKeys);
}

function requestTags(): Tag[] {
  return [
    ...makeZapRequest({
      pubkey: recipientPub,
      amount: 21_000,
      relays: ["wss://zap.example/"],
      comment: "thanks",
      lnurl: "lnurl1provider0",
    }).tags,
  ];
}

function receiptInvoice(description: string, hrp = "lnbc210n"): string {
  return invoice(hrp, CREATED_AT + 100, [
    bytesField(1, sha256(preimage)),
    bytesField(23, sha256(utf8Encoder.encode(description))),
  ]);
}

type ReceiptCase = {
  name: string;
  receipt: Event;
  nostrPubkey: string;
  lnurl?: string;
  result: { valid: true; request: Event; amountMsats?: number } | { valid: false; reason: string };
};

const receiptCases: ReceiptCase[] = [];

function receiptCase(
  name: string,
  receipt: Event,
  ctx: { nostrPubkey?: string; lnurl?: string } = {},
): void {
  const nostrPubkey = ctx.nostrPubkey ?? providerKeys.publicKey;
  const result = validateZapReceipt(receipt, { nostrPubkey, lnurl: ctx.lnurl });
  receiptCases.push({
    name,
    receipt,
    nostrPubkey,
    ...(ctx.lnurl === undefined ? {} : { lnurl: ctx.lnurl }),
    result: result.valid
      ? {
          valid: true,
          request: result.request,
          ...(result.amountMsats === undefined ? {} : { amountMsats: result.amountMsats }),
        }
      : { valid: false, reason: result.reason },
  });
}

// Canonical valid receipt.
{
  const request = requestWith([...requestTags(), ["P", providerKeys.publicKey]]);
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["preimage", bytesToHex(preimage)],
      ["p", recipientPub],
      ["P", senderKeys.publicKey],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("valid profile zap receipt", receipt, { lnurl: "lnurl1provider0" });
}

// Valid receipt with no invoice amount: the request carries no amount tag,
// so a bare hrp matches and amountMsats stays absent.
{
  const request = requestWith([
    ["p", recipientPub],
    ["relays", "wss://zap.example/"],
  ]);
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description, "lnbc")],
      ["description", description],
      ["p", recipientPub],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("valid receipt without invoice amount", receipt);
}

// Valid event zap receipt with e tag.
{
  const request = requestWith(
    makeZapRequest({
      event: kind1Target,
      amount: 21_000,
      relays: ["wss://zap.example/"],
    }).tags,
  );
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["p", kind1Target.pubkey],
      ["e", kind1Target.id],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("valid event zap receipt", receipt);
}

function mutationReceipt(
  mutateRequest: (tags: Tag[]) => Tag[],
  mutateReceipt: (tags: Tag[], description: string) => Tag[],
): { receipt: Event } {
  const request = requestWith(mutateRequest(requestTags()));
  const description = JSON.stringify(request);
  const receipt = signed(
    mutateReceipt(
      [
        ["bolt11", receiptInvoice(description)],
        ["description", description],
        ["preimage", bytesToHex(preimage)],
        ["p", recipientPub],
        ["P", senderKeys.publicKey],
      ],
      description,
    ),
    Kind.Zap,
    providerKeys,
  );
  return { receipt };
}

// Invalid receipt — right shape but the signature does not verify.
{
  const { receipt } = mutationReceipt(
    (tags) => tags,
    (tags) => tags,
  );
  const broken = { ...receipt, content: "tampered" };
  receiptCase("signature does not verify", broken);
}
{
  const request = requestWith(requestTags());
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["p", recipientPub],
    ],
    Kind.ZapRequest,
    providerKeys,
  );
  receiptCase("wrong kind is not a receipt", receipt);
}
{
  const { receipt } = mutationReceipt(
    (tags) => tags,
    (tags) => tags,
  );
  receiptCase("pubkey mismatch", receipt, { nostrPubkey: otherPub });
}

// Invalid zap request inside description.
{
  const receipt = signed(
    [
      ["bolt11", receiptInvoice("not json")],
      ["description", "not json"],
      ["p", recipientPub],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("description is not JSON", receipt);
}
{
  const notARequest = signed([], Kind.TextNote, senderKeys);
  const description = JSON.stringify(notARequest);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["p", recipientPub],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("description kind is not 9734", receipt);
}
{
  const receipt = signed(
    [
      ["bolt11", receiptInvoice("")],
      ["p", recipientPub],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("description tag missing", receipt);
}

// Request shape checks.
receiptCase(
  "request with zero p tags",
  mutationReceipt(
    (tags) => tags.filter((tag) => tag[0] !== "p"),
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request with two p tags",
  mutationReceipt(
    (tags) => [...tags, ["p", otherPub]],
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request with two e tags",
  mutationReceipt(
    (tags) => [...tags, ["e", kind1Target.id], ["e", addrTarget.id]],
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request without relays tag",
  mutationReceipt(
    (tags) => tags.filter((tag) => tag[0] !== "relays"),
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request with empty relays value",
  mutationReceipt(
    (tags) => tags.map((tag) => (tag[0] === "relays" ? ["relays"] : tag)),
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request a tag unparsable",
  mutationReceipt(
    (tags) => [...tags, ["a", "not-an-address"]],
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request a tag non-addressable kind",
  mutationReceipt(
    (tags) => [...tags, ["a", `1:${senderKeys.publicKey}:id`]],
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request with two P tags",
  mutationReceipt(
    (tags) => [...tags, ["P", providerKeys.publicKey], ["P", providerKeys.publicKey]],
    (tags) => tags,
  ).receipt,
);
receiptCase(
  "request P mismatch",
  mutationReceipt(
    (tags) => [...tags, ["P", otherPub]],
    (tags) => tags,
  ).receipt,
);

// bolt11 checks.
receiptCase(
  "missing bolt11 tag",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.filter((tag) => tag[0] !== "bolt11"),
  ).receipt,
);
receiptCase(
  "unparsable bolt11",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.map((tag) => (tag[0] === "bolt11" ? ["bolt11", "lnbc1broken"] : tag)),
  ).receipt,
);
receiptCase(
  "bolt11 without description hash",
  mutationReceipt(
    (tags) => tags,
    (tags) =>
      tags.map((tag) =>
        tag[0] === "bolt11"
          ? ["bolt11", invoice("lnbc210n", CREATED_AT, [bytesField(1, sha256(preimage))])]
          : tag,
      ),
  ).receipt,
);
receiptCase(
  "amount mismatch",
  mutationReceipt(
    (tags) => tags,
    (tags, description) =>
      tags.map((tag) =>
        tag[0] === "bolt11" ? ["bolt11", receiptInvoice(description, "lnbc100n")] : tag,
      ),
  ).receipt,
);
receiptCase(
  "description hash mismatch",
  mutationReceipt(
    (tags) => tags,
    (tags) =>
      tags.map((tag) =>
        tag[0] === "bolt11"
          ? [
              "bolt11",
              invoice("lnbc210n", CREATED_AT, [
                bytesField(1, sha256(preimage)),
                bytesField(23, sha256(utf8Encoder.encode("something else"))),
              ]),
            ]
          : tag,
      ),
  ).receipt,
);
{
  const { receipt } = mutationReceipt(
    (tags) => tags,
    (tags) => tags,
  );
  receiptCase("lnurl mismatch", receipt, { lnurl: "lnurl1other" });
}
receiptCase(
  "preimage mismatch",
  mutationReceipt(
    (tags) => tags,
    (tags) =>
      tags.map((tag) =>
        tag[0] === "preimage" ? ["preimage", bytesToHex(hexToBytes("77".repeat(32)))] : tag,
      ),
  ).receipt,
);
receiptCase(
  "preimage invalid hex",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.map((tag) => (tag[0] === "preimage" ? ["preimage", "xyz-not-hex"] : tag)),
  ).receipt,
);

// Receipt tag consistency.
receiptCase(
  "receipt missing p",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.filter((tag) => tag[0] !== "p"),
  ).receipt,
);
receiptCase(
  "receipt p does not match request p",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.map((tag) => (tag[0] === "p" ? ["p", otherPub] : tag)),
  ).receipt,
);
{
  const request = requestWith(
    makeZapRequest({ event: kind1Target, amount: 21_000, relays: ["wss://zap.example/"] }).tags,
  );
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["p", kind1Target.pubkey],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("receipt missing e", receipt);
}
{
  const request = requestWith(
    makeZapRequest({ event: addrTarget, amount: 21_000, relays: ["wss://zap.example/"] }).tags,
  );
  const description = JSON.stringify(request);
  const receipt = signed(
    [
      ["bolt11", receiptInvoice(description)],
      ["description", description],
      ["p", addrTarget.pubkey],
      ["e", addrTarget.id],
    ],
    Kind.Zap,
    providerKeys,
  );
  receiptCase("receipt missing a", receipt);
}
receiptCase(
  "receipt P does not match request pubkey",
  mutationReceipt(
    (tags) => tags,
    (tags) => tags.map((tag) => (tag[0] === "P" ? ["P", otherPub] : tag)),
  ).receipt,
);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip57.zap",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  zap_request: zapRequestCases,
  bolt11: bolt11Cases,
  receipt: receiptCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip57 codec: ${zapRequestCases.length} zap_request + ${bolt11Cases.length} bolt11 + ${receiptCases.length} receipt cases written`,
);
