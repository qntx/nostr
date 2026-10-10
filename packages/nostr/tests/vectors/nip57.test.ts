import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vite-plus/test";

import { EventValidationError } from "../../src/core/error.ts";
import type { Event, EventTemplate } from "../../src/core/event.ts";
import type { Tag } from "../../src/core/tag.ts";
import { bytesToHex } from "../../src/core/util.ts";
import type { Bolt11Fields, ZapReceiptValidation } from "../../src/nips/nip57.ts";
import { makeZapRequest, parseBolt11, validateZapReceipt } from "../../src/nips/nip57.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type ZapOut = { kind: number; created_at: number; content: string; tags: Tag[] };

type ZapRequestCase = {
  name: string;
  rust?: boolean;
  input: { pubkey?: string; event?: Event };
  amount: number;
  relays: string[];
  comment?: string;
  lnurl?: string;
  out?: ZapOut;
  err?: string;
};

type Bolt11Out = {
  amountMsats?: number;
  description?: string;
  descriptionHash?: string;
  paymentHash?: string;
  timestamp: number;
  expiry: number;
};

type Bolt11Case = {
  name: string;
  invoice: string;
  out?: Bolt11Out;
};

type ReceiptCase = {
  name: string;
  receipt: Event;
  nostrPubkey: string;
  lnurl?: string;
  result: { valid: true; request: Event; amountMsats?: number } | { valid: false; reason: string };
};

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip57/codec.json"), "utf8"),
) as { zap_request: ZapRequestCase[]; bolt11: Bolt11Case[]; receipt: ReceiptCase[] };

const zapOk = codec.zap_request.filter((c) => c.out !== undefined);
const zapErr = codec.zap_request.filter((c) => c.err !== undefined);
const bolt11Ok = codec.bolt11.filter((c) => c.out !== undefined);
const bolt11None = codec.bolt11.filter((c) => c.out === undefined);
const receiptValid = codec.receipt.filter((c) => c.result.valid);
const receiptInvalid = codec.receipt.filter((c) => !c.result.valid);

const realDateNow = Date.now;

afterEach(() => {
  Date.now = realDateNow;
});

function replayZapRequest(c: ZapRequestCase): EventTemplate {
  const params = {
    amount: c.amount,
    relays: c.relays,
    ...(c.comment === undefined ? {} : { comment: c.comment }),
    ...(c.lnurl === undefined ? {} : { lnurl: c.lnurl }),
  };
  return c.input.event === undefined
    ? makeZapRequest({ pubkey: c.input.pubkey ?? "", ...params })
    : makeZapRequest({ event: c.input.event, ...params });
}

function outOf(c: ZapRequestCase): ZapOut {
  const { out } = c;
  if (out === undefined) {
    throw new Error(`zap_request case ${c.name} has no out`);
  }
  return out;
}

function serializeBolt11(fields: Bolt11Fields | undefined): Bolt11Out | null {
  if (fields === undefined) {
    return null;
  }
  return {
    ...(fields.amountMsats === undefined ? {} : { amountMsats: fields.amountMsats }),
    ...(fields.description === undefined ? {} : { description: fields.description }),
    ...(fields.descriptionHash === undefined
      ? {}
      : { descriptionHash: bytesToHex(fields.descriptionHash) }),
    ...(fields.paymentHash === undefined ? {} : { paymentHash: bytesToHex(fields.paymentHash) }),
    timestamp: fields.timestamp,
    expiry: fields.expiry,
  };
}

function validate(c: ReceiptCase): ZapReceiptValidation {
  return validateZapReceipt(c.receipt, {
    nostrPubkey: c.nostrPubkey,
    ...(c.lnurl === undefined ? {} : { lnurl: c.lnurl }),
  });
}

function serializeResult(validation: ZapReceiptValidation) {
  return validation.valid
    ? {
        valid: true as const,
        request: validation.request,
        ...(validation.amountMsats === undefined ? {} : { amountMsats: validation.amountMsats }),
      }
    : { valid: false as const, reason: validation.reason };
}

describe("vectors/nip57/codec.json", () => {
  test("makeZapRequest templates match", () => {
    for (const c of zapOk) {
      const out = outOf(c);
      Date.now = () => out.created_at * 1000;
      const got = replayZapRequest(c);
      expect(got.kind).toBe(out.kind);
      expect(got.created_at).toBe(out.created_at);
      expect(got.content).toBe(out.content);
      expect(got.tags).toStrictEqual(out.tags);
    }
  });

  test("makeZapRequest rejections match", () => {
    for (const c of zapErr) {
      expect(c.err).toBe("EventValidationError");
      expect(() => replayZapRequest(c)).toThrow(EventValidationError);
    }
  });

  test("parseBolt11 decodes the recorded fields", () => {
    for (const c of bolt11Ok) {
      expect(serializeBolt11(parseBolt11(c.invoice))).toStrictEqual(c.out);
    }
  });

  test("parseBolt11 rejects the recorded non-invoices", () => {
    for (const c of bolt11None) {
      expect(parseBolt11(c.invoice)).toBeUndefined();
    }
  });

  test("validateZapReceipt verdicts match", () => {
    for (const c of [...receiptValid, ...receiptInvalid]) {
      expect(serializeResult(validate(c))).toStrictEqual(c.result);
    }
  });
});
