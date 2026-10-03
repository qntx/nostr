/**
 * NIP-57 Lightning Zaps — zap request template (kind 9734) and receipt validation (kind 9735). Does
 * not fetch LNURL. Receipt checks never throw.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/57.md
 */
import { equalBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";

import { EventValidationError } from "../core/error.ts";
import { validateSignedEvent } from "../core/event.ts";
import type { Event, EventTemplate } from "../core/event.ts";
import { isAddressableKind, Kind } from "../core/kind.ts";
import { eventAddress, firstTagValue, getDTag, parseEventAddress, Tag } from "../core/tag.ts";
import { hexToBytes, nowSeconds, utf8Encoder } from "../core/util.ts";
import { verifyEvent } from "../core/verifier.ts";

export type ProfileZapRequest = {
  pubkey: string;
  /** Amount in millisats. */
  amount: number;
  relays: ReadonlyArray<string>;
  comment?: string;
  lnurl?: string;
};

export type EventZapRequest = {
  event: Event;
  /** Amount in millisats. */
  amount: number;
  relays: ReadonlyArray<string>;
  comment?: string;
  lnurl?: string;
};

export function makeZapRequest(params: ProfileZapRequest | EventZapRequest): EventTemplate {
  if (!Number.isSafeInteger(params.amount) || params.amount <= 0) {
    throw new EventValidationError("zap amount must be a positive integer (msats)");
  }
  if (params.relays.length === 0) {
    throw new EventValidationError("relays tag requires one or more URLs");
  }

  const recipient = "event" in params ? params.event.pubkey : params.pubkey;
  const tags: Tag[] = [
    Tag.p(recipient),
    ["amount", params.amount.toString()],
    ["relays", ...params.relays],
  ];

  if ("event" in params) {
    const { event } = params;
    tags.push(Tag.e(event.id));
    if (isAddressableKind(event.kind)) {
      const d = getDTag(event.tags);
      if (d === undefined) {
        throw new EventValidationError("d tag not found");
      }
      const addr = eventAddress(event);
      if (addr !== undefined) {
        tags.push(["a", addr]);
      }
    }
    tags.push(["k", event.kind.toString()]);
  }

  if (params.lnurl !== undefined && params.lnurl !== "") {
    tags.push(["lnurl", params.lnurl]);
  }

  return {
    kind: Kind.ZapRequest,
    created_at: nowSeconds(),
    content: params.comment ?? "",
    tags,
  };
}

export type ZapReceiptContext = {
  nostrPubkey: string;
  lnurl?: string;
};

export type ZapReceiptValidation =
  | {
      readonly valid: true;
      readonly request: Event;
      readonly amountMsats: number | undefined;
    }
  | { readonly valid: false; readonly reason: string };

export type Bolt11Fields = {
  amountMsats?: number;
  /** The `d` tagged field, UTF-8 decoded; omitted on invalid UTF-8. */
  description?: string;
  descriptionHash?: Uint8Array;
  paymentHash?: Uint8Array;
  /** Invoice creation time (unix seconds). */
  timestamp: number;
  /** `x` tagged field — seconds after `timestamp` until expiry. Defaults to 3600 when absent. */
  expiry: number;
};

function fail(reason: string): ZapReceiptValidation {
  return { valid: false, reason };
}

const MSATS_PER_BTC = 100_000_000_000;
const MSATS_PER_MILLI = 100_000_000;
const MSATS_PER_MICRO = 100_000;
const MSATS_PER_NANO = 100;

/** Amount is digits after `ln` + currency letters, optional m/u/n/p. Non-integer pico is omitted. */
function amountMsatsFromHrp(hrp: string): number | undefined {
  if (!hrp.startsWith("ln")) {
    return undefined;
  }
  let i = 2;
  while (i < hrp.length) {
    const c = hrp.codePointAt(i);
    if (c === undefined || c < 97 || c > 122) {
      break;
    }
    i++;
  }
  if (i === hrp.length) {
    return undefined;
  }
  const rest = hrp.slice(i);
  const m = /^([0-9]+)([munp])?$/.exec(rest);
  if (!m) {
    return undefined;
  }
  const n = Number(m[1]);
  if (!Number.isSafeInteger(n)) {
    return undefined;
  }
  const mul = m.at(2);
  const factor =
    mul === undefined
      ? MSATS_PER_BTC
      : mul === "m"
        ? MSATS_PER_MILLI
        : mul === "u"
          ? MSATS_PER_MICRO
          : mul === "n"
            ? MSATS_PER_NANO
            : 0;
  if (factor !== 0) {
    const msats = n * factor;
    return Number.isSafeInteger(msats) ? msats : undefined;
  }
  // p: 0.1 msat; drop amounts that are not whole millisats
  if (n % 10 !== 0) {
    return undefined;
  }
  return n / 10;
}

function parseMsatsTag(value: string): number | undefined {
  if (!/^[0-9]+$/.test(value)) {
    return undefined;
  }
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : undefined;
}

function countTags(tags: ReadonlyArray<Tag>, name: string): number {
  let n = 0;
  for (const tag of tags) {
    if (tag[0] === name) {
      n++;
    }
  }
  return n;
}

function hasHexTagValue(tags: ReadonlyArray<Tag>, name: string, value: string): boolean {
  const needle = value.toLowerCase();
  for (const tag of tags) {
    if (tag[0] === name && tag[1] !== undefined && tag[1].toLowerCase() === needle) {
      return true;
    }
  }
  return false;
}

function hasAddressTag(tags: ReadonlyArray<Tag>, value: string): boolean {
  const want = parseEventAddress(value);
  if (!want) {
    return false;
  }
  for (const tag of tags) {
    if (tag[0] !== "a" || tag[1] === undefined) {
      continue;
    }
    const got = parseEventAddress(tag[1]);
    if (
      got &&
      got.kind === want.kind &&
      got.pubkey === want.pubkey &&
      got.identifier === want.identifier
    ) {
      return true;
    }
  }
  return false;
}

const BOLT11_TIMESTAMP_WORDS = 7;
const BOLT11_SIGNATURE_WORDS = 104;
const BOLT11_HASH_WORDS = 52;
const HASH_BYTES = 32;
const BOLT11_TAG_PAYMENT_HASH = 1;
const BOLT11_TAG_EXPIRY = 6;
const BOLT11_TAG_DESCRIPTION = 13;
const BOLT11_TAG_DESCRIPTION_HASH = 23;
const DEFAULT_EXPIRY_SECONDS = 3600;

const utf8DecoderFatal = new TextDecoder("utf-8", { fatal: true });

/** Big-endian 5-bit words as a JS number (safe below 2^53). */
function wordsToInt(words: ReadonlyArray<number>): number {
  let value = 0;
  for (const word of words) {
    value = value * 32 + word;
  }
  return value;
}

/** Decode a BOLT11 invoice. Never throws. Requires a 32-byte payment hash (type 1). */
export function parseBolt11(pr: string): Bolt11Fields | undefined {
  try {
    // Invoices exceed bech32's default 90-char limit.
    const { prefix, words } = bech32.decode(pr.toLowerCase(), false);
    if (!prefix.startsWith("ln")) {
      return undefined;
    }
    // timestamp (7) + tagged fields + secp256k1 signature (104)
    if (words.length < BOLT11_TIMESTAMP_WORDS + BOLT11_SIGNATURE_WORDS) {
      return undefined;
    }
    const fields: Bolt11Fields = {
      timestamp: wordsToInt(words.slice(0, BOLT11_TIMESTAMP_WORDS)),
      expiry: DEFAULT_EXPIRY_SECONDS,
    };
    let sawExpiry = false;
    const amountMsats = amountMsatsFromHrp(prefix);
    if (amountMsats !== undefined) {
      fields.amountMsats = amountMsats;
    }
    const tlvEnd = words.length - BOLT11_SIGNATURE_WORDS;
    let i = BOLT11_TIMESTAMP_WORDS;
    while (i + 3 <= tlvEnd) {
      const type = words[i];
      const lenHigh = words[i + 1];
      const lenLow = words[i + 2];
      if (type === undefined || lenHigh === undefined || lenLow === undefined) {
        break;
      }
      const dataLen = lenHigh * 32 + lenLow;
      i += 3;
      if (i + dataLen > tlvEnd) {
        break;
      }
      const data = words.slice(i, i + dataLen);
      i += dataLen;
      if (type === BOLT11_TAG_EXPIRY) {
        if (!sawExpiry) {
          sawExpiry = true;
          fields.expiry = wordsToInt(data);
        }
        continue;
      }
      if (type === BOLT11_TAG_DESCRIPTION) {
        const bytes = bech32.fromWordsUnsafe(data);
        if (bytes !== undefined) {
          try {
            fields.description ??= utf8DecoderFatal.decode(bytes);
          } catch {
            // Invalid UTF-8 — drop the field, not the invoice.
          }
        }
        continue;
      }
      if (
        (type !== BOLT11_TAG_PAYMENT_HASH && type !== BOLT11_TAG_DESCRIPTION_HASH) ||
        dataLen !== BOLT11_HASH_WORDS
      ) {
        continue;
      }
      const bytes = bech32.fromWordsUnsafe(data);
      if (!bytes || bytes.length !== HASH_BYTES) {
        continue;
      }
      if (type === BOLT11_TAG_PAYMENT_HASH) {
        fields.paymentHash ??= bytes;
      } else {
        fields.descriptionHash ??= bytes;
      }
    }
    if (!fields.paymentHash) {
      return undefined;
    }
    return fields;
  } catch {
    return undefined;
  }
}

/** Parse the `description` tag of a kind 9735 receipt as a signed kind 9734. Never throws. */
export function parseZapRequestFromReceipt(receipt: Event): Event | undefined {
  try {
    const raw = firstTagValue(receipt.tags, "description");
    if (raw === undefined) {
      return undefined;
    }
    const parsed: unknown = JSON.parse(raw);
    if (!validateSignedEvent(parsed) || parsed.kind !== Kind.ZapRequest) {
      return undefined;
    }
    if (!verifyEvent(parsed)) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

/** Validate a kind 9735 zap receipt. Never throws. */
export function validateZapReceipt(receipt: Event, ctx: ZapReceiptContext): ZapReceiptValidation {
  try {
    if (receipt.kind !== Kind.Zap || !verifyEvent(receipt)) {
      return fail("invalid receipt");
    }
    if (receipt.pubkey.toLowerCase() !== ctx.nostrPubkey.toLowerCase()) {
      return fail("pubkey mismatch");
    }

    const descriptionRaw = firstTagValue(receipt.tags, "description");
    const request = parseZapRequestFromReceipt(receipt);
    if (descriptionRaw === undefined || !request) {
      return fail("invalid zap request");
    }
    if (countTags(request.tags, "p") !== 1) {
      return fail("invalid p count");
    }
    if (countTags(request.tags, "e") > 1) {
      return fail("too many e tags");
    }
    const relaysValue = firstTagValue(request.tags, "relays");
    if (relaysValue === undefined || relaysValue === "") {
      return fail("missing relays");
    }

    for (const tag of request.tags) {
      if (tag[0] !== "a") {
        continue;
      }
      if (tag[1] === undefined) {
        return fail("invalid a");
      }
      const parsed = parseEventAddress(tag[1]);
      if (!parsed || !isAddressableKind(parsed.kind)) {
        return fail("invalid a");
      }
    }

    // Request P is the LNURL provider (receipt pubkey), not the zap sender.
    const requestPCount = countTags(request.tags, "P");
    if (requestPCount > 1) {
      return fail("too many P tags");
    }
    if (requestPCount === 1) {
      const requestP = firstTagValue(request.tags, "P");
      if (requestP === undefined || requestP.toLowerCase() !== receipt.pubkey.toLowerCase()) {
        return fail("request P mismatch");
      }
    }

    const bolt11Tag = firstTagValue(receipt.tags, "bolt11");
    if (bolt11Tag === undefined) {
      return fail("missing bolt11");
    }
    const bolt11 = parseBolt11(bolt11Tag);
    if (!bolt11 || !bolt11.descriptionHash) {
      return fail("invalid bolt11");
    }

    const requestAmount = firstTagValue(request.tags, "amount");
    if (requestAmount !== undefined) {
      const msats = parseMsatsTag(requestAmount);
      if (msats === undefined || bolt11.amountMsats !== msats) {
        return fail("amount mismatch");
      }
    }

    // Hash the tag payload, not JSON.stringify(parsed) (key order may differ).
    const digest = sha256(utf8Encoder.encode(descriptionRaw));
    if (!equalBytes(digest, bolt11.descriptionHash)) {
      return fail("description hash mismatch");
    }

    const requestLnurl = firstTagValue(request.tags, "lnurl");
    if (
      requestLnurl !== undefined &&
      ctx.lnurl !== undefined &&
      requestLnurl.toLowerCase() !== ctx.lnurl.toLowerCase()
    ) {
      return fail("lnurl mismatch");
    }

    const preimageHex = firstTagValue(receipt.tags, "preimage");
    if (preimageHex !== undefined && bolt11.paymentHash) {
      let preimage: Uint8Array;
      try {
        preimage = hexToBytes(preimageHex);
      } catch {
        return fail("preimage mismatch");
      }
      if (!equalBytes(sha256(preimage), bolt11.paymentHash)) {
        return fail("preimage mismatch");
      }
    }

    const recipient = firstTagValue(request.tags, "p");
    if (recipient === undefined || !hasHexTagValue(receipt.tags, "p", recipient)) {
      return fail("missing p");
    }
    const requestE = firstTagValue(request.tags, "e");
    if (requestE !== undefined && !hasHexTagValue(receipt.tags, "e", requestE)) {
      return fail("missing e");
    }
    for (const tag of request.tags) {
      if (tag[0] !== "a" || tag[1] === undefined) {
        continue;
      }
      if (!hasAddressTag(receipt.tags, tag[1])) {
        return fail("missing a");
      }
    }

    // Receipt P is the zap sender (request pubkey). Do not copy request tag P.
    for (const tag of receipt.tags) {
      if (tag[0] !== "P") {
        continue;
      }
      if (tag[1] === undefined || tag[1].toLowerCase() !== request.pubkey.toLowerCase()) {
        return fail("receipt P mismatch");
      }
    }

    const amountMsats =
      bolt11.amountMsats ??
      (requestAmount === undefined ? undefined : parseMsatsTag(requestAmount));
    return { valid: true, request, amountMsats };
  } catch {
    return fail("invalid receipt");
  }
}
