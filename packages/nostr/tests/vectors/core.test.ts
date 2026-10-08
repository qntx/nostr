import { readFileSync } from "node:fs";
import { join } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { EventBuilder } from "../../src/core/builder.ts";
import type { ProfileMetadata } from "../../src/core/builder.ts";
import { EventValidationError, HexError, MessageError, UrlError } from "../../src/core/error.ts";
import { serializeEvent, getEventHash, validateSignedEvent } from "../../src/core/event.ts";
import type { Event, UnsignedEvent } from "../../src/core/event.ts";
import {
  canonicalizeFilter,
  filterFingerprint,
  getFilterLimit,
  matchFilter,
} from "../../src/core/filter.ts";
import type { Filter } from "../../src/core/filter.ts";
import { Keys, signEvent } from "../../src/core/key.ts";
import type { SigningBackend } from "../../src/core/key.ts";
import {
  classifyKind,
  isAddressableKind,
  isEphemeralKind,
  isRegularKind,
  isReplaceableKind,
} from "../../src/core/kind.ts";
import {
  encodeClientMessage,
  encodeRelayMessage,
  mergeCountHll,
  parseClientMessage,
  parseRelayMessage,
} from "../../src/core/message.ts";
import { formatEventAddress, parseEventAddress } from "../../src/core/tag.ts";
import { assertHex32, bytesToHex, hexToBytes, isHex32, normalizeURL } from "../../src/core/util.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun scripts/parity/gen/core.ts`.
type Cases<T> = { cases: T[] };

function readVector<T>(name: string): T[] {
  const doc = JSON.parse(
    readFileSync(join(import.meta.dirname, "../../../../vectors/core", name), "utf8"),
  ) as Cases<T>;
  return doc.cases;
}

const serialize = readVector<{
  unsigned: UnsignedEvent;
  serialized: string;
  id: string;
}>("event-serialize.json");
const signed = readVector<{
  secretKey: string;
  aux: string;
  unsigned: UnsignedEvent;
  event: Event;
}>("event-sign.json");
const invalidEvents = readVector<{ reason: string; raw: string; error: string }>(
  "event-validate.json",
);
const matchFilterCases = readVector<{ filter: Filter; event: Event; matches: boolean }>(
  "filter-match.json",
);
const filterLimitCases = readVector<{ filter: Filter; limit: number | null }>("filter-limit.json");
const canonicalizeCases = readVector<{ input: Filter; canonicalJson: string }>(
  "filter-canonicalize.json",
);
const fingerprintCases = readVector<{ filters: Filter[]; fingerprint: string }>(
  "filter-fingerprint.json",
);
const clientMessageCases = readVector<{ raw: string; encoded?: string; error?: string }>(
  "message-client.json",
);
const relayMessageCases = readVector<{ raw: string; encoded?: string; error?: string }>(
  "message-relay.json",
);
const mergeHllCases = readVector<{ inputs: string[]; output?: string; error?: string }>(
  "count-hll.json",
);
const kindCases = readVector<{
  kind: number;
  regular: boolean;
  replaceable: boolean;
  ephemeral: boolean;
  addressable: boolean;
  class: string;
}>("kind-classify.json");
type AddressParseCase = {
  op: "parse";
  input: string;
  parsed: { kind: number; pubkey: string; identifier: string } | null;
};
type AddressFormatCase = {
  op: "format";
  kind: number;
  pubkey: string;
  identifier: string;
  formatted: string;
};
const addressCases = readVector<AddressParseCase | AddressFormatCase>("tag-address.json");
const normalizeUrlCases = readVector<{ input: string; output?: string; error?: string }>(
  "url-normalize.json",
);
const hexCases = readVector<{
  op: "caller" | "wire";
  input: string;
  output?: string;
  error?: string;
}>("hex.json");

type BuilderCase = {
  op: string;
  content?: string;
  kind?: number;
  tags?: string[][];
  meta?: ProfileMetadata;
  pubkeys?: string[];
  targets?: ReadonlyArray<string | { id: string; kind?: number } | { address: string }>;
  reason?: string;
  target?: Event;
  relay?: string;
  p_pubkey?: string;
  unsignedJson?: string;
  error?: string;
};
const builderCases = readVector<BuilderCase>("builder.json");
const builderValid = builderCases.filter((c) => c.error === undefined);
const builderInvalid = builderCases.filter((c) => c.error !== undefined);

const BUILD_PK = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";

function runBuilderCase(c: BuilderCase): EventBuilder {
  switch (c.op) {
    case "text_note":
      return EventBuilder.textNote(c.content ?? "");
    case "new": {
      const builder = new EventBuilder(c.kind ?? 0, c.content ?? "");
      builder.tags(c.tags ?? []);
      return builder;
    }
    case "metadata":
      return EventBuilder.metadata(c.meta ?? {});
    case "contacts":
      return EventBuilder.contacts(c.pubkeys ?? []);
    case "deletion":
      return EventBuilder.deletion(c.targets ?? [], c.reason ?? "");
    case "reaction":
      if (c.target === undefined) {
        throw new Error("reaction case missing target");
      }
      return EventBuilder.reaction(
        c.target,
        c.content ?? "+",
        c.relay === undefined ? undefined : { relayHint: c.relay },
      );
    case "repost":
      if (c.target === undefined) {
        throw new Error("repost case missing target");
      }
      return EventBuilder.repost(c.target, { relayHint: c.relay ?? "" });
    case "generic_repost":
      if (c.target === undefined) {
        throw new Error("generic_repost case missing target");
      }
      if (c.p_pubkey === undefined) {
        return EventBuilder.genericRepost(c.target, { relayHint: c.relay ?? "" });
      }
      return EventBuilder.genericRepost(c.target, {
        relayHint: c.relay ?? "",
        pPubkey: c.p_pubkey,
      });
    default:
      throw new Error(`unknown builder op ${c.op}`);
  }
}

// Derived vectors kept out of the test bodies: `??`, `||` and ternaries inside
// `test` callbacks are rejected by the no-conditional-in-test lint.
const filterLimits = filterLimitCases.map((c) => ({
  filter: c.filter,
  limit: c.limit ?? Number.POSITIVE_INFINITY,
}));
const clientMessages = clientMessageCases
  .filter((c) => c.error === undefined)
  .map((c) => ({ raw: c.raw, expected: c.encoded ?? c.raw }));
const clientMessagesInvalid = clientMessageCases.filter((c) => c.error !== undefined);
const relayMessages = relayMessageCases
  .filter((c) => c.error === undefined)
  .map((c) => ({ raw: c.raw, expected: c.encoded ?? c.raw }));
const relayMessagesInvalid = relayMessageCases.filter((c) => c.error !== undefined);
const mergeHllValid = mergeHllCases.filter((c) => c.error === undefined);
const mergeHllInvalid = mergeHllCases.filter((c) => c.error !== undefined);
const addressParse = addressCases
  .filter((c): c is AddressParseCase => c.op === "parse")
  .map((c) => ({ input: c.input, expected: c.parsed ?? undefined }));
const addressFormats = addressCases.filter((c): c is AddressFormatCase => c.op === "format");
const normalizeUrlValid = normalizeUrlCases.filter((c) => c.error === undefined);
const normalizeUrlInvalid = normalizeUrlCases.filter((c) => c.error !== undefined);
const hexCallerValid = hexCases.filter((c) => c.op === "caller" && c.error === undefined);
const hexCallerInvalid = hexCases.filter((c) => c.op === "caller" && c.error !== undefined);
const hexWireValid = hexCases.filter((c) => c.op === "wire" && c.error === undefined);
const hexWireInvalid = hexCases.filter((c) => c.op === "wire" && c.error !== undefined);

describe("vectors/core", () => {
  test("event serialize: canonical serialization and id", () => {
    for (const c of serialize) {
      expect(serializeEvent(c.unsigned)).toBe(c.serialized);
      expect(getEventHash(c.unsigned)).toBe(c.id);
    }
  });

  test("event sign: signEvent with fixed aux reproduces id and sig", () => {
    for (const c of signed) {
      const aux = hexToBytes(c.aux);
      const backend: SigningBackend = {
        publicKey: (sk) => schnorr.getPublicKey(sk),
        sign: (id, sk) => schnorr.sign(id, sk, aux),
      };
      const keys = Keys.fromSecretKey(c.secretKey, backend);
      const event = signEvent(c.unsigned, keys);
      expect(event).toStrictEqual(c.event);
    }
  });

  test("event validate: invalid wire events rejected", () => {
    for (const c of invalidEvents) {
      expect(validateSignedEvent(JSON.parse(c.raw) as unknown)).toBe(false);
    }
  });

  test("filter match", () => {
    for (const c of matchFilterCases) {
      expect(matchFilter(c.filter, c.event)).toBe(c.matches);
    }
  });

  test("filter limit (null = unbounded)", () => {
    for (const c of filterLimits) {
      expect(getFilterLimit(c.filter)).toBe(c.limit);
    }
  });

  test("filter canonicalize and fingerprint", () => {
    for (const c of canonicalizeCases) {
      expect(JSON.stringify(canonicalizeFilter(c.input))).toBe(c.canonicalJson);
    }
    for (const c of fingerprintCases) {
      expect(filterFingerprint(c.filters)).toBe(c.fingerprint);
    }
  });

  test("client messages: parse -> encode", () => {
    for (const c of clientMessages) {
      expect(encodeClientMessage(parseClientMessage(c.raw))).toBe(c.expected);
    }
  });

  test("client messages: invalid rejected", () => {
    for (const c of clientMessagesInvalid) {
      expect(() => parseClientMessage(c.raw)).toThrow(MessageError);
    }
  });

  test("relay messages: parse -> encode", () => {
    for (const c of relayMessages) {
      expect(encodeRelayMessage(parseRelayMessage(c.raw))).toBe(c.expected);
    }
  });

  test("relay messages: invalid rejected", () => {
    for (const c of relayMessagesInvalid) {
      expect(() => parseRelayMessage(c.raw)).toThrow(MessageError);
    }
  });

  test("count hll merges sketches", () => {
    for (const c of mergeHllValid) {
      expect(mergeCountHll(c.inputs)).toBe(c.output);
    }
  });

  test("count hll rejects malformed sketches", () => {
    for (const c of mergeHllInvalid) {
      expect(() => mergeCountHll(c.inputs)).toThrow(MessageError);
    }
  });

  test("kind classification", () => {
    for (const c of kindCases) {
      expect(isRegularKind(c.kind)).toBe(c.regular);
      expect(isReplaceableKind(c.kind)).toBe(c.replaceable);
      expect(isEphemeralKind(c.kind)).toBe(c.ephemeral);
      expect(isAddressableKind(c.kind)).toBe(c.addressable);
      expect(classifyKind(c.kind)).toBe(c.class);
    }
  });

  test("tag address parse/format", () => {
    for (const c of addressParse) {
      expect(parseEventAddress(c.input)).toStrictEqual(c.expected);
    }
    for (const c of addressFormats) {
      expect(formatEventAddress(c.kind, c.pubkey, c.identifier)).toBe(c.formatted);
    }
  });

  test("hex: caller decode accepts any case", () => {
    for (const c of hexCallerValid) {
      expect(assertHex32(c.input, "hex")).toBe(c.output);
    }
  });

  test("hex: caller decode rejects malformed input", () => {
    for (const c of hexCallerInvalid) {
      expect(() => assertHex32(c.input, "hex")).toThrow(HexError);
    }
  });

  test("hex: wire decode is strict lowercase", () => {
    for (const c of hexWireValid) {
      expect(isHex32(c.input)).toBe(true);
      expect(bytesToHex(hexToBytes(c.input))).toBe(c.output);
    }
    for (const c of hexWireInvalid) {
      expect(isHex32(c.input)).toBe(false);
    }
  });

  test("url normalize", () => {
    for (const c of normalizeUrlValid) {
      expect(normalizeURL(c.input)).toBe(c.output);
    }
  });

  test("url normalize rejects invalid URLs", () => {
    for (const c of normalizeUrlInvalid) {
      expect(c.error).toBe("UrlError");
      expect(() => normalizeURL(c.input)).toThrow(UrlError);
    }
  });

  test("builder: unsigned wire JSON", () => {
    for (const c of builderValid) {
      const unsigned = runBuilderCase(c).createdAt(1_700_000_000).buildUnsigned(BUILD_PK);
      const wire = JSON.stringify({
        pubkey: unsigned.pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
      });
      expect(wire).toBe(c.unsignedJson);
    }
  });

  test("builder: invalid inputs raise EventValidationError", () => {
    for (const c of builderInvalid) {
      expect(c.error).toBe("EventValidationError");
      expect(() => runBuilderCase(c)).toThrow(EventValidationError);
    }
  });
});
