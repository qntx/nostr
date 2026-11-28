/* oxlint-disable vitest/no-conditional-in-test, vitest/no-conditional-expect -- vector cases branch on their encoded expectation class */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../../src/core/index.ts";
import { bytesToHex } from "../../src/core/index.ts";
import { isRecord } from "../../src/core/util.ts";
import {
  NwcError,
  decodeResponse,
  encodeRequestPayload,
  isResponseTo,
  negotiateEncryption,
  parseInfoEvent,
  parseNotificationPayload,
  parseNwcUri,
  parseResponsePayload,
} from "../../src/nips/nip47.ts";
import type { NwcMethod, NwcRequest, NwcResult } from "../../src/nips/nip47.ts";
import { KeysSigner } from "../../src/signer/keys.ts";

type Codec = {
  keys: { clientSecret: string };
  uri: Array<{ name: string; input: string; ok: boolean; expect?: Record<string, unknown> }>;
  info: Array<{
    name: string;
    event: Event;
    expect?: {
      methods?: string[];
      encryptions?: string[] | null;
      extensions?: string[];
      notifications?: string[];
      encryption?: string | null;
    };
    error?: boolean;
  }>;
  request: Array<{ name: string; request: NwcRequest; json: string }>;
  response: Array<{
    name: string;
    method: NwcMethod;
    json: string;
    expect?: Record<string, unknown> | null;
    error?: boolean;
    nonCanonicalJson?: boolean;
  }>;
  notification: Array<{
    name: string;
    json: string;
    expect?: Record<string, unknown> | null;
    error?: boolean;
  }>;
  envelope: Array<{ name: string; request: Event; response: Event; matches: boolean }>;
  encrypted: Array<{
    name: string;
    scheme: "nip44_v2" | "nip04";
    method: NwcMethod;
    request: Event;
    response: Event;
    expect: Record<string, unknown>;
  }>;
};

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip47/codec.json"), "utf8"),
) as Codec;

const undefNull = (value: unknown): unknown => {
  if (value === undefined) {
    return null;
  }
  if (Array.isArray(value)) {
    return value.map(undefNull);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, undefNull(entry)]));
  }
  return value;
};

const normalized = (value: unknown): unknown =>
  value === undefined ? null : undefNull(structuredClone(value));

describe("vectors/nip47/codec.json", () => {
  test.each(codec.uri)("uri: $name", (c) => {
    if (!c.ok) {
      expect(() => parseNwcUri(c.input)).toThrow(NwcError);
      return;
    }
    const parsed = parseNwcUri(c.input);
    expect(parsed.walletPubkey).toMatch(/^[0-9a-f]{64}$/);
    if (c.expect?.["walletPubkey"] !== undefined) {
      expect(parsed.walletPubkey).toBe(c.expect["walletPubkey"]);
    }
    if (c.expect?.["relays"] !== undefined) {
      expect([...parsed.relays]).toStrictEqual(c.expect["relays"]);
    }
    if (c.expect?.["secret"] !== undefined) {
      expect(bytesToHex(parsed.secret)).toBe(c.expect["secret"]);
    }
    if (c.expect?.["lud16"] !== undefined) {
      expect(parsed.lud16).toBe(c.expect["lud16"]);
    }
  });

  test.each(codec.info)("info: $name", (c) => {
    if (c.error === true) {
      expect(() => parseInfoEvent(c.event)).toThrow(NwcError);
      return;
    }
    const parsed = parseInfoEvent(c.event);
    if (c.expect?.methods !== undefined) {
      expect([...parsed.methods]).toStrictEqual(c.expect.methods);
    }
    if (c.expect?.encryptions !== undefined) {
      expect(parsed.encryptions === undefined ? null : [...parsed.encryptions]).toStrictEqual(
        c.expect.encryptions,
      );
    }
    if (c.expect?.extensions !== undefined) {
      expect([...parsed.extensions]).toStrictEqual(c.expect.extensions);
    }
    if (c.expect?.notifications !== undefined) {
      expect([...parsed.notifications]).toStrictEqual(c.expect.notifications);
    }
    if (c.expect?.encryption !== undefined) {
      if (c.expect.encryption === null) {
        expect(() => negotiateEncryption(parsed)).toThrow(NwcError);
      } else {
        expect(negotiateEncryption(parsed)).toBe(c.expect.encryption);
      }
    }
  });

  test.each(codec.request)("request json: $name", (c) => {
    expect(encodeRequestPayload(c.request)).toBe(c.json);
  });

  test.each(codec.response)("response payload: $name", (c) => {
    if (c.error === true) {
      expect(() => parseResponsePayload(c.method, c.json)).toThrow(NwcError);
      return;
    }
    const parsed = parseResponsePayload(c.method, c.json);
    if (!parsed.ok) {
      expect(normalized(parsed.error)).toStrictEqual(c.expect);
      return;
    }
    const got = normalized(parsed.result satisfies NwcResult);
    if (
      parsed.result.method === "get_budget" &&
      parsed.result.budget === undefined &&
      isRecord(got)
    ) {
      got["budget"] = null;
    }
    expect(got).toStrictEqual(c.expect);
  });

  test.each(codec.notification)("notification payload: $name", (c) => {
    if (c.error === true) {
      expect(() => parseNotificationPayload(c.json)).toThrow(NwcError);
      return;
    }
    expect(normalized(parseNotificationPayload(c.json))).toStrictEqual(c.expect);
  });

  test.each(codec.envelope)("response envelope: $name", (c) => {
    expect(
      isResponseTo(c.response, {
        event: c.request,
        method: "get_balance",
        encryption: "nip44_v2",
      }),
    ).toBe(c.matches);
  });

  test.each(codec.encrypted)("encrypted response: $name", async (c) => {
    const signer = new KeysSigner(codec.keys.clientSecret);
    try {
      const decoded = await decodeResponse(signer, c.response, {
        event: c.request,
        method: c.method,
        encryption: c.scheme,
      });
      if (!decoded.ok) {
        throw new Error("vector response unexpectedly carries an error");
      }
      expect(normalized(decoded.result)).toStrictEqual(c.expect);
    } finally {
      signer.dispose();
    }
  });
});
