import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/index.ts";
import type { NwcMethod } from "../src/nips/nip47.ts";
import {
  NwcError,
  decodeResponse,
  encodeRequest,
  parseConnectionUri,
  parseInfoEvent,
} from "../src/nips/nip47.ts";
import { KeysSigner } from "../src/signer/keys.ts";

type Case = {
  id: string;
  kind: "uri" | "info" | "response";
  input: unknown;
  request?: Event;
  method?: NwcMethod;
  ok: boolean;
  expect?: Record<string, unknown>;
};

const doc = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../vectors/nip47.json"), "utf8"),
) as { keys: { clientSecret: string; walletSecret: string; walletPubkey: string }; cases: Case[] };

const crypto = new KeysSigner(doc.keys.clientSecret);

describe("nip47 vectors", () => {
  const uriOk = doc.cases.filter((c) => c.kind === "uri" && c.ok);
  const uriBad = doc.cases.filter((c) => c.kind === "uri" && !c.ok);
  const info = doc.cases.filter((c) => c.kind === "info");
  const respOk = doc.cases.filter(
    (c) => c.kind === "response" && c.ok && c.expect?.["code"] === undefined,
  );
  const respErr = doc.cases.filter(
    (c) => c.kind === "response" && c.ok && c.expect?.["code"] !== undefined,
  );
  const respBad = doc.cases.filter((c) => c.kind === "response" && !c.ok);

  test.each(uriOk.map((c) => [c.id, c.input as string] as const))(
    "uri %s parses",
    (_id: string, uri: string) => {
      const conn = parseConnectionUri(uri);
      expect(conn.walletPubkey).toHaveLength(64);
      expect(conn.secret).toHaveLength(32);
      expect(conn.relays.length).toBeGreaterThan(0);
    },
  );

  test.each(uriBad.map((c) => [c.id, c.input as string] as const))(
    "uri %s rejects",
    (_id: string, uri: string) => {
      expect(() => parseConnectionUri(uri)).toThrow(NwcError);
    },
  );

  test.each(info.map((c) => [c.id, c] as const))("info %s parses", (_id: string, c: Case) => {
    const parsed = parseInfoEvent(c.input as Event);
    expect(parsed.methods).toStrictEqual(c.expect?.["methods"]);
    expect(parsed.nip44).toBe(c.expect?.["nip44"]);
  });

  test.each(respOk.map((c) => [c.id, c] as const))(
    "response %s decodes",
    async (_id: string, c: Case) => {
      const res = await decodeResponse(crypto, c.input as Event, {
        event: c.request!,
        method: c.method!,
      });
      expect(res.error).toBeNull();
    },
  );

  test.each(respErr.map((c) => [c.id, c] as const))(
    "response %s is the error arm",
    async (_id: string, c: Case) => {
      const res = await decodeResponse(crypto, c.input as Event, {
        event: c.request!,
        method: c.method!,
      });
      expect(res.error?.code).toBe(c.expect?.["code"]);
    },
  );

  test.each(respBad.map((c) => [c.id, c] as const))(
    "response %s rejects",
    async (_id: string, c: Case) => {
      await expect(
        decodeResponse(crypto, c.input as Event, {
          event: c.request!,
          method: c.method!,
        }),
      ).rejects.toThrow(NwcError);
    },
  );
});

describe("nip47 round-trip", () => {
  test("encodeRequest → kind/p/encryption tags; decodeResponse recovers the result", async () => {
    const wallet = new KeysSigner(doc.keys.walletSecret);
    const sent = await encodeRequest(crypto, doc.keys.walletPubkey, {
      method: "get_balance",
      params: {},
    });
    expect(sent.event.kind).toBe(23194);
    expect(sent.event.tags).toContainEqual(["p", doc.keys.walletPubkey]);
    expect(sent.event.tags).toContainEqual(["encryption", "nip44_v2"]);
    const reqPlain = await wallet.nip44Decrypt(crypto.keys.publicKey, sent.event.content);
    expect(JSON.parse(reqPlain).method).toBe("get_balance");

    // wallet answers
    const responsePayload = JSON.stringify({
      result_type: "get_balance",
      result: { balance: 42_000 },
      error: null,
    });
    const response = await wallet.signEvent({
      pubkey: await wallet.getPublicKey(),
      kind: 23195,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["p", crypto.keys.publicKey],
        ["e", sent.event.id],
      ],
      content: await wallet.nip44Encrypt(crypto.keys.publicKey, responsePayload),
    });
    const decoded = await decodeResponse(crypto, response, sent);
    expect(decoded.error).toBeNull();
    expect(decoded.result).toMatchObject({ method: "get_balance", balance: 42_000 });
    wallet.dispose();
    crypto.dispose();
  });
});
