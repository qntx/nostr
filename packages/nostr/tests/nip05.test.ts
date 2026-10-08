import { describe, expect, test } from "vite-plus/test";

import {
  NIP05_REGEX,
  Nip05Error,
  isNip05,
  lookupFromDocument,
  parseNip05,
  parseNip05Document,
  queryProfile,
  verifyNip05,
  wellKnownUrl,
  queryNip05Document,
} from "../src/nips/nip05.ts";
import type { Nip05Fetch } from "../src/nips/nip05.ts";

const hasKey = (obj: object | undefined, key: string): boolean => key in (obj ?? {});

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc";

const nip05Cases: Array<[string, boolean]> = [
  ["bob@example.com", true],
  ["Bob.Smith-99@EXAMPLE.com", true],
  ["_@example.com", true],
  ["example.com", true],
  ["a+b@example.com", false],
  ["a b@example.com", false],
  ["a%b@example.com", false],
  ["a/b@example.com", false],
  ["日本語@example.com", false],
];

describe("nip05 parse", () => {
  test("NIP05_REGEX and isNip05", () => {
    expect(NIP05_REGEX.test("_@bob.com.br")).toBe(true);
    expect(NIP05_REGEX.test("bob@bob.com.br")).toBe(true);
    expect(NIP05_REGEX.test("bob.com.br")).toBe(true);
    expect(NIP05_REGEX.test("b&b@bob.com.br")).toBe(false);
    expect(isNip05("bob@bob.com.br")).toBe(true);
    expect(isNip05("b&b@bob.com.br")).toBe(false);
    expect(isNip05(null)).toBe(false);
  });

  test("parseNip05 forms", () => {
    expect(parseNip05("Bob@Example.COM")).toStrictEqual({ local: "bob", domain: "example.com" });
    expect(parseNip05("_@example.com")).toStrictEqual({ local: "_", domain: "example.com" });
    expect(parseNip05("example.com")).toStrictEqual({ local: "_", domain: "example.com" });
    expect(() => parseNip05("not an id")).toThrow(/invalid NIP-05/);
  });

  test.each(nip05Cases)("isNip05(%s) = %s", (input, valid) => {
    expect(isNip05(input)).toBe(valid);
  });

  test.each(nip05Cases.filter(([, valid]) => valid))("parseNip05(%s) parses", (input) => {
    expect(() => parseNip05(input)).not.toThrow();
  });

  test.each(nip05Cases.filter(([, valid]) => !valid))("parseNip05(%s) rejects", (input) => {
    expect(() => parseNip05(input)).toThrow(Nip05Error);
  });

  test("wellKnownUrl", () => {
    expect(wellKnownUrl({ local: "bob", domain: "example.com" })).toBe(
      "https://example.com/.well-known/nostr.json?name=bob",
    );
    expect(wellKnownUrl({ local: "_", domain: "example.com" })).toBe(
      "https://example.com/.well-known/nostr.json?name=_",
    );
  });

  test("parseNip05Document and lookupFromDocument", () => {
    const doc = parseNip05Document({
      names: { Bob: PK.toUpperCase(), _: PK2 },
      relays: {
        [PK.toUpperCase()]: ["wss://a.example", "wss://b.example"],
      },
    });
    expect(doc.names["bob"]).toBe(PK);
    expect(lookupFromDocument(doc, { local: "bob", domain: "example.com" })).toStrictEqual({
      pubkey: PK,
      relays: ["wss://a.example", "wss://b.example"],
    });
    expect(lookupFromDocument(doc, { local: "_", domain: "example.com" })).toStrictEqual({
      pubkey: PK2,
    });
    expect(lookupFromDocument(doc, { local: "missing", domain: "example.com" })).toBeUndefined();
  });

  test("parseNip05Document nip46 appendix shape; ignores hex-pubkey maps", () => {
    const spec = parseNip05Document({
      names: { bob: PK },
      nip46: {
        relays: ["wss://spec.example", ""],
        nostrconnect_url: "nostrconnect://abc",
      },
    });
    expect(spec.nip46).toStrictEqual({
      relays: ["wss://spec.example"],
      nostrconnectUrl: "nostrconnect://abc",
    });
    expect(hasKey(spec.nip46, "relaysByPubkey")).toBe(false);

    const hexOnly = parseNip05Document({
      names: { bob: PK },
      nip46: { [PK.toUpperCase()]: ["wss://bunker.example"] },
    });
    expect(hexOnly.nip46).toBeUndefined();

    const mixed = parseNip05Document({
      names: { bob: PK },
      relays: { [PK]: ["wss://profile.example"] },
      nip46: {
        relays: ["wss://spec.example"],
        nostrconnect_url: "nostrconnect://abc",
        [PK]: ["wss://map.example"],
      },
    });
    expect(mixed.nip46).toStrictEqual({
      relays: ["wss://spec.example"],
      nostrconnectUrl: "nostrconnect://abc",
    });
    expect(hasKey(mixed.nip46, "relaysByPubkey")).toBe(false);
    expect(lookupFromDocument(mixed, { local: "bob", domain: "example.com" })).toStrictEqual({
      pubkey: PK,
      relays: ["wss://profile.example"],
    });
  });

  test("parseNip05Document omits empty nip46", () => {
    const ignored = parseNip05Document({
      names: { bob: PK },
      nip46: { ignored: ["wss://x"] },
    });
    expect(ignored.nip46).toBeUndefined();

    const emptyRelays = parseNip05Document({
      names: { bob: PK },
      nip46: { relays: [] },
    });
    expect(emptyRelays.nip46).toStrictEqual({ relays: [] });

    const urlOnly = parseNip05Document({
      names: { bob: PK },
      nip46: { nostrconnect_url: "nostrconnect://abc" },
    });
    expect(urlOnly.nip46).toStrictEqual({ nostrconnectUrl: "nostrconnect://abc" });

    const emptyUrl = parseNip05Document({
      names: { bob: PK },
      nip46: { nostrconnect_url: "" },
    });
    expect(emptyUrl.nip46).toBeUndefined();

    const notObject = parseNip05Document({
      names: { bob: PK },
      nip46: ["wss://x"],
    });
    expect(notObject.nip46).toBeUndefined();

    const badUrlType = parseNip05Document({
      names: { bob: PK },
      nip46: { nostrconnect_url: 1 },
    });
    expect(badUrlType.nip46).toBeUndefined();
  });
});

describe("nip05 query", () => {
  function jsonResponse(status: number, body: unknown): Awaited<ReturnType<Nip05Fetch>> {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      json: async () => {
        await Promise.resolve();
        return body;
      },
      arrayBuffer: async () => {
        await Promise.resolve();
        return new ArrayBuffer(0);
      },
    };
  }

  function mockFetch(map: Record<string, { status: number; body: unknown }>): Nip05Fetch {
    return async (url, init) => {
      await Promise.resolve();
      expect(init?.redirect).toBe("manual");
      const entry = map[url];
      if (!entry) {
        return jsonResponse(404, {});
      }
      return jsonResponse(entry.status, entry.body);
    };
  }

  function abortError(): Error {
    const err = new Error("aborted");
    err.name = "AbortError";
    return err;
  }

  test("queryProfile resolves names and relays", async () => {
    const fetchImpl = mockFetch({
      "https://fiatjaf.com/.well-known/nostr.json?name=_": {
        status: 200,
        body: {
          names: { _: PK },
          relays: { [PK]: ["wss://pyramid.fiatjaf.com", "wss://nos.lol"] },
        },
      },
      "https://compile-error.net/.well-known/nostr.json?name=_": {
        status: 200,
        body: { names: { _: PK2 } },
      },
      "https://example.com/.well-known/nostr.json?name=alice": {
        status: 200,
        body: { names: { alice: PK } },
      },
    });

    const root = await queryProfile("fiatjaf.com", { fetch: fetchImpl });
    expect(root).toStrictEqual({
      pubkey: PK,
      relays: ["wss://pyramid.fiatjaf.com", "wss://nos.lol"],
    });

    const bare = await queryProfile("_@fiatjaf.com", { fetch: fetchImpl });
    expect(bare?.pubkey).toBe(PK);

    const other = await queryProfile("compile-error.net", { fetch: fetchImpl });
    expect(other?.pubkey).toBe(PK2);

    const named = await queryProfile("alice@example.com", { fetch: fetchImpl });
    expect(named?.pubkey).toBe(PK);
  });

  test("queryProfile rejects non-200 and missing names", async () => {
    const fetchImpl = mockFetch({
      "https://redir.example/.well-known/nostr.json?name=_": {
        status: 302,
        body: { names: { _: PK } },
      },
      "https://empty.example/.well-known/nostr.json?name=bob": {
        status: 200,
        body: { names: {} },
      },
    });

    await expect(queryProfile("redir.example", { fetch: fetchImpl })).resolves.toBeUndefined();
    await expect(queryProfile("bob@empty.example", { fetch: fetchImpl })).resolves.toBeUndefined();
    await expect(queryProfile("%%%", { fetch: fetchImpl })).resolves.toBeUndefined();
  });

  test("aborted signal throws AbortError, not null", async () => {
    const controller = new AbortController();
    controller.abort();
    const aborted = abortError();
    const fetchImpl: Nip05Fetch = (_url, init) => {
      expect(init?.signal).toBe(controller.signal);
      expect(init?.signal?.aborted).toBe(true);
      throw aborted;
    };
    await expect(
      queryNip05Document("bob@example.com", { fetch: fetchImpl, signal: controller.signal }),
    ).rejects.toBe(aborted);
  });

  test("network and parse failures return null, not Nip05Error", async () => {
    const net: Nip05Fetch = () => {
      throw new TypeError("fetch failed");
    };
    await expect(queryNip05Document("bob@example.com", { fetch: net })).resolves.toBeUndefined();
    await expect(queryProfile("bob@example.com", { fetch: net })).resolves.toBeUndefined();

    const badDoc: Nip05Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(200, { names: "nope" });
    };
    await expect(queryNip05Document("bob@example.com", { fetch: badDoc })).resolves.toBeUndefined();
  });

  test("verifyNip05", async () => {
    const fetchImpl = mockFetch({
      "https://example.com/.well-known/nostr.json?name=bob": {
        status: 200,
        body: { names: { bob: PK } },
      },
    });

    await expect(verifyNip05(PK, "bob@example.com", { fetch: fetchImpl })).resolves.toBe(true);
    await expect(verifyNip05(PK2, "bob@example.com", { fetch: fetchImpl })).resolves.toBe(false);
    await expect(verifyNip05("zz", "bob@example.com", { fetch: fetchImpl })).resolves.toBe(false);
  });
});
