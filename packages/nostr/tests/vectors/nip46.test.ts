import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type {
  BunkerPointer,
  NostrConnectParams,
  Nip46Request,
  Nip46Response,
} from "../../src/nips/nip46.ts";
import {
  Nip46Error,
  createNostrConnectURI,
  decodeNip46Request,
  decodeNip46Response,
  encodeNip46Request,
  encodeNip46Response,
  parseBunkerURL,
  parseNostrConnectURI,
  toBunkerURL,
} from "../../src/nips/nip46.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type BunkerJson = { pubkey: string; relays: string[]; secret: string | null };
type ConnectJson = {
  clientPubkey: string;
  relays: string[];
  secret: string;
  perms: string[];
  name: string | null;
  url: string | null;
  image: string | null;
};
type RequestJson = { id: string; method: string; params: string[] };
type ResponseJson = { id: string; result: string | null; error: string | null };

type Codec = {
  bunker_parse: Array<{ name: string; uri: string; out: BunkerJson | null }>;
  bunker: Array<{
    name: string;
    pubkey: string;
    relays: string[];
    secret?: string;
    out: string;
  }>;
  connect_parse: Array<{ name: string; uri: string; out?: ConnectJson; err?: string }>;
  connect: Array<{
    name: string;
    input: NostrConnectParams;
    out?: string;
    err?: string;
  }>;
  request: Array<{ name: string; request: RequestJson; json: string }>;
  request_parse: Array<{ name: string; json: string; out?: RequestJson; err?: string }>;
  response: Array<{ name: string; response: ResponseJson; json: string }>;
  response_parse: Array<{ name: string; json: string; out?: ResponseJson; err?: string }>;
};

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip46/codec.json"), "utf8"),
) as Codec;

const bunkerJson = (p: BunkerPointer): BunkerJson => ({
  pubkey: p.pubkey,
  relays: [...p.relays],
  secret: p.secret ?? null,
});

const bunkerOrNull = (p: BunkerPointer | undefined): BunkerJson | null =>
  p === undefined ? null : bunkerJson(p);

const connectJson = (p: NostrConnectParams): ConnectJson => ({
  clientPubkey: p.clientPubkey,
  relays: [...p.relays],
  secret: p.secret,
  perms: [...(p.perms ?? [])],
  name: p.name ?? null,
  url: p.url ?? null,
  image: p.image ?? null,
});

const requestJson = (r: Nip46Request): RequestJson => ({
  id: r.id,
  method: r.method,
  params: [...r.params],
});

const responseJson = (r: Nip46Response): ResponseJson => ({
  id: r.id,
  result: r.result ?? null,
  error: r.error ?? null,
});

// `null` in the vector means the field was absent — rebuild the sparse
// object without conditional statements inside the test body.
const responseFrom = (j: ResponseJson): Nip46Response => ({
  id: j.id,
  ...(typeof j.result === "string" ? { result: j.result } : {}),
  ...(typeof j.error === "string" ? { error: j.error } : {}),
});

const connectParseOk = codec.connect_parse.filter((c) => c.out !== undefined);
const connectParseErr = codec.connect_parse.filter((c) => c.err !== undefined);
const connectOk = codec.connect.filter((c) => c.out !== undefined);
const connectErr = codec.connect.filter((c) => c.err !== undefined);
const requestParseOk = codec.request_parse.filter((c) => c.out !== undefined);
const requestParseErr = codec.request_parse.filter((c) => c.err !== undefined);
const responseParseOk = codec.response_parse.filter((c) => c.out !== undefined);
const responseParseErr = codec.response_parse.filter((c) => c.err !== undefined);

describe("vectors/nip46/codec.json", () => {
  test.each(codec.bunker_parse)("parseBunkerURL: $name", (c) => {
    expect(bunkerOrNull(parseBunkerURL(c.uri))).toStrictEqual(c.out);
  });

  test.each(codec.bunker)("toBunkerURL encodes: $name", (c) => {
    expect(toBunkerURL({ pubkey: c.pubkey, relays: c.relays, secret: c.secret })).toBe(c.out);
  });

  test.each(connectParseOk)("parseNostrConnectURI parses: $name", (c) => {
    expect(connectJson(parseNostrConnectURI(c.uri))).toStrictEqual(c.out);
  });

  test.each(connectParseErr)("parseNostrConnectURI rejects: $name", (c) => {
    expect(() => parseNostrConnectURI(c.uri)).toThrow(Nip46Error);
  });

  test.each(connectOk)("createNostrConnectURI builds: $name", (c) => {
    expect(createNostrConnectURI(c.input)).toBe(c.out);
  });

  test.each(connectErr)("createNostrConnectURI rejects: $name", (c) => {
    expect(() => createNostrConnectURI(c.input)).toThrow(Nip46Error);
  });

  test.each(codec.request)("encodeNip46Request/decodeNip46Request: $name", (c) => {
    expect(encodeNip46Request(c.request)).toBe(c.json);
    expect(decodeNip46Request(c.json)).toStrictEqual(c.request);
  });

  test.each(requestParseOk)("decodeNip46Request parses: $name", (c) => {
    expect(requestJson(decodeNip46Request(c.json))).toStrictEqual(c.out);
  });

  test.each(requestParseErr)("decodeNip46Request rejects: $name", (c) => {
    expect(() => decodeNip46Request(c.json)).toThrow(Nip46Error);
  });

  test.each(codec.response)("encodeNip46Response/decodeNip46Response: $name", (c) => {
    const response = responseFrom(c.response);
    expect(encodeNip46Response(response)).toBe(c.json);
    expect(decodeNip46Response(c.json)).toStrictEqual(response);
  });

  test.each(responseParseOk)("decodeNip46Response parses: $name", (c) => {
    expect(responseJson(decodeNip46Response(c.json))).toStrictEqual(c.out);
  });

  test.each(responseParseErr)("decodeNip46Response rejects: $name", (c) => {
    expect(() => decodeNip46Response(c.json)).toThrow(Nip46Error);
  });
});
