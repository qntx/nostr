/// <reference types="node" />
// Generates vectors/nip46/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS NIP-46 URI codecs (`parseBunkerURL`/`toBunkerURL`,
// `createNostrConnectURI`/`parseNostrConnectURI`) and RPC JSON codecs
// (`encode`/`decode` `Nip46Request`/`Nip46Response`) as frozen vectors shared
// by the TS test suite (tests/vectors/nip46.test.ts) and the nk-* Rust
// crates. All cases go through the real exported functions — nothing is
// hand-computed.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { NostrConnectParams, Nip46Request, Nip46Response } from "../../../src/nips/nip46.ts";
import {
  createNostrConnectURI,
  decodeNip46Request,
  decodeNip46Response,
  encodeNip46Request,
  encodeNip46Response,
  parseBunkerURL,
  parseNostrConnectURI,
  toBunkerURL,
} from "../../../src/nips/nip46.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/nip46");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";

/** Normalized `parseBunkerURL` output: `secret`/`undefined` → null. */
type BunkerJson = {
  pubkey: string;
  relays: string[];
  // oxlint-disable-next-line no-restricted-types -- the vector encodes "absent" as null
  secret: string | null;
};

/** Normalized `parseNostrConnectURI` output: absent metadata → null. */
type ConnectJson = {
  clientPubkey: string;
  relays: string[];
  secret: string;
  perms: string[];
  // oxlint-disable no-restricted-types -- the vector encodes "absent" as null
  name: string | null;
  url: string | null;
  image: string | null;
  // oxlint-enable no-restricted-types
};

type RequestJson = { id: string; method: string; params: string[] };
type ResponseJson = {
  id: string;
  // oxlint-disable no-restricted-types -- the vector encodes "absent" as null
  result: string | null;
  error: string | null;
  // oxlint-enable no-restricted-types
};

type BunkerParseCase = {
  name: string;
  uri: string;
  // oxlint-disable-next-line no-restricted-types -- `null` records the TS `undefined` return
  out: BunkerJson | null;
};
type BunkerCase = {
  name: string;
  pubkey: string;
  relays: string[];
  secret?: string | undefined;
  out: string;
};
type ConnectParseCase = { name: string; uri: string; out?: ConnectJson; err?: string };
type ConnectCase = { name: string; input: NostrConnectParams; out?: string; err?: string };
type RequestCase = { name: string; request: RequestJson; json: string };
type RequestParseCase = { name: string; json: string; out?: RequestJson; err?: string };
type ResponseCase = { name: string; response: ResponseJson; json: string };
type ResponseParseCase = { name: string; json: string; out?: ResponseJson; err?: string };

const bunkerParseCases: BunkerParseCase[] = [];
const bunkerCases: BunkerCase[] = [];
const connectParseCases: ConnectParseCase[] = [];
const connectCases: ConnectCase[] = [];
const requestCases: RequestCase[] = [];
const requestParseCases: RequestParseCase[] = [];
const responseCases: ResponseCase[] = [];
const responseParseCases: ResponseParseCase[] = [];

const errorName = (error: unknown): string => (error instanceof Error ? error.name : "Error");

function bunkerParseCase(name: string, uri: string): void {
  const parsed = parseBunkerURL(uri);
  bunkerParseCases.push({
    name,
    uri,
    out:
      parsed === undefined
        ? null
        : { pubkey: parsed.pubkey, relays: [...parsed.relays], secret: parsed.secret ?? null },
  });
}

function bunkerCase(name: string, pubkey: string, relays: string[], secret?: string): void {
  bunkerCases.push({ name, pubkey, relays, secret, out: toBunkerURL({ pubkey, relays, secret }) });
}

function connectParseCase(name: string, uri: string): void {
  try {
    const parsed = parseNostrConnectURI(uri);
    connectParseCases.push({ name, uri, out: connectJson(parsed) });
  } catch (error) {
    connectParseCases.push({ name, uri, err: errorName(error) });
  }
}

function connectJson(p: NostrConnectParams): ConnectJson {
  return {
    clientPubkey: p.clientPubkey,
    relays: [...p.relays],
    secret: p.secret,
    perms: [...(p.perms ?? [])],
    name: p.name ?? null,
    url: p.url ?? null,
    image: p.image ?? null,
  };
}

function connectCase(name: string, input: NostrConnectParams): void {
  try {
    connectCases.push({ name, input, out: createNostrConnectURI(input) });
  } catch (error) {
    connectCases.push({ name, input, err: errorName(error) });
  }
}

/** `json` is `encodeNip46Request(request)`; the same case checks decode. */
function requestCase(name: string, request: Nip46Request): void {
  const json = encodeNip46Request(request);
  const decoded = decodeNip46Request(json);
  requestCases.push({
    name,
    request: { id: request.id, method: request.method, params: [...request.params] },
    json,
  });
  requestParseCases.push({
    name: `round-trip ${name}`,
    json,
    out: { id: decoded.id, method: decoded.method, params: [...decoded.params] },
  });
}

function requestParseCase(name: string, json: string): void {
  try {
    const decoded = decodeNip46Request(json);
    requestParseCases.push({
      name,
      json,
      out: { id: decoded.id, method: decoded.method, params: [...decoded.params] },
    });
  } catch (error) {
    requestParseCases.push({ name, json, err: errorName(error) });
  }
}

function responseCase(name: string, response: Nip46Response): void {
  const json = encodeNip46Response(response);
  const decoded = decodeNip46Response(json);
  responseCases.push({
    name,
    response: {
      id: response.id,
      result: response.result ?? null,
      error: response.error ?? null,
    },
    json,
  });
  responseParseCases.push({
    name: `round-trip ${name}`,
    json,
    out: { id: decoded.id, result: decoded.result ?? null, error: decoded.error ?? null },
  });
}

function responseParseCase(name: string, json: string): void {
  try {
    const decoded = decodeNip46Response(json);
    responseParseCases.push({
      name,
      json,
      out: { id: decoded.id, result: decoded.result ?? null, error: decoded.error ?? null },
    });
  } catch (error) {
    responseParseCases.push({ name, json, err: errorName(error) });
  }
}

// bunker:// parsing
bunkerParseCase("bare pubkey", `bunker://${PK}`);
bunkerParseCase(
  "relays and secret",
  `bunker://${PK}?relay=wss%3A%2F%2Frelay.one&relay=wss%3A%2F%2Frelay.two%2Fp&secret=s%20e`,
);
bunkerParseCase(
  "plus-decoded relay and encoded secret",
  `bunker://${PK}?relay=wss%3A%2F%2Fa+b%2Fc&secret=x%26y%3Dz`,
);
bunkerParseCase("uppercase authority", `bunker://${PK.toUpperCase()}`);
bunkerParseCase(
  "percent-encoded authority",
  `bunker://%33bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d`,
);
bunkerParseCase("empty secret pair", `bunker://${PK}?secret=`);
bunkerParseCase("whitespace-padded input", `  bunker://${PK}  `);
bunkerParseCase("opaque-path fallback", `bunker:${PK}`);
bunkerParseCase("nip-05 identifier", "alice@example.com");
bunkerParseCase("non-bunker scheme", "https://bunker.example");
bunkerParseCase("nostrconnect is not bunker", `nostrconnect://${PK}?relay=wss%3A%2F%2Fr&secret=s`);
bunkerParseCase("non-hex authority", "bunker://xyz");
bunkerParseCase("short hex authority", `bunker://${PK.slice(0, 32)}`);
bunkerParseCase("userinfo shifts the authority", `bunker://${PK}@evil`);
bunkerParseCase("unparsable url", "bunker://[bad");

// toBunkerURL
bunkerCase("pubkey only", PK, []);
bunkerCase("relays and secret", PK, ["wss://relay.one", "wss://relay.two/p"], "s e");
bunkerCase("empty secret omitted", PK, ["wss://r"], "");
bunkerCase("reserved chars in secret", PK, [], "s e&c=");
bunkerCase("unicode relay", PK, ["wss://例え.jp/"], undefined);

// nostrconnect:// parsing
connectParseCase(
  "full metadata",
  `nostrconnect://${PK}?relay=wss%3A%2F%2Frelay.damus.io&relay=wss%3A%2F%2Frelay.two&secret=hunter2&perms=nip44_encrypt%2Csign_event&name=My+App&url=https%3A%2F%2Fmy.app%2F&image=https%3A%2F%2Fmy.app%2Fi.png`,
);
connectParseCase("minimal", `nostrconnect://${PK}?relay=wss%3A%2F%2Fr&secret=s`);
connectParseCase(
  "uppercase authority lowercased",
  `nostrconnect://${PK.toUpperCase()}?relay=r&secret=s`,
);
connectParseCase("empty perms list", `nostrconnect://${PK}?relay=r&secret=s&perms=`);
connectParseCase("comma-only perms", `nostrconnect://${PK}?relay=r&secret=s&perms=%2C`);
connectParseCase(
  "perms drop empty entries",
  `nostrconnect://${PK}?relay=r&secret=s&perms=a%2C%2Cb`,
);
connectParseCase("present-but-empty name kept", `nostrconnect://${PK}?relay=r&secret=s&name=`);
connectParseCase("first secret wins", `nostrconnect://${PK}?relay=r&secret=a&secret=b`);
connectParseCase("wrong scheme", `bunker://${PK}?secret=s&relay=r`);
connectParseCase("unparsable url", "not a uri at all");
connectParseCase("non-hex pubkey", "nostrconnect://xyz?secret=s&relay=r");
connectParseCase("empty authority", "nostrconnect:?secret=s&relay=r");
connectParseCase("missing secret", `nostrconnect://${PK}?relay=r`);
connectParseCase("empty secret", `nostrconnect://${PK}?relay=r&secret=`);
connectParseCase("missing relays", `nostrconnect://${PK}?secret=s`);
connectParseCase("empty relay kept", `nostrconnect://${PK}?relay=&secret=s`);

// createNostrConnectURI
connectCase("full metadata", {
  clientPubkey: PK,
  relays: ["wss://relay.damus.io", "wss://relay.two"],
  secret: "hunter2",
  perms: ["nip44_encrypt", "sign_event"],
  name: "My App",
  url: "https://my.app/",
  image: "https://my.app/i.png",
});
connectCase("minimal", { clientPubkey: PK, relays: ["wss://r"], secret: "s" });
connectCase("empty perms omitted", {
  clientPubkey: PK,
  relays: ["wss://r"],
  secret: "s",
  perms: [],
});
connectCase("empty metadata omitted", {
  clientPubkey: PK,
  relays: ["wss://r"],
  secret: "s",
  name: "",
  url: "",
  image: "",
});
connectCase("reserved chars encoded", {
  clientPubkey: PK,
  relays: ["wss://a&b/?x=1 y"],
  secret: "s&e=c r",
  name: "A&B",
});
connectCase("missing secret throws", { clientPubkey: PK, relays: ["wss://r"], secret: "" });
connectCase("missing relays throws", { clientPubkey: PK, relays: [], secret: "s" });
connectCase("uppercase client lowercased", {
  clientPubkey: PK.toUpperCase(),
  relays: ["wss://r"],
  secret: "s",
});
connectCase("non-hex client throws", { clientPubkey: "xyz", relays: ["wss://r"], secret: "s" });
connectCase("short client throws", {
  clientPubkey: PK.slice(0, 32),
  relays: ["wss://r"],
  secret: "s",
});

// request codec
requestCase("connect", {
  id: "req-1",
  method: "connect",
  params: [PK2, "secret-token"],
});
requestCase("sign_event with a json payload", {
  id: "2",
  method: "sign_event",
  params: [`{"kind":1,"content":"héllo"}`],
});
requestCase("empty params", { id: "3", method: "ping", params: [] });
requestCase("unicode and escapes", {
  id: "r\t4",
  method: "get_relays",
  params: ["héllo\nwörld", '"quoted"'],
});

requestParseCase("malformed json", `{"id":"x","method":"m","params":[`);
requestParseCase("non-object array", "[]");
requestParseCase("non-object number", "42");
requestParseCase("non-string id", `{"id":1,"method":"m","params":[]}`);
requestParseCase("missing method", `{"id":"x","params":[]}`);
requestParseCase("missing params", `{"id":"x","method":"m"}`);
requestParseCase("non-array params", `{"id":"x","method":"m","params":"p"}`);
requestParseCase("non-string param", `{"id":"x","method":"m","params":[1]}`);
// N10: JSON.parse accepts lone surrogates, serde_json does not.
requestParseCase("lone surrogate in id", `{"id":"\\ud800","method":"m","params":[]}`);
requestParseCase("lone surrogate in params", `{"id":"x","method":"m","params":["\\udfff"]}`);
requestParseCase("lone surrogate in a key", `{"\\ud800":"x","id":"i","method":"m","params":[]}`);
requestParseCase("extra fields ignored", `{"id":"x","method":"m","params":[],"extra":1}`);

// response codec
responseCase("result only", { id: "r1", result: "sig-value" });
responseCase("error only", { id: "r2", error: "denied" });
responseCase("neither field", { id: "r3" });
responseCase("both fields", { id: "r4", result: "ok", error: "late" });

responseParseCase("malformed json", `{"id":"r"`);
responseParseCase("non-object", `"text"`);
responseParseCase("missing id", `{"result":"x"}`);
responseParseCase("non-string id", `{"id":7}`);
responseParseCase("explicit nulls are absent", `{"id":"r","result":null,"error":null}`);
responseParseCase("non-string result", `{"id":"r","result":123}`);
responseParseCase("non-string error", `{"id":"r","error":{}}`);
responseParseCase("null error keeps result", `{"id":"r","result":"x","error":null}`);
responseParseCase("lone surrogate in result", `{"id":"r","result":"\\ud8ff"}`);
responseParseCase("extra fields ignored", `{"id":"r","result":"x","extra":[1,2]}`);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "nip46.codec",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  bunker_parse: bunkerParseCases,
  bunker: bunkerCases,
  connect_parse: connectParseCases,
  connect: connectCases,
  request: requestCases,
  request_parse: requestParseCases,
  response: responseCases,
  response_parse: responseParseCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `nip46 codec: ${bunkerParseCases.length} bunker-parse + ${bunkerCases.length} bunker + ` +
    `${connectParseCases.length} connect-parse + ${connectCases.length} connect + ` +
    `${requestCases.length} request + ${requestParseCases.length} request-parse + ` +
    `${responseCases.length} response + ${responseParseCases.length} response-parse cases written`,
);
