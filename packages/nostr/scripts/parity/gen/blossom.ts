/// <reference types="node" />
// Generates vectors/blossom/codec.json — run with
// `bun packages/nostr/scripts/parity/gen/all.ts` (or this file alone).
// Captures the TS Blossom semantics (URL hashing, server normalization,
// auth templates, authorization header, server lists, blob descriptors)
// as frozen vectors shared by the TS test suite
// (tests/vectors/blossom.test.ts) and crates/nk-core.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Event } from "../../../src/core/event.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import { hexToBytes } from "../../../src/core/util.ts";
import {
  blossomServerListEventBuilder,
  createAuthTemplate,
  encodeAuthorizationHeader,
  getHashFromURL,
  parseBlobDescriptor,
  parseBlossomServerList,
} from "../../../src/nips/blossom.ts";
import type { BlossomAuthVerb } from "../../../src/nips/blossom.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");
const vectors = join(root, "vectors/blossom");

const pkgJson: unknown = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
const version =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "0.0.0";

const PK = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const PK2 = "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc";
const ALICE = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
const AUX = hexToBytes("07".repeat(32));
const EPOCH = 1_700_000_000;

// oxlint-disable-next-line typescript/no-restricted-types -- the vector encodes "absent" as null
type HashCase = { name: string; input: string; out: string | null };
// oxlint-disable-next-line typescript/no-restricted-types -- the vector encodes "absent" as null
type ServerCase = { name: string; input: string; out: string | null };
type EndpointCase = { name: string; base: string; path: string; out: string };
type AuthCase = {
  name: string;
  verb: string;
  expiration: number;
  sha256?: string;
  message?: string;
  servers?: string[];
  out: unknown;
  rust?: boolean;
};
type HeaderCase = { name: string; event: Event; out: string };
type ServerListBuildCase = { name: string; servers: string[]; out: unknown };
type ServerListParseCase = { name: string; kind: number; tags: string[][]; out: unknown };
type DescriptorCase = { name: string; json: string; out: unknown };

const hashCases: HashCase[] = [];
const serverCases: ServerCase[] = [];
const endpointCases: EndpointCase[] = [];
const authCases: AuthCase[] = [];
const headerCases: HeaderCase[] = [];
const serverListBuildCases: ServerListBuildCase[] = [];
const serverListParseCases: ServerListParseCase[] = [];
const descriptorCases: DescriptorCase[] = [];

function hashCase(name: string, input: string): void {
  hashCases.push({ name, input, out: getHashFromURL(input) ?? null });
}

/// `parseHttpUrl` via the list builder: normalized base or undefined.
function normalizeServer(input: string): string | undefined {
  try {
    return blossomServerListEventBuilder([input]).toTemplate().tags.at(0)?.at(1);
  } catch {
    return undefined;
  }
}

function serverCase(name: string, input: string): void {
  serverCases.push({ name, input, out: normalizeServer(input) ?? null });
}

// Mirrors `blossomUrl(base, path)` — parseHttpUrl is private, so a
// list builder's normalized tag gives the same base.
function endpointCase(name: string, base: string, path: string): void {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  endpointCases.push({ name, base, path, out: `${normalizeServer(base) ?? ""}${suffix}` });
}

function authCase(name: string, verb: string, opts: Omit<AuthCase, "name" | "verb" | "out">): void {
  let out: unknown;
  try {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- vector cases carry raw strings, one invalid verb on purpose
    const template = createAuthTemplate(verb as BlossomAuthVerb, opts);
    out = { tags: template.tags, content: template.content };
  } catch {
    out = { err: true };
  }
  authCases.push({ name, verb, out, ...opts });
}

function headerCase(name: string, kind: number, tags: string[][], content: string): void {
  const keys = Keys.fromSecretKey(ALICE);
  const signed = signEvent(
    { pubkey: keys.publicKey, created_at: EPOCH, kind, tags, content },
    keys,
    AUX,
  );
  // Reorder into the canonical (relay wire) key order — what a
  // JSON.parse'd event object looks like — so `JSON.stringify` matches
  // Rust `Event::to_json` byte-for-byte.
  const event: Event = {
    id: signed.id,
    pubkey: signed.pubkey,
    created_at: signed.created_at,
    kind: signed.kind,
    tags: signed.tags,
    content: signed.content,
    sig: signed.sig,
  };
  headerCases.push({ name, event, out: encodeAuthorizationHeader(event) });
}

function serverListBuildCase(name: string, servers: string[]): void {
  let out: unknown;
  try {
    out = { tags: blossomServerListEventBuilder(servers).toTemplate().tags };
  } catch {
    out = { err: true };
  }
  serverListBuildCases.push({ name, servers, out });
}

function serverListParseCase(name: string, kind: number, tags: string[][]): void {
  let out: unknown;
  try {
    out = parseBlossomServerList({ kind, tags });
  } catch {
    out = { err: true };
  }
  serverListParseCases.push({ name, kind, tags, out });
}

function descriptorCase(name: string, doc: unknown): void {
  const json = JSON.stringify(doc);
  let out: unknown;
  try {
    out = parseBlobDescriptor(JSON.parse(json));
  } catch {
    out = { err: true };
  }
  descriptorCases.push({ name, json, out });
}

hashCase("hash in path", `https://cdn.example.com/${PK}`);
hashCase("uppercase folds", `https://cdn.example.com/${PK.toUpperCase()}`);
hashCase("hash with extension", `https://cdn.example.com/${PK}.png`);
hashCase("several hashes: last wins", `https://x.example/${PK}/${PK2}`);
hashCase("hash only in query is null", `https://x.example/img.png?sha=${PK}`);
hashCase("no hash", "https://x.example/blobs/view");
hashCase("invalid url", "not a url");

serverCase("trailing slash stripped", "https://cdn.example.com/");
serverCase("many trailing slashes", "http://localhost:8080///");
serverCase("path prefix kept", "https://x.example/api/");
serverCase("nested path prefix kept", "https://x.example/api/v2//");
serverCase("non-http scheme rejected", "wss://x.example");
serverCase("ftp rejected", "ftp://x.example");
serverCase("invalid url", "not a url");
serverCase("port kept", "https://x.example:8443/");

endpointCase("root server", "https://cdn.example.com/", "/upload");
endpointCase("path prefix", "https://x.example/api/", "/upload");
endpointCase("mirror", "https://x.example/api/v2//", "/mirror");
endpointCase("list", "https://cdn.example.com", `/list/${PK}`);

authCase("upload bare", "upload", { expiration: EPOCH + 3600 });
authCase("delete with sha256", "delete", { expiration: EPOCH + 60, sha256: PK });
authCase("uppercase sha256 folds", "delete", { expiration: EPOCH + 60, sha256: PK.toUpperCase() });
authCase("list custom expiration", "list", { expiration: EPOCH + 5 });
authCase("media message", "media", { expiration: EPOCH + 10, message: "photos!" });
authCase("get with servers", "get", {
  expiration: EPOCH + 30,
  sha256: PK2,
  servers: ["https://a.example.com", "A.EXAMPLE.COM", "ftp://b.com", "cdn.example.net"],
});
authCase("empty message", "upload", { expiration: EPOCH, message: "" });
authCase("whitespace message", "upload", { expiration: EPOCH, message: "   " });
authCase("invalid sha256", "delete", { expiration: EPOCH, sha256: "not-hex" });
authCase("unknown verb", "mirror", { expiration: EPOCH, rust: false });

headerCase(
  "upload auth",
  24242,
  [
    ["t", "upload"],
    ["expiration", String(EPOCH + 3600)],
  ],
  "Upload Blob",
);
headerCase(
  "delete auth",
  24242,
  [
    ["t", "delete"],
    ["expiration", String(EPOCH)],
    ["x", PK],
  ],
  "bye",
);

serverListBuildCase("dedupe and normalize", [
  "https://a.example.com/",
  "HTTPS://A.EXAMPLE.COM/",
  "wss://b.example.com",
  "http://b.example.com/api/",
  "not a url",
]);
serverListBuildCase("single server", ["https://cdn.example.com/"]);
serverListBuildCase("all invalid", ["wss://a.example.com", "not a url", ""]);
serverListBuildCase("empty list", []);

serverListParseCase("round trip", 10063, [
  ["server", "https://a.example.com/"],
  ["server", "https://a.example.com"],
  ["relay", "wss://ignored.example.com"],
  ["server", "not a url"],
]);
serverListParseCase("empty ok", 10063, []);
serverListParseCase("wrong kind", 1, [["server", "https://a.example.com"]]);
serverListParseCase("missing value skipped", 10063, [
  ["server"],
  ["server", ""],
  ["server", "https://a.example.com"],
]);

descriptorCase("full", {
  url: `https://cdn.example.com/${PK}`,
  sha256: PK,
  size: 42,
  type: "image/png",
  uploaded: EPOCH,
});
descriptorCase("minimal", { url: `https://cdn.example.com/${PK}`, sha256: PK, size: 0 });
descriptorCase("uppercase sha256 folds", {
  url: "https://x.example/b",
  sha256: PK.toUpperCase(),
  size: 7,
});
descriptorCase("missing url", { sha256: PK, size: 1 });
descriptorCase("empty url", { url: "", sha256: PK, size: 1 });
descriptorCase("bad sha256", { url: "https://x.example/b", sha256: "nope", size: 1 });
descriptorCase("missing sha256", { url: "https://x.example/b", size: 1 });
descriptorCase("negative size", { url: "https://x.example/b", sha256: PK, size: -1 });
descriptorCase("fractional size", { url: "https://x.example/b", sha256: PK, size: 1.5 });
descriptorCase("missing size", { url: "https://x.example/b", sha256: PK });
descriptorCase("wrong-typed type dropped", {
  url: "https://x.example/b",
  sha256: PK,
  size: 1,
  type: 42,
});
descriptorCase("wrong-typed uploaded dropped", {
  url: "https://x.example/b",
  sha256: PK,
  size: 1,
  uploaded: "later",
});
descriptorCase("negative uploaded dropped", {
  url: "https://x.example/b",
  sha256: PK,
  size: 1,
  uploaded: -5,
});
descriptorCase("non-object", [1, 2]);

mkdirSync(vectors, { recursive: true });
const doc = {
  schema: 1,
  capability: "blossom.codec",
  source: { kind: "generated", generator: "@qntx/nostr", version },
  hash_from_url: hashCases,
  server: serverCases,
  endpoint: endpointCases,
  auth: authCases,
  header: headerCases,
  server_list_build: serverListBuildCases,
  server_list_parse: serverListParseCases,
  descriptor: descriptorCases,
};
writeFileSync(join(vectors, "codec.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(
  `blossom codec: ${hashCases.length} hash + ${serverCases.length} server + ${endpointCases.length} endpoint + ${authCases.length} auth + ${headerCases.length} header + ${serverListBuildCases.length} build + ${serverListParseCases.length} parse + ${descriptorCases.length} descriptor cases written`,
);
