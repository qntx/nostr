import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { EventValidationError } from "../../src/core/error.ts";
import type { Event } from "../../src/core/event.ts";
import type { Tag } from "../../src/core/tag.ts";
import {
  BlossomError,
  blossomServerListEventBuilder,
  createAuthTemplate,
  encodeAuthorizationHeader,
  getHashFromURL,
  parseBlobDescriptor,
  parseBlossomServerList,
} from "../../src/nips/blossom.ts";
import type { BlobDescriptor, BlossomAuthVerb } from "../../src/nips/blossom.ts";

// Shared vectors replayed by crates/nk-core/tests/it/blossom.rs;
// regenerate with `bun packages/nostr/scripts/parity/gen/all.ts`.
type HashCase = { name: string; input: string; out: string | null };
type ServerCase = { name: string; input: string; out: string | null };
type EndpointCase = { name: string; base: string; path: string; out: string };
type AuthCase = {
  name: string;
  verb: string;
  expiration: number;
  sha256?: string;
  message?: string;
  servers?: string[];
  out: { tags: ReadonlyArray<Tag>; content: string } | { err: true };
  rust?: boolean;
};
type HeaderCase = { name: string; event: Event; out: string };
type ServerListBuildCase = {
  name: string;
  servers: string[];
  out: { tags: Tag[] } | { err: true };
};
type ServerListParseCase = {
  name: string;
  kind: number;
  tags: string[][];
  out: string[] | { err: true };
};
type DescriptorCase = { name: string; json: string; out: BlobDescriptor | { err: true } };

const codec = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/blossom/codec.json"), "utf8"),
) as {
  hash_from_url: HashCase[];
  server: ServerCase[];
  endpoint: EndpointCase[];
  auth: AuthCase[];
  header: HeaderCase[];
  server_list_build: ServerListBuildCase[];
  server_list_parse: ServerListParseCase[];
  descriptor: DescriptorCase[];
};

const descriptorOk = codec.descriptor.filter((c) => !("err" in c.out));
const descriptorErr = codec.descriptor.filter((c) => "err" in c.out);
const authOk = codec.auth.filter((c) => !("err" in c.out));
const authErr = codec.auth.filter((c) => "err" in c.out);
type BuildOut = { tags: ReadonlyArray<Tag> };
const buildOk = codec.server_list_build.filter(
  (c): c is ServerListBuildCase & { out: BuildOut } => !("err" in c.out),
);
const buildErr = codec.server_list_build.filter((c) => "err" in c.out);
const parseOk = codec.server_list_parse.filter((c) => !("err" in c.out));
const parseErr = codec.server_list_parse.filter((c) => "err" in c.out);

/// `parseHttpUrl` via the list builder: normalized base or null.
function normalizedServer(input: string): string | null {
  try {
    return blossomServerListEventBuilder([input]).toTemplate().tags.at(0)?.at(1) ?? null;
  } catch {
    return null;
  }
}

/// `blossomUrl(base, path)`: normalized base + path join.
function endpointUrl(base: string, path: string): string {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${normalizedServer(base) ?? ""}${suffix}`;
}

/// `getHashFromURL` with undefined flattened to null.
function hashOrNull(input: string): string | null {
  return getHashFromURL(input) ?? null;
}

function authTemplate(c: AuthCase): { tags: ReadonlyArray<Tag>; content: string } {
  const { verb, ...opts } = c;
  const template = createAuthTemplate(verb as BlossomAuthVerb, {
    sha256: opts.sha256,
    expiration: opts.expiration,
    message: opts.message,
    servers: opts.servers,
  });
  return { tags: template.tags, content: template.content };
}

describe("vectors/blossom/codec.json", () => {
  test.each(codec.hash_from_url)("getHashFromURL: $name", (c) => {
    expect(hashOrNull(c.input)).toBe(c.out);
  });

  test.each(codec.server)("server normalization: $name", (c) => {
    expect(normalizedServer(c.input)).toBe(c.out);
  });

  test.each(codec.endpoint)("endpoint join: $name", (c) => {
    expect(endpointUrl(c.base, c.path)).toBe(c.out);
  });

  test.each(authOk)("createAuthTemplate: $name", (c) => {
    expect(authTemplate(c)).toStrictEqual(c.out);
  });

  test.each(authErr)("createAuthTemplate invalid: $name", (c) => {
    expect(() => authTemplate(c)).toThrow(Error);
  });

  test.each(codec.header)("encodeAuthorizationHeader: $name", (c) => {
    expect(encodeAuthorizationHeader(c.event)).toBe(c.out);
  });

  test.each(buildOk)("server list build: $name", (c) => {
    expect(blossomServerListEventBuilder(c.servers).toTemplate().tags).toStrictEqual(c.out.tags);
  });

  test.each(buildErr)("server list build invalid: $name", (c) => {
    expect(() => blossomServerListEventBuilder(c.servers)).toThrow(BlossomError);
  });

  test.each(parseOk)("server list parse: $name", (c) => {
    expect(parseBlossomServerList({ kind: c.kind, tags: c.tags })).toStrictEqual(c.out);
  });

  test.each(parseErr)("server list parse invalid: $name", (c) => {
    expect(() => parseBlossomServerList({ kind: c.kind, tags: c.tags })).toThrow(
      EventValidationError,
    );
  });

  test.each(descriptorOk)("parseBlobDescriptor: $name", (c) => {
    expect(parseBlobDescriptor(JSON.parse(c.json))).toStrictEqual(c.out);
  });

  test.each(descriptorErr)("parseBlobDescriptor invalid: $name", (c) => {
    // `assertHex32` errors are HexError, descriptor-shape errors BlossomError.
    expect(() => parseBlobDescriptor(JSON.parse(c.json))).toThrow(Error);
  });
});
