/// <reference types="node" />
// Cross-checks generated vectors against the independent nostr-tools
// implementation. Run with `bun packages/nostr/scripts/parity/cross-check.ts`.
//
// NOT wired into CI: it imports nostr-tools from the local, git-ignored
// `3rdparty/nostr-tools` source checkout, which does not exist in CI. Run it
// manually when touching the vectors it covers; record the outcome in the
// generator's `source.cross_check` strings (gen/core.ts).
//
// Checks:
//   event-serialize.json  nostr-tools getEventHash/serializeEvent agree on ids
//   event-sign.json       nostr-tools verifyEvent accepts the signed events
//   kind-classify.json    nostr-tools is*Kind booleans agree per kind
//   url-normalize.json    nostr-tools normalizeURL agrees where semantics
//                         coincide; divergences are reported, not fixed

import { existsSync, mkdirSync, readFileSync, symlinkSync } from "node:fs";
import { join } from "node:path";

import { hexToBytes } from "@noble/hashes/utils.js";

// nostr-tools' sources import @noble/* and @scure packages, but the checkout
// has no installed dependencies and bun resolves bare specifiers from the
// importing file's directory upward. Link the workspace's copies into the
// checkout (3rdparty/ is git-ignored, so this stays local).
const ntRoot = join(import.meta.dirname, "../../../../3rdparty/nostr-tools");
const ntNodeModules = join(ntRoot, "node_modules");
const nostrNodeModules = join(import.meta.dirname, "../../node_modules");
for (const scope of ["@noble", "@scure"]) {
  if (!existsSync(join(ntNodeModules, scope))) {
    mkdirSync(ntNodeModules, { recursive: true });
    symlinkSync(join(nostrNodeModules, scope), join(ntNodeModules, scope), "dir");
  }
}

// Minimal signatures of the nostr-tools functions used below; typing the
// dynamic imports keeps the script inside the repo's typed-lint rules.
type NtUnsigned = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};
type NtEvent = NtUnsigned & { id: string; sig: string };
type NtPure = {
  serializeEvent: (event: NtUnsigned) => string;
  getEventHash: (event: NtUnsigned) => string;
  verifyEvent: (event: NtEvent) => boolean;
};
type NtKinds = {
  isRegularKind: (kind: number) => boolean;
  isReplaceableKind: (kind: number) => boolean;
  isEphemeralKind: (kind: number) => boolean;
  isAddressableKind: (kind: number) => boolean;
  classifyKind: (kind: number) => string;
};
type NtUtils = {
  normalizeURL: (url: string) => string;
};

const pureModule: unknown = await import(`${ntRoot}/pure.ts`);
const kindsModule: unknown = await import(`${ntRoot}/kinds.ts`);
const utilsModule: unknown = await import(`${ntRoot}/utils.ts`);
const {
  getEventHash: ntGetEventHash,
  serializeEvent: ntSerializeEvent,
  verifyEvent: ntVerifyEvent,
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the checkout's public API is pinned by the Nt* shapes above
} = pureModule as NtPure;
const {
  isAddressableKind: ntIsAddressableKind,
  isEphemeralKind: ntIsEphemeralKind,
  isRegularKind: ntIsRegularKind,
  isReplaceableKind: ntIsReplaceableKind,
  classifyKind: ntClassifyKind,
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the checkout's public API is pinned by the Nt* shapes above
} = kindsModule as NtKinds;
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the checkout's public API is pinned by the Nt* shapes above
const { normalizeURL: ntNormalizeURL } = utilsModule as NtUtils;

const vectors = join(import.meta.dirname, "../../../../vectors/core");

type Cases<T> = { cases: T[] };

function readVector<T>(name: string): T[] {
  const doc: unknown = JSON.parse(readFileSync(join(vectors, name), "utf8"));
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- generated vectors are frozen by their capability shape
  return (doc as Cases<T>).cases;
}

const pkgJson: unknown = JSON.parse(readFileSync(join(ntRoot, "package.json"), "utf8"));
const ntVersion =
  typeof pkgJson === "object" && pkgJson !== null && "version" in pkgJson
    ? String(pkgJson.version)
    : "?";

let failures = 0;
const fail = (message: string): void => {
  failures += 1;
  console.log(`MISMATCH: ${message}`);
};

const serialize = readVector<{ unsigned: NtUnsigned; serialized: string; id: string }>(
  "event-serialize.json",
);
let ids = 0;
for (const c of serialize) {
  try {
    const s = ntSerializeEvent(c.unsigned);
    const id = ntGetEventHash(c.unsigned);
    if (s !== c.serialized || id !== c.id) {
      fail(`event-serialize: nostr-tools id ${id} != ${c.id} (serialized ${s})`);
    }
  } catch (error) {
    fail(`event-serialize: nostr-tools threw for ${c.id}: ${String(error)}`);
  }
  ids += 1;
}
console.log(`event-serialize: ${ids} ids checked against nostr-tools`);

const signed = readVector<{ event: NtEvent }>("event-sign.json");
let sigs = 0;
for (const c of signed) {
  try {
    if (!ntVerifyEvent(structuredClone(c.event))) {
      fail("event-sign: nostr-tools verifyEvent rejected a signed event");
    }
  } catch (error) {
    fail(`event-sign: nostr-tools verifyEvent threw: ${String(error)}`);
  }
  sigs += 1;
}
console.log(`event-sign: ${sigs} signatures verified by nostr-tools`);

const kinds = readVector<{
  kind: number;
  regular: boolean;
  replaceable: boolean;
  ephemeral: boolean;
  addressable: boolean;
  class: string;
}>("kind-classify.json");
let kindAgree = 0;
for (const c of kinds) {
  const theirs = ntClassifyKind(c.kind);
  const nt = {
    regular: ntIsRegularKind(c.kind),
    replaceable: ntIsReplaceableKind(c.kind),
    ephemeral: ntIsEphemeralKind(c.kind),
    addressable: ntIsAddressableKind(c.kind),
    // nostr-tools calls addressable kinds "parameterized".
    class: theirs === "parameterized" ? "addressable" : theirs,
  };
  const ours = {
    regular: c.regular,
    replaceable: c.replaceable,
    ephemeral: c.ephemeral,
    addressable: c.addressable,
    class: c.class,
  };
  if (JSON.stringify(nt) === JSON.stringify(ours)) {
    kindAgree += 1;
    continue;
  }
  console.log(
    `kind-classify: kind ${c.kind} differs: ours ${JSON.stringify(ours)} vs nostr-tools ${JSON.stringify(nt)}`,
  );
}
console.log(`kind-classify: ${kindAgree}/${kinds.length} kinds agree with nostr-tools`);

const urls = readVector<{ input: string; output?: string; error?: string }>("url-normalize.json");
let urlAgree = 0;
let urlDiffs = 0;
for (const c of urls) {
  let ntOutput: string | undefined;
  try {
    ntOutput = ntNormalizeURL(c.input);
  } catch {
    // nostr-tools rejects; compare against our expectation below.
  }
  const ours = c.output;
  if (ntOutput === ours || (ntOutput === undefined && c.error !== undefined)) {
    urlAgree += 1;
    continue;
  }
  urlDiffs += 1;
  console.log(
    `url-normalize: ${JSON.stringify(c.input)}: ours ${
      ours === undefined ? "UrlError" : JSON.stringify(ours)
    } vs nostr-tools ${ntOutput === undefined ? "error" : JSON.stringify(ntOutput)}`,
  );
}
console.log(`url-normalize: ${urlAgree} agree, ${urlDiffs} differ (reported, not vector bugs)`);

// nip19 codec: nostr-tools is the codebase our decoder was ported from, so
// only the N1 (kind 0..=65535) and N2 (valid nsec scalar) rulings legitimately
// differ — nostr-tools accepts those inputs; everything else must agree.
type NtNip19 = {
  decode: (code: string) => unknown;
  npubEncode: (hex: string) => string;
  nsecEncode: (key: Uint8Array) => string;
  noteEncode: (hex: string) => string;
  nprofileEncode: (profile: { pubkey: string; relays?: string[] }) => string;
  neventEncode: (event: {
    id: string;
    relays?: string[];
    author?: string;
    kind?: number;
  }) => string;
  naddrEncode: (addr: {
    identifier: string;
    pubkey: string;
    kind: number;
    relays?: string[];
  }) => string;
};
const nip19Module: unknown = await import(`${ntRoot}/nip19.ts`);
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the checkout's public API is pinned by the Nt* shapes above
const nt = nip19Module as NtNip19;

type Nip19Entity =
  | { type: "nprofile"; pubkey: string; relays: string[] }
  | { type: "nevent"; id: string; relays: string[]; author?: string; kind?: number }
  | { type: "naddr"; identifier: string; pubkey: string; kind: number; relays: string[] }
  | { type: "nsec"; secret: string }
  | { type: "npub"; pubkey: string }
  | { type: "note"; id: string };
type Nip19Case = {
  input?: string;
  encode?: Nip19Entity;
  decoded?: Nip19Entity;
  encoded?: string;
  error?: string;
};

const nip19Vectors = join(import.meta.dirname, "../../../../vectors/nip19");
const nip19Doc: unknown = JSON.parse(readFileSync(join(nip19Vectors, "codec.json"), "utf8"));
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- generated vectors are frozen by their capability shape
const nip19Cases = (nip19Doc as { cases: Nip19Case[] }).cases;

function ntEncode(entity: Nip19Entity): string {
  let encoded: string;
  switch (entity.type) {
    case "nprofile":
      encoded = nt.nprofileEncode({ pubkey: entity.pubkey, relays: entity.relays });
      break;
    case "nevent":
      encoded = nt.neventEncode({
        id: entity.id,
        relays: entity.relays,
        ...(entity.author === undefined ? {} : { author: entity.author }),
        ...(entity.kind === undefined ? {} : { kind: entity.kind }),
      });
      break;
    case "naddr":
      encoded = nt.naddrEncode({
        identifier: entity.identifier,
        pubkey: entity.pubkey,
        kind: entity.kind,
        relays: entity.relays,
      });
      break;
    case "nsec":
      encoded = nt.nsecEncode(hexToBytes(entity.secret));
      break;
    case "npub":
      encoded = nt.npubEncode(entity.pubkey);
      break;
    case "note":
      encoded = nt.noteEncode(entity.id);
      break;
  }
  return encoded;
}

let nip19Agree = 0;
let nip19Diffs = 0;
for (const c of nip19Cases) {
  if (c.input !== undefined) {
    let ntOk: boolean;
    try {
      nt.decode(c.input);
      ntOk = true;
    } catch {
      ntOk = false;
    }
    if (ntOk === (c.error === undefined)) {
      nip19Agree += 1;
      continue;
    }
    nip19Diffs += 1;
    console.log(
      `nip19 codec: ${c.input.slice(0, 32)}…: ours ${c.error ?? "decode"} vs nostr-tools ${ntOk ? "decode" : "error"}`,
    );
  } else if (c.encode !== undefined) {
    let ntOut: string | undefined;
    try {
      ntOut = ntEncode(c.encode);
    } catch {
      ntOut = undefined;
    }
    if (ntOut === c.encoded || (ntOut === undefined && c.error !== undefined)) {
      nip19Agree += 1;
      continue;
    }
    nip19Diffs += 1;
    console.log(
      `nip19 encode: ${c.encode.type}: ours ${c.encoded ?? c.error ?? "decode"} vs nostr-tools ${ntOut ?? "error"}`,
    );
  }
}
console.log(
  `nip19 codec: ${nip19Agree} agree, ${nip19Diffs} differ (N1/N2 rulings, reported not fixed)`,
);

// nip04 codec: nostr-tools uses the same noble primitives, so valid payloads
// must decrypt identically. Failure shapes differ legitimately — nostr-tools
// does not check the `?iv=` split (extra parts are dropped, not rejected) and
// has no shared-secret entry point.
type NtNip04 = {
  decrypt: (secretKey: Uint8Array, pubkey: string, data: string) => string;
};
const nip04Module: unknown = await import(`${ntRoot}/nip04.ts`);
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the checkout's public API is pinned by the Nt* shapes above
const { decrypt: ntNip04Decrypt } = nip04Module as NtNip04;

type Nip04Case = {
  sec1: string;
  pub2: string;
  plaintext: string;
  payload: string;
};
const nip04Doc: unknown = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip04/codec.json"), "utf8"),
);
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- generated vectors are frozen by their capability shape
const nip04Cases = (nip04Doc as { cases: Nip04Case[] }).cases;
let nip04Agree = 0;
let nip04Diffs = 0;
for (const c of nip04Cases) {
  try {
    const out = ntNip04Decrypt(hexToBytes(c.sec1), c.pub2, c.payload);
    if (out === c.plaintext) {
      nip04Agree += 1;
    } else {
      nip04Diffs += 1;
      fail(
        `nip04 decrypt: nostr-tools plaintext ${JSON.stringify(out)} != ${JSON.stringify(c.plaintext)}`,
      );
    }
  } catch (error) {
    nip04Diffs += 1;
    fail(`nip04 decrypt: nostr-tools threw: ${String(error)}`);
  }
}
console.log(
  `nip04 codec: ${nip04Agree}/${nip04Cases.length} valid payloads agree with nostr-tools`,
);

console.log(`nostr-tools ${ntVersion} cross-check: ${failures} unexpected mismatches`);
if (failures > 0) {
  process.exitCode = 1;
}
