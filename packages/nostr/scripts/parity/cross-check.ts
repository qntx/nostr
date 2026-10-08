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

// nostr-tools' sources import @noble/* packages, but the checkout has no
// installed dependencies and bun resolves bare specifiers from the importing
// file's directory upward. Link the workspace's @noble copies into the
// checkout (3rdparty/ is git-ignored, so this stays local).
const ntRoot = join(import.meta.dirname, "../../../../3rdparty/nostr-tools");
const ntNodeModules = join(ntRoot, "node_modules");
const nobleTarget = join(import.meta.dirname, "../../node_modules/@noble");
if (!existsSync(join(ntNodeModules, "@noble"))) {
  mkdirSync(ntNodeModules, { recursive: true });
  symlinkSync(nobleTarget, join(ntNodeModules, "@noble"), "dir");
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

console.log(`nostr-tools ${ntVersion} cross-check: ${failures} unexpected mismatches`);
if (failures > 0) {
  process.exitCode = 1;
}
