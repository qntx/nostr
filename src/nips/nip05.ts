/**
 * NIP-05: Mapping Nostr keys to DNS-based internet identifiers
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/05.md
 */
import { NostrError } from "../core/error.ts";
import { isHex32 } from "../core/util.ts";
import { fetchManual, requireGlobalFetch } from "./http.ts";
import type { ManualFetch } from "./http.ts";
import type { ProfilePointer } from "./nip19.ts";

/** Root local-part (`_@domain` rendered as just the domain). */
export const NIP05_ROOT_LOCAL = "_";

export const WELL_KNOWN_PATH = "/.well-known/nostr.json";

/**
 * NIP-05 identifier string.
 *
 * - Full: `name@domain`
 * - Root: `domain` or `_@domain`
 */
export type Nip05 = string;

export type Nip05Address = {
  /** Local part (lowercased). `_` for domain-only identifiers. */
  local: string;
  /** Domain (lowercased). */
  domain: string;
};

/** 46.md appendix discovery metadata (`{relays, nostrconnect_url}`). Not a bunker pointer. */
export type Nip05Nip46 = {
  relays?: string[];
  nostrconnectUrl?: string;
};

export type Nip05Document = {
  names: Record<string, string>;
  /** NIP-05 profile relay hints */
  relays?: Record<string, string[]>;
  nip46?: Nip05Nip46;
};

export type Nip05Fetch = ManualFetch;

export class Nip05Error extends NostrError {
  override name = "Nip05Error";
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}

/** Matches optional local@domain. Groups: 1=local (optional), 2=domain. */
// oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires the annotation for dts emit
export const NIP05_REGEX: RegExp = /^(?:([a-z0-9._-]+)@)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i;

export function isNip05(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  try {
    parseNip05(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Parse an identifier into local + domain. Accepts `name@domain`, `_@domain`, or bare `domain`
 * (local becomes `_`).
 */
export function parseNip05(input: string): Nip05Address {
  const match = NIP05_REGEX.exec(input.trim());
  const domain = match?.at(2);
  if (match === null || domain === undefined || domain === "") {
    throw new Nip05Error(`invalid NIP-05 identifier: ${input}`);
  }
  const localRaw = match.at(1) ?? NIP05_ROOT_LOCAL;
  return { local: localRaw.toLowerCase(), domain: domain.toLowerCase() };
}

/** Build the well-known HTTPS URL for an address. */
export function wellKnownUrl(address: Nip05Address): string {
  const url = new URL(`https://${address.domain}${WELL_KNOWN_PATH}`);
  url.searchParams.set("name", address.local);
  return url.toString();
}

function stringUrls(list: unknown): string[] | undefined {
  if (!Array.isArray(list)) {
    return undefined;
  }
  return list.filter((u): u is string => typeof u === "string" && u.length > 0);
}

/**
 * Parse nostr.json `nip46`: 46.md appendix `{relays, nostrconnect_url}`. Hex-pubkey maps and other
 * keys are ignored.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseNip05Nip46(raw: unknown): Nip05Nip46 | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const obj = raw;
  const result: Nip05Nip46 = {};

  if (Array.isArray(obj["relays"])) {
    result.relays = stringUrls(obj["relays"]) ?? [];
  }

  if (typeof obj["nostrconnect_url"] === "string" && obj["nostrconnect_url"].length > 0) {
    result.nostrconnectUrl = obj["nostrconnect_url"];
  }

  if (result.relays === undefined && result.nostrconnectUrl === undefined) {
    return undefined;
  }
  return result;
}

/** Parse and validate a nostr.json document body. */
export function parseNip05Document(json: unknown): Nip05Document {
  if (!isRecord(json)) {
    throw new Nip05Error("NIP-05 document must be a JSON object");
  }
  const raw = json;
  if (!isRecord(raw["names"])) {
    throw new Nip05Error("NIP-05 document missing names map");
  }

  const names: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw["names"])) {
    if (typeof v !== "string" || !isHex32(v.toLowerCase())) {
      continue;
    }
    names[k.toLowerCase()] = v.toLowerCase();
  }

  const rawRelays = raw["relays"];
  let relays: Record<string, string[]> | undefined;
  if (isRecord(rawRelays)) {
    relays = {};
    for (const [pk, list] of Object.entries(rawRelays)) {
      if (!isHex32(pk.toLowerCase())) {
        continue;
      }
      const urls = stringUrls(list);
      if (urls !== undefined && urls.length > 0) {
        relays[pk.toLowerCase()] = urls;
      }
    }
  }

  const doc: Nip05Document = { names };
  if (relays !== undefined) {
    doc.relays = relays;
  }
  const nip46 = parseNip05Nip46(raw["nip46"]);
  if (nip46 !== undefined) {
    doc.nip46 = nip46;
  }
  return doc;
}

/** Resolve local name from an already-parsed document. */
export function lookupFromDocument(
  doc: Nip05Document,
  address: Nip05Address,
): ProfilePointer | undefined {
  const pubkey = doc.names[address.local];
  if (pubkey === undefined) {
    return undefined;
  }
  const relays = doc.relays?.[pubkey];
  return relays !== undefined && relays.length > 0 ? { pubkey, relays: [...relays] } : { pubkey };
}

/**
 * Fetch and parse `/.well-known/nostr.json`. Returns `undefined` on network/parse failure (does not
 * throw for those). Rejects HTTP redirects (non-200) per NIP-05 security constraints. AbortError
 * rethrows; it is not mapped to `undefined`.
 */
export async function queryNip05Document(
  identifier: string,
  opts?: { fetch?: Nip05Fetch; signal?: AbortSignal },
): Promise<{ address: Nip05Address; doc: Nip05Document } | undefined> {
  let address: Nip05Address;
  try {
    address = parseNip05(identifier);
  } catch {
    return undefined;
  }

  const url = wellKnownUrl(address);
  const fetchImpl =
    opts?.fetch ??
    requireGlobalFetch(() => new Nip05Error("no fetch implementation available; pass opts.fetch"));

  try {
    const res = await fetchManual(fetchImpl, url, { signal: opts?.signal }, (err) =>
      err instanceof Error ? err : new Error("NIP-05 request failed"),
    );
    // Redirects and errors must not be trusted (NIP-05 security).
    if (res.status !== 200) {
      return undefined;
    }
    const json = await res.json();
    return { address, doc: parseNip05Document(json) };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw error;
    }
    return undefined;
  }
}

/**
 * Query `/.well-known/nostr.json` for an identifier. Returns `undefined` on network/parse/lookup
 * failure (does not throw for those). Profile `relays` only. `nip46` is discovery metadata, not a
 * bunker pointer.
 */
export async function queryProfile(
  identifier: string,
  opts?: { fetch?: Nip05Fetch; signal?: AbortSignal },
): Promise<ProfilePointer | undefined> {
  const fetched = await queryNip05Document(identifier, opts);
  if (fetched === undefined) {
    return undefined;
  }
  return lookupFromDocument(fetched.doc, fetched.address);
}

/** True when the identifier resolves to exactly `pubkey`. */
export async function verifyNip05(
  pubkey: string,
  identifier: string,
  opts?: { fetch?: Nip05Fetch; signal?: AbortSignal },
): Promise<boolean> {
  if (!isHex32(pubkey.toLowerCase())) {
    return false;
  }
  const profile = await queryProfile(identifier, opts);
  return profile !== undefined && profile.pubkey === pubkey.toLowerCase();
}
