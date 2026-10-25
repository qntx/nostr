/**
 * NIP-21: `nostr:` URI scheme
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/21.md
 */
import { NostrError } from "../core/error.ts";
import { lowerAscii } from "../core/util.ts";
import { decode } from "./nip19.ts";
import type { DecodedResult } from "./nip19.ts";

/** Error thrown by {@link parseNostrURI} on malformed or non-decodable URIs. */
export class Nip21Error extends NostrError {
  override name = "Nip21Error";
}

/**
 * Matches `nostr:<bech32>` (not anchored). Case classes are written out so matching is
 * case-insensitive for ASCII only: the `i` flag would also fold U+212A (K) into `k`.
 */
// oxlint-disable-next-line typescript/no-inferrable-types -- isolatedDeclarations requires the annotation for dts emit
export const NOSTR_URI_REGEX: RegExp =
  /[Nn][Oo][Ss][Tt][Rr]:([A-Za-z0-9]+1[02-9AC-HJ-NP-Zac-hj-np-z]+)/;

export type NostrURI = {
  /** Full URI including `nostr:` */
  readonly uri: `nostr:${string}`;
  /** Bech32 entity without prefix */
  readonly value: string;
  readonly decoded: DecodedResult;
};

export function isNostrURI(value: unknown): value is `nostr:${string}` {
  if (typeof value !== "string") {
    return false;
  }
  if (!/^[Nn][Oo][Ss][Tt][Rr]:[A-Za-z0-9]+1[02-9AC-HJ-NP-Zac-hj-np-z]+$/.test(value)) {
    return false;
  }
  return !lowerAscii(value).startsWith("nostr:nsec1");
}

/** Parse and decode a full `nostr:…` URI. NIP-21 excludes `nsec`. */
export function parseNostrURI(uri: string): NostrURI {
  const match = /^[Nn][Oo][Ss][Tt][Rr]:([A-Za-z0-9]+1[02-9AC-HJ-NP-Zac-hj-np-z]+)$/.exec(uri);
  const entity = match?.at(1);
  if (entity === undefined) {
    throw new Nip21Error(`invalid Nostr URI: ${uri}`);
  }
  if (lowerAscii(entity).startsWith("nsec1")) {
    throw new Nip21Error("NIP-21 identifiers exclude nsec");
  }
  let decoded: DecodedResult;
  try {
    decoded = decode(entity);
  } catch (error) {
    throw new Nip21Error(`invalid Nostr URI: ${uri}`, { cause: error });
  }
  return {
    uri: `nostr:${entity}`,
    value: entity,
    decoded,
  };
}
