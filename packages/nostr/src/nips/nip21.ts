/**
 * NIP-21: `nostr:` URI scheme
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/21.md
 */
import { NostrError } from "../core/error.ts";
import { decode } from "./nip19.ts";
import type { DecodedResult } from "./nip19.ts";

/** Error thrown by {@link parseNostrURI} on malformed or non-decodable URIs. */
export class Nip21Error extends NostrError {
  override name = "Nip21Error";
}

/** Matches `nostr:<bech32>` (not anchored). */
// oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires the annotation for dts emit
export const NOSTR_URI_REGEX: RegExp = /nostr:([a-z0-9]+1[02-9ac-hj-np-z]+)/i;

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
  if (!/^nostr:[a-z0-9]+1[02-9ac-hj-np-z]+$/i.test(value)) {
    return false;
  }
  return !value.toLowerCase().startsWith("nostr:nsec1");
}

/** Parse and decode a full `nostr:…` URI. NIP-21 excludes `nsec`. */
export function parseNostrURI(uri: string): NostrURI {
  const match = /^nostr:([a-z0-9]+1[02-9ac-hj-np-z]+)$/i.exec(uri);
  const entity = match?.at(1);
  if (entity === undefined) {
    throw new Nip21Error(`invalid Nostr URI: ${uri}`);
  }
  if (entity.toLowerCase().startsWith("nsec1")) {
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
