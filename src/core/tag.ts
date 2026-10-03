import { isAddressableKind, isReplaceableKind } from "./kind.ts";
import { isHex32 } from "./util.ts";

/** A NIP-01 tag: first element is the name, rest are values. */
export type Tag = ReadonlyArray<string>;

/** Mutable tag builder input. */
export type TagInput = string[];

/** Type guard: a non-empty array of strings. */
export function isTag(value: unknown): value is Tag {
  if (!Array.isArray(value) || value.length === 0) {
    return false;
  }
  for (const item of value) {
    if (typeof item !== "string") {
      return false;
    }
  }
  return true;
}

/** First element of a tag (its name). */
export function tagName(tag: Tag): string {
  return tag[0] ?? "";
}

/** Second element of a tag (its primary value), or undefined for a bare name tag. */
export function tagValue(tag: Tag): string | undefined {
  return tag[1];
}

/** Construct common tags. */
export const Tag = {
  e(id: string, relay?: string, marker?: string, pubkey?: string): Tag {
    const t: string[] = ["e", id.toLowerCase()];
    if (relay !== undefined) {
      t.push(relay);
    }
    if (marker !== undefined) {
      t.push(marker);
    }
    if (pubkey !== undefined) {
      t.push(pubkey.toLowerCase());
    }
    return t;
  },
  p(pubkey: string, relay?: string, petname?: string): Tag {
    const t: string[] = ["p", pubkey.toLowerCase()];
    if (relay !== undefined) {
      t.push(relay);
    }
    if (petname !== undefined) {
      t.push(petname);
    }
    return t;
  },
  a(coordinate: string, relay?: string): Tag {
    const t: string[] = ["a", coordinate];
    if (relay !== undefined) {
      t.push(relay);
    }
    return t;
  },
  d(identifier: string): Tag {
    return ["d", identifier];
  },
  t(hashtag: string): Tag {
    return ["t", hashtag];
  },
  r(url: string, marker?: string): Tag {
    const t: string[] = ["r", url];
    if (marker !== undefined) {
      t.push(marker);
    }
    return t;
  },
  k(kind: number | string): Tag {
    return ["k", String(kind)];
  },
} as const;

/** First tag value with the given name, or undefined when no such tag has a value. */
export function firstTagValue(tags: ReadonlyArray<Tag>, name: string): string | undefined {
  for (const tag of tags) {
    if (tag[0] === name && tag[1] !== undefined) {
      return tag[1];
    }
  }
  return undefined;
}

/** First `d` tag value on an event, if any. */
export function getDTag(tags: ReadonlyArray<Tag>): string | undefined {
  return firstTagValue(tags, "d");
}

/** NIP-01 `a` tag: `kind:pubkey:identifier` (identifier may be empty and may contain extra colons). */
export type EventAddress = {
  kind: number;
  pubkey: string;
  identifier: string;
};

/** Parse a NIP-01 addressable/replaceable coordinate. */
export function parseEventAddress(value: string): EventAddress | undefined {
  const first = value.indexOf(":");
  if (first <= 0) {
    return undefined;
  }
  const second = value.indexOf(":", first + 1);
  if (second === -1) {
    return undefined;
  }
  const kindText = value.slice(0, first);
  // Strict decimal: Number() also accepts "1e4", "0x10", " 1", "+1" — none are NIP-19 kinds.
  if (!/^\d{1,5}$/.test(kindText)) {
    return undefined;
  }
  const kind = Number(kindText);
  if (kind > 65535) {
    return undefined;
  }
  const pubkey = value.slice(first + 1, second).toLowerCase();
  if (!isHex32(pubkey)) {
    return undefined;
  }
  return { kind, pubkey, identifier: value.slice(second + 1) };
}

/** Format an address as a `kind:pubkey:dTag` coordinate string. */
export function formatEventAddress(kind: number, pubkey: string, identifier = ""): string {
  return `${kind}:${pubkey.toLowerCase()}:${identifier}`;
}

/**
 * Coordinate for replaceable (`kind:pubkey:`) and addressable (`kind:pubkey:d`) events. Undefined
 * for regular/ephemeral kinds.
 */
export function eventAddress(event: {
  kind: number;
  pubkey: string;
  tags: ReadonlyArray<Tag>;
}): string | undefined {
  if (isAddressableKind(event.kind)) {
    return formatEventAddress(event.kind, event.pubkey, getDTag(event.tags) ?? "");
  }
  if (isReplaceableKind(event.kind)) {
    return formatEventAddress(event.kind, event.pubkey, "");
  }
  return undefined;
}
