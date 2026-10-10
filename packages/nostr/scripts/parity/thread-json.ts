// Canonical JSON encoding of NIP-10 `ThreadReferences` — shared by
// `gen/nip10.ts` (codec vectors) and `diff.ts` (the seeded `nip10.thread`
// differential stream), and mirrored by the Rust replay in
// crates/nk-vectors/tests/diff.rs + common/. Key order is identical on both
// sides; missing `author`/`kind` hints encode as null.
// oxlint-disable typescript/no-restricted-types -- the canonical vector JSON encodes absent hints as null

import type { ThreadReferences } from "../../src/nips/nip10.ts";
import type { AddressPointer, EventPointer, ProfilePointer } from "../../src/nips/nip19.ts";

export type EventPointerJson = {
  id: string;
  relays: string[];
  author: string | null;
  kind: number | null;
};

export type QuoteJson =
  | ({ type: "event" } & EventPointerJson)
  | {
      type: "address";
      identifier: string;
      pubkey: string;
      kind: number;
      relays: string[];
    };

export type ThreadJson = {
  root: EventPointerJson | null;
  reply: EventPointerJson | null;
  mentions: EventPointerJson[];
  quotes: QuoteJson[];
  profiles: Array<{ pubkey: string; relays: string[] }>;
};

export function pointerJson(p: EventPointer): EventPointerJson {
  return {
    id: p.id,
    relays: [...(p.relays ?? [])],
    author: p.author ?? null,
    kind: p.kind ?? null,
  };
}

export function quoteJson(q: EventPointer | AddressPointer): QuoteJson {
  if ("id" in q) {
    return { type: "event", ...pointerJson(q) };
  }
  return {
    type: "address",
    identifier: q.identifier,
    pubkey: q.pubkey,
    kind: q.kind,
    relays: [...(q.relays ?? [])],
  };
}

export function profileJson(p: ProfilePointer): { pubkey: string; relays: string[] } {
  return { pubkey: p.pubkey, relays: [...(p.relays ?? [])] };
}

export function threadJson(t: ThreadReferences): ThreadJson {
  return {
    root: t.root === undefined ? null : pointerJson(t.root),
    reply: t.reply === undefined ? null : pointerJson(t.reply),
    mentions: t.mentions.map(pointerJson),
    quotes: t.quotes.map(quoteJson),
    profiles: t.profiles.map(profileJson),
  };
}
