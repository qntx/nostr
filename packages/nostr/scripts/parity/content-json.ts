// Canonical `ContentBlock` JSON for the NIP-27 vectors (`vectors/nip27/
// codec.json`, produced by gen/nip27.ts) and the `nip27.tokenize`
// differential stream (diff.ts). Mirrored by the Rust replay in
// crates/nk-vectors/tests/common/. Key sets are fixed on both sides —
// absent pointer hints serialize as null.
//
// The Rust `Reference` enum cannot tell `npub` from a relay-less `nprofile`
// (both are `ProfilePointer` with `relays: []`), so the canonical shape
// normalizes by pointer family: `profile` / `event` / `address`, with
// `relays`/`author`/`kind` filled to `[]`/`null` when absent.
// oxlint-disable typescript/no-restricted-types -- the canonical vector JSON encodes absent hints as null

import type { AddressPointer, EventPointer, ProfilePointer } from "../../src/nips/nip19.ts";
import type { ContentBlock } from "../../src/nips/nip27.ts";

type ReferencePointer =
  | ProfilePointer
  | EventPointer
  | AddressPointer
  | { readonly pubkey: string }
  | { readonly id: string };

export type PointerJson =
  | { type: "profile"; pubkey: string; relays: string[] }
  | {
      type: "event";
      id: string;
      relays: string[];
      author: string | null;
      kind: number | null;
    }
  | {
      type: "address";
      identifier: string;
      pubkey: string;
      kind: number;
      relays: string[];
    };

function pointerJson(pointer: ReferencePointer): PointerJson {
  if ("identifier" in pointer) {
    return {
      type: "address",
      identifier: pointer.identifier,
      pubkey: pointer.pubkey,
      kind: pointer.kind,
      relays: [...(pointer.relays ?? [])],
    };
  }
  if ("id" in pointer) {
    return {
      type: "event",
      id: pointer.id,
      relays: [...("relays" in pointer ? (pointer.relays ?? []) : [])],
      author: "author" in pointer ? (pointer.author ?? null) : null,
      kind: "kind" in pointer ? (pointer.kind ?? null) : null,
    };
  }
  return {
    type: "profile",
    pubkey: pointer.pubkey,
    relays: [...("relays" in pointer ? (pointer.relays ?? []) : [])],
  };
}

export type BlockJson =
  | { type: "text"; text: string }
  | { type: "reference"; bare: boolean; pointer: PointerJson }
  | { type: "url" | "image" | "video" | "audio" | "relay"; url: string }
  | { type: "hashtag"; value: string }
  | { type: "emoji"; shortcode: string; url: string }
  | { type: "invoice"; bolt11: string };

export function blocksJson(blocks: ReadonlyArray<ContentBlock>): BlockJson[] {
  return blocks.map((block) => {
    // Each arm assigns rather than returns so the lint sees a single exit.
    let json: BlockJson;
    switch (block.type) {
      case "text":
        json = { type: "text", text: block.text };
        break;
      case "reference":
        json = { type: "reference", bare: block.bare, pointer: pointerJson(block.pointer) };
        break;
      case "url":
      case "image":
      case "video":
      case "audio":
      case "relay":
        json = { type: block.type, url: block.url };
        break;
      case "hashtag":
        json = { type: "hashtag", value: block.value };
        break;
      case "emoji":
        json = { type: "emoji", shortcode: block.shortcode, url: block.url };
        break;
      case "invoice":
        json = { type: "invoice", bolt11: block.bolt11 };
        break;
    }
    return json;
  });
}
