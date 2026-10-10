import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { EventValidationError } from "../../src/core/error.ts";
import type { Event } from "../../src/core/event.ts";
import type { Tag } from "../../src/core/tag.ts";
import {
  parseRelayList,
  relayListEventBuilder,
  relayListToTags,
  readRelays,
  writeRelays,
} from "../../src/nips/nip65.ts";
import type { RelayListItem } from "../../src/nips/nip65.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type ParseCase = {
  name: string;
  event: Event;
  out?: RelayListItem[];
  err?: string;
};

type BuildCase = {
  name: string;
  rust?: boolean;
  items: Array<{ url: string; marker: string }>;
  relay_list: { kind: number; content: string };
  out_tags: Tag[];
  read: string[];
  write: string[];
};

const { parse, build } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip65/codec.json"), "utf8"),
) as { parse: ParseCase[]; build: BuildCase[] };

const parseOk = parse.filter((c) => c.err === undefined);
const parseErr = parse.filter((c) => c.err !== undefined);

function itemsOf(c: BuildCase): RelayListItem[] {
  return c.items as RelayListItem[];
}

describe("vectors/nip65/codec.json", () => {
  test("parseRelayList normalizes, dedups, and marks", () => {
    for (const c of parseOk) {
      expect(parseRelayList(c.event)).toStrictEqual(c.out);
    }
  });

  test("parseRelayList rejects non-10002 kinds", () => {
    for (const c of parseErr) {
      expect(() => parseRelayList(c.event)).toThrow(EventValidationError);
    }
  });

  test("relayListToTags emits the recorded r tags", () => {
    for (const c of build) {
      expect(relayListToTags(itemsOf(c))).toStrictEqual(c.out_tags);
    }
  });

  test("relayListEventBuilder wraps the tags in a kind-10002 builder", () => {
    for (const c of build) {
      const builder = relayListEventBuilder(itemsOf(c));
      expect(builder.currentKind).toBe(c.relay_list.kind);
      expect(builder.currentContent).toBe(c.relay_list.content);
      expect(builder.currentTags).toStrictEqual(c.out_tags);
    }
  });

  test("readRelays/writeRelays filter the marker views", () => {
    for (const c of build) {
      expect(readRelays(itemsOf(c))).toStrictEqual(c.read);
      expect(writeRelays(itemsOf(c))).toStrictEqual(c.write);
    }
  });
});
