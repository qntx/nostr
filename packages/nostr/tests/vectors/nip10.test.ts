import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { threadJson } from "../../scripts/parity/thread-json.ts";
import type { ThreadJson } from "../../scripts/parity/thread-json.ts";
import { EventValidationError } from "../../src/core/error.ts";
import type { Event } from "../../src/core/event.ts";
import type { Tag } from "../../src/core/tag.ts";
import { buildReplyTags, parseThreadTags, replyTo } from "../../src/nips/nip10.ts";
import type { ReplyTagsOptions } from "../../src/nips/nip10.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`. The canonical
// `ThreadReferences` JSON shape lives in scripts/parity/thread-json.ts.
type ParseCase = {
  name: string;
  rust?: boolean;
  tags: unknown[];
  out?: ThreadJson;
  err?: string;
};

type ReplyCase = {
  name: string;
  rust?: boolean;
  parent: Event;
  relay_hint: string | null;
  quotes: NonNullable<ReplyTagsOptions["quotes"]>;
  reply_to?: { content: string; kind: number };
  out_tags?: Tag[];
  err?: string;
};

const { parse, reply } = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip10/codec.json"), "utf8"),
) as { parse: ParseCase[]; reply: ReplyCase[] };

const parseOk = parse.filter((c) => c.err === undefined);
const parseErr = parse.filter((c) => c.err !== undefined);
const replyOk = reply.filter((c) => c.err === undefined && c.reply_to === undefined);
const replyToOk = reply.filter(
  (c): c is ReplyCase & { reply_to: { content: string; kind: number } } =>
    c.err === undefined && c.reply_to !== undefined,
);
const replyErr = reply.filter((c) => c.err !== undefined);

// Deliberately malformed elements are what the `err` cases exercise; the
// cast narrows the vector's `unknown` to the API's input shape.
const asTags = (tags: unknown): Tag[] => tags as Tag[];

function optionsOf(c: ReplyCase): ReplyTagsOptions {
  return {
    parent: c.parent,
    relayHint: c.relay_hint ?? undefined,
    quotes: c.quotes,
  };
}

describe("vectors/nip10/codec.json", () => {
  test("parseThreadTags produces the canonical thread shape", () => {
    for (const c of parseOk) {
      expect(threadJson(parseThreadTags({ tags: asTags(c.tags) }))).toStrictEqual(c.out);
    }
  });

  test("parseThreadTags throws on malformed tag elements", () => {
    for (const c of parseErr) {
      // The vector records the constructor name the TS side threw.
      let thrown: unknown;
      try {
        parseThreadTags({ tags: asTags(c.tags) });
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(Error);
      expect((thrown as Error).name).toBe(c.err);
    }
  });

  test("buildReplyTags emits the recorded e/p/q tags", () => {
    for (const c of replyOk) {
      expect(buildReplyTags(optionsOf(c))).toStrictEqual(c.out_tags);
    }
  });

  test("replyTo wraps the same tags in a kind-1 builder", () => {
    for (const c of replyToOk) {
      const builder = replyTo(c.parent, c.reply_to.content, optionsOf(c));
      expect(builder.currentKind).toBe(c.reply_to.kind);
      expect(builder.currentContent).toBe(c.reply_to.content);
      expect(builder.currentTags).toStrictEqual(c.out_tags);
    }
  });

  test("non-kind-1 parents reject with EventValidationError", () => {
    for (const c of replyErr) {
      expect(() => buildReplyTags(optionsOf(c))).toThrow(EventValidationError);
    }
  });
});
