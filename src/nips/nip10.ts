/**
 * NIP-10: Text Notes and Threads
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/10.md
 */
import { EventBuilder } from "../core/builder.ts";
import { EventValidationError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import { Kind } from "../core/kind.ts";
import { formatEventAddress, parseEventAddress, Tag } from "../core/tag.ts";
import type { Mutable } from "../core/util.ts";
import { isHex32 } from "../core/util.ts";
import type { AddressPointer, EventPointer, ProfilePointer } from "./nip19.ts";

/** Parsed NIP-10 thread references from an event's `e`/`q`/`p` tags. */
export type ThreadReferences = {
  /** Pointer to the root of the thread. */
  readonly root: EventPointer | undefined;
  /** Pointer to the parent event this note replies to. */
  readonly reply: EventPointer | undefined;
  /** Other e-tagged events (not root/reply). */
  readonly mentions: ReadonlyArray<EventPointer>;
  /** Quoted events (`q` tags): event ids or addresses. Discriminate with `"id" in q`. */
  readonly quotes: ReadonlyArray<EventPointer | AddressPointer>;
  /** P-tagged profiles involved in the thread. */
  readonly profiles: ReadonlyArray<ProfilePointer>;
};

type ReplyParent = Pick<Event, "id" | "pubkey" | "tags" | "kind">;
type QuoteInput = string | EventPointer | AddressPointer;

function eTagAuthor(tag: ReadonlyArray<string>): string | undefined {
  // NIP-10 5-tuple pubkey is index 4; NIP-01 4-tuple pubkey is index 3.
  for (const author of [tag[4], tag[3]]) {
    if (author !== undefined && isHex32(author.toLowerCase())) {
      return author.toLowerCase();
    }
  }
  return undefined;
}

function eventPointerFromETag(tag: ReadonlyArray<string>): EventPointer | undefined {
  const id = tag.at(1);
  if (tag[0] !== "e" || id === undefined || !isHex32(id.toLowerCase())) {
    return undefined;
  }
  const pointer: Mutable<EventPointer> = {
    id: id.toLowerCase(),
    relays: tag[2] !== undefined && tag[2] !== "" ? [tag[2]] : [],
  };
  const author = eTagAuthor(tag);
  if (author !== undefined) {
    pointer.author = author;
  }
  return pointer;
}

function quoteFromQTag(tag: ReadonlyArray<string>): EventPointer | AddressPointer | undefined {
  const value = tag.at(1);
  if (tag[0] !== "q" || value === undefined || value === "") {
    return undefined;
  }
  const relays = tag[2] !== undefined && tag[2] !== "" ? [tag[2]] : [];
  if (isHex32(value.toLowerCase())) {
    const pointer: Mutable<EventPointer> = { id: value.toLowerCase(), relays };
    const author = tag.at(3);
    if (author !== undefined && isHex32(author.toLowerCase())) {
      pointer.author = author.toLowerCase();
    }
    return pointer;
  }
  const addr = parseEventAddress(value);
  if (!addr) {
    return undefined;
  }
  // Address q tags do not use the event-id pubkey slot (index 3).
  return {
    identifier: addr.identifier,
    pubkey: addr.pubkey,
    kind: addr.kind,
    relays,
  };
}

type BuiltQuote = { tag: Tag; author?: string | undefined; relay?: string | undefined };

function quoteToTag(quote: QuoteInput): BuiltQuote | undefined {
  if (typeof quote === "string") {
    if (isHex32(quote.toLowerCase())) {
      return { tag: ["q", quote.toLowerCase()] };
    }
    const addr = parseEventAddress(quote);
    if (!addr) {
      return undefined;
    }
    return { tag: ["q", formatEventAddress(addr.kind, addr.pubkey, addr.identifier)] };
  }
  if ("id" in quote) {
    const id = quote.id.toLowerCase();
    const relay = quote.relays?.[0];
    const author =
      quote.author !== undefined && isHex32(quote.author.toLowerCase())
        ? quote.author.toLowerCase()
        : undefined;
    let tag: Tag;
    if (author === undefined) {
      tag = relay !== undefined && relay !== "" ? ["q", id, relay] : ["q", id];
    } else {
      tag = ["q", id, relay ?? "", author];
    }
    return { tag, author, relay };
  }
  const coord = formatEventAddress(quote.kind, quote.pubkey, quote.identifier);
  const relay = quote.relays?.[0];
  const tag: Tag = relay !== undefined && relay !== "" ? ["q", coord, relay] : ["q", coord];
  return { tag, author: quote.pubkey, relay };
}

function assertKind1Parent(parent: ReplyParent): void {
  // NIP-10 is kind 1 only; comments are NIP-22.
  if (parent.kind !== Kind.TextNote) {
    throw new EventValidationError("NIP-10 replyTo is for kind 1");
  }
}

/** Parse NIP-10 thread markers and legacy positional e-tags from an event. */
export function parseThreadTags(event: Pick<Event, "tags">): ThreadReferences {
  const mentions: EventPointer[] = [];
  const quotes: Array<EventPointer | AddressPointer> = [];
  const profiles: ProfilePointer[] = [];
  let root: EventPointer | undefined;
  let reply: EventPointer | undefined;

  let maybeParent: EventPointer | undefined;
  let maybeRoot: EventPointer | undefined;

  for (let i = event.tags.length - 1; i >= 0; i--) {
    const tag = event.tags[i];
    if (tag === undefined) {
      continue;
    }

    const eValue = tag.at(1);
    if (tag[0] === "e" && eValue !== undefined && isHex32(eValue.toLowerCase())) {
      const pointer = eventPointerFromETag(tag);
      if (pointer === undefined) {
        continue;
      }
      const marker = tag.at(3);

      if (marker === "root") {
        root = pointer;
        continue;
      }
      if (marker === "reply") {
        reply = pointer;
        continue;
      }
      // Preferred markers are root/reply only. A hex32 at index 3 is NIP-01 pubkey, not a marker.
      if (marker !== undefined && marker !== "" && !isHex32(marker.toLowerCase())) {
        mentions.push(pointer);
        continue;
      }

      // Legacy positional: last unmarked is parent, second-to-last is root.
      if (maybeParent) {
        maybeRoot = pointer;
      } else {
        maybeParent = pointer;
      }
      mentions.push(pointer);
      continue;
    }

    if (tag[0] === "q") {
      const quote = quoteFromQTag(tag);
      if (quote) {
        quotes.push(quote);
      }
      continue;
    }

    const pValue = tag.at(1);
    if (tag[0] === "p" && pValue !== undefined && isHex32(pValue.toLowerCase())) {
      profiles.push({
        pubkey: pValue.toLowerCase(),
        relays: tag[2] !== undefined && tag[2] !== "" ? [tag[2]] : [],
      });
    }
  }

  root ??= maybeRoot ?? maybeParent ?? reply;
  reply ??= maybeParent ?? root;

  // Drop root/reply from mentions (by id).
  const drop = new Set([root?.id, reply?.id].filter((id): id is string => Boolean(id)));
  const keptMentions = mentions.filter((m) => !drop.has(m.id));

  // Inherit relay hints from matching p-tags.
  const inheritHints = (ref: EventPointer): EventPointer => {
    const refAuthor = ref.author;
    if (refAuthor === undefined || refAuthor === "") {
      return ref;
    }
    const profileRelays = profiles.find((p) => p.pubkey === refAuthor)?.relays;
    if (profileRelays === undefined || profileRelays.length === 0) {
      return ref;
    }
    const relays = [...(ref.relays ?? [])];
    for (const url of profileRelays) {
      if (!relays.includes(url)) {
        relays.push(url);
      }
    }
    return { ...ref, relays };
  };

  return {
    root: root === undefined ? undefined : inheritHints(root),
    reply: reply === undefined ? undefined : inheritHints(reply),
    mentions: keptMentions.map(inheritHints),
    quotes,
    profiles,
  };
}

/** Options for {@link buildReplyTags}. */
export type ReplyTagsOptions = {
  /** Parent event being replied to. */
  parent: ReplyParent;
  /** Optional relay hint for the parent e-tag. */
  relayHint?: string | undefined;
  /** Quoted events (`q` tags): hex ids, `kind:pubkey:d` coords, or pointers. */
  quotes?: QuoteInput[] | undefined;
};

/**
 * Build NIP-10 e/p tags for a reply to `parent`. Uses marked tags (`root` / `reply`) per preferred
 * modern style.
 */
export function buildReplyTags(opts: ReplyTagsOptions): Tag[] {
  assertKind1Parent(opts.parent);
  const thread = parseThreadTags(opts.parent);
  const root = thread.root ?? { id: opts.parent.id, relays: [], author: opts.parent.pubkey };
  const parentIsRoot = root.id.toLowerCase() === opts.parent.id.toLowerCase();

  const tags: Tag[] = [];
  const rootRelay = root.relays?.[0] ?? opts.relayHint ?? "";
  tags.push(Tag.e(root.id, rootRelay, "root", root.author));

  if (!parentIsRoot) {
    tags.push(Tag.e(opts.parent.id, opts.relayHint ?? "", "reply", opts.parent.pubkey));
  }

  // Ensure root + parent authors are p-tagged.
  const pSeen = new Set<string>();
  const addP = (pk: string, relay?: string) => {
    const key = pk.toLowerCase();
    if (pSeen.has(key)) {
      return;
    }
    pSeen.add(key);
    tags.push(Tag.p(pk, relay ?? undefined));
  };
  if (root.author !== undefined && root.author !== "") {
    addP(root.author, root.relays?.[0]);
  }
  addP(opts.parent.pubkey, opts.relayHint);
  for (const p of thread.profiles) {
    addP(p.pubkey, p.relays?.[0]);
  }

  const qTags: Tag[] = [];
  for (const quote of opts.quotes ?? []) {
    const built = quoteToTag(quote);
    if (built === undefined) {
      continue;
    }
    if (built.author !== undefined && built.author !== "") {
      addP(built.author, built.relay);
    }
    qTags.push(built.tag);
  }
  tags.push(...qTags);

  return tags;
}

/**
 * Build an {@link EventBuilder} reply with NIP-10 tags. Lives here (not on EventBuilder) so core
 * does not depend on nips.
 */
export function replyTo(
  parent: ReplyParent,
  content: string,
  opts?: Pick<ReplyTagsOptions, "relayHint" | "quotes">,
): EventBuilder {
  return EventBuilder.textNote(content).tags(
    buildReplyTags({
      parent,
      relayHint: opts?.relayHint,
      quotes: opts?.quotes,
    }),
  );
}
