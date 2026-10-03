/**
 * NIP-17: Private Direct Messages. Kind 10050 advertises where gift-wraps should be delivered. Kind
 * 14 rumor construction and per-recipient wrap live here. Envelope primitives live in nip59.ts.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/17.md
 */
import { EventBuilder } from "../core/builder.ts";
import { EventValidationError, NostrError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import { Kind } from "../core/kind.ts";
import type { Tag } from "../core/tag.ts";
import { Tag as TagBuilder } from "../core/tag.ts";
import { assertHex32, normalizeRelayUrls } from "../core/util.ts";
import { createGiftWrap, createRumor, createSeal } from "./nip59.ts";
import type { Nip59Crypto, Rumor, WrapOptions } from "./nip59.ts";

export class Nip17Error extends NostrError {
  override name = "Nip17Error";
}

export type Recipient = {
  readonly pubkey: string;
  readonly relayHint?: string | undefined;
};

export type ReplyTo = {
  readonly id: string;
  readonly relayHint?: string | undefined;
};

export type ChatMessageOptions = {
  readonly created_at?: number | undefined;
  readonly subject?: string | undefined;
  readonly replyTo?: ReplyTo | undefined;
};

/** Parse kind:10050 DM relay list (`["relay", url]` tags). */
export function parseDmRelayList(event: Pick<Event, "kind" | "tags">): string[] {
  if (event.kind !== Kind.DirectMessageRelaysList) {
    throw new EventValidationError(
      `expected kind ${Kind.DirectMessageRelaysList}, got ${event.kind}`,
    );
  }
  const urls: string[] = [];
  for (const tag of event.tags) {
    const value = tag.at(1);
    if (tag[0] === "relay" && value !== undefined) {
      urls.push(value);
    }
  }
  return normalizeRelayUrls(urls);
}

/** Encode DM relay URLs as NIP-17 `relay` tags. */
export function dmRelayListToTags(relays: ReadonlyArray<string>): Tag[] {
  return normalizeRelayUrls(relays).map((url) => ["relay", url]);
}

/** Build an unsigned kind:10050 EventBuilder. NIP-17 requires ≥1 relay tag. */
export function dmRelayListEventBuilder(relays: ReadonlyArray<string>): EventBuilder {
  const tags = dmRelayListToTags(relays);
  if (tags.length === 0) {
    throw new Nip17Error("DM relay list requires at least one relay");
  }
  return new EventBuilder(Kind.DirectMessageRelaysList, "").tags(tags);
}

function isRecipient(value: unknown): value is Recipient {
  return typeof value === "object" && value !== null && "pubkey" in value;
}

function asRecipientList(
  input: string | Recipient | ReadonlyArray<string | Recipient>,
): ReadonlyArray<string | Recipient> {
  if (typeof input === "string" || isRecipient(input)) {
    return [input];
  }
  return input;
}

/** Accept a hex pubkey, a Recipient, or a readonly array of either. Dedup by pubkey. */
export function normalizeRecipients(
  input: string | Recipient | ReadonlyArray<string | Recipient>,
): Recipient[] {
  const out: Recipient[] = [];
  const seen = new Set<string>();
  for (const item of asRecipientList(input)) {
    const rec: Recipient = typeof item === "string" ? { pubkey: item } : item;
    const pubkey = assertHex32(rec.pubkey, "public key");
    if (seen.has(pubkey)) {
      continue;
    }
    seen.add(pubkey);
    out.push({ pubkey, relayHint: rec.relayHint });
  }
  return out;
}

export function buildChatMessageRumor(
  senderPubkey: string,
  recipients: ReadonlyArray<Recipient>,
  content: string,
  opts?: ChatMessageOptions,
): Rumor {
  if (recipients.length === 0) {
    throw new Nip17Error("recipients must not be empty");
  }
  const tags: Tag[] = [];
  for (const recipient of recipients) {
    const pk = assertHex32(recipient.pubkey, "public key");
    tags.push(TagBuilder.p(pk, recipient.relayHint));
  }
  if (opts?.replyTo) {
    // Kind 14 reply e-tag is unmarked: ["e", <id>, <relay-url>]
    tags.push(TagBuilder.e(assertHex32(opts.replyTo.id, "event id"), opts.replyTo.relayHint ?? ""));
  }
  if (opts?.subject !== undefined) {
    tags.push(["subject", opts.subject]);
  }
  return createRumor(senderPubkey, {
    kind: Kind.PrivateDirectMessage,
    content,
    tags,
    created_at: opts?.created_at,
  });
}

function wrapTargets(sender: string, recipients: ReadonlyArray<Recipient>): Recipient[] {
  const senderPk = sender.toLowerCase();
  const self = recipients.find((r) => r.pubkey.toLowerCase() === senderPk);
  const out: Recipient[] = [{ pubkey: senderPk, relayHint: self?.relayHint }];
  const seen = new Set<string>([senderPk]);
  for (const recipient of recipients) {
    const pk = recipient.pubkey.toLowerCase();
    if (seen.has(pk)) {
      continue;
    }
    seen.add(pk);
    out.push({ pubkey: pk, relayHint: recipient.relayHint });
  }
  return out;
}

export async function wrapDirectMessage(
  crypto: Nip59Crypto,
  recipients: ReadonlyArray<Recipient>,
  rumor: Rumor,
  opts?: Pick<WrapOptions, "now" | "randomInt" | "timestamps" | "randomize">,
): Promise<ReadonlyArray<{ recipient: string; wrap: Event }>> {
  if (recipients.length === 0) {
    throw new Nip17Error("recipients must not be empty");
  }
  const targets = wrapTargets(rumor.pubkey, recipients);
  const out: Array<{ recipient: string; wrap: Event }> = [];
  const timeOpts = opts
    ? {
        now: opts.now,
        randomInt: opts.randomInt,
        timestamps: opts.timestamps,
        randomize: opts.randomize,
      }
    : undefined;
  for (const target of targets) {
    // oxlint-disable-next-line no-await-in-loop -- signer calls stay ordered, one recipient at a time
    const seal = await createSeal(crypto, target.pubkey, rumor, timeOpts);
    const wrap = createGiftWrap(seal, target.pubkey, {
      ...timeOpts,
      relayHint: target.relayHint,
    });
    out.push({ recipient: target.pubkey, wrap });
  }
  return out;
}

export function requireDmRelays(pubkey: string, relays: ReadonlyArray<string>): string[] {
  if (relays.length === 0) {
    throw new Nip17Error(`pubkey ${pubkey} is not ready to receive DMs (no kind 10050)`);
  }
  return [...relays];
}
