import { EventValidationError } from "./error.ts";
import type { Event, EventTemplate, UnsignedEvent } from "./event.ts";
import { finalizeEvent } from "./key.ts";
import type { Keys, SecretKeyInput } from "./key.ts";
import { Kind, isAddressableKind, isReplaceableKind } from "./kind.ts";
import { Tag, formatEventAddress, getDTag, parseEventAddress } from "./tag.ts";
import { normalizeURL, nowSeconds } from "./util.ts";
import type { Mutable } from "./util.ts";

/** NIP-18 e third entry MUST be a relay URL; empty string is not one. */
function requireRelayUrl(relayHint: string | undefined): string {
  if (relayHint === undefined || relayHint === "") {
    throw new EventValidationError("relayHint must be a relay URL");
  }
  return normalizeURL(relayHint);
}

/** Profile metadata JSON (kind 0 content). NIP-05 is not verified here. */
export type ProfileMetadata = {
  readonly name?: string | undefined;
  readonly display_name?: string | undefined;
  readonly about?: string | undefined;
  readonly picture?: string | undefined;
  readonly banner?: string | undefined;
  readonly website?: string | undefined;
  readonly nip05?: string | undefined;
  readonly lud06?: string | undefined;
  readonly lud16?: string | undefined;
};

/** ProfileMetadata keys in declaration order (NIP-01 kind 0 content). */
const PROFILE_METADATA_KEYS = [
  "name",
  "display_name",
  "about",
  "picture",
  "banner",
  "website",
  "nip05",
  "lud06",
  "lud16",
] as const satisfies ReadonlyArray<keyof ProfileMetadata>;

/**
 * Fluent builder for event templates. Decouples intent (kind/content/tags) from signing (Keys /
 * NostrSigner).
 */
export class EventBuilder {
  #kind: number;
  #content: string;
  readonly #tags: Tag[] = [];
  #createdAt: number | undefined;

  constructor(kind: number, content = "") {
    this.#kind = kind;
    this.#content = content;
  }

  static textNote(content: string): EventBuilder {
    return new EventBuilder(Kind.TextNote, content);
  }

  static metadata(meta: ProfileMetadata): EventBuilder {
    // Emit keys in the ProfileMetadata declaration order so the content is
    // stable regardless of the caller's object insertion order (NIP-01; the
    // Rust EventBuilder::metadata matches byte-for-byte).
    const ordered: Mutable<ProfileMetadata> = {};
    for (const key of PROFILE_METADATA_KEYS) {
      const value = meta[key];
      if (value !== undefined) {
        ordered[key] = value;
      }
    }
    return new EventBuilder(Kind.Metadata, JSON.stringify(ordered));
  }

  static contacts(pubkeys: ReadonlyArray<string>): EventBuilder {
    const b = new EventBuilder(Kind.Contacts, "");
    for (const pk of pubkeys) {
      b.#tags.push(Tag.p(pk));
    }
    return b;
  }

  /**
   * Kind-5 deletion. Each target is a bare event id string (or `{ id, kind }`), or `{ address }`
   * for a `kind:pubkey:d` coordinate. Known kinds are emitted as deduped `k` tags (NIP-09 SHOULD).
   */
  static deletion(
    targets: ReadonlyArray<string | { id: string; kind?: number } | { address: string }>,
    reason = "",
  ): EventBuilder {
    const b = new EventBuilder(Kind.EventDeletion, reason);
    const kinds = new Set<number>();
    for (const target of targets) {
      if (typeof target === "string") {
        b.#tags.push(Tag.e(target));
        continue;
      }
      if ("address" in target) {
        const parsed = parseEventAddress(target.address);
        if (parsed) {
          kinds.add(parsed.kind);
        }
        b.#tags.push(Tag.a(target.address));
        continue;
      }
      b.#tags.push(Tag.e(target.id));
      if (target.kind !== undefined) {
        kinds.add(target.kind);
      }
    }
    for (const kind of kinds) {
      b.#tags.push(Tag.k(kind));
    }
    return b;
  }

  static reaction(target: Event, content = "+", opts?: { relayHint?: string }): EventBuilder {
    const hint = opts?.relayHint === undefined ? undefined : requireRelayUrl(opts.relayHint);
    let coord: string | undefined;
    if (isAddressableKind(target.kind)) {
      const d = getDTag(target.tags);
      if (d === undefined) {
        throw new EventValidationError("addressable event is missing d tag");
      }
      coord = formatEventAddress(target.kind, target.pubkey, d);
    }

    const b = new EventBuilder(Kind.Reaction, content);
    // NIP-25 e is [e, id, relay, pubkey]; Tag.e third arg is a NIP-10 marker.
    b.#tags.push(["e", target.id.toLowerCase(), hint ?? "", target.pubkey.toLowerCase()]);
    b.#tags.push(Tag.p(target.pubkey, hint));
    b.#tags.push(["k", String(target.kind)]);
    if (coord !== undefined) {
      b.#tags.push(Tag.a(coord, hint));
    }
    return b;
  }

  static repost(target: Event, opts: { relayHint: string }): EventBuilder {
    if (target.kind !== Kind.TextNote) {
      throw new EventValidationError("non-kind-1 uses EventBuilder.genericRepost");
    }
    const hint = requireRelayUrl(opts.relayHint);
    const content = target.tags.some((tag) => tag[0] === "-") ? "" : JSON.stringify(target);
    const b = new EventBuilder(Kind.Repost, content);
    b.#tags.push(Tag.e(target.id, hint));
    b.#tags.push(Tag.p(target.pubkey));
    return b;
  }

  static genericRepost(target: Event, opts: { relayHint: string; pPubkey?: string }): EventBuilder {
    if (target.kind === Kind.TextNote) {
      throw new EventValidationError("kind 1 uses EventBuilder.repost");
    }
    const hint = requireRelayUrl(opts.relayHint);
    const replaceable = isReplaceableKind(target.kind);
    const addressable = isAddressableKind(target.kind);
    const d = getDTag(target.tags);
    if (addressable && d === undefined) {
      throw new EventValidationError("addressable event is missing d tag");
    }

    const protectedTag = target.tags.some((tag) => tag[0] === "-");
    const content = protectedTag || replaceable || addressable ? "" : JSON.stringify(target);
    const b = new EventBuilder(Kind.GenericRepost, content);
    b.#tags.push(Tag.e(target.id, hint));
    b.#tags.push(Tag.p(opts.pPubkey ?? target.pubkey));
    b.#tags.push(Tag.k(target.kind));
    if (replaceable || addressable) {
      b.#tags.push(Tag.a(formatEventAddress(target.kind, target.pubkey, d ?? "")));
    }
    return b;
  }

  kind(kind: number): this {
    this.#kind = kind;
    return this;
  }

  content(content: string): this {
    this.#content = content;
    return this;
  }

  tag(tag: Tag): this {
    this.#tags.push(tag);
    return this;
  }

  tags(tags: Iterable<Tag>): this {
    for (const t of tags) {
      this.#tags.push(t);
    }
    return this;
  }

  createdAt(ts: number): this {
    this.#createdAt = ts;
    return this;
  }

  get currentKind(): number {
    return this.#kind;
  }

  get currentContent(): string {
    return this.#content;
  }

  get currentTags(): ReadonlyArray<Tag> {
    return this.#tags;
  }

  get currentCreatedAt(): number | undefined {
    return this.#createdAt;
  }

  /** Snapshot as EventTemplate (uses wall clock if created_at unset). */
  toTemplate(): EventTemplate {
    return {
      kind: this.#kind,
      content: this.#content,
      tags: [...this.#tags],
      created_at: this.#createdAt ?? nowSeconds(),
    };
  }

  /** Build unsigned event with the given pubkey. */
  buildUnsigned(pubkey: string): UnsignedEvent {
    const template = this.toTemplate();
    return {
      ...template,
      pubkey: pubkey.toLowerCase(),
    };
  }

  /** Sign with local Keys (synchronous). */
  signWithKeys(keys: Keys | SecretKeyInput): Event {
    return finalizeEvent(this.toTemplate(), keys);
  }

  /**
   * Sign via any NostrSigner-shaped object. Accepts a structural type so core does not depend on
   * the signer module.
   */
  async sign(signer: {
    getPublicKey: () => Promise<string>;
    signEvent: (unsigned: UnsignedEvent) => Promise<Event>;
  }): Promise<Event> {
    const pubkey = await signer.getPublicKey();
    return signer.signEvent(this.buildUnsigned(pubkey));
  }
}
