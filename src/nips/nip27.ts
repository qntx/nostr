/**
 * NIP-27: Text Note References. Tokenizes note content into text, `nostr:` references, URLs, media,
 * relays, hashtags, custom emoji, and Lightning invoices.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/27.md
 */
import type { Event } from "../core/event.ts";
import { decode } from "./nip19.ts";
import type { AddressPointer, EventPointer, ProfilePointer } from "./nip19.ts";

export type ContentBlock =
  | { readonly type: "text"; readonly text: string }
  | {
      readonly type: "reference";
      readonly pointer: ProfilePointer | EventPointer | AddressPointer;
      /**
       * `true` when the reference had no `nostr:` prefix (see
       * {@link ParseContentOptions.legacyBech32}).
       */
      readonly bare: boolean;
    }
  | { readonly type: "url"; readonly url: string }
  | { readonly type: "image" | "video" | "audio"; readonly url: string }
  | { readonly type: "relay"; readonly url: string }
  | { readonly type: "hashtag"; readonly value: string }
  | { readonly type: "emoji"; readonly shortcode: string; readonly url: string }
  | { readonly type: "invoice"; readonly bolt11: string };

export type ParseContentOptions = {
  /**
   * Recognize bare `npub`, `nprofile`, `note`, `nevent`, `naddr` without the `nostr:` prefix.
   * Default `false`.
   */
  legacyBech32?: boolean | undefined;
  /**
   * URL → MIME type (the `m` field of NIP-92 `imeta` tags); takes precedence over extension
   * classification.
   */
  imeta?: ReadonlyMap<string, string> | undefined;
};

// Bech32 data charset ([02-9ac-hj-np-z], case-insensitive) and the NIP-19 entity prefixes.
const BECH32_CHARS = "02-9ac-hj-np-z";
const NIP19_PREFIX = "(?:npub|nprofile|note|nevent|naddr|nsec)1";
const NIP19_BARE_PREFIX = "(?:npub|nprofile|note|nevent|naddr)1";

// A URL run ends at whitespace, angle brackets, double quotes, CJK punctuation
// (U+3000–U+303F), or full-width forms (U+FF00–U+FFEF).
const URL_RUN = `[^\\s<>"\\u3000-\\u303f\\uff00-\\uffef]+`;

// Rule order matters: at every position the first matching alternative wins.
const SCAN_BODY = [
  // 1. nostr: URIs carry a NIP-19 entity.
  `(?<nostr>nostr:${NIP19_PREFIX}[${BECH32_CHARS}]+)`,
  // 2./3. http(s) and ws(s) URLs share the same boundary rules.
  `(?<url>https?://${URL_RUN})`,
  `(?<relay>wss?://${URL_RUN})`,
  // 4. BOLT11 invoices, with an optional lightning: URI prefix. The HRP may carry an amount
  // (`lnbc10u1…` = ln + currency + amount + multiplier + the `1` separator).
  `(?<invoice>(?:lightning:)?ln(?:bcrt|tbs|bc|tb)(?:\\d+[munp]?)?1[${BECH32_CHARS}]+)`,
  // 5. Hashtags: Unicode letters/marks/numbers and underscore, at most 42 code points.
  `(?<hashtag>#[\\p{L}\\p{M}\\p{N}_]{1,42})`,
  // 6. Custom emoji shortcodes (validated against the event's emoji tags). NIP-30 allows
  // alphanumerics, hyphens, and underscores.
  `(?<emoji>:[A-Za-z0-9_-]+:)`,
].join("|");

const SCAN = new RegExp(SCAN_BODY, "giu");
// 7. Bare NIP-19 entities — legacy rendering support, opt-in only.
const SCAN_LEGACY = new RegExp(
  `${SCAN_BODY}|(?<bare>${NIP19_BARE_PREFIX}[${BECH32_CHARS}]+)`,
  "giu",
);

// The character before `#` must be absent or a non-tag character.
const TAG_CHAR = /[\p{L}\p{M}\p{N}_]/u;
// Invoice and bare-bech32 tokens must not be glued to a letter or digit.
const WORD_CHAR = /[\p{L}\p{N}]/u;

const TRAILING_URL_CHARS = new Set([".", ",", ";", ":", "!", "?", "'"]);

const IMAGE_EXT = new Set(["jpg", "jpeg", "png", "gif", "webp", "avif", "svg"]);
const VIDEO_EXT = new Set(["mp4", "webm", "mov", "m4v", "m3u8"]);
const AUDIO_EXT = new Set(["mp3", "m4a", "ogg", "oga", "opus", "wav", "flac", "aac"]);

function isChar(cp: number | undefined, re: RegExp): boolean {
  return cp !== undefined && re.test(String.fromCodePoint(cp));
}

/** Drop trailing sentence punctuation and closers that have no opener inside the URL. */
function trimUrlTail(raw: string): string {
  let url = raw;
  for (;;) {
    const last = url.at(-1);
    if (last !== undefined && TRAILING_URL_CHARS.has(last)) {
      url = url.slice(0, -1);
      continue;
    }
    if (last === ")" || last === "]") {
      const open = last === ")" ? "(" : "[";
      let opens = 0;
      let closes = 0;
      for (const c of url) {
        if (c === open) {
          opens++;
        } else if (c === last) {
          closes++;
        }
      }
      if (closes > opens) {
        url = url.slice(0, -1);
        continue;
      }
    }
    return url;
  }
}

type MediaType = "image" | "video" | "audio";

function mimeMedia(mime: string | undefined): MediaType | undefined {
  if (mime === undefined) {
    return undefined;
  }
  const slash = mime.indexOf("/");
  const base = slash === -1 ? mime : mime.slice(0, slash);
  return base === "image" || base === "video" || base === "audio" ? base : undefined;
}

function extMedia(pathname: string): MediaType | undefined {
  const dot = pathname.lastIndexOf(".");
  if (dot === -1) {
    return undefined;
  }
  const ext = pathname.slice(dot + 1).toLowerCase();
  if (IMAGE_EXT.has(ext)) {
    return "image";
  }
  if (VIDEO_EXT.has(ext)) {
    return "video";
  }
  return AUDIO_EXT.has(ext) ? "audio" : undefined;
}

function urlBlock(
  raw: string,
  relay: boolean,
  imeta: ReadonlyMap<string, string> | undefined,
): ContentBlock | undefined {
  const url = trimUrlTail(raw);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (!parsed.hostname.includes(".")) {
    return undefined;
  }
  if (relay) {
    return { type: "relay", url };
  }
  const media = mimeMedia(imeta?.get(url)) ?? extMedia(parsed.pathname);
  return media === undefined ? { type: "url", url } : { type: media, url };
}

function referenceFor(code: string, bare: boolean): ContentBlock | undefined {
  let pointer: ProfilePointer | EventPointer | AddressPointer;
  try {
    const decoded = decode(code);
    switch (decoded.type) {
      case "npub":
        pointer = { pubkey: decoded.data };
        break;
      case "note":
        pointer = { id: decoded.data };
        break;
      case "nprofile":
      case "nevent":
      case "naddr":
        pointer = decoded.data;
        break;
      case "nsec":
        return undefined;
    }
  } catch {
    return undefined;
  }
  return { type: "reference", pointer, bare };
}

/**
 * Parse note content (or a full event, to pick up `emoji` tags) into ordered blocks. One
 * left-to-right scan; at every position the rules fire in the alternation order above. Adjacent
 * text merges and no empty text blocks are emitted.
 */
export function parseContent(
  content: string | Pick<Event, "content" | "tags">,
  opts?: ParseContentOptions,
): ContentBlock[] {
  const emojis = new Map<string, string>();
  let text: string;
  if (typeof content === "string") {
    text = content;
  } else {
    for (const tag of content.tags) {
      if (
        tag[0] === "emoji" &&
        tag[1] !== undefined &&
        tag[1] !== "" &&
        tag[2] !== undefined &&
        tag[2] !== ""
      ) {
        emojis.set(tag[1], tag[2]);
      }
    }
    text = content.content;
  }

  const scan = opts?.legacyBech32 === true ? SCAN_LEGACY : SCAN;
  scan.lastIndex = 0;

  const blocks: ContentBlock[] = [];
  let textStart = 0;
  const flushText = (end: number): void => {
    if (end > textStart) {
      blocks.push({ type: "text", text: text.slice(textStart, end) });
    }
  };

  for (let m = scan.exec(text); m !== null; m = scan.exec(text)) {
    const start = m.index;
    const [token] = m;
    const end = start + token.length;
    const g = m.groups;
    let block: ContentBlock | undefined;

    if (g?.["nostr"] !== undefined) {
      block = referenceFor(token.slice("nostr:".length), false);
    } else if (g?.["url"] !== undefined) {
      block = urlBlock(token, false, opts?.imeta);
    } else if (g?.["relay"] !== undefined) {
      block = urlBlock(token, true, undefined);
    } else if (g?.["invoice"] !== undefined) {
      const prev = start === 0 ? undefined : text.codePointAt(start - 1);
      if (!isChar(prev, WORD_CHAR) && !isChar(text.codePointAt(end), WORD_CHAR)) {
        const invoice = token.toLowerCase().startsWith("lightning:")
          ? token.slice("lightning:".length)
          : token;
        block = { type: "invoice", bolt11: invoice.toLowerCase() };
      }
    } else if (g?.["hashtag"] !== undefined) {
      const prev = start === 0 ? undefined : text.codePointAt(start - 1);
      // A tag char right after the match means the {1,42} cap truncated a longer
      // run; the whole run is text, not a hashtag plus remainder.
      if (!isChar(prev, TAG_CHAR) && !isChar(text.codePointAt(end), TAG_CHAR)) {
        block = { type: "hashtag", value: token.slice(1) };
      }
    } else if (g?.["emoji"] !== undefined) {
      const url = emojis.get(token.slice(1, -1));
      if (url !== undefined) {
        block = { type: "emoji", shortcode: token.slice(1, -1), url };
      }
    } else if (g?.["bare"] !== undefined) {
      const prev = start === 0 ? undefined : text.codePointAt(start - 1);
      if (!isChar(prev, WORD_CHAR) && !isChar(text.codePointAt(end), WORD_CHAR)) {
        block = referenceFor(token, true);
      }
    }

    if (block === undefined) {
      // The candidate is plain text; resume scanning one code unit later so any token inside
      // its span can still match.
      scan.lastIndex = start + 1;
      continue;
    }
    flushText(start);
    blocks.push(block);
    // URL-family blocks may end before the regex run once trailing punctuation is trimmed.
    textStart =
      block.type === "url" ||
      block.type === "relay" ||
      block.type === "image" ||
      block.type === "video" ||
      block.type === "audio"
        ? start + block.url.length
        : end;
  }

  flushText(text.length);
  return blocks;
}
