/**
 * NIP-27: Text Note References. Tokenizes note content into text, `nostr:` references, URLs, media,
 * relays, hashtags, custom emoji, and Lightning invoices.
 *
 * The tokenizer is a hand-written scanner — one left-to-right walk over Unicode scalar values. At
 * position `i` the first rule whose shape matches decides; a candidate that fails validation makes
 * `i` text and the scan resumes at the next scalar (no later rule is tried at `i`). Keywords
 * compare ASCII case-insensitively; there is no Unicode case folding and no regex backtracking.
 * `crates/nk-core/src/nips/nip27.rs` implements the same rules line for line.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/27.md
 */
import type { Event } from "../core/event.ts";
import { lowerAscii } from "../core/util.ts";
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

// Per-scalar character classes — each test takes exactly one code point.
const WORD_CHAR = /[\p{L}\p{N}]/u;
const TAG_CHAR = /[\p{L}\p{M}\p{N}_]/u;
const WHITE_SPACE = /\p{White_Space}/u;

/** ASCII lowercase of one code point (`A`-`Z` → `a`-`z`; everything else unchanged). */
function foldAscii(c: string): string {
  return c >= "A" && c <= "Z" ? c.toLowerCase() : c;
}

/** `0`, `2`–`9`, `a c-h j-n p-z`, both ASCII cases — the bech32 data charset. */
function isBech32Char(c: string): boolean {
  const l = foldAscii(c);
  return (
    (l >= "0" && l <= "9" && l !== "1") ||
    (l >= "a" && l <= "z" && l !== "b" && l !== "i" && l !== "o")
  );
}

/** `[A-Za-z0-9_-]` — the emoji shortcode charset. */
function isEmojiChar(c: string): boolean {
  return (
    (c >= "a" && c <= "z") ||
    (c >= "A" && c <= "Z") ||
    (c >= "0" && c <= "9") ||
    c === "_" ||
    c === "-"
  );
}

function isTagChar(c: string): boolean {
  return TAG_CHAR.test(c);
}

function isWordChar(c: string): boolean {
  return WORD_CHAR.test(c);
}

/** URL-run stops: Unicode White_Space plus `<>`, `"`, CJK punctuation and full-width forms. */
function isUrlStop(c: string): boolean {
  if (WHITE_SPACE.test(c) || c === "<" || c === ">" || c === '"') {
    return true;
  }
  const cp = c.codePointAt(0);
  return cp !== undefined && ((cp >= 0x3000 && cp <= 0x303f) || (cp >= 0xff00 && cp <= 0xffef));
}

/**
 * ASCII-insensitive literal match at the start of `rest` — the keyword form (`nostr:`,
 * `lightning:`, `http`…). Returns the matched length in UTF-16 units, or `undefined`. Literals are
 * ASCII, so the length equals the literal's length.
 */
function litAt(rest: string, lit: string): number | undefined {
  if (rest.length < lit.length) {
    return undefined;
  }
  for (let i = 0; i < lit.length; i++) {
    if (foldAscii(rest[i] ?? "") !== lit[i]) {
      return undefined;
    }
  }
  return lit.length;
}

/** UTF-16 length of the maximal bech32-charset run at the start of `rest` (may be 0). */
function bech32Run(rest: string): number {
  let n = 0;
  for (const c of rest) {
    if (!isBech32Char(c)) {
      break;
    }
    n += c.length;
  }
  return n;
}

/** `1` then a non-empty bech32-charset run — the entity/invoice separator and data. */
function sepThenData(rest: string, at: number): number | undefined {
  if (rest[at] !== "1") {
    return undefined;
  }
  const run = bech32Run(rest.slice(at + 1));
  return run > 0 ? at + 1 + run : undefined;
}

const NIP19_PREFIXES = ["npub", "nprofile", "note", "nevent", "naddr", "nsec"] as const;
const BARE_PREFIXES = ["npub", "nprofile", "note", "nevent", "naddr"] as const;

/** `nostr:` + NIP-19 prefix + `1` + charset. Returns `[codeStart, end]` — code start skips `nostr:`. */
function nostrAt(rest: string): [number, number] | undefined {
  const codeStart = litAt(rest, "nostr:");
  if (codeStart === undefined) {
    return undefined;
  }
  let at = codeStart;
  let prefixLen: number | undefined;
  for (const p of NIP19_PREFIXES) {
    prefixLen = litAt(rest.slice(at), p);
    if (prefixLen !== undefined) {
      break;
    }
  }
  if (prefixLen === undefined) {
    return undefined;
  }
  at += prefixLen;
  const end = sepThenData(rest, at);
  return end === undefined ? undefined : [codeStart, end];
}

/** `http(s)://` / `ws(s)://` + URL run. Returns the raw match end. */
function urlAt(rest: string, ws: boolean): number | undefined {
  const base = ws ? "ws" : "http";
  let at = litAt(rest, base);
  if (at === undefined) {
    return undefined;
  }
  // `s?` — optional second s, ASCII-only.
  const s = rest[at];
  if (s !== undefined && foldAscii(s) === "s") {
    at += 1;
  }
  const sep = litAt(rest.slice(at), "://");
  if (sep === undefined) {
    return undefined;
  }
  at += sep;
  let run = 0;
  for (const c of rest.slice(at)) {
    if (isUrlStop(c)) {
      break;
    }
    run += c.length;
  }
  return run > 0 ? at + run : undefined;
}

const INVOICE_CURRENCIES = ["bcrt", "tbs", "bc", "tb"] as const;

/**
 * `(lightning:)?ln(bcrt|tbs|bc|tb)` + a maximal `BECH32 ∪ {1}` run, then split at the run's last
 * `1`: the amount before it is empty or `\d+` plus at most one of `munp` (ASCII either case), and
 * the data after it is non-empty. Returns `[prefixLen, end]`.
 */
function invoiceAt(rest: string): [number, number] | undefined {
  const prefix = litAt(rest, "lightning:") ?? 0;
  const ln = litAt(rest.slice(prefix), "ln");
  if (ln === undefined) {
    return undefined;
  }
  let at = prefix + ln;
  let currency: number | undefined;
  for (const cur of INVOICE_CURRENCIES) {
    currency = litAt(rest.slice(at), cur);
    if (currency !== undefined) {
      break;
    }
  }
  if (currency === undefined) {
    return undefined;
  }
  at += currency;
  // The maximal run may contain `1`s — the LAST `1` is the bech32 separator.
  let runEnd = at;
  let lastSep = -1;
  for (const c of rest.slice(at)) {
    if (c === "1") {
      lastSep = runEnd;
      runEnd += 1;
      continue;
    }
    if (!isBech32Char(c)) {
      break;
    }
    runEnd += c.length;
  }
  if (lastSep === -1) {
    return undefined;
  }
  const data = rest.slice(lastSep + 1, runEnd);
  if (data.length === 0) {
    return undefined;
  }
  const amount = rest.slice(at, lastSep);
  if (amount.length > 0) {
    let i = 0;
    for (const c of amount) {
      if (c < "0" || c > "9") {
        break;
      }
      i += c.length;
    }
    const tail = amount.slice(i);
    if (i === 0 || tail.length > 1 || (tail.length === 1 && !"munpMUNP".includes(tail))) {
      return undefined;
    }
  }
  return [prefix, runEnd];
}

/** `#` + a maximal `TAG` run — returns the run end (the 1–42 length cap is a validation). */
function hashtagAt(rest: string): [number, number] | undefined {
  if (!rest.startsWith("#")) {
    return undefined;
  }
  let end = 1;
  let count = 0;
  for (const c of rest.slice(1)) {
    if (!isTagChar(c)) {
      break;
    }
    count += 1;
    end += c.length;
  }
  return count === 0 ? undefined : [end, count];
}

/** `:[A-Za-z0-9_-]+:` — a shortcode candidate (membership checked at validation). */
function emojiAt(rest: string): number | undefined {
  if (!rest.startsWith(":")) {
    return undefined;
  }
  let run = 0;
  for (const c of rest.slice(1)) {
    if (!isEmojiChar(c)) {
      break;
    }
    run += c.length;
  }
  if (run === 0) {
    return undefined;
  }
  return rest[1 + run] === ":" ? 1 + run + 1 : undefined;
}

/** `npub|nprofile|note|nevent|naddr` + `1` + charset — the legacy bare rule. */
function bareAt(rest: string): number | undefined {
  for (const p of BARE_PREFIXES) {
    const len = litAt(rest, p);
    if (len !== undefined) {
      return sepThenData(rest, len);
    }
  }
  return undefined;
}

type Token =
  | { kind: "nostr"; codeStart: number }
  | { kind: "hashtag"; count: number }
  | { kind: "url" | "relay" | "emoji" | "bare" }
  | { kind: "invoice"; prefixLen: number };

/** First shape match at `pos`, in rule order. Returns the token and the raw match end. */
function candidateAt(rest: string, legacy: boolean): [Token, number] | undefined {
  const nostr = nostrAt(rest);
  if (nostr !== undefined) {
    return [{ kind: "nostr", codeStart: nostr[0] }, nostr[1]];
  }
  const url = urlAt(rest, false);
  if (url !== undefined) {
    return [{ kind: "url" }, url];
  }
  const relay = urlAt(rest, true);
  if (relay !== undefined) {
    return [{ kind: "relay" }, relay];
  }
  const invoice = invoiceAt(rest);
  if (invoice !== undefined) {
    return [{ kind: "invoice", prefixLen: invoice[0] }, invoice[1]];
  }
  const hashtag = hashtagAt(rest);
  if (hashtag !== undefined) {
    return [{ kind: "hashtag", count: hashtag[1] }, hashtag[0]];
  }
  const emoji = emojiAt(rest);
  if (emoji !== undefined) {
    return [{ kind: "emoji" }, emoji];
  }
  if (legacy) {
    const bare = bareAt(rest);
    if (bare !== undefined) {
      return [{ kind: "bare" }, bare];
    }
  }
  return undefined;
}

const TRAILING_URL_CHARS = new Set([".", ",", ";", ":", "!", "?", "'"]);

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

const IMAGE_EXT = new Set(["jpg", "jpeg", "png", "gif", "webp", "avif", "svg"]);
const VIDEO_EXT = new Set(["mp4", "webm", "mov", "m4v", "m3u8"]);
const AUDIO_EXT = new Set(["mp3", "m4a", "ogg", "oga", "opus", "wav", "flac", "aac"]);

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

type UrlBlock =
  | { readonly type: "url" | "relay"; readonly url: string }
  | { readonly type: "image" | "video" | "audio"; readonly url: string };

function urlBlock(
  raw: string,
  relay: boolean,
  imeta: ReadonlyMap<string, string> | undefined,
): UrlBlock | undefined {
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

function scalarAt(text: string, utf16: number): string | undefined {
  const cp = text.codePointAt(utf16);
  return cp === undefined ? undefined : String.fromCodePoint(cp);
}

/** The scalar value immediately before `pos` (astral-safe). */
function scalarBefore(text: string, pos: number): string | undefined {
  if (pos <= 0) {
    return undefined;
  }
  // An astral scalar starting at `pos - 2` is a surrogate pair ending exactly at `pos`.
  const pair = pos >= 2 ? text.codePointAt(pos - 2) : undefined;
  if (pair !== undefined && pair > 0xffff) {
    return String.fromCodePoint(pair);
  }
  return scalarAt(text, pos - 1);
}

/**
 * Parse note content (or a full event, to pick up `emoji` tags) into ordered blocks. One
 * left-to-right scan over Unicode scalar values; adjacent text merges and no empty text blocks are
 * emitted.
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

  const blocks: ContentBlock[] = [];
  const legacy = opts?.legacyBech32 === true;
  let textStart = 0;
  const flushText = (end: number): void => {
    if (end > textStart) {
      blocks.push({ type: "text", text: text.slice(textStart, end) });
    }
  };

  let pos = 0;
  while (pos < text.length) {
    const rest = text.slice(pos);
    const candidate = candidateAt(rest, legacy);
    if (candidate === undefined) {
      const c = scalarAt(text, pos);
      pos += c === undefined ? 1 : c.length;
      continue;
    }
    const [token, endRel] = candidate;
    const end = pos + endRel;
    const prevScalar = scalarBefore(text, pos);
    const next = scalarAt(text, end);

    let outcome: [ContentBlock, number] | undefined;
    switch (token.kind) {
      case "nostr": {
        const block = referenceFor(rest.slice(token.codeStart, endRel), false);
        outcome = block === undefined ? undefined : [block, end];
        break;
      }
      case "url": {
        const block = urlBlock(rest.slice(0, endRel), false, opts?.imeta);
        outcome = block === undefined ? undefined : [block, pos + block.url.length];
        break;
      }
      case "relay": {
        const block = urlBlock(rest.slice(0, endRel), true, undefined);
        outcome = block === undefined ? undefined : [block, pos + block.url.length];
        break;
      }
      case "invoice": {
        const glued =
          (prevScalar !== undefined && isWordChar(prevScalar)) ||
          (next !== undefined && isWordChar(next));
        outcome = glued
          ? undefined
          : [{ type: "invoice", bolt11: lowerAscii(rest.slice(token.prefixLen, endRel)) }, end];
        break;
      }
      case "hashtag": {
        const invalid = token.count > 42 || (prevScalar !== undefined && isTagChar(prevScalar));
        outcome = invalid ? undefined : [{ type: "hashtag", value: rest.slice(1, endRel) }, end];
        break;
      }
      case "emoji": {
        const shortcode = rest.slice(1, endRel - 1);
        const url = emojis.get(shortcode);
        outcome = url === undefined ? undefined : [{ type: "emoji", shortcode, url }, end];
        break;
      }
      case "bare":
        if (
          (prevScalar !== undefined && isWordChar(prevScalar)) ||
          (next !== undefined && isWordChar(next))
        ) {
          outcome = undefined;
        } else {
          const block = referenceFor(rest.slice(0, endRel), true);
          outcome = block === undefined ? undefined : [block, end];
        }
        break;
    }

    if (outcome === undefined) {
      // Shape matched but validation failed — `pos` is text, resume at the next scalar.
      const c = scalarAt(text, pos);
      pos += c === undefined ? 1 : c.length;
      continue;
    }
    const [block, nextTextStart] = outcome;
    flushText(pos);
    blocks.push(block);
    textStart = nextTextStart;
    pos = end;
  }

  flushText(text.length);
  return blocks;
}
