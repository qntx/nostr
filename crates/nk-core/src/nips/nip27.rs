//! NIP-27 content tokenization — a hand-written scanner over Unicode
//! scalar values; `packages/nostr/src/nips/nip27.ts` implements the same
//! rules line for line.
//!
//! At position `i` the first rule whose shape matches decides — nostr,
//! http(s), ws(s), invoice, hashtag, emoji, then (with `legacy_bech32`) bare
//! bech32; a candidate that fails validation makes `i` text and the scan
//! resumes at the next scalar (no later rule is tried at `i`). Keywords
//! compare ASCII case-insensitively; there is no Unicode case folding and no
//! backtracking.
//!
//! `\p{L}`/`\p{M}`/`\p{N}` come from `unicode-properties`; `STOP` is Unicode
//! `White_Space` (`char::is_whitespace`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{Event, Tags};
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};
use url::Url;

use crate::nips::nip19::{AddressPointer, Entity, EventPointer, ProfilePointer};

/// A decoded NIP-19 reference carried by [`ContentBlock::Reference`].
///
/// `npub` yields a [`ProfilePointer`] with no relay hints, `note` an
/// [`EventPointer`] with only the id — the bare `note` mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reference {
    /// `npub` or `nprofile`.
    Profile(ProfilePointer),
    /// `note` or `nevent`.
    Event(EventPointer),
    /// `naddr`.
    Address(AddressPointer),
}

/// One tokenized piece of note content. `Text`, URL-family, `Hashtag`, and
/// `Emoji` blocks borrow from the input; `Invoice` owns its lowercased text.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentBlock<'a> {
    /// Plain text between tokens; adjacent runs merge, never empty.
    Text(&'a str),
    /// A `nostr:` URI (`bare: false`) or a legacy bare bech32 entity
    /// (`bare: true`).
    Reference {
        /// The decoded NIP-19 pointer.
        reference: Reference,
        /// `true` when the entity had no `nostr:` prefix.
        bare: bool,
    },
    /// A non-media http(s) URL.
    Url(&'a str),
    /// An http(s) URL classified as an image (imeta MIME, then extension).
    Image(&'a str),
    /// An http(s) URL classified as a video.
    Video(&'a str),
    /// An http(s) URL classified as audio.
    Audio(&'a str),
    /// A `ws://`/`wss://` relay URL; never consults imeta.
    Relay(&'a str),
    /// A `#hashtag` without the `#`.
    Hashtag(&'a str),
    /// A `:shortcode:` whose value is an `emoji` tag on the parsed content.
    Emoji {
        /// The shortcode without the surrounding colons.
        shortcode: &'a str,
        /// The image URL from the matching `emoji` tag.
        url: &'a str,
    },
    /// A BOLT11 invoice, lowercased with any `lightning:` prefix removed.
    Invoice(String),
}

/// Options for [`parse_content`] / [`parse_event_content`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ParseOptions<'a> {
    /// Also recognize bare `npub`/`nprofile`/`note`/`nevent`/`naddr` without
    /// the `nostr:` prefix (the NIP-27 legacy form, default `false`).
    pub legacy_bech32: bool,
    /// URL → MIME map (the `m` field of NIP-92 `imeta` tags); consulted before
    /// extension classification and never for relay blocks.
    pub imeta: Option<&'a BTreeMap<String, String>>,
}

/// ASCII-only case folding — the literal prefixes (`nostr:`, `https`,
/// `lightning:`) are matched ASCII-insensitively (`asciiCi` in TS).
const fn fold_ascii(c: char) -> char {
    c.to_ascii_lowercase()
}

/// Matches an ASCII literal case-insensitively (ASCII fold only).
fn lit_at(rest: &str, lit: &str) -> Option<usize> {
    let mut consumed = 0;
    let mut chars = rest.char_indices();
    for want in lit.chars() {
        match chars.next() {
            Some((i, c)) if fold_ascii(c) == want => consumed = i + c.len_utf8(),
            _ => return None,
        }
    }
    Some(consumed)
}

/// The bech32 data charset — `0`, `2`–`9`, `a c-h j-n p-z`, both ASCII cases.
const fn is_bech32_char(c: char) -> bool {
    matches!(
        fold_ascii(c),
        '0' | '2'..='9' | 'a' | 'c'..='h' | 'j'..='n' | 'p'..='z'
    )
}

/// Bytes of the maximal bech32-charset run at the start of `rest` (may be 0).
fn bech32_run(rest: &str) -> usize {
    rest.chars()
        .take_while(|c| is_bech32_char(*c))
        .map(char::len_utf8)
        .sum()
}

/// The emoji-token class `[A-Za-z0-9_-]`.
const fn is_emoji_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-')
}

/// `[\p{L}\p{M}\p{N}_]` — the hashtag/boundary tag character.
fn is_tag_char(c: char) -> bool {
    c == '_'
        || matches!(
            c.general_category_group(),
            GeneralCategoryGroup::Letter
                | GeneralCategoryGroup::Mark
                | GeneralCategoryGroup::Number
        )
}

/// `[\p{L}\p{N}]` — the word character that must not touch invoice or
/// bare-bech32 candidates.
fn is_word_char(c: char) -> bool {
    matches!(
        c.general_category_group(),
        GeneralCategoryGroup::Letter | GeneralCategoryGroup::Number
    )
}

/// URL-run stop characters: Unicode `White_Space`, `<`, `>`, `"`, CJK
/// punctuation U+3000–U+303F, and full-width forms U+FF00–U+FFEF.
fn is_url_stop(c: char) -> bool {
    c.is_whitespace()
        || matches!(c, '<' | '>' | '"')
        || ('\u{3000}'..='\u{303f}').contains(&c)
        || ('\u{ff00}'..='\u{ffef}').contains(&c)
}

/// NIP-19 prefixes inside `nostr:` — `nsec` is accepted by the pattern and
/// rejected by [`reference_block`].
const NIP19_PREFIXES: [&str; 6] = ["npub", "nprofile", "note", "nevent", "naddr", "nsec"];
/// Bare prefixes for the legacy rule — no `nsec`.
const BARE_PREFIXES: [&str; 5] = ["npub", "nprofile", "note", "nevent", "naddr"];

/// `1` then a non-empty bech32-charset run; returns the end offset.
fn sep_then_data(rest: &str, at: usize) -> Option<usize> {
    rest.get(at..)?.starts_with('1').then(|| {
        let run = bech32_run(&rest[at + 1..]);
        (run > 0).then_some(at + 1 + run)
    })?
}

/// `nostr:` + NIP-19 prefix + `1` + charset. Returns `(code_start, end)` —
/// `code_start` skips the URI prefix.
fn nostr_at(rest: &str) -> Option<(usize, usize)> {
    let code_start = lit_at(rest, "nostr:")?;
    let mut at = code_start;
    at += NIP19_PREFIXES.iter().find_map(|p| lit_at(&rest[at..], p))?;
    let end = sep_then_data(rest, at)?;
    Some((code_start, end))
}

/// `https?://` / `wss?://` + URL run. Returns the raw match end.
fn url_at(rest: &str, ws: bool) -> Option<usize> {
    let base = if ws { "ws" } else { "http" };
    let mut at = lit_at(rest, base)?;
    // `s?` — optional second s, ASCII-only folding.
    if let Some(c) = rest[at..].chars().next().filter(|c| fold_ascii(*c) == 's') {
        at += c.len_utf8();
    }
    at += lit_at(&rest[at..], "://")?;
    let run = rest[at..]
        .chars()
        .take_while(|c| !is_url_stop(*c))
        .map(char::len_utf8)
        .sum::<usize>();
    (run > 0).then_some(at + run)
}

/// `(lightning:)?ln(bcrt|tbs|bc|tb)` + a maximal `BECH32 ∪ {1}` run, then
/// split at the run's last `1`: the amount before it is empty or `\d+` plus
/// at most one of `munp` (ASCII either case), and the data after it is
/// non-empty. Returns `(prefix_len, end)`.
fn invoice_at(rest: &str) -> Option<(usize, usize)> {
    let prefix = lit_at(rest, "lightning:").unwrap_or(0);
    let mut at = prefix + lit_at(&rest[prefix..], "ln")?;
    at += ["bcrt", "tbs", "bc", "tb"]
        .iter()
        .find_map(|cur| lit_at(&rest[at..], cur))?;
    // The maximal run may contain `1`s — the LAST `1` is the separator.
    let mut run_end = at;
    let mut last_sep = None;
    for (off, c) in rest[at..].char_indices() {
        if c == '1' {
            last_sep = Some(at + off);
        } else if !is_bech32_char(c) {
            break;
        }
        run_end = at + off + c.len_utf8();
    }
    let last_sep = last_sep?;
    if last_sep + 1 == run_end {
        return None; // empty data
    }
    let amount = &rest[at..last_sep];
    if !amount.is_empty() {
        let digits = amount.bytes().take_while(u8::is_ascii_digit).count();
        let tail = &amount[digits..];
        if digits == 0
            || tail.len() > 1
            || (tail.len() == 1
                && !matches!(
                    tail.chars().next().map(fold_ascii),
                    Some('m' | 'u' | 'n' | 'p')
                ))
        {
            return None;
        }
    }
    Some((prefix, run_end))
}

/// `#` + a maximal `TAG` run — returns `(end, scalar count)`; the 1–42
/// length cap is a validation.
fn hashtag_at(rest: &str) -> Option<(usize, usize)> {
    if !rest.starts_with('#') {
        return None;
    }
    let mut end = 1;
    let mut count = 0;
    for (i, c) in rest[1..].char_indices() {
        if !is_tag_char(c) {
            break;
        }
        count += 1;
        end = 1 + i + c.len_utf8();
    }
    (count > 0).then_some((end, count))
}

/// `:[A-Za-z0-9_-]+:` — a shortcode candidate (membership checked later).
fn emoji_at(rest: &str) -> Option<usize> {
    if !rest.starts_with(':') {
        return None;
    }
    let run: usize = rest[1..]
        .chars()
        .take_while(|c| is_emoji_char(*c))
        .map(char::len_utf8)
        .sum();
    if run == 0 {
        return None;
    }
    rest[1 + run..].starts_with(':').then_some(1 + run + 1)
}

/// `npub|nprofile|note|nevent|naddr` + `1` + charset — the legacy bare rule.
fn bare_at(rest: &str) -> Option<usize> {
    let at = BARE_PREFIXES.iter().find_map(|p| lit_at(rest, p))?;
    sep_then_data(rest, at)
}

/// Which rule matched at a position, in alternation order.
enum Token {
    Nostr { code_start: usize },
    Url,
    Relay,
    Invoice { prefix_len: usize },
    Hashtag { count: usize },
    Emoji,
    Bare,
}

/// First textual match at `pos` — the leftmost-first alternation order of
/// the tokenizer. Returns the token kind and the raw match end
/// (byte offset relative to `rest`).
fn candidate_at(rest: &str, legacy: bool) -> Option<(Token, usize)> {
    if let Some((code_start, end)) = nostr_at(rest) {
        return Some((Token::Nostr { code_start }, end));
    }
    if let Some(end) = url_at(rest, false) {
        return Some((Token::Url, end));
    }
    if let Some(end) = url_at(rest, true) {
        return Some((Token::Relay, end));
    }
    if let Some((prefix_len, end)) = invoice_at(rest) {
        return Some((Token::Invoice { prefix_len }, end));
    }
    if let Some((end, count)) = hashtag_at(rest) {
        return Some((Token::Hashtag { count }, end));
    }
    if let Some(end) = emoji_at(rest) {
        return Some((Token::Emoji, end));
    }
    if legacy && let Some(end) = bare_at(rest) {
        return Some((Token::Bare, end));
    }
    None
}

/// `nostr:` or bare code → reference block; `nsec` and decode failures yield
/// no block (the candidate becomes plain text).
fn reference_block(code: &str, bare: bool) -> Option<ContentBlock<'_>> {
    let reference = match Entity::from_bech32(code).ok()? {
        Entity::Profile(pointer) => Reference::Profile(pointer),
        Entity::Event(pointer) => Reference::Event(pointer),
        Entity::Address(pointer) => Reference::Address(pointer),
        Entity::Public(pubkey) => Reference::Profile(ProfilePointer {
            pubkey,
            relays: Vec::new(),
        }),
        Entity::Note(id) => Reference::Event(EventPointer {
            id,
            relays: Vec::new(),
            author: None,
            kind: None,
        }),
        _ => return None,
    };
    Some(ContentBlock::Reference { reference, bare })
}

const TRAILING_URL_CHARS: [char; 7] = ['.', ',', ';', ':', '!', '?', '\''];

/// `trimUrlTail`: drop trailing sentence punctuation and closers `)`/`]`
/// that have no matching opener inside the run.
fn trim_url_tail(mut url: &str) -> &str {
    loop {
        let last = url.chars().next_back();
        if last.is_some_and(|c| TRAILING_URL_CHARS.contains(&c)) {
            url = &url[..url.len() - 1];
            continue;
        }
        let (open, close) = match last {
            Some(')') => ('(', ')'),
            Some(']') => ('[', ']'),
            _ => return url,
        };
        let mut opens = 0usize;
        let mut closes = 0usize;
        for c in url.chars() {
            if c == open {
                opens += 1;
            } else if c == close {
                closes += 1;
            }
        }
        if closes <= opens {
            return url;
        }
        url = &url[..url.len() - 1];
    }
}

#[derive(Clone, Copy)]
enum Media {
    Image,
    Video,
    Audio,
}

/// `mimeMedia`: the MIME base (before the first `/`) must literally be
/// `image`, `video`, or `audio`.
fn mime_media(mime: &str) -> Option<Media> {
    let base = mime.split('/').next().unwrap_or_default();
    match base {
        "image" => Some(Media::Image),
        "video" => Some(Media::Video),
        "audio" => Some(Media::Audio),
        _ => None,
    }
}

const IMAGE_EXT: [&str; 7] = ["jpg", "jpeg", "png", "gif", "webp", "avif", "svg"];
const VIDEO_EXT: [&str; 5] = ["mp4", "webm", "mov", "m4v", "m3u8"];
const AUDIO_EXT: [&str; 8] = ["mp3", "m4a", "ogg", "oga", "opus", "wav", "flac", "aac"];

/// `extMedia`: the pathname's last `.` suffix, lowercased.
fn ext_media(pathname: &str) -> Option<Media> {
    let ext = pathname.rsplit_once('.')?.1.to_lowercase();
    if IMAGE_EXT.contains(&ext.as_str()) {
        Some(Media::Image)
    } else if VIDEO_EXT.contains(&ext.as_str()) {
        Some(Media::Video)
    } else {
        AUDIO_EXT.contains(&ext.as_str()).then_some(Media::Audio)
    }
}

/// `urlBlock`: trim, `new URL` validity (host must contain `.`), then
/// relay/media/plain classification. Returns the block and the trimmed
/// length so the caller can set the text cursor like TS does.
fn url_block<'a>(
    raw: &'a str,
    relay: bool,
    imeta: Option<&BTreeMap<String, String>>,
) -> Option<(ContentBlock<'a>, usize)> {
    let url = trim_url_tail(raw);
    let parsed = Url::parse(url).ok()?;
    if !parsed.host_str().is_some_and(|host| host.contains('.')) {
        return None;
    }
    if relay {
        return Some((ContentBlock::Relay(url), url.len()));
    }
    let media = imeta
        .and_then(|map| map.get(url))
        .and_then(|mime| mime_media(mime))
        .or_else(|| ext_media(parsed.path()));
    let block = match media {
        None => ContentBlock::Url(url),
        Some(Media::Image) => ContentBlock::Image(url),
        Some(Media::Video) => ContentBlock::Video(url),
        Some(Media::Audio) => ContentBlock::Audio(url),
    };
    Some((block, url.len()))
}

/// `tag[0] === "emoji"` entries with non-empty shortcode and url, later
/// duplicates overwriting earlier ones like `Map.set`.
fn emoji_map(tags: Option<&Tags>) -> BTreeMap<&'_ str, &'_ str> {
    let mut map = BTreeMap::new();
    for tag in tags.into_iter().flatten() {
        let [name, shortcode, url, ..] = tag.as_slice() else {
            continue;
        };
        if name == "emoji" && !shortcode.is_empty() && !url.is_empty() {
            map.insert(shortcode.as_str(), url.as_str());
        }
    }
    map
}

/// Parses note content into ordered blocks.
///
/// `emoji_tags` supplies the `emoji` tags when parsing standalone content
/// (`None` means no emoji ever matches); [`parse_event_content`] passes the
/// event's own tags. One left-to-right scan; adjacent text merges and no
/// empty text blocks are emitted.
#[must_use]
pub fn parse_content<'a>(
    content: &'a str,
    emoji_tags: Option<&'a Tags>,
    options: ParseOptions<'a>,
) -> Vec<ContentBlock<'a>> {
    let emojis = emoji_map(emoji_tags);
    let mut blocks = Vec::new();
    let mut text_start = 0usize;
    let mut pos = 0usize;

    while pos < content.len() {
        let rest = &content[pos..];
        let Some((token, end_rel)) = candidate_at(rest, options.legacy_bech32) else {
            // `u` flag advances one code point per position.
            pos += rest.chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let end = pos + end_rel;
        let prev = content[..pos].chars().next_back();
        let next = content[end..].chars().next();

        let outcome = match token {
            Token::Nostr { code_start } => {
                reference_block(&rest[code_start..end_rel], false).map(|b| (b, end))
            }
            Token::Url => {
                url_block(&rest[..end_rel], false, options.imeta).map(|(b, n)| (b, pos + n))
            }
            Token::Relay => url_block(&rest[..end_rel], true, None).map(|(b, n)| (b, pos + n)),
            Token::Invoice { prefix_len } => {
                if prev.is_some_and(is_word_char) || next.is_some_and(is_word_char) {
                    None
                } else {
                    Some((
                        ContentBlock::Invoice(rest[prefix_len..end_rel].to_lowercase()),
                        end,
                    ))
                }
            }
            Token::Hashtag { count } => {
                if count > 42 || prev.is_some_and(is_tag_char) {
                    None
                } else {
                    Some((ContentBlock::Hashtag(&rest[1..end_rel]), end))
                }
            }
            Token::Emoji => {
                let shortcode = &rest[1..end_rel - 1];
                emojis
                    .get(shortcode)
                    .map(|url| (ContentBlock::Emoji { shortcode, url }, end))
            }
            Token::Bare => {
                if prev.is_some_and(is_word_char) || next.is_some_and(is_word_char) {
                    None
                } else {
                    reference_block(&rest[..end_rel], true).map(|b| (b, end))
                }
            }
        };

        let Some((block, next_text_start)) = outcome else {
            // Failed candidate → resume one char after its start (the first
            // char is ASCII for every rule).
            pos += 1;
            continue;
        };
        if pos > text_start {
            blocks.push(ContentBlock::Text(&content[text_start..pos]));
        }
        blocks.push(block);
        text_start = next_text_start;
        pos = end;
    }

    if content.len() > text_start {
        blocks.push(ContentBlock::Text(&content[text_start..]));
    }
    blocks
}

/// Parse an event's `content`, picking up its `emoji` tags.
#[must_use]
pub fn parse_event_content<'a>(
    event: &'a Event,
    options: ParseOptions<'a>,
) -> Vec<ContentBlock<'a>> {
    parse_content(event.content(), Some(event.tags()), options)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use crate::{PublicKey, Tag, Tags};

    use super::*;

    fn text_blocks(content: &str) -> Vec<ContentBlock<'_>> {
        parse_content(content, None, ParseOptions::default())
    }

    #[test]
    fn url_tail_trimming() {
        let blocks = text_blocks("see https://a.b/c). and https://d.e/(f)");
        assert_eq!(
            blocks,
            vec![
                ContentBlock::Text("see "),
                ContentBlock::Url("https://a.b/c"),
                ContentBlock::Text("). and "),
                ContentBlock::Url("https://d.e/(f)"),
            ]
        );
    }

    #[test]
    fn invoice_amount_backtracking() {
        // `lnbc101xyz`: the greedy `\d+` backtracks — amount `10`, the third
        // `1` is the separator, `xyz` the data run.
        let blocks = text_blocks("pay lnbc101xyz now");
        assert_eq!(
            blocks,
            vec![
                ContentBlock::Text("pay "),
                ContentBlock::Invoice("lnbc101xyz".to_owned()),
                ContentBlock::Text(" now"),
            ]
        );
    }

    #[test]
    fn kelvin_and_long_s_fold() {
        // U+212A matches `k` inside the bech32 charset, U+017F matches `s` in
        // `nostr:` — the invoice stays text (bad boundary via `x`).
        let blocks = text_blocks(
            "no\u{17f}tr:nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq x\u{212a}y",
        );
        assert!(
            blocks
                .iter()
                .all(|b| !matches!(b, ContentBlock::Reference { .. })),
            "nsec must be ignored even through the folded `nostr:` prefix"
        );
    }

    #[test]
    fn hashtag_boundaries() {
        // `x#bad` — a tag char before `#` makes the candidate text; `#not`'s
        // match ends where `#tag` begins, so `t` counts as `#tag`'s previous
        // char and it is text too.
        let blocks = text_blocks("#ok x#bad #end #not#tag");
        assert_eq!(
            blocks,
            vec![
                ContentBlock::Hashtag("ok"),
                ContentBlock::Text(" x#bad "),
                ContentBlock::Hashtag("end"),
                ContentBlock::Text(" "),
                ContentBlock::Hashtag("not"),
                ContentBlock::Text("#tag"),
            ]
        );
    }

    #[test]
    fn legacy_bare_entities() {
        let npub = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m";
        assert_eq!(text_blocks(npub), vec![ContentBlock::Text(npub)]);
        let blocks = parse_content(
            npub,
            None,
            ParseOptions {
                legacy_bech32: true,
                ..ParseOptions::default()
            },
        );
        assert_eq!(
            blocks,
            vec![ContentBlock::Reference {
                reference: Reference::Profile(ProfilePointer {
                    pubkey: PublicKey::from_hex(
                        "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"
                    )
                    .unwrap(),
                    relays: Vec::new(),
                }),
                bare: true,
            }]
        );
    }

    #[test]
    fn emoji_needs_tag() {
        let tags = Tags::from_iter([Tag::custom("emoji", ["wave", "https://a.b/w.gif"])]);
        let without: Vec<ContentBlock<'_>> =
            parse_content("hi :wave:", None, ParseOptions::default());
        let with = parse_content("hi :wave:", Some(&tags), ParseOptions::default());
        assert_eq!(without, vec![ContentBlock::Text("hi :wave:")]);
        assert_eq!(
            with,
            vec![
                ContentBlock::Text("hi "),
                ContentBlock::Emoji {
                    shortcode: "wave",
                    url: "https://a.b/w.gif"
                },
            ]
        );
    }

    #[test]
    fn imeta_precedes_extension() {
        let mut imeta = BTreeMap::new();
        imeta.insert("https://a.b/f".to_owned(), "video/mp4".to_owned());
        let blocks = parse_content(
            "https://a.b/f.png https://a.b/f",
            None,
            ParseOptions {
                imeta: Some(&imeta),
                ..ParseOptions::default()
            },
        );
        assert_eq!(
            blocks,
            vec![
                ContentBlock::Image("https://a.b/f.png"),
                ContentBlock::Text(" "),
                ContentBlock::Video("https://a.b/f"),
            ]
        );
    }
}
