//! NIP-51 lists: parse the public tags of the standard list kinds and encode
//! or decode the NIP-44 private `.content` the author encrypts to themselves.
//!
//! The list parsers mirror the TS `parseMuteList`/`parsePinList`/
//! `parseBookmarkList`/`parseUserEmojiList`/`parseRelaySet`/
//! `parseFavoriteRelays`/`parseEmojiSet`/`parseFollowPack`; [`mute_items`] is
//! the kind-unchecked variant TS reuses on decrypted private tags.
//!
//! The private-tag layer follows the same split as NIP-59: TS injects an
//! async `Nip51Crypto` while Rust offers the pure steps
//! ([`private_tags_plaintext`]/[`parse_private_tags`]) plus the local-key flow
//! [`encrypt_private_tags_with_rng`]/[`encrypt_private_tags`]/
//! [`decrypt_private_tags`]. Remote-signer composition lives in nk-signer.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/51.md>

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    Event, EventAddress, EventBuilder, EventId, Keys, Kind, PublicKey, RelayUrl, Tag, Tags,
};

use crate::nips::error::{Error, ErrorKind, Result};
use crate::nips::nip44::{self, ConversationKey};

/// A public mute-list item (`p`/`e`/`t`/`word` tags). `Word` values are
/// lowercased like TS `toLowerCase()`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MuteItem {
    /// A muted public key (`p` tag).
    PublicKey(PublicKey),
    /// A muted event (`e` tag).
    Event(EventId),
    /// A muted hashtag (`t` tag — NIP-51 does not case-fold hashtags).
    Hashtag(String),
    /// A muted word (`word` tag, lowercased).
    Word(String),
}

/// One `emoji` tag entry: shortcode plus image URL, both non-empty.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Emoji {
    /// The `:shortcode:` name.
    pub shortcode: String,
    /// The image URL, stored verbatim.
    pub url: String,
}

/// A parsed kind-10003 bookmark list: `e` tags as event ids, `a` tags kept as
/// raw coordinate strings (TS does not validate them).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BookmarkList {
    /// Bookmarked event ids.
    pub events: Vec<EventId>,
    /// Bookmarked address coordinates, verbatim.
    pub addresses: Vec<String>,
}

/// A parsed kind-10030 user emoji list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserEmojiList {
    /// Custom emoji the user marks as favourites.
    pub emoji: Vec<Emoji>,
    /// Emoji-set coordinates (`a` tags), verbatim.
    pub sets: Vec<String>,
}

/// A parsed kind-30002 relay set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySet {
    /// The `d` tag identifier (`""` when absent).
    pub identifier: String,
    /// `relay` tag URLs, normalized and deduplicated first-seen.
    pub relays: Vec<RelayUrl>,
}

/// A parsed kind-10012 favorite-relays list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FavoriteRelays {
    /// `relay` tag URLs, normalized and deduplicated first-seen.
    pub relays: Vec<RelayUrl>,
    /// Kind-30002 relay-set coordinates (`a` tags), verbatim.
    pub sets: Vec<String>,
}

/// A parsed kind-30030 emoji set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmojiSet {
    /// The `d` tag identifier (`""` when absent).
    pub identifier: String,
    /// The `title` tag (`None` when absent or empty).
    pub title: Option<String>,
    /// The set's `emoji` entries.
    pub emoji: Vec<Emoji>,
}

/// A parsed kind-39089 starter (follow) pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FollowPack {
    /// The `d` tag identifier (`""` when absent).
    pub identifier: String,
    /// Recommended profiles (`p` tags).
    pub pubkeys: Vec<PublicKey>,
}

/// The kind check every `parse_*` entry point performs — TS `requireKind`:
/// `expected kind <expected>, got <actual>`.
fn require_kind(event: &Event, kind: Kind) -> Result<()> {
    if event.kind() != kind {
        return Err(Error::new(
            ErrorKind::EventValidation,
            alloc::format!(
                "expected kind {}, got {}",
                kind.as_u16(),
                event.kind().as_u16()
            ),
        ));
    }
    Ok(())
}

/// The tag value at index 1, or `None` when missing or `""` — the TS
/// `value === undefined || value === ""` guard.
fn non_empty_value(tag: &Tag) -> Option<&str> {
    tag.value().filter(|value| !value.is_empty())
}

/// `emoji` tags with a non-empty shortcode and URL — TS `collectEmoji`.
fn collect_emoji(tags: &Tags) -> Vec<Emoji> {
    let mut out = Vec::new();
    for tag in tags {
        if tag.name() != "emoji" {
            continue;
        }
        let items = tag.as_slice();
        let (Some(shortcode), Some(url)) = (items.get(1), items.get(2)) else {
            continue;
        };
        if shortcode.is_empty() || url.is_empty() {
            continue;
        }
        out.push(Emoji {
            shortcode: shortcode.clone(),
            url: url.clone(),
        });
    }
    out
}

/// `relay` tag values normalized like TS `collectRelays`: empty and invalid
/// entries are skipped, results deduplicated in first-seen order.
fn collect_relays(tags: &Tags) -> Vec<RelayUrl> {
    RelayUrl::normalize_all(tags.iter().filter_map(|tag| {
        if tag.name() == "relay" {
            tag.value()
        } else {
            None
        }
    }))
}

/// The `d` tag identifier or `""` — TS `identifier(tags)`.
fn identifier(tags: &Tags) -> String {
    String::from(tags.identifier().unwrap_or(""))
}

/// The NIP-51 a-tag shape `30002:<64-hex-pubkey>:<d>` with `d` possibly
/// containing `:` — TS `isRelaySetAddress`.
fn is_relay_set_address(value: &str) -> bool {
    let Some(kind_sep) = value.find(':') else {
        return false;
    };
    // String equality like TS `!== String(Kind.RelaySets)` — "030002" rejects.
    if &value[..kind_sep] != "30002" {
        return false;
    }
    let Some(pk_sep) = value[kind_sep + 1..].find(':').map(|i| kind_sep + 1 + i) else {
        return false;
    };
    let pubkey = &value[kind_sep + 1..pk_sep];
    let d = &value[pk_sep + 1..];
    PublicKey::from_hex(pubkey).is_ok() && !d.is_empty()
}

/// Mute items from a tag list without a kind check — what TS applies to
/// decrypted private tags via `parseMuteList`.
#[must_use]
pub fn mute_items(tags: &Tags) -> Vec<MuteItem> {
    let mut items = Vec::new();
    for tag in tags {
        let Some(value) = non_empty_value(tag) else {
            continue;
        };
        match tag.name() {
            "p" => {
                if let Ok(pubkey) = PublicKey::from_hex(value) {
                    items.push(MuteItem::PublicKey(pubkey));
                }
            }
            "e" => {
                if let Ok(id) = EventId::from_hex(value) {
                    items.push(MuteItem::Event(id));
                }
            }
            "t" => items.push(MuteItem::Hashtag(String::from(value))),
            "word" => items.push(MuteItem::Word(value.to_lowercase())),
            _ => {}
        }
    }
    items
}

/// Parses the public `p`/`e`/`t`/`word` tags of a kind-10000 mute list — the
/// TS `parseMuteList`.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10000, got <kind>`.
pub fn parse_mute_list(event: &Event) -> Result<Vec<MuteItem>> {
    require_kind(event, Kind::MUTE_LIST)?;
    Ok(mute_items(event.tags()))
}

/// An unsigned kind-10000 [`EventBuilder`] from public mute items — the TS
/// `muteListEventBuilder`. Empty hashtag/word items are not written; words
/// are lowercased.
pub fn mute_list(items: &[MuteItem]) -> EventBuilder {
    let mut tags = Vec::new();
    for item in items {
        match item {
            MuteItem::PublicKey(pubkey) => tags.push(Tag::public_key(*pubkey, None, None)),
            MuteItem::Event(id) => tags.push(Tag::event(*id, None, None, None)),
            MuteItem::Hashtag(hashtag) => {
                if !hashtag.is_empty() {
                    tags.push(Tag::hashtag(hashtag));
                }
            }
            MuteItem::Word(word) => {
                if !word.is_empty() {
                    tags.push(Tag::custom("word", [word.to_lowercase()]));
                }
            }
        }
    }
    EventBuilder::new(Kind::MUTE_LIST, "").tags(tags)
}

/// Parses the public `e` tags of a kind-10001 pin list — the TS
/// `parsePinList`. Non-hex values are skipped.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10001, got <kind>`.
pub fn parse_pin_list(event: &Event) -> Result<Vec<EventId>> {
    require_kind(event, Kind::PIN_LIST)?;
    Ok(event
        .tags()
        .iter()
        .filter(|tag| tag.name() == "e")
        .filter_map(|tag| tag.value())
        .filter_map(|value| EventId::from_hex(value).ok())
        .collect())
}

/// An unsigned kind-10001 [`EventBuilder`] from event ids — the TS
/// `pinListEventBuilder`.
pub fn pin_list(ids: &[EventId]) -> EventBuilder {
    EventBuilder::new(Kind::PIN_LIST, "")
        .tags(ids.iter().map(|id| Tag::event(*id, None, None, None)))
}

/// Parses the public `e`/`a` tags of a kind-10003 bookmark list — the TS
/// `parseBookmarkList`. `a` values are stored verbatim.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10003, got <kind>`.
pub fn parse_bookmark_list(event: &Event) -> Result<BookmarkList> {
    require_kind(event, Kind::BOOKMARK_LIST)?;
    let mut list = BookmarkList::default();
    for tag in event.tags() {
        let Some(value) = non_empty_value(tag) else {
            continue;
        };
        match tag.name() {
            "e" => {
                if let Ok(id) = EventId::from_hex(value) {
                    list.events.push(id);
                }
            }
            "a" => list.addresses.push(String::from(value)),
            _ => {}
        }
    }
    Ok(list)
}

/// An unsigned kind-10003 [`EventBuilder`] — the TS `bookmarkListEventBuilder`.
/// `e` tags are written before `a` tags.
pub fn bookmark_list(events: &[EventId], addresses: &[EventAddress]) -> EventBuilder {
    EventBuilder::new(Kind::BOOKMARK_LIST, "").tags(
        events
            .iter()
            .map(|id| Tag::event(*id, None, None, None))
            .chain(addresses.iter().map(|a| Tag::address(a, None))),
    )
}

/// Parses the public `emoji`/`a` tags of a kind-10030 user emoji list — the
/// TS `parseUserEmojiList`.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10030, got <kind>`.
pub fn parse_user_emoji_list(event: &Event) -> Result<UserEmojiList> {
    require_kind(event, Kind::USER_EMOJI_LIST)?;
    let sets = event
        .tags()
        .iter()
        .filter(|tag| tag.name() == "a")
        .filter_map(non_empty_value)
        .map(String::from)
        .collect();
    Ok(UserEmojiList {
        emoji: collect_emoji(event.tags()),
        sets,
    })
}

/// Parses the `d`/`relay` tags of a kind-30002 relay set — the TS
/// `parseRelaySet`.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 30002, got <kind>`.
pub fn parse_relay_set(event: &Event) -> Result<RelaySet> {
    require_kind(event, Kind::RELAY_SETS)?;
    Ok(RelaySet {
        identifier: identifier(event.tags()),
        relays: collect_relays(event.tags()),
    })
}

/// Parses the `relay`/`a` tags of a kind-10012 favorite-relays list — the TS
/// `parseFavoriteRelays`. Only `a` values shaped like kind-30002 coordinates
/// are kept as `sets`.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10012, got <kind>`.
pub fn parse_favorite_relays(event: &Event) -> Result<FavoriteRelays> {
    require_kind(event, Kind::FAVORITE_RELAYS)?;
    let sets = event
        .tags()
        .iter()
        .filter(|tag| tag.name() == "a")
        .filter_map(|tag| tag.value())
        .filter(|value| is_relay_set_address(value))
        .map(String::from)
        .collect();
    Ok(FavoriteRelays {
        relays: collect_relays(event.tags()),
        sets,
    })
}

/// Parses the `d`/`title`/`emoji` tags of a kind-30030 emoji set — the TS
/// `parseEmojiSet`. An empty `title` is treated as absent.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 30030, got <kind>`.
pub fn parse_emoji_set(event: &Event) -> Result<EmojiSet> {
    require_kind(event, Kind::EMOJI_SET)?;
    Ok(EmojiSet {
        identifier: identifier(event.tags()),
        title: event
            .tags()
            .first_value("title")
            .filter(|title| !title.is_empty())
            .map(String::from),
        emoji: collect_emoji(event.tags()),
    })
}

/// Parses the `d`/`p` tags of a kind-39089 starter pack — the TS
/// `parseFollowPack`.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 39089, got <kind>`.
pub fn parse_follow_pack(event: &Event) -> Result<FollowPack> {
    require_kind(event, Kind::STARTER_PACK)?;
    Ok(FollowPack {
        identifier: identifier(event.tags()),
        pubkeys: event
            .tags()
            .iter()
            .filter(|tag| tag.name() == "p")
            .filter_map(|tag| tag.value())
            .filter_map(|value| PublicKey::from_hex(value).ok())
            .collect(),
    })
}

/// The plaintext serialized private tags — `JSON.stringify(tags)` on the TS
/// side, compact serde JSON here. Serializing a `Tags` cannot fail.
#[must_use]
pub fn private_tags_plaintext(tags: &Tags) -> String {
    serde_json::to_string(tags).unwrap_or_default()
}

/// Parses a decrypted private-tag plaintext — the array-of-nonempty-string-
/// arrays shape TS validates with `isTag`. `serde_json` also rejects the lone
/// surrogates `JSON.parse` accepts (N10).
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `invalid NIP-51 private tags` for any
/// non-array, non-tag-array, or malformed JSON input.
pub fn parse_private_tags(plaintext: &str) -> Result<Tags> {
    serde_json::from_str::<Tags>(plaintext)
        .map_err(|_| Error::new(ErrorKind::EventValidation, "invalid NIP-51 private tags"))
}

/// NIP-44 ciphertext of the private tags, conversation peer = the author's
/// own public key — the TS `encryptPrivateTags` for a local key.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on a NIP-44 failure.
pub fn encrypt_private_tags_with_rng<R>(keys: &Keys, tags: &Tags, rng: &mut R) -> Result<String>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let own = keys.public_key();
    let conversation = ConversationKey::derive(keys.secret_key(), &own)?;
    nip44::encrypt_with_rng(&private_tags_plaintext(tags), &conversation, rng)
}

/// [`encrypt_private_tags_with_rng`] with an OS-entropy nonce.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on a NIP-44 failure.
///
/// # Panics
///
/// When the OS entropy source fails — the same contract as
/// [`crate::SecretKey::generate`].
#[cfg(feature = "os-rng")]
pub fn encrypt_private_tags(keys: &Keys, tags: &Tags) -> Result<String> {
    encrypt_private_tags_with_rng(keys, tags, &mut rand_core::UnwrapErr(getrandom::SysRng))
}

/// Decrypts NIP-51 `.content` — the TS `decryptPrivateTags` for a local key.
/// An empty `content` is no private tags, not ciphertext; the event author
/// must be `keys` (the author encrypts to themselves).
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `NIP-51 private content is only for the
/// author` when the event pubkey differs, or `invalid NIP-51 private tags`
/// when the plaintext is not a tag array. [`ErrorKind::Crypto`] on a NIP-44
/// failure.
pub fn decrypt_private_tags(keys: &Keys, event: &Event) -> Result<Tags> {
    if event.content().is_empty() {
        return Ok(Tags::new());
    }
    let own = keys.public_key();
    if event.pubkey() != own {
        return Err(Error::new(
            ErrorKind::EventValidation,
            "NIP-51 private content is only for the author",
        ));
    }
    let conversation = ConversationKey::derive(keys.secret_key(), &own)?;
    let plaintext = nip44::decrypt(event.content(), &conversation)?;
    parse_private_tags(&plaintext)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::string::ToString;
    use alloc::vec;

    use crate::{SecretKey, Timestamp};

    use super::*;

    const SK: &str = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";
    const PK1: &str = "166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99";
    const ID1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn keys() -> Keys {
        Keys::new(SecretKey::from_hex(SK).unwrap())
    }

    fn pk(hex: &str) -> PublicKey {
        PublicKey::from_hex(hex).unwrap()
    }

    fn id(hex: &str) -> EventId {
        EventId::from_hex(hex).unwrap()
    }

    fn tags(raw: &[&[&str]]) -> Tags {
        raw.iter()
            .map(|items| Tag::new(items.iter().map(|s| String::from(*s))).unwrap())
            .collect()
    }

    fn event(raw: &[&[&str]], kind: u16) -> Event {
        let unsigned = crate::UnsignedEvent::new(
            keys().public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::new(kind),
            tags(raw),
            "",
        );
        keys().sign_event_with_aux(unsigned, &[7u8; 32]).unwrap()
    }

    #[test]
    fn mute_items_parse_and_lowercase() {
        let event = event(
            &[
                &[
                    "p",
                    "166BF3765EBD1FC55DECFE395BEFF2EA3B2A4E0A8946E7EB578512B555737C99",
                ],
                &["e", ID1],
                &["t", "Spam"],
                &["word", "SCAM"],
                &["emoji", "ignored", "https://x.example/x.png"],
                &["p", "not-hex"],
                &["e", ""],
            ],
            10000,
        );
        let items = parse_mute_list(&event).unwrap();
        assert_eq!(
            items,
            vec![
                MuteItem::PublicKey(pk(PK1)),
                MuteItem::Event(id(ID1)),
                MuteItem::Hashtag("Spam".to_owned()),
                MuteItem::Word("scam".to_owned()),
            ]
        );
    }

    #[test]
    fn mute_list_round_trips() {
        let items = vec![
            MuteItem::PublicKey(pk(PK1)),
            MuteItem::Event(id(ID1)),
            MuteItem::Hashtag("spam".to_owned()),
            MuteItem::Word("SCAM".to_owned()),
            MuteItem::Hashtag(String::new()),
            MuteItem::Word(String::new()),
        ];
        let unsigned = mute_list(&items).build_at(pk(PK1), Timestamp::from_secs(0));
        assert_eq!(unsigned.kind(), Kind::MUTE_LIST);
        assert_eq!(unsigned.content(), "");
        let slices: Vec<Vec<String>> = unsigned
            .tags()
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        assert_eq!(
            slices,
            vec![
                vec!["p".to_owned(), PK1.to_owned()],
                vec!["e".to_owned(), ID1.to_owned()],
                vec!["t".to_owned(), "spam".to_owned()],
                vec!["word".to_owned(), "scam".to_owned()],
            ]
        );
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        let event = event(&[], 1);
        let error = parse_mute_list(&event).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EventValidation);
        assert_eq!(
            error.to_string(),
            "event validation: expected kind 10000, got 1"
        );
    }

    #[test]
    fn favorite_relays_keeps_only_relay_set_addresses() {
        let event = event(
            &[
                &["relay", "wss://a.example"],
                &[
                    "a",
                    "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:home",
                ],
                &[
                    "a",
                    "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:home:extra",
                ],
                &["a", "30002"],
                &[
                    "a",
                    "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99",
                ],
                &[
                    "a",
                    "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:",
                ],
                &[
                    "a",
                    "30000:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:x",
                ],
                &["relay", "://bad"],
            ],
            10012,
        );
        let parsed = parse_favorite_relays(&event).unwrap();
        assert_eq!(parsed.relays.len(), 1);
        assert_eq!(
            parsed.sets,
            vec![
                "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:home"
                    .to_owned(),
                "30002:166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99:home:extra"
                    .to_owned(),
            ]
        );
    }

    /// A deterministic `CryptoRng` for the round-trip test — the nonce bytes
    /// are throwaway here, no secrecy needed.
    struct ZeroRng;

    impl rand_core::TryRng for ZeroRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
            dest.fill(0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for ZeroRng {}

    #[test]
    fn private_tags_round_trip() {
        let keys = keys();
        let list = tags(&[&["p", PK1], &["word", "secret"]]);
        let content = encrypt_private_tags_with_rng(&keys, &list, &mut ZeroRng).unwrap();
        assert_ne!(content, private_tags_plaintext(&list));
        let event = {
            let unsigned = crate::UnsignedEvent::new(
                keys.public_key(),
                Timestamp::from_secs(0),
                Kind::MUTE_LIST,
                tags(&[&["p", PK1]]),
                &content,
            );
            keys.sign_event_with_aux(unsigned, &[3u8; 32]).unwrap()
        };
        let decrypted = decrypt_private_tags(&keys, &event).unwrap();
        let slices: Vec<Vec<String>> = decrypted.iter().map(|t| t.as_slice().to_vec()).collect();
        assert_eq!(
            slices,
            vec![
                vec!["p".to_owned(), PK1.to_owned()],
                vec!["word".to_owned(), "secret".to_owned()]
            ]
        );
    }

    fn event_with_content(content: &str) -> Event {
        let unsigned = crate::UnsignedEvent::new(
            keys().public_key(),
            Timestamp::from_secs(0),
            Kind::MUTE_LIST,
            Tags::new(),
            content,
        );
        keys().sign_event_with_aux(unsigned, &[9u8; 32]).unwrap()
    }

    #[test]
    fn private_tags_reject_foreign_author_and_bad_json() {
        let keys = keys();
        // The author check runs before NIP-44: an event declaring another
        // author is rejected without touching the ciphertext. Deserialize so
        // the event carries a foreign author — signing would demand the key.
        let foreign: Event = serde_json::from_value(serde_json::json!({
            "id": "01".repeat(32),
            "pubkey": "cc".repeat(32),
            "created_at": 0,
            "kind": 10000,
            "tags": [],
            "content": "ciphertext",
            "sig": "02".repeat(64),
        }))
        .unwrap();
        let error = decrypt_private_tags(&keys, &foreign).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EventValidation);
        assert_eq!(
            error.to_string(),
            "event validation: NIP-51 private content is only for the author"
        );

        // Empty content means no private tags — not ciphertext.
        assert_eq!(
            decrypt_private_tags(&keys, &event_with_content("")).unwrap(),
            Tags::new()
        );

        for bad in [
            "{}",
            "null",
            "1",
            "\"x\"",
            "[[]]",
            "[[\"p\", 1]]",
            "[1]",
            "not-json",
        ] {
            assert!(parse_private_tags(bad).is_err(), "{bad} must reject");
        }
    }
}
