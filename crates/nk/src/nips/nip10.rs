//! NIP-10 thread references: parsing marked and legacy positional `e` tags
//! plus `q` quotes and `p` profiles out of an event's tag list, and building
//! reply tags in the preferred marked style.
//!
//! [`parse_thread_tags`] is the counterpart of the TS `parseThreadTags`;
//! [`reply_tags`]/[`reply_to`] mirror `buildReplyTags`/`replyTo` (marked
//! `root`/`reply` style, `q` tags appended last). Relay strings read from
//! tags stay raw [`String`]s and are written back verbatim; the optional
//! caller-supplied relay hint is a normalized [`RelayUrl`] (NK3-00 N4).
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/10.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{Event, EventAddress, EventBuilder, EventId, Kind, PublicKey, RelayUrl, Tag, Tags};

use crate::nips::error::{Error, ErrorKind, Result};
use crate::nips::nip19::{AddressPointer, EventPointer, ProfilePointer};

/// A quoted event (`q` tag): an event id or an addressable coordinate.
/// Discriminate by variant — the counterpart of TS `"id" in quote`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Quote {
    /// An `EventPointer` (`id` plus relay/author hints).
    Event(EventPointer),
    /// An `AddressPointer` (`kind:pubkey:identifier`).
    Address(AddressPointer),
}

/// Parsed NIP-10 thread references from an event's `e`/`q`/`p` tags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadReferences {
    /// Pointer to the root of the thread.
    pub root: Option<EventPointer>,
    /// Pointer to the parent event the note replies to.
    pub reply: Option<EventPointer>,
    /// Other e-tagged events (not root/reply).
    pub mentions: Vec<EventPointer>,
    /// Quoted events (`q` tags), in scan order.
    pub quotes: Vec<Quote>,
    /// P-tagged profiles involved in the thread.
    pub profiles: Vec<ProfilePointer>,
}

/// 64-hex of any case, the counterpart of TS `isHex32(v.toLowerCase())`.
fn is_hex32(value: &str) -> bool {
    EventId::from_hex(value).is_ok()
}

/// `tag[i]` as a one-element relay list, or empty when absent/`""` — the TS
/// `tag[2] !== undefined && tag[2] !== "" ? [tag[2]] : []` pattern. The string
/// is kept verbatim (hints are opaque, never normalized).
fn relay_slot(items: &[String], index: usize) -> Vec<String> {
    match items.get(index) {
        Some(value) if !value.is_empty() => alloc::vec![value.clone()],
        _ => Vec::new(),
    }
}

/// The NIP-10 5-tuple pubkey is index 4; the NIP-01 4-tuple pubkey is index 3.
fn e_tag_author(items: &[String]) -> Option<PublicKey> {
    for index in [4usize, 3] {
        if let Some(author) = items.get(index)
            && let Ok(pubkey) = PublicKey::from_hex(author)
        {
            return Some(pubkey);
        }
    }
    None
}

/// TS `eventPointerFromETag`: `["e", id, relay?, …]` with a mixed-case
/// hex32 id; relay hint kept verbatim, author from index 4 or 3.
fn event_pointer(items: &[String]) -> Option<EventPointer> {
    let id = EventId::from_hex(items.get(1)?).ok()?;
    let mut pointer = EventPointer {
        id,
        relays: relay_slot(items, 2),
        author: None,
        kind: None,
    };
    pointer.author = e_tag_author(items);
    Some(pointer)
}

/// TS `quoteFromQTag`: a hex32 value is an [`EventPointer`] (index 3 is the
/// author slot); anything else is parsed as an address and invalid values are
/// ignored. Address-form `q` tags never use index 3.
fn quote_from_tag(items: &[String]) -> Option<Quote> {
    let value = items.get(1)?;
    if value.is_empty() {
        return None;
    }
    let relays = relay_slot(items, 2);
    if let Ok(id) = EventId::from_hex(value) {
        let author = items.get(3).and_then(|a| PublicKey::from_hex(a).ok());
        return Some(Quote::Event(EventPointer {
            id,
            relays,
            author,
            kind: None,
        }));
    }
    let address = value.parse::<EventAddress>().ok()?;
    Some(Quote::Address(AddressPointer {
        identifier: String::from(address.identifier()),
        pubkey: address.pubkey(),
        kind: address.kind(),
        relays,
    }))
}

/// Merges a matching `p` tag's relay hints into `ptr` (dedup, order kept) —
/// the TS `inheritHints` closure.
fn inherit_hints(mut ptr: EventPointer, profiles: &[ProfilePointer]) -> EventPointer {
    let Some(author) = ptr.author else {
        return ptr;
    };
    let Some(profile) = profiles.iter().find(|p| p.pubkey == author) else {
        return ptr;
    };
    for url in &profile.relays {
        if !ptr.relays.contains(url) {
            ptr.relays.push(url.clone());
        }
    }
    ptr
}

/// Parses NIP-10 thread markers and legacy positional e-tags from `tags`.
///
/// Mirrors the TS `parseThreadTags` rule by rule: the scan runs from the last
/// tag backwards; `root`/`reply` markers win; a 64-hex index 3 is a NIP-01
/// pubkey, not a marker; without markers the last unmarked `e` is the parent
/// and the second-to-last the root; `root`/`reply` back-fill each other;
/// mentions drop whichever ids became root or reply; event pointers inherit
/// relay hints from a `p` tag on the same author (dedup, order kept).
/// `q` and `p` entries collect in the same scan order.
#[must_use]
pub fn parse_thread_tags(tags: &Tags) -> ThreadReferences {
    let mut mentions = Vec::new();
    let mut quotes = Vec::new();
    let mut profiles = Vec::new();
    let mut root: Option<EventPointer> = None;
    let mut reply: Option<EventPointer> = None;
    let mut maybe_parent: Option<EventPointer> = None;
    let mut maybe_root: Option<EventPointer> = None;

    for tag in tags.iter().rev() {
        let items = tag.as_slice();
        let value = items.get(1);
        if tag.name() == "e" && value.is_some_and(|v| is_hex32(v)) {
            let Some(pointer) = event_pointer(items) else {
                continue;
            };
            let marker = items.get(3).map(String::as_str);

            if marker == Some("root") {
                root = Some(pointer);
                continue;
            }
            if marker == Some("reply") {
                reply = Some(pointer);
                continue;
            }
            // Preferred markers are root/reply only. A hex32 at index 3 is a
            // NIP-01 pubkey, not a marker.
            if let Some(marker) = marker
                && !marker.is_empty()
                && !is_hex32(marker)
            {
                mentions.push(pointer);
                continue;
            }

            // Legacy positional: last unmarked is parent, second-to-last root.
            if maybe_parent.is_some() {
                maybe_root = Some(pointer.clone());
            } else {
                maybe_parent = Some(pointer.clone());
            }
            mentions.push(pointer);
            continue;
        }

        if tag.name() == "q" {
            if let Some(quote) = quote_from_tag(items) {
                quotes.push(quote);
            }
            continue;
        }

        if tag.name() == "p"
            && let Some(p_value) = value
            && let Ok(pubkey) = PublicKey::from_hex(p_value)
        {
            profiles.push(ProfilePointer {
                pubkey,
                relays: relay_slot(items, 2),
            });
        }
    }

    let root = root
        .or(maybe_root)
        .or_else(|| maybe_parent.clone())
        .or_else(|| reply.clone());
    let reply = reply.or(maybe_parent).or_else(|| root.clone());

    // Drop root/reply from mentions (by id).
    let drop: Vec<EventId> = [root.as_ref(), reply.as_ref()]
        .into_iter()
        .flatten()
        .map(|p| p.id)
        .collect();
    mentions.retain(|m| !drop.contains(&m.id));

    ThreadReferences {
        root: root.map(|r| inherit_hints(r, &profiles)),
        reply: reply.map(|r| inherit_hints(r, &profiles)),
        mentions: mentions
            .into_iter()
            .map(|m| inherit_hints(m, &profiles))
            .collect(),
        quotes,
        profiles,
    }
}

/// Positional tag values, exactly like `Tag::event`/`Tag::public_key` but with
/// the raw relay string tags carry (a typed [`RelayUrl`] cannot express a
/// verbatim `""` or unnormalized hint): absent slots before a present one
/// emit `""`, trailing absent slots are omitted.
fn push_positions(items: &mut Vec<String>, positions: &[Option<String>]) {
    let end = positions
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i| i + 1);
    for position in positions.iter().take(end) {
        items.push(position.clone().unwrap_or_default());
    }
}

/// `["e", id, relay, marker, pubkey]` with `Tag.e` positional trimming.
fn e_tag(
    id: EventId,
    relay: Option<String>,
    marker: Option<&str>,
    pubkey: Option<PublicKey>,
) -> Tag {
    let mut items = alloc::vec![id.to_hex()];
    push_positions(
        &mut items,
        &[
            relay,
            marker.map(String::from),
            pubkey.map(PublicKey::to_hex),
        ],
    );
    Tag::custom("e", items)
}

/// `["p", pubkey, relay]` with `Tag.p` positional trimming.
fn p_tag(pubkey: PublicKey, relay: Option<String>) -> Tag {
    let mut items = alloc::vec![pubkey.to_hex()];
    push_positions(&mut items, &[relay]);
    Tag::custom("p", items)
}

/// Appends `["p", pubkey, relay?]`, once per pubkey (first occurrence kept).
fn add_p_tag(
    tags: &mut Vec<Tag>,
    seen: &mut Vec<PublicKey>,
    pubkey: PublicKey,
    relay: Option<String>,
) {
    if seen.contains(&pubkey) {
        return;
    }
    seen.push(pubkey);
    tags.push(p_tag(pubkey, relay));
}

/// A built `q` tag plus the author/relay hints TS uses to p-tag the author.
struct BuiltQuote {
    tag: Tag,
    author: Option<PublicKey>,
    relay: Option<String>,
}

/// TS `quoteToTag` for typed quotes: `["q", id]` / `["q", id, relay]` /
/// `["q", id, relay, author]` for events (author forces the relay slot, `""`
/// when absent) and `["q", coord]` / `["q", coord, relay]` for addresses.
fn quote_to_tag(quote: &Quote) -> BuiltQuote {
    match quote {
        Quote::Event(pointer) => {
            let relay = pointer.relays.first().cloned();
            match pointer.author {
                Some(author) => BuiltQuote {
                    tag: Tag::custom(
                        "q",
                        [
                            pointer.id.to_hex(),
                            relay.clone().unwrap_or_default(),
                            author.to_hex(),
                        ],
                    ),
                    author: Some(author),
                    relay,
                },
                None => BuiltQuote {
                    tag: match &relay {
                        Some(relay) if !relay.is_empty() => {
                            Tag::custom("q", [pointer.id.to_hex(), relay.clone()])
                        }
                        _ => Tag::custom("q", [pointer.id.to_hex()]),
                    },
                    author: None,
                    relay,
                },
            }
        }
        Quote::Address(pointer) => {
            let coordinate =
                EventAddress::new(pointer.kind, pointer.pubkey, &pointer.identifier).to_string();
            let relay = pointer.relays.first().cloned();
            let tag = match &relay {
                Some(relay) if !relay.is_empty() => Tag::custom("q", [coordinate, relay.clone()]),
                _ => Tag::custom("q", [coordinate]),
            };
            BuiltQuote {
                tag,
                author: Some(pointer.pubkey),
                relay,
            }
        }
    }
}

/// NIP-10 e/p/q tags for a reply to `parent` — the TS `buildReplyTags`.
///
/// Preferred marked style: an `e` tag for the thread root (`root` marker,
/// the root's first relay hint falling back to `relay_hint`), an `e` tag for
/// `parent` (`reply` marker, skipped when the parent *is* the root), `p`
/// tags for the root author, the parent author, every thread profile, and
/// quoted-event authors (deduped, first-seen order), then the `q` tags last.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `NIP-10 replyTo is for kind 1` — NIP-10 is
/// kind 1 only (comments are NIP-22).
pub fn reply_tags(parent: &Event, relay_hint: Option<&RelayUrl>, quotes: &[Quote]) -> Result<Tags> {
    if parent.kind() != Kind::TEXT_NOTE {
        return Err(Error::new(
            ErrorKind::EventValidation,
            "NIP-10 replyTo is for kind 1",
        ));
    }
    let thread = parse_thread_tags(parent.tags());
    let root = thread.root.unwrap_or_else(|| EventPointer {
        id: parent.id(),
        relays: Vec::new(),
        author: Some(parent.pubkey()),
        kind: None,
    });
    let parent_is_root = root.id == parent.id();

    let mut tags = Vec::new();
    let root_relay = root
        .relays
        .first()
        .cloned()
        .or_else(|| relay_hint.map(|url| String::from(url.as_str())))
        .unwrap_or_default();
    tags.push(e_tag(root.id, Some(root_relay), Some("root"), root.author));

    if !parent_is_root {
        tags.push(e_tag(
            parent.id(),
            Some(relay_hint.map_or_else(String::new, |url| String::from(url.as_str()))),
            Some("reply"),
            Some(parent.pubkey()),
        ));
    }

    // Ensure root + parent authors are p-tagged.
    let mut seen: Vec<PublicKey> = Vec::new();
    if let Some(author) = root.author {
        add_p_tag(&mut tags, &mut seen, author, root.relays.first().cloned());
    }
    add_p_tag(
        &mut tags,
        &mut seen,
        parent.pubkey(),
        relay_hint.map(|url| String::from(url.as_str())),
    );
    for profile in &thread.profiles {
        add_p_tag(
            &mut tags,
            &mut seen,
            profile.pubkey,
            profile.relays.first().cloned(),
        );
    }

    let mut q_tags = Vec::new();
    for quote in quotes {
        let built = quote_to_tag(quote);
        if let Some(author) = built.author {
            add_p_tag(&mut tags, &mut seen, author, built.relay.clone());
        }
        q_tags.push(built.tag);
    }
    tags.extend(q_tags);

    Ok(tags.into_iter().collect())
}

/// A kind-1 [`EventBuilder`] reply with NIP-10 tags — the TS `replyTo`.
/// Lives here (not on `EventBuilder`) so nk does not depend on NIPs.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `NIP-10 replyTo is for kind 1` — same as
/// [`reply_tags`].
pub fn reply_to(
    parent: &Event,
    content: &str,
    relay_hint: Option<&RelayUrl>,
    quotes: &[Quote],
) -> Result<EventBuilder> {
    Ok(EventBuilder::text_note(content).tags(reply_tags(parent, relay_hint, quotes)?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::string::ToString;

    use crate::{SecretKey, Timestamp};

    use super::*;

    const PK1: &str = "166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99";
    const PK2: &str = "3550510ffb21f7663873ebf343d701d871b958743cf78ff6c151fe03125e5858";
    const ID1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn id(hex: &str) -> EventId {
        EventId::from_hex(hex).unwrap()
    }

    fn pk(hex: &str) -> PublicKey {
        PublicKey::from_hex(hex).unwrap()
    }

    fn tags(raw: &[&[&str]]) -> Tags {
        raw.iter()
            .map(|items| Tag::new(items.iter().map(|s| String::from(*s))).unwrap())
            .collect()
    }

    fn note(raw: &[&[&str]], kind: u16) -> Event {
        let keys = crate::Keys::new(
            SecretKey::from_hex("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
                .unwrap(),
        );
        let unsigned = crate::UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::new(kind),
            tags(raw),
            "n",
        );
        keys.sign_event_with_aux(unsigned, &[7u8; 32]).unwrap()
    }

    #[test]
    fn positional_parent_and_root() {
        let thread = parse_thread_tags(&tags(&[&["e", ID1], &["e", ID2]]));
        assert_eq!(thread.root.map(|r| r.id), Some(id(ID1)));
        assert_eq!(thread.reply.map(|r| r.id), Some(id(ID2)));
        assert_eq!(thread.mentions.len(), 0);
    }

    #[test]
    fn hex_at_marker_slot_is_a_nip01_author() {
        let thread = parse_thread_tags(&tags(&[&["e", ID1, "wss://r", PK1]]));
        let root = thread.root.unwrap();
        assert_eq!(root.author, Some(pk(PK1)));
        assert_eq!(thread.mentions.len(), 0);
    }

    #[test]
    fn marked_reply_backfills_root() {
        let thread = parse_thread_tags(&tags(&[&["e", ID1, "", "reply"]]));
        assert_eq!(thread.root.map(|r| r.id), Some(id(ID1)));
        assert_eq!(thread.reply.map(|r| r.id), Some(id(ID1)));
    }

    #[test]
    fn reply_tags_rejects_non_kind1() {
        let parent = note(&[], 6);
        let error = reply_tags(&parent, None, &[]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EventValidation);
        assert_eq!(
            error.to_string(),
            "event validation: NIP-10 replyTo is for kind 1"
        );
    }

    #[test]
    fn reply_tags_root_parent_emits_one_e_tag() {
        let parent = note(&[], 1);
        let out = reply_tags(&parent, None, &[]).unwrap();
        let slices: Vec<Vec<String>> = out.iter().map(|t| t.as_slice().to_vec()).collect();
        let parent_id = parent.id().to_hex();
        let parent_pk = parent.pubkey().to_hex();
        assert_eq!(
            slices,
            alloc::vec![
                alloc::vec![
                    "e".to_owned(),
                    parent_id,
                    String::new(),
                    "root".to_owned(),
                    parent_pk.clone()
                ],
                alloc::vec!["p".to_owned(), parent_pk],
            ]
        );
    }

    #[test]
    fn quote_address_writes_coordinate_and_author_p() {
        let parent = note(&[], 1);
        let quote = Quote::Address(AddressPointer {
            identifier: "post".into(),
            pubkey: pk(PK2),
            kind: Kind::new(30023),
            relays: alloc::vec!["wss://a.example".to_owned()],
        });
        let out = reply_tags(&parent, None, &[quote]).unwrap();
        let slices: Vec<Vec<String>> = out.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(slices.contains(&alloc::vec![
            "q".to_owned(),
            alloc::format!("30023:{PK2}:post"),
            "wss://a.example".to_owned()
        ]));
        assert!(slices.contains(&alloc::vec![
            "p".to_owned(),
            PK2.to_owned(),
            "wss://a.example".to_owned()
        ]));
    }
}
