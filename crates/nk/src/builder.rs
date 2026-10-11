//! Event builders —
//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md),
//! [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md),
//! [NIP-18](https://github.com/nostr-protocol/nips/blob/master/18.md),
//! [NIP-25](https://github.com/nostr-protocol/nips/blob/master/25.md).
//!
//! `EventBuilder` collects kind, content, and tags and produces an
//! [`UnsignedEvent`]; signing is left to `Keys` or a signer.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::event::{Event, EventId, UnsignedEvent};
use crate::key::PublicKey;
use crate::kind::Kind;
use crate::tag::{EventAddress, Tag};
use crate::time::Timestamp;
use crate::url::RelayUrl;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Why a builder could not produce an event.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An addressable target has no `d` tag, so no coordinate can be built.
    #[error("addressable event is missing d tag")]
    MissingIdentifier,
    /// The target kind is not valid for this builder.
    #[error("invalid repost target kind {found}")]
    InvalidTargetKind {
        /// The target's kind.
        found: Kind,
    },
}

/// Kind-0 profile metadata (the content of a metadata event).
///
/// Serializes with keys in declaration order and `None` fields omitted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Alternate display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Bio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Avatar URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Banner image URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Website URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// NIP-05 identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    /// LNURL pay (bech32, deprecated in favor of `lud16`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud06: Option<String>,
    /// Lightning address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
}

impl ProfileMetadata {
    /// `{"name":..,"display_name":..,..}` in declaration order, `None`
    /// fields omitted, with the canonical string escaping.
    fn to_json(&self) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (key, value) in [
            ("name", &self.name),
            ("display_name", &self.display_name),
            ("about", &self.about),
            ("picture", &self.picture),
            ("banner", &self.banner),
            ("website", &self.website),
            ("nip05", &self.nip05),
            ("lud06", &self.lud06),
            ("lud16", &self.lud16),
        ] {
            let Some(value) = value else {
                continue;
            };
            if !first {
                out.push(',');
            }
            first = false;
            canonical::push_json_string(key, &mut out);
            out.push(':');
            canonical::push_json_string(value, &mut out);
        }
        out.push('}');
        out
    }
}

/// One target of a kind-5 deletion request (NIP-09).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionTarget {
    /// A bare event id; `kind` is emitted as a `k` tag when known.
    Event {
        /// The event id to delete.
        id: EventId,
        /// The event kind for the deduplicated `k` tag (NIP-09 SHOULD).
        kind: Option<Kind>,
    },
    /// A `kind:pubkey:d` coordinate, emitted as an `a` tag plus a `k`
    /// tag derived from the coordinate kind.
    Address(EventAddress),
}

/// Fluent builder for unsigned events.
///
/// # Example
///
/// ```
/// # use nk::{EventBuilder, Keys, SecretKey, Tag, Timestamp};
/// # fn main() -> Result<(), nk::key::Error> {
/// let keys = Keys::new(SecretKey::from_bytes([1; 32])?);
/// let unsigned = EventBuilder::text_note("hello")
///     .tag(Tag::hashtag("nostr"))
///     .build_at(keys.public_key(), Timestamp::from_secs(1_700_000_000));
/// let signed = keys.sign_event_with_aux(unsigned, &[0; 32])?;
/// # Ok(())
/// # }
/// ```
#[cfg_attr(not(feature = "clock"), doc = "```compile_fail")]
#[cfg_attr(
    not(feature = "clock"),
    doc = "let _ = nk::EventBuilder::text_note(\"x\")"
)]
#[cfg_attr(
    not(feature = "clock"),
    doc = "    .build(nk::PublicKey::from_bytes([0; 32]));"
)]
#[cfg_attr(not(feature = "clock"), doc = "```")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct EventBuilder {
    kind: Kind,
    content: String,
    tags: Vec<Tag>,
}

impl EventBuilder {
    /// A builder with the given kind and content and no tags.
    pub fn new<S: Into<String>>(kind: Kind, content: S) -> Self {
        Self {
            kind,
            content: content.into(),
            tags: Vec::new(),
        }
    }

    /// A kind-1 text note.
    pub fn text_note<S: Into<String>>(content: S) -> Self {
        Self::new(Kind::TEXT_NOTE, content)
    }

    /// A kind-0 profile-metadata event; the content is the metadata
    /// serialized in field-declaration order.
    pub fn metadata(metadata: &ProfileMetadata) -> Self {
        Self::new(Kind::METADATA, metadata.to_json())
    }

    /// A kind-3 contact list with one `p` tag per pubkey.
    pub fn contacts<I>(pubkeys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let mut builder = Self::new(Kind::CONTACTS, "");
        builder.tags.extend(
            pubkeys
                .into_iter()
                .map(|pk| Tag::public_key(pk, None, None)),
        );
        builder
    }

    /// A kind-5 deletion request (NIP-09): `e`/`a` tags in target order,
    /// then `k` tags deduplicated in first-seen order.
    pub fn deletion<I, S>(targets: I, reason: S) -> Self
    where
        I: IntoIterator<Item = DeletionTarget>,
        S: Into<String>,
    {
        let mut builder = Self::new(Kind::EVENT_DELETION, reason);
        let mut kinds: Vec<Kind> = Vec::new();
        for target in targets {
            let kind = match &target {
                DeletionTarget::Event { id, kind } => {
                    builder.tags.push(Tag::event(*id, None, None, None));
                    *kind
                }
                DeletionTarget::Address(address) => {
                    builder.tags.push(Tag::address(address, None));
                    Some(address.kind())
                }
            };
            if let Some(kind) = kind
                && !kinds.contains(&kind)
            {
                kinds.push(kind);
            }
        }
        builder.tags.extend(kinds.into_iter().map(Tag::kind));
        builder
    }

    /// A kind-7 reaction (NIP-25): `["e", id, relay_or_empty, pubkey]`,
    /// `p` with the same relay hint, `k` with the target kind, and an
    /// `a` tag when the target is addressable.
    ///
    /// # Errors
    ///
    /// [`Error::MissingIdentifier`] when an addressable target has no `d`
    /// tag.
    pub fn reaction<S>(target: &Event, content: S, relay_hint: Option<&RelayUrl>) -> Result<Self>
    where
        S: Into<String>,
    {
        let coord = if target.kind().is_addressable() {
            let d = target.tags().identifier().ok_or(Error::MissingIdentifier)?;
            Some(EventAddress::new(target.kind(), target.pubkey(), d))
        } else {
            None
        };
        let mut builder = Self::new(Kind::REACTION, content);
        // NIP-25's four-slot e tag: `["e", id, relay_or_"", pubkey]`; an
        // absent hint leaves the relay slot empty.
        builder.tags.push(Tag::custom(
            "e",
            [
                target.id().to_hex(),
                relay_hint.map_or_else(String::new, |url| String::from(url.as_str())),
                target.pubkey().to_hex(),
            ],
        ));
        builder
            .tags
            .push(Tag::public_key(target.pubkey(), relay_hint, None));
        builder.tags.push(Tag::kind(target.kind()));
        if let Some(coord) = coord {
            builder.tags.push(Tag::address(&coord, relay_hint));
        }
        Ok(builder)
    }

    /// A kind-6 repost (NIP-18): the serialized target event as content,
    /// empty for NIP-70-protected targets, plus `e`/`p` tags.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTargetKind`] when the target is not kind 1; kind 1
    /// targets use this method, other kinds use
    /// [`EventBuilder::generic_repost`].
    pub fn repost(target: &Event, relay_hint: &RelayUrl) -> Result<Self> {
        if target.kind() != Kind::TEXT_NOTE {
            return Err(Error::InvalidTargetKind {
                found: target.kind(),
            });
        }
        let content = if protected(target) {
            String::new()
        } else {
            signed_json(target)
        };
        let mut builder = Self::new(Kind::REPOST, content);
        builder
            .tags
            .push(Tag::event(target.id(), Some(relay_hint), None, None));
        builder
            .tags
            .push(Tag::public_key(target.pubkey(), None, None));
        Ok(builder)
    }

    /// A kind-16 generic repost (NIP-18): embeds the serialized target
    /// for regular kinds, empty content for protected, replaceable, or
    /// addressable targets; `e`/`p`/`k` tags plus `a` for replaceable
    /// and addressable targets.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTargetKind`] when the target is kind 1 — those use
    /// [`EventBuilder::repost`]; [`Error::MissingIdentifier`] when the
    /// target is addressable without a `d` tag.
    pub fn generic_repost(
        target: &Event,
        relay_hint: &RelayUrl,
        p_pubkey: Option<PublicKey>,
    ) -> Result<Self> {
        if target.kind() == Kind::TEXT_NOTE {
            return Err(Error::InvalidTargetKind {
                found: target.kind(),
            });
        }
        let replaceable = target.kind().is_replaceable();
        let addressable = target.kind().is_addressable();
        let d = target.tags().identifier();
        if addressable && d.is_none() {
            return Err(Error::MissingIdentifier);
        }
        let content = if protected(target) || replaceable || addressable {
            String::new()
        } else {
            signed_json(target)
        };
        let mut builder = Self::new(Kind::GENERIC_REPOST, content);
        builder
            .tags
            .push(Tag::event(target.id(), Some(relay_hint), None, None));
        builder.tags.push(Tag::public_key(
            p_pubkey.unwrap_or_else(|| target.pubkey()),
            None,
            None,
        ));
        builder.tags.push(Tag::kind(target.kind()));
        if replaceable || addressable {
            let address = EventAddress::new(target.kind(), target.pubkey(), d.unwrap_or_default());
            builder.tags.push(Tag::address(&address, None));
        }
        Ok(builder)
    }

    /// Appends one tag.
    pub fn tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// Appends multiple tags.
    pub fn tags<I>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = Tag>,
    {
        self.tags.extend(tags);
        self
    }

    /// Produces the unsigned event at an explicit timestamp.
    #[must_use]
    pub fn build_at(self, pubkey: PublicKey, created_at: Timestamp) -> UnsignedEvent {
        UnsignedEvent::new(
            pubkey,
            created_at,
            self.kind,
            self.tags.into_iter().collect(),
            self.content,
        )
    }

    /// Produces the unsigned event at the current wall-clock time.
    ///
    /// Requires the `clock` feature.
    #[cfg(feature = "clock")]
    #[must_use]
    pub fn build(self, pubkey: PublicKey) -> UnsignedEvent {
        self.build_at(pubkey, Timestamp::now())
    }
}

/// `true` for NIP-70-protected events (a `-` tag).
fn protected(event: &Event) -> bool {
    event.tags().iter().any(|tag| tag.name() == "-")
}

/// The signed wire object in canonical field order and escaping.
fn signed_json(event: &Event) -> String {
    let mut out = String::new();
    canonical::write_signed(event, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::event::Event;
    use crate::key::Keys;

    const SK_HEX: &str = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
    const RELAY: &str = "wss://r.example/nostr";

    fn keys() -> Keys {
        Keys::new(crate::key::SecretKey::from_hex(SK_HEX).unwrap())
    }

    fn sign(builder: EventBuilder) -> Event {
        let unsigned = builder.build_at(keys().public_key(), Timestamp::from_secs(1));
        keys().sign_event_with_aux(unsigned, &[0; 32]).unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse(RELAY).unwrap()
    }

    fn tag_slices(event: &UnsignedEvent) -> Vec<Vec<String>> {
        event
            .tags()
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect()
    }

    #[test]
    fn text_note() {
        let unsigned = EventBuilder::text_note("hello")
            .tag(Tag::hashtag("nostr"))
            .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000));
        assert_eq!(unsigned.kind(), Kind::TEXT_NOTE);
        assert_eq!(unsigned.content(), "hello");
        assert_eq!(tag_slices(&unsigned), vec![vec!["t", "nostr"]]);
    }

    #[test]
    fn metadata_declared_key_order() {
        let meta = ProfileMetadata {
            lud16: Some("a@b".to_owned()),
            name: Some("alice".to_owned()),
            nip05: Some("n@x".to_owned()),
            ..ProfileMetadata::default()
        };
        let unsigned =
            EventBuilder::metadata(&meta).build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.kind(), Kind::METADATA);
        assert_eq!(
            unsigned.content(),
            r#"{"name":"alice","nip05":"n@x","lud16":"a@b"}"#
        );
    }

    #[test]
    fn metadata_json_matches_serde() {
        let meta = ProfileMetadata {
            name: Some("a\u{2028}b\n".to_owned()),
            display_name: Some("d".to_owned()),
            about: Some("\u{1F600}".to_owned()),
            ..ProfileMetadata::default()
        };
        assert_eq!(meta.to_json(), serde_json::to_string(&meta).unwrap());
    }

    #[test]
    fn contacts() {
        let pk = keys().public_key();
        let unsigned = EventBuilder::contacts(vec![pk, pk]).build_at(pk, Timestamp::from_secs(1));
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec!["p".to_owned(), pk.to_hex()],
                vec!["p".to_owned(), pk.to_hex()]
            ]
        );
    }

    #[test]
    fn deletion_mixed_targets() {
        let id = EventId::from_bytes([7; 32]);
        let address = EventAddress::new(Kind::new(30023), keys().public_key(), "d1");
        let unsigned = EventBuilder::deletion(
            vec![
                DeletionTarget::Event {
                    id,
                    kind: Some(Kind::TEXT_NOTE),
                },
                DeletionTarget::Event { id, kind: None },
                DeletionTarget::Address(address.clone()),
                DeletionTarget::Event {
                    id,
                    kind: Some(Kind::TEXT_NOTE),
                },
            ],
            "spam",
        )
        .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.content(), "spam");
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec!["e".to_owned(), id.to_hex()],
                vec!["e".to_owned(), id.to_hex()],
                vec!["a".to_owned(), address.to_string()],
                vec!["e".to_owned(), id.to_hex()],
                vec!["k".to_owned(), "1".to_owned()],
                vec!["k".to_owned(), "30023".to_owned()],
            ]
        );
    }

    #[test]
    fn reaction_tags() {
        let target = sign(EventBuilder::text_note("n"));
        let unsigned = EventBuilder::reaction(&target, "+", Some(&relay()))
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.kind(), Kind::REACTION);
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec![
                    "e".to_owned(),
                    target.id().to_hex(),
                    RELAY.to_owned(),
                    target.pubkey().to_hex()
                ],
                vec!["p".to_owned(), target.pubkey().to_hex(), RELAY.to_owned()],
                vec!["k".to_owned(), "1".to_owned()],
            ]
        );
    }

    #[test]
    fn reaction_no_hint_empty_relay_slot() {
        let target = sign(EventBuilder::text_note("n"));
        let unsigned = EventBuilder::reaction(&target, "+", None)
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec![
                    "e".to_owned(),
                    target.id().to_hex(),
                    String::new(),
                    target.pubkey().to_hex()
                ],
                vec!["p".to_owned(), target.pubkey().to_hex()],
                vec!["k".to_owned(), "1".to_owned()],
            ]
        );
    }

    #[test]
    fn reaction_addressable() {
        let target = sign(EventBuilder::new(Kind::new(30023), "v").tag(Tag::identifier("ep1")));
        let unsigned = EventBuilder::reaction(&target, "🔥", None)
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec![
                    "e".to_owned(),
                    target.id().to_hex(),
                    String::new(),
                    target.pubkey().to_hex()
                ],
                vec!["p".to_owned(), target.pubkey().to_hex()],
                vec!["k".to_owned(), "30023".to_owned()],
                vec![
                    "a".to_owned(),
                    format!("30023:{}:ep1", target.pubkey().to_hex())
                ],
            ]
        );
    }

    #[test]
    fn reaction_addressable_without_d_errors() {
        let target = sign(EventBuilder::new(Kind::new(30023), "v"));
        let err = EventBuilder::reaction(&target, "+", None).unwrap_err();
        assert!(matches!(err, Error::MissingIdentifier));
    }

    #[test]
    fn repost_embeds_event_json() {
        let target = sign(EventBuilder::text_note("esc \" \\ \n 😀").tag(Tag::identifier("d")));
        let unsigned = EventBuilder::repost(&target, &relay())
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.content(), serde_json::to_string(&target).unwrap());
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec!["e".to_owned(), target.id().to_hex(), RELAY.to_owned()],
                vec!["p".to_owned(), target.pubkey().to_hex()],
            ]
        );
    }

    #[test]
    fn repost_protected_empty_content() {
        let target = sign(EventBuilder::text_note("p").tag(Tag::new(vec!["-"]).unwrap()));
        let unsigned = EventBuilder::repost(&target, &relay())
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.content(), "");
    }

    #[test]
    fn repost_rejects_non_kind_1() {
        let target = sign(EventBuilder::new(Kind::REACTION, "+"));
        let err = EventBuilder::repost(&target, &relay()).unwrap_err();
        assert!(matches!(err, Error::InvalidTargetKind { .. }));
    }

    #[test]
    fn generic_repost_embeds_regular_target() {
        let target = sign(EventBuilder::new(Kind::new(20), "img"));
        let unsigned = EventBuilder::generic_repost(&target, &relay(), None)
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.kind(), Kind::GENERIC_REPOST);
        assert_eq!(unsigned.content(), serde_json::to_string(&target).unwrap());
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec!["e".to_owned(), target.id().to_hex(), RELAY.to_owned()],
                vec!["p".to_owned(), target.pubkey().to_hex()],
                vec!["k".to_owned(), "20".to_owned()],
            ]
        );
    }

    #[test]
    fn generic_repost_kind_0_empty_a_identifier() {
        let target = sign(EventBuilder::metadata(&ProfileMetadata {
            name: Some("alice".to_owned()),
            ..ProfileMetadata::default()
        }));
        let unsigned = EventBuilder::generic_repost(&target, &relay(), None)
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.content(), "");
        assert!(tag_slices(&unsigned).contains(&vec![
            "a".to_owned(),
            format!("0:{}:", target.pubkey().to_hex())
        ]));
    }

    #[test]
    fn generic_repost_rejects_kind_1() {
        let target = sign(EventBuilder::text_note("n"));
        let err = EventBuilder::generic_repost(&target, &relay(), None).unwrap_err();
        assert!(matches!(err, Error::InvalidTargetKind { .. }));
    }

    #[test]
    fn generic_repost_addressable_without_d_errors() {
        let target = sign(EventBuilder::new(Kind::new(34235), "v"));
        let err = EventBuilder::generic_repost(&target, &relay(), None).unwrap_err();
        assert!(matches!(err, Error::MissingIdentifier));
    }

    #[test]
    fn generic_repost_addressable_emits_a_tag() {
        let target = sign(EventBuilder::new(Kind::new(34235), "v").tag(Tag::identifier("ep1")));
        let other = Keys::new(crate::key::SecretKey::from_bytes([7; 32]).unwrap()).public_key();
        let unsigned = EventBuilder::generic_repost(&target, &relay(), Some(other))
            .unwrap()
            .build_at(keys().public_key(), Timestamp::from_secs(1));
        assert_eq!(unsigned.content(), "");
        assert_eq!(
            tag_slices(&unsigned),
            vec![
                vec!["e".to_owned(), target.id().to_hex(), RELAY.to_owned()],
                vec!["p".to_owned(), other.to_hex()],
                vec!["k".to_owned(), "34235".to_owned()],
                vec![
                    "a".to_owned(),
                    format!("34235:{}:ep1", target.pubkey().to_hex())
                ],
            ]
        );
    }

    #[test]
    fn wire_signed_event_field_order() {
        let event = sign(EventBuilder::text_note("x"));
        let expected = format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"x\",\"sig\":\"{}\"}}",
            event.id().to_hex(),
            event.pubkey().to_hex(),
            event.sig().to_hex()
        );
        assert_eq!(signed_json(&event), expected);
    }

    #[test]
    fn builder_eq_and_clone() {
        let a = EventBuilder::text_note("x").tag(Tag::identifier("d"));
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[cfg(feature = "clock")]
    #[test]
    fn build_uses_the_wall_clock() {
        let unsigned = EventBuilder::text_note("x").build(keys().public_key());
        assert!(unsigned.created_at().as_secs() > 1_700_000_000);
    }
}
