//! NIP-01 tags, tag collections, and `kind:pubkey:identifier` event
//! addresses — the counterpart of `@qntx/nostr`'s `core/tag.ts`.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, ErrorKind, Result};
use crate::event::EventId;
use crate::key::PublicKey;
use crate::kind::Kind;
use crate::url::RelayUrl;

/// Pushes positional tag values: absent slots before a present one emit `""`,
/// trailing absent slots are omitted (NIP-10 `e` and NIP-02 `p` layout).
fn push_positions<const N: usize>(items: &mut Vec<String>, positions: [Option<String>; N]) {
    let end = positions
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i| i + 1);
    items.extend(
        positions
            .into_iter()
            .take(end)
            .map(Option::unwrap_or_default),
    );
}

/// A NIP-01 tag: the first element is the name, the rest are values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tag(Vec<String>);

impl Tag {
    /// Builds a tag from its elements.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::EventValidation`] when `items` is empty.
    pub fn new<I, S>(items: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let items: Vec<String> = items.into_iter().map(Into::into).collect();
        if items.is_empty() {
            return Err(Error::new(
                ErrorKind::EventValidation,
                "tag must not be empty",
            ));
        }
        Ok(Self(items))
    }

    /// Builds a tag `["name", ...values]` — the required name element keeps
    /// the tag non-empty, so construction is infallible. Prefer the typed
    /// constructors ([`Tag::event`], [`Tag::public_key`], …) where they fit,
    /// and [`Tag::new`] when the tag shape itself comes from untrusted input.
    ///
    /// ```
    /// use nk::Tag;
    ///
    /// let tag = Tag::custom("nonce", ["17", "8"]);
    /// assert_eq!(tag.as_slice(), ["nonce", "17", "8"]);
    /// assert_eq!(tag.name(), "nonce");
    /// ```
    #[must_use]
    pub fn custom<N, I, S>(name: N, values: I) -> Self
    where
        N: Into<String>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(
            core::iter::once(name.into())
                .chain(values.into_iter().map(Into::into))
                .collect(),
        )
    }

    /// NIP-10 `e` tag: `["e", id, relay, marker, pubkey]`.
    #[must_use]
    pub fn event(
        id: EventId,
        relay: Option<&RelayUrl>,
        marker: Option<&str>,
        pubkey: Option<PublicKey>,
    ) -> Self {
        let mut items = vec![String::from("e"), id.to_hex()];
        push_positions(
            &mut items,
            [
                relay.map(|url| String::from(url.as_str())),
                marker.map(String::from),
                pubkey.map(PublicKey::to_hex),
            ],
        );
        Self(items)
    }

    /// NIP-02 `p` tag: `["p", pubkey, relay, petname]`.
    #[must_use]
    pub fn public_key(pubkey: PublicKey, relay: Option<&RelayUrl>, petname: Option<&str>) -> Self {
        let mut items = vec![String::from("p"), pubkey.to_hex()];
        push_positions(
            &mut items,
            [
                relay.map(|url| String::from(url.as_str())),
                petname.map(String::from),
            ],
        );
        Self(items)
    }

    /// NIP-01 `a` tag: `["a", address, relay]`.
    #[must_use]
    pub fn address(address: &EventAddress, relay: Option<&RelayUrl>) -> Self {
        let mut items = vec![String::from("a"), alloc::format!("{address}")];
        push_positions(&mut items, [relay.map(|url| String::from(url.as_str()))]);
        Self(items)
    }

    /// `d` tag: `["d", identifier]`.
    #[must_use]
    pub fn identifier<S: Into<String>>(identifier: S) -> Self {
        Self(vec![String::from("d"), identifier.into()])
    }

    /// `t` tag: `["t", hashtag]`.
    #[must_use]
    pub fn hashtag<S: Into<String>>(hashtag: S) -> Self {
        Self(vec![String::from("t"), hashtag.into()])
    }

    /// `r` tag: `["r", url, marker]`.
    #[must_use]
    pub fn reference<S: Into<String>>(url: S, marker: Option<&str>) -> Self {
        let mut items = vec![String::from("r"), url.into()];
        push_positions(&mut items, [marker.map(String::from)]);
        Self(items)
    }

    /// `k` tag: `["k", kind]`.
    #[must_use]
    pub fn kind(kind: Kind) -> Self {
        Self(vec![String::from("k"), alloc::format!("{kind}")])
    }

    /// The tag name (first element).
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.first().map_or("", String::as_str)
    }

    /// The primary value (second element), if any.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.0.get(1).map(String::as_str)
    }

    /// All elements including the name.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl Serialize for Tag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<String>::deserialize(deserializer)?;
        if items.is_empty() {
            return Err(serde::de::Error::custom("tag must not be empty"));
        }
        Ok(Self(items))
    }
}

/// An ordered list of tags; serializes as a JSON array.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Tags(Vec<Tag>);

impl Tags {
    /// An empty tag list.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a tag.
    pub fn push(&mut self, tag: Tag) {
        self.0.push(tag);
    }

    /// Iterates the tags in order.
    pub fn iter(&self) -> core::slice::Iter<'_, Tag> {
        self.0.iter()
    }

    /// The tag count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// First value of a tag with `name`, skipping same-name tags without a
    /// value, or `None` when none carries one (TS `firstTagValue`).
    #[must_use]
    pub fn first_value(&self, name: &str) -> Option<&str> {
        self.0.iter().find_map(|tag| {
            if tag.name() == name {
                tag.value()
            } else {
                None
            }
        })
    }

    /// The first `d` tag value (TS `getDTag`).
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.first_value("d")
    }

    /// Values of `p` tags that are valid public keys, in order.
    pub fn public_keys(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.0
            .iter()
            .filter(|tag| tag.name() == "p")
            .filter_map(Tag::value)
            .filter_map(|value| PublicKey::from_hex(value).ok())
    }

    /// Values of `e` tags that are valid event ids, in order.
    pub fn event_ids(&self) -> impl Iterator<Item = EventId> + '_ {
        self.0
            .iter()
            .filter(|tag| tag.name() == "e")
            .filter_map(Tag::value)
            .filter_map(|value| EventId::from_hex(value).ok())
    }

    /// Values of `t` tags, in order.
    pub fn hashtags(&self) -> impl Iterator<Item = &str> + '_ {
        self.0
            .iter()
            .filter(|tag| tag.name() == "t")
            .filter_map(Tag::value)
    }
}

impl FromIterator<Tag> for Tags {
    fn from_iter<I: IntoIterator<Item = Tag>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Extend<Tag> for Tags {
    fn extend<I: IntoIterator<Item = Tag>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = vec::IntoIter<Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Tags {
    type Item = &'a Tag;
    type IntoIter = core::slice::Iter<'a, Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Serialize for Tags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(Vec::<Tag>::deserialize(deserializer)?))
    }
}

/// A NIP-01 `kind:pubkey:identifier` coordinate for replaceable and
/// addressable events.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventAddress {
    kind: Kind,
    pubkey: PublicKey,
    identifier: String,
}

impl EventAddress {
    /// Builds an address from its parts.
    #[must_use]
    pub fn new<S: Into<String>>(kind: Kind, pubkey: PublicKey, identifier: S) -> Self {
        Self {
            kind,
            pubkey,
            identifier: identifier.into(),
        }
    }

    /// The event kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The author public key.
    #[must_use]
    pub const fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    /// The `d`-tag identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl FromStr for EventAddress {
    type Err = Error;

    /// TS `parseEventAddress`: `kind` is 1–5 digits and ≤ 65535, `pubkey` is
    /// 32 bytes of hex (any case, normalized to lowercase), and `identifier`
    /// may be empty or contain further colons.
    fn from_str(value: &str) -> Result<Self> {
        let invalid = || Error::new(ErrorKind::EventValidation, "invalid event address");
        let (kind_text, rest) = value.split_once(':').ok_or_else(invalid)?;
        if kind_text.is_empty()
            || kind_text.len() > 5
            || !kind_text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let kind = kind_text.parse::<u16>().map_err(|_| invalid())?;
        let (pubkey_text, identifier) = rest.split_once(':').ok_or_else(invalid)?;
        let pubkey = PublicKey::from_hex(pubkey_text).map_err(|_| invalid())?;
        Ok(Self::new(Kind::new(kind), pubkey, identifier))
    }
}

impl fmt::Display for EventAddress {
    /// TS `formatEventAddress`: `kind:pubkey:identifier`, pubkey lowercase.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.kind, self.pubkey, self.identifier)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    const ID: &str = "abababababababababababababababababababababababababababababababab";
    const PK: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    fn event_id() -> EventId {
        EventId::from_hex(ID).unwrap()
    }

    fn pubkey() -> PublicKey {
        PublicKey::from_hex(PK).unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("relay.example").unwrap()
    }

    #[test]
    fn event_tag_pads_absent_positions() {
        assert_eq!(
            Tag::event(event_id(), None, Some("root"), None).as_slice(),
            ["e", ID, "", "root"]
        );
        assert_eq!(
            Tag::event(event_id(), None, None, Some(pubkey())).as_slice(),
            ["e", ID, "", "", PK]
        );
        assert_eq!(
            Tag::event(event_id(), Some(&relay()), None, Some(pubkey())).as_slice(),
            ["e", ID, "wss://relay.example/", "", PK]
        );
        assert_eq!(
            Tag::event(event_id(), Some(&relay()), Some("reply"), None).as_slice(),
            ["e", ID, "wss://relay.example/", "reply"]
        );
        assert_eq!(
            Tag::event(event_id(), None, None, None).as_slice(),
            ["e", ID]
        );
    }

    #[test]
    fn public_key_tag_pads_absent_relay() {
        assert_eq!(
            Tag::public_key(pubkey(), None, Some("alice")).as_slice(),
            ["p", PK, "", "alice"]
        );
        assert_eq!(Tag::public_key(pubkey(), None, None).as_slice(), ["p", PK]);
    }

    #[test]
    fn custom_builds_named_tag() {
        assert_eq!(
            Tag::custom("nonce", ["17", "8"]).as_slice(),
            ["nonce", "17", "8"]
        );
        assert_eq!(
            Tag::custom("name", Vec::<String>::new()).as_slice(),
            ["name"]
        );
        assert_eq!(Tag::custom("nonce", ["1"]).name(), "nonce");
        assert_eq!(Tag::custom("nonce", ["1"]).value(), Some("1"));
    }

    #[test]
    fn new_rejects_empty() {
        assert_eq!(
            Tag::new(Vec::<String>::new()).unwrap_err().kind(),
            ErrorKind::EventValidation
        );
    }

    #[test]
    fn tags_accessors() {
        let mut tags = Tags::new();
        tags.push(Tag::identifier("post"));
        tags.push(Tag::hashtag("nostr"));
        tags.push(Tag::public_key(pubkey(), None, None));
        tags.push(Tag::event(event_id(), None, None, None));
        assert_eq!(tags.len(), 4);
        assert!(!tags.is_empty());
        assert_eq!(tags.identifier(), Some("post"));
        assert_eq!(tags.first_value("t"), Some("nostr"));
        assert_eq!(tags.first_value("missing"), None);
        tags.push(Tag::new(["d"]).unwrap());
        assert_eq!(
            tags.identifier(),
            Some("post"),
            "first_value skips value-less tags"
        );
        let mut only_bare = Tags::new();
        only_bare.push(Tag::new(["d"]).unwrap());
        only_bare.push(Tag::identifier("x"));
        assert_eq!(only_bare.identifier(), Some("x"));
        assert_eq!(tags.public_keys().collect::<Vec<_>>(), vec![pubkey()]);
        assert_eq!(tags.event_ids().collect::<Vec<_>>(), vec![event_id()]);
        assert_eq!(tags.hashtags().collect::<Vec<_>>(), vec!["nostr"]);
    }

    #[test]
    fn tag_serde_roundtrip_and_empty_rejected() {
        let tag = Tag::hashtag("x");
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, "[\"t\",\"x\"]");
        serde_json::from_str::<Tag>("[]").unwrap_err();
        serde_json::from_str::<Tag>("[\"e\",5]").unwrap_err();
    }

    #[test]
    fn address_parses_and_formats() {
        let address: EventAddress = alloc::format!("30023:{}:post", PK.to_uppercase())
            .parse()
            .unwrap();
        assert_eq!(address.kind(), Kind::new(30023));
        assert_eq!(address.pubkey(), pubkey());
        assert_eq!(address.identifier(), "post");
        assert_eq!(address.to_string(), alloc::format!("30023:{PK}:post"));
        assert!("1:nothex:x".parse::<EventAddress>().is_err());
        assert!("65536:ab:x".parse::<EventAddress>().is_err());
        assert!("nocolon".parse::<EventAddress>().is_err());
        assert!(alloc::format!("1:{PK}").parse::<EventAddress>().is_err());
        let empty: EventAddress = alloc::format!("0:{PK}:").parse().unwrap();
        assert_eq!(empty.identifier(), "");
    }

    #[test]
    fn tags_glue() {
        let mut tags = Tags::new();
        tags.extend([Tag::hashtag("a"), Tag::hashtag("b")]);
        let values: Vec<Option<&str>> = (&tags).into_iter().map(Tag::value).collect();
        assert_eq!(values, [Some("a"), Some("b")]);
        assert_eq!(tags.clone().into_iter().count(), 2);
        let json = serde_json::to_string(&tags).unwrap();
        assert_eq!(serde_json::from_str::<Tags>(&json).unwrap(), tags);
        // A tag must be a non-empty string array.
        assert!(serde_json::from_str::<Tag>("[]").is_err());
    }
}
