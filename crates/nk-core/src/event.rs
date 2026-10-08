//! The NIP-01 event model: event ids, signatures, unsigned and signed events,
//! and the canonical serialization used for hashing — the counterpart of
//! `@qntx/nostr`'s `core/event.ts`.
//!
//! `Signature::verify` and `Event::verify` arrive with `secp256k1` in NK1-03.

use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorKind, Result};
use crate::hex;
use crate::key::PublicKey;
use crate::kind::Kind;
use crate::tag::{EventAddress, Tags};
use crate::time::Timestamp;

/// An event id: the SHA-256 digest of the canonical serialization (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Wraps 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copies a byte slice into an id.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Hex, "invalid event id length"))?;
        Ok(Self(array))
    }

    /// Parses 64-character hex of any case.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when the input is not 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(hex::decode_caller(hex)?))
    }

    /// SHA-256 of `canonical` — used by nk-wasm's `verify_serialized`.
    #[must_use]
    pub fn hash(canonical: &[u8]) -> Self {
        Self(Sha256::digest(canonical).into())
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical lowercase hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({})", self.to_hex())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for EventId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(
            hex::decode_wire(&raw).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// A BIP-340 Schnorr signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps 64 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Copies a byte slice into a signature.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when `bytes` is not exactly 64 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Hex, "invalid signature length"))?;
        Ok(Self(array))
    }

    /// Parses 128-character hex of any case.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when the input is not 128 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(hex::decode_caller(hex)?))
    }

    /// The raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// The canonical lowercase hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(
            hex::decode_wire(&raw).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// The canonical `[0, pubkey, created_at, kind, tags, content]` writer.
///
/// Escapes exactly like `JSON.stringify` (`\"`, `\\`, the `\b \f \n \r \t`
/// short forms, every other U+0000–U+001F as lowercase `\u00xx`, everything
/// else as raw UTF-8) and writes into either a `String` or the SHA-256 hasher
/// with no intermediate buffer — `serde_json` cannot do this under `no_std`.
mod canonical {
    use alloc::string::String;

    use sha2::{Digest, Sha256};

    use super::UnsignedEvent;

    /// Output target for canonical serialization.
    pub(super) trait Sink {
        /// Appends a UTF-8 chunk.
        fn push_str(&mut self, s: &str);
        /// Appends one ASCII character.
        fn push_char(&mut self, c: char);
    }

    impl Sink for String {
        fn push_str(&mut self, s: &str) {
            self.push_str(s);
        }

        fn push_char(&mut self, c: char) {
            self.push(c);
        }
    }

    impl Sink for Sha256 {
        fn push_str(&mut self, s: &str) {
            Digest::update(self, s.as_bytes());
        }

        fn push_char(&mut self, c: char) {
            let mut buf = [0u8; 4];
            Digest::update(self, c.encode_utf8(&mut buf).as_bytes());
        }
    }

    fn hex_digit(nibble: u8) -> char {
        if nibble < 10 {
            char::from(b'0' + nibble)
        } else {
            char::from(b'a' + (nibble - 10))
        }
    }

    /// Writes `n` as decimal digits (a `u64` needs at most 20) filled from
    /// the right of a stack buffer, then pushed as one slice.
    fn push_u64(n: u64, out: &mut impl Sink) {
        let mut buf = [0u8; 20];
        let mut value = n;
        let mut written = 0;
        for slot in buf.iter_mut().rev() {
            *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
            written += 1;
            if value == 0 {
                break;
            }
        }
        out.push_str(
            core::str::from_utf8(buf.get(buf.len() - written..).unwrap_or(&[])).unwrap_or(""),
        );
    }

    /// Writes `c` (below U+0020, a single UTF-8 byte) as a `\u00xx` escape.
    fn push_control_escape(c: char, out: &mut impl Sink) {
        out.push_str("\\u00");
        for byte in c.encode_utf8(&mut [0; 4]).bytes() {
            out.push_char(hex_digit(byte >> 4));
            out.push_char(hex_digit(byte & 0x0f));
        }
    }

    /// Writes `s` as a JSON string with `JSON.stringify` escaping, flushing
    /// maximal unescaped runs as single slices.
    fn push_json_string(s: &str, out: &mut impl Sink) {
        out.push_char('"');
        let mut run_start = 0;
        for (i, c) in s.char_indices() {
            if c != '"' && c != '\\' && c >= '\u{20}' {
                continue;
            }
            out.push_str(s.get(run_start..i).unwrap_or_default());
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c => push_control_escape(c, out),
            }
            run_start = i + c.len_utf8();
        }
        out.push_str(s.get(run_start..).unwrap_or_default());
        out.push_char('"');
    }

    /// Writes one tag as a JSON string array.
    fn push_tag(tag: &crate::tag::Tag, out: &mut impl Sink) {
        out.push_char('[');
        for (i, item) in tag.as_slice().iter().enumerate() {
            if i > 0 {
                out.push_char(',');
            }
            push_json_string(item, out);
        }
        out.push_char(']');
    }

    /// Writes the canonical event serialization.
    pub(super) fn write(event: &UnsignedEvent, out: &mut impl Sink) {
        out.push_str("[0,\"");
        for byte in event.pubkey().as_bytes() {
            out.push_char(hex_digit(byte >> 4));
            out.push_char(hex_digit(byte & 0x0f));
        }
        out.push_str("\",");
        push_u64(event.created_at().as_secs(), out);
        out.push_char(',');
        push_u64(u64::from(event.kind().as_u16()), out);
        out.push_char(',');
        out.push_char('[');
        for (i, tag) in event.tags().iter().enumerate() {
            if i > 0 {
                out.push_char(',');
            }
            push_tag(tag, out);
        }
        out.push_str("],");
        push_json_string(event.content(), out);
        out.push_char(']');
    }
}

/// An unsigned event: `pubkey`, `created_at`, `kind`, `tags`, `content`.
///
/// Constructed directly or via `nk-core`'s future `EventBuilder`; signature
/// turns it into an [`Event`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnsignedEvent {
    pubkey: PublicKey,
    created_at: Timestamp,
    kind: Kind,
    tags: Tags,
    content: String,
}

impl UnsignedEvent {
    /// Builds an unsigned event from its parts.
    #[must_use]
    pub fn new<S: Into<String>>(
        pubkey: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: Tags,
        content: S,
    ) -> Self {
        Self {
            pubkey,
            created_at,
            kind,
            tags,
            content: content.into(),
        }
    }

    /// The author public key.
    #[must_use]
    pub const fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    /// The creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// The event kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The tag list.
    #[must_use]
    pub const fn tags(&self) -> &Tags {
        &self.tags
    }

    /// The event content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// The canonical NIP-01 serialization `[0,pubkey,created_at,kind,tags,content]`
    /// — byte-for-byte `JSON.stringify` on the wire array.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        canonical::write(self, &mut out);
        out
    }

    /// The event id: SHA-256 over the canonical serialization, written
    /// straight into the hasher with no intermediate string.
    #[must_use]
    pub fn id(&self) -> EventId {
        let mut hasher = Sha256::new();
        canonical::write(self, &mut hasher);
        EventId::from_bytes(hasher.finalize().into())
    }
}

impl Serialize for UnsignedEvent {
    /// The wire object: `pubkey`, `created_at`, `kind`, `tags`, `content`.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Ref<'a> {
            pubkey: &'a PublicKey,
            created_at: Timestamp,
            kind: Kind,
            tags: &'a Tags,
            content: &'a str,
        }
        Ref {
            pubkey: &self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnsignedEvent {
    /// Strictness matches TS `validateEvent`: `pubkey` is 64-char lowercase
    /// hex, `created_at` a non-negative integer, `kind` an integer in
    /// `0..=65535`, `content` a string, `tags` an array of non-empty string
    /// arrays; unknown fields are ignored.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct De {
            pubkey: PublicKey,
            created_at: Timestamp,
            kind: Kind,
            tags: Tags,
            content: String,
        }
        let event = De::deserialize(deserializer)?;
        Ok(Self {
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
        })
    }
}

/// A fully formed NIP-01 event with id and signature.
///
/// Obtained through deserialization or `Keys::sign_event*` (NK1-03); there is
/// no public constructor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Event {
    id: EventId,
    pubkey: PublicKey,
    created_at: Timestamp,
    kind: Kind,
    tags: Tags,
    content: String,
    sig: Signature,
}

impl Event {
    /// The event id.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// The author public key.
    #[must_use]
    pub const fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    /// The creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// The event kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The tag list.
    #[must_use]
    pub const fn tags(&self) -> &Tags {
        &self.tags
    }

    /// The event content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// The BIP-340 signature over the id.
    #[must_use]
    pub const fn sig(&self) -> Signature {
        self.sig
    }

    /// The `kind:pubkey:d` coordinate for replaceable and addressable events
    /// (TS `eventAddress`); `None` for regular and ephemeral kinds.
    #[must_use]
    pub fn address(&self) -> Option<EventAddress> {
        if self.kind.is_addressable() {
            Some(EventAddress::new(
                self.kind,
                self.pubkey,
                self.tags.identifier().unwrap_or_default(),
            ))
        } else if self.kind.is_replaceable() {
            Some(EventAddress::new(self.kind, self.pubkey, ""))
        } else {
            None
        }
    }

    /// Whether this is the signed form of `unsigned` (TS
    /// `signedMatchesUnsigned`): `kind`, `content`, `created_at`, `tags`, and
    /// `pubkey` all equal.
    #[must_use]
    pub fn matches_unsigned(&self, unsigned: &UnsignedEvent) -> bool {
        self.kind == unsigned.kind
            && self.content == unsigned.content
            && self.created_at == unsigned.created_at
            && self.tags == unsigned.tags
            && self.pubkey == unsigned.pubkey
    }

    /// NIP-01 replaceable/addressable winner (TS `isReplaceableWinner`):
    /// higher `created_at`, or equal timestamp and lexicographically lower id.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        if self.created_at != other.created_at {
            return self.created_at > other.created_at;
        }
        self.id < other.id
    }

    /// Drops id and sig, returning the unsigned form.
    #[must_use]
    pub fn into_unsigned(self) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
        }
    }
}

impl Serialize for Event {
    /// The wire object in canonical field order: `id`, `pubkey`,
    /// `created_at`, `kind`, `tags`, `content`, `sig`.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Ref<'a> {
            id: &'a EventId,
            pubkey: &'a PublicKey,
            created_at: Timestamp,
            kind: Kind,
            tags: &'a Tags,
            content: &'a str,
            sig: &'a Signature,
        }
        Ref {
            id: &self.id,
            pubkey: &self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
            sig: &self.sig,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Event {
    /// Strictness matches TS `validateSignedEvent`: [`UnsignedEvent`] rules
    /// plus `id` and `sig` as exact-length lowercase hex.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct De {
            id: EventId,
            pubkey: PublicKey,
            created_at: Timestamp,
            kind: Kind,
            tags: Tags,
            content: String,
            sig: Signature,
        }
        let event = De::deserialize(deserializer)?;
        Ok(Self {
            id: event.id,
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
            sig: event.sig,
        })
    }
}

/// NIP-01 newest-first order (TS `compareEventsDesc`/`sortEvents`):
/// `created_at` descending, `id` ascending as the tie-break.
#[must_use]
pub fn cmp_newest_first(a: &Event, b: &Event) -> Ordering {
    b.created_at
        .cmp(&a.created_at)
        .then_with(|| a.id.cmp(&b.id))
}

/// Negentropy item order (TS `itemCompare`): `created_at` ascending, `id`
/// ascending as the tie-break — the same id direction as
/// [`cmp_newest_first`].
#[must_use]
pub fn cmp_oldest_first(a: &Event, b: &Event) -> Ordering {
    a.created_at
        .cmp(&b.created_at)
        .then_with(|| a.id.cmp(&b.id))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::{String, ToString};

    use super::*;
    use crate::tag::Tag;

    const PK: &str = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";

    fn unsigned() -> UnsignedEvent {
        let mut tags = Tags::new();
        tags.push(Tag::hashtag("smoke"));
        UnsignedEvent::new(
            PublicKey::from_hex(PK).unwrap(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            tags,
            "hello",
        )
    }

    /// The id/serialized values frozen in `vectors/core/event-serialize.json`.
    fn signed(json: &str) -> Event {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn canonical_json_and_id_are_stable() {
        let event = unsigned();
        assert_eq!(
            event.canonical_json(),
            alloc::format!("[0,\"{PK}\",1700000000,1,[[\"t\",\"smoke\"]],\"hello\"]")
        );
        assert_eq!(
            event.id().to_hex(),
            "659f3c96e7c424216353386f3720992d8d7be0717a9a0c23422094f7f9bb591f"
        );
    }

    #[test]
    fn id_matches_hash_of_canonical_bytes() {
        let event = unsigned();
        assert_eq!(event.id(), EventId::hash(event.canonical_json().as_bytes()));
    }

    #[test]
    fn canonical_json_flushes_long_runs_and_sparse_escapes() {
        let mut content = String::with_capacity(10_000);
        let mut escaped = String::with_capacity(10_000);
        for i in 0..10_000 {
            if i % 1024 == 512 {
                content.push('\n');
                escaped.push_str("\\n");
            } else {
                content.push('x');
                escaped.push('x');
            }
        }
        let event = UnsignedEvent::new(
            PublicKey::from_hex(PK).unwrap(),
            Timestamp::from_secs(0),
            Kind::METADATA,
            Tags::new(),
            content,
        );
        assert_eq!(
            event.canonical_json(),
            alloc::format!("[0,\"{PK}\",0,0,[],\"{escaped}\"]")
        );
        assert_eq!(event.id(), EventId::hash(event.canonical_json().as_bytes()));
    }

    #[test]
    fn unsigned_wire_roundtrip() {
        let event = unsigned();
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            alloc::format!(
                "{{\"pubkey\":\"{PK}\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"t\",\"smoke\"]],\"content\":\"hello\"}}"
            )
        );
        assert_eq!(serde_json::from_str::<UnsignedEvent>(&json).unwrap(), event);
    }

    #[test]
    fn event_wire_roundtrip_and_accessors() {
        let raw = alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"t\",\"smoke\"]],\"content\":\"hello\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(64),
        );
        let event = signed(&raw);
        assert_eq!(serde_json::to_string(&event).unwrap(), raw);
        assert_eq!(event.id().to_hex(), "ab".repeat(32));
        assert_eq!(event.pubkey().to_hex(), PK);
        assert_eq!(event.created_at(), Timestamp::from_secs(1_700_000_000));
        assert_eq!(event.kind(), Kind::TEXT_NOTE);
        assert_eq!(event.content(), "hello");
        assert_eq!(event.sig().to_hex(), "cd".repeat(64));
        assert!(event.matches_unsigned(&unsigned()));
        assert_eq!(event.into_unsigned(), unsigned());
    }

    #[test]
    fn address_only_for_replaceable_and_addressable() {
        let regular = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(64),
        ));
        assert!(regular.address().is_none());
        let ephemeral = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1,\"kind\":20000,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(64),
        ));
        assert!(ephemeral.address().is_none());
        let addressable = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1,\"kind\":30023,\"tags\":[[\"d\",\"post\"]],\"content\":\"\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(64),
        ));
        assert_eq!(
            addressable.address().unwrap().to_string(),
            alloc::format!("30023:{PK}:post")
        );
        let replaceable = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1,\"kind\":10000,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(64),
        ));
        assert_eq!(
            replaceable.address().unwrap().to_string(),
            alloc::format!("10000:{PK}:")
        );
    }

    #[test]
    fn ordering_and_supersedes() {
        let a = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":2,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "aa".repeat(32),
            "cd".repeat(64),
        ));
        let b = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "bb".repeat(32),
            "cd".repeat(64),
        ));
        assert_eq!(cmp_newest_first(&a, &b), Ordering::Less);
        assert_eq!(cmp_oldest_first(&a, &b), Ordering::Greater);
        assert!(a.supersedes(&b));
        assert!(!b.supersedes(&a));
        // Equal timestamps: lexicographically lower id wins.
        let c = signed(&alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":2,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "cc".repeat(32),
            "cd".repeat(64),
        ));
        assert!(a.supersedes(&c));
        assert!(!c.supersedes(&a));
    }

    #[test]
    fn strict_wire_rules() {
        let base = |patch: &str| {
            alloc::format!(
                "{{\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"t\",\"smoke\"]],\"content\":\"hello\",\"sig\":\"{}\"{patch}}}",
                "ab".repeat(32),
                "cd".repeat(64),
            )
        };
        assert!(serde_json::from_str::<Event>(&base("")).is_ok());
        // Unknown fields are ignored.
        assert!(serde_json::from_str::<Event>(&base(",\"extra\":1")).is_ok());
    }
}
