//! The NIP-01 event model: event ids, signatures, unsigned and signed events,
//! and the canonical serialization used for hashing — the counterpart of
//! `@qntx/nostr`'s `core/event.ts`.

use alloc::borrow::Cow;
use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use serde::de::{Error as DeError, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::{Error, ErrorKind, Result};
use crate::hex;
use crate::json::{self, Captured, MAX_SAFE_INTEGER, WireCow, WireInt, WireStr, WireTags};
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

    /// BIP-340 verification of this signature over `id` for `pubkey`
    /// (TS `verifyEvent`'s crypto step).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `pubkey` is not a valid curve point or the
    /// signature does not verify.
    pub fn verify(&self, id: &EventId, pubkey: &PublicKey) -> Result<()> {
        // `secp256k1::Error` is not `core::error::Error` without its `std`
        // feature, so crypto failures carry only a kind and a fixed message —
        // the upstream variant adds no detail callers can act on.
        let pubkey = secp256k1::XOnlyPublicKey::from_byte_array(*pubkey.as_bytes())
            .map_err(|_| Error::new(ErrorKind::Crypto, "invalid public key"))?;
        let signature = secp256k1::schnorr::Signature::from_byte_array(self.0);
        secp256k1::schnorr::verify(&signature, id.as_bytes(), &pubkey)
            .map_err(|_| Error::new(ErrorKind::Crypto, "invalid signature"))
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

/// An unsigned event: `pubkey`, `created_at`, `kind`, `tags`, `content`.
///
/// Constructed directly or via `nk`'s future `EventBuilder`; signature
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
        canonical::write_event(self, &mut out);
        out
    }

    /// The event id: SHA-256 over the canonical serialization, written
    /// straight into the hasher with no intermediate string.
    #[must_use]
    pub fn id(&self) -> EventId {
        let mut hasher = Sha256::new();
        canonical::write_event(self, &mut hasher);
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

/// Captured wire fields shared by the `Event` and `UnsignedEvent`
/// visitors; a later duplicate key overwrites the earlier capture
/// (`JSON.parse` semantics, NK-ADR-012 ruling 7).
#[derive(Default)]
struct EventFields<'de> {
    id: Option<Captured<Cow<'de, str>>>,
    pubkey: Option<Captured<Cow<'de, str>>>,
    created_at: Option<Captured<u64>>,
    kind: Option<Captured<u64>>,
    tags: Option<Captured<Tags>>,
    content: Option<Captured<String>>,
    sig: Option<Captured<Cow<'de, str>>>,
}

impl<'de> EventFields<'de> {
    /// Captures every entry of `map`. `Cow` keys and hex-field values
    /// borrow the input unless they contain JSON escapes.
    fn collect<M: MapAccess<'de>>(mut map: M) -> core::result::Result<Self, M::Error> {
        let mut fields = Self::default();
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            fields.read(&key, &mut map)?;
        }
        Ok(fields)
    }

    /// Reads one map entry: a lenient capture for known keys, `IgnoredAny`
    /// for anything else.
    fn read<M: MapAccess<'de>>(
        &mut self,
        key: &str,
        map: &mut M,
    ) -> core::result::Result<(), M::Error> {
        match key {
            "id" => self.id = Some(map.next_value::<WireCow<'de>>()?.0),
            "pubkey" => self.pubkey = Some(map.next_value::<WireCow<'de>>()?.0),
            "created_at" => {
                self.created_at = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0);
            }
            "kind" => {
                self.kind = Some(map.next_value::<WireInt<{ u16::MAX as u64 }>>()?.0);
            }
            "tags" => self.tags = Some(map.next_value::<WireTags>()?.0),
            "content" => self.content = Some(map.next_value::<WireStr>()?.0),
            "sig" => self.sig = Some(map.next_value::<WireCow<'de>>()?.0),
            _ => {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// Finalizes a captured `kind` (`0..=u16::MAX` already enforced).
fn kind_value<E: DeError>(slot: Option<Captured<u64>>) -> core::result::Result<u16, E> {
    let value = json::finish(slot, "kind")?;
    u16::try_from(value).map_err(|_| E::custom("invalid kind: integer out of range"))
}

/// Finalizes a captured hex field through the type's wire `Deserialize`
/// (lowercase hex, exact length).
fn hex_field<const N: usize, T, E: DeError>(
    slot: Option<Captured<Cow<'_, str>>>,
    field: &'static str,
    build: fn([u8; N]) -> T,
) -> core::result::Result<T, E> {
    let raw = json::finish(slot, field)?;
    hex::decode_wire::<N>(&raw).map(build).map_err(E::custom)
}

impl<'de> Deserialize<'de> for UnsignedEvent {
    /// Strictness matches TS `validateEvent`: `pubkey` is 64-char lowercase
    /// hex, `created_at` a non-negative safe integer, `kind` an integer in
    /// `0..=65535`, `content` a string, `tags` an array of non-empty string
    /// arrays; unknown fields are ignored and a duplicate key takes the last
    /// value (NK-ADR-012 ruling 7), matching `JSON.parse`.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnsignedVisitor;

        impl<'de> Visitor<'de> for UnsignedVisitor {
            type Value = UnsignedEvent;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an unsigned NIP-01 event object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<UnsignedEvent, M::Error> {
                let EventFields {
                    pubkey,
                    created_at,
                    kind,
                    tags,
                    content,
                    ..
                } = EventFields::collect(map)?;
                Ok(UnsignedEvent {
                    pubkey: hex_field(pubkey, "pubkey", PublicKey::from_bytes)?,
                    created_at: Timestamp::from_secs(json::finish(created_at, "created_at")?),
                    kind: Kind::new(kind_value(kind)?),
                    tags: json::finish(tags, "tags")?,
                    content: json::finish(content, "content")?,
                })
            }
        }

        deserializer.deserialize_map(UnsignedVisitor)
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

    /// Assembles a signed event from its parts; only `Keys::sign_event*`
    /// and deserialization can produce `Event`s.
    pub(crate) fn new_signed(unsigned: UnsignedEvent, id: EventId, sig: Signature) -> Self {
        Self {
            id,
            pubkey: unsigned.pubkey,
            created_at: unsigned.created_at,
            kind: unsigned.kind,
            tags: unsigned.tags,
            content: unsigned.content,
            sig,
        }
    }

    /// Full NIP-01 verification: recomputes the id from the canonical
    /// serialization, then BIP-340-verifies `sig` over it (TS `verifyEvent`,
    /// which returns a boolean — the failing stage is reported here instead).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::EventValidation`] when the stored id does not match the
    /// recomputed id; [`ErrorKind::Crypto`] when the public key is not on the
    /// curve or the signature is invalid.
    pub fn verify(&self) -> Result<()> {
        let computed = UnsignedEvent::new(
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags.clone(),
            self.content.clone(),
        )
        .id();
        if computed != self.id {
            return Err(Error::new(
                ErrorKind::EventValidation,
                "event id does not match the event contents",
            ));
        }
        self.sig.verify(&self.id, &self.pubkey)
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
        struct EventVisitor;

        impl<'de> Visitor<'de> for EventVisitor {
            type Value = Event;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a signed NIP-01 event object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Event, M::Error> {
                let EventFields {
                    id,
                    pubkey,
                    created_at,
                    kind,
                    tags,
                    content,
                    sig,
                } = EventFields::collect(map)?;
                Ok(Event {
                    id: hex_field(id, "id", EventId::from_bytes)?,
                    pubkey: hex_field(pubkey, "pubkey", PublicKey::from_bytes)?,
                    created_at: Timestamp::from_secs(json::finish(created_at, "created_at")?),
                    kind: Kind::new(kind_value(kind)?),
                    tags: json::finish(tags, "tags")?,
                    content: json::finish(content, "content")?,
                    sig: hex_field(sig, "sig", Signature::from_bytes)?,
                })
            }
        }

        deserializer.deserialize_map(EventVisitor)
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
        // Visitor `expecting` text reaches the deserialization error message.
        let error = serde_json::from_str::<UnsignedEvent>("[]").unwrap_err();
        assert!(
            error.to_string().contains("unsigned NIP-01 event"),
            "{error}"
        );
    }

    /// `vectors/core/event-sign.json` case 0 — sk=3, aux=1.
    fn valid_event() -> Event {
        signed(
            "{\"id\":\"791e76a4715f1514309947f51c1d20a6f80698833ecc97b7b3a9c56cc3063113\",\"pubkey\":\"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"t\",\"hi\"]],\"content\":\"gm\",\"sig\":\"35931bdb21989c9049272418de0df733b0ebede3bcb45c54161511d8633cab516d6b25cd808ddb8cbba7600940678e3ba3fe655a830abbe631e640e9fc460ff1\"}",
        )
    }

    #[test]
    fn verify_accepts_a_correctly_signed_event() {
        valid_event().verify().unwrap();
    }

    #[test]
    fn verify_rejects_an_id_mismatch() {
        let mut value = serde_json::to_value(valid_event()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("content".into(), "tampered".into());
        let event: Event = serde_json::from_value(value).unwrap();
        assert_eq!(
            event.verify().unwrap_err().kind(),
            ErrorKind::EventValidation
        );
    }

    #[test]
    fn verify_rejects_a_bad_signature() {
        let mut value = serde_json::to_value(valid_event()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("sig".into(), "ff".repeat(64).into());
        let event: Event = serde_json::from_value(value).unwrap();
        assert_eq!(event.verify().unwrap_err().kind(), ErrorKind::Crypto);
    }

    #[test]
    fn signature_verify_rejects_an_off_curve_pubkey() {
        let event = valid_event();
        let off_curve = PublicKey::from_bytes([0xff; 32]);
        assert_eq!(
            event
                .sig()
                .verify(&event.id(), &off_curve)
                .unwrap_err()
                .kind(),
            ErrorKind::Crypto
        );
    }

    #[test]
    fn signature_verify_rejects_a_wrong_message() {
        let event = valid_event();
        let other_id = EventId::from_bytes([0u8; 32]);
        assert_eq!(
            event
                .sig()
                .verify(&other_id, &event.pubkey())
                .unwrap_err()
                .kind(),
            ErrorKind::Crypto
        );
    }

    #[test]
    fn event_id_glue() {
        let id = EventId::from_bytes([0xab; 32]);
        assert_eq!(EventId::from_slice(id.as_bytes()).unwrap(), id);
        assert_eq!(
            EventId::from_slice(&[0u8; 31]).unwrap_err().kind(),
            ErrorKind::Hex
        );
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_eq!(
            alloc::format!("{id:?}"),
            alloc::format!("EventId({})", "ab".repeat(32))
        );
        // `FromStr` accepts any case (caller input); wire decoding stays strict.
        assert_eq!("AB".repeat(32).parse::<EventId>().unwrap(), id);
        assert!("ab".parse::<EventId>().is_err());
        let wire: EventId = serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
        assert_eq!(wire, id);
        assert!(
            serde_json::from_str::<EventId>(&alloc::format!("\"{}\"", "AB".repeat(32))).is_err()
        );
    }

    #[test]
    fn signature_glue_and_wire_rejects() {
        let sig = Signature::from_bytes([0xcd; 64]);
        assert_eq!(Signature::from_slice(sig.as_bytes()).unwrap(), sig);
        assert_eq!(
            Signature::from_slice(&[0u8; 63]).unwrap_err().kind(),
            ErrorKind::Hex
        );
        assert_eq!(sig.to_string(), "cd".repeat(64));
        assert_eq!(
            alloc::format!("{sig:?}"),
            alloc::format!("Signature({})", "cd".repeat(64))
        );
        assert_eq!("CD".repeat(64).parse::<Signature>().unwrap(), sig);
        assert!("cd".parse::<Signature>().is_err());
        let wire: Signature = serde_json::from_str(&serde_json::to_string(&sig).unwrap()).unwrap();
        assert_eq!(wire, sig);
        // Strict wire decoding: uppercase, short, and non-strings fail.
        assert!(
            serde_json::from_str::<Signature>(&alloc::format!("\"{}\"", "CD".repeat(64))).is_err()
        );
        assert!(serde_json::from_str::<Signature>("\"cd\"").is_err());
        assert!(serde_json::from_str::<Signature>("5").is_err());
        assert!(serde_json::from_str::<Signature>("null").is_err());
    }
}
