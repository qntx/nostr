//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) —
//! the event model: event ids, signatures, unsigned and signed events,
//! kinds, tags, builders, and the canonical serialization used for hashing.

mod builder;
pub(crate) mod canonical;
mod id;
mod kind;
mod tag;
mod unsigned;

pub use builder::{DeletionTarget, EventBuilder, Metadata};
pub use id::EventId;
pub use kind::{Kind, KindClass};
pub use tag::{Coordinate, Tag, Tags};
pub use unsigned::UnsignedEvent;

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::json::{self, JsonError, WireHex, WireInt, WireTags};
use crate::key::{PublicKey, Signature};
use crate::limits::MAX_SAFE_INTEGER;
use crate::time::Timestamp;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Why an event operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A byte input was not the required length.
    #[error("invalid length: expected {expected} bytes, got {found}")]
    InvalidLength {
        /// The required byte count.
        expected: usize,
        /// The actual byte count.
        found: usize,
    },
    /// The input is not valid hexadecimal for the required width.
    #[error("invalid hex input")]
    InvalidHex,
    /// A tag must contain at least its name element.
    #[error("tag must not be empty")]
    EmptyTag,
    /// The text is not a `kind:pubkey:identifier` coordinate.
    #[error("invalid event address")]
    InvalidCoordinate,
    /// The stored id does not match the recomputed hash of the contents.
    #[error("event id does not match the event contents")]
    IdMismatch,
    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature {
        /// The verification failure.
        #[source]
        source: crate::key::Error,
    },
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

/// A fully formed NIP-01 event with id and signature.
///
/// Obtained through deserialization or [`crate::key::Keys::sign_event`];
/// there is no public constructor.
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

/// A borrowed view of the fields the canonical writer needs; lets the
/// id hash and [`Event::verify`] run without cloning the event.
pub(crate) struct EventParts<'a> {
    /// The author public key.
    pub pubkey: &'a PublicKey,
    /// The creation timestamp.
    pub created_at: Timestamp,
    /// The event kind.
    pub kind: Kind,
    /// The tag list.
    pub tags: &'a Tags,
    /// The event content.
    pub content: &'a str,
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

    /// The `kind:pubkey:d` coordinate for replaceable and addressable
    /// events; `None` for regular and ephemeral kinds. An addressable event
    /// without a `d` tag takes the empty identifier.
    #[must_use]
    pub fn address(&self) -> Option<Coordinate> {
        if self.kind.is_addressable() {
            Some(Coordinate::new(
                self.kind,
                self.pubkey,
                self.tags.identifier().unwrap_or_default(),
            ))
        } else if self.kind.is_replaceable() {
            Some(Coordinate::new(self.kind, self.pubkey, ""))
        } else {
            None
        }
    }

    /// Whether this is the signed form of `unsigned`: `kind`, `content`,
    /// `created_at`, `tags`, and `pubkey` all equal.
    #[must_use]
    pub fn matches_unsigned(&self, unsigned: &UnsignedEvent) -> bool {
        self.kind == unsigned.kind
            && self.content == unsigned.content
            && self.created_at == unsigned.created_at
            && self.tags == unsigned.tags
            && self.pubkey == unsigned.pubkey
    }

    /// NIP-01 replaceable/addressable winner: higher `created_at`, or equal
    /// timestamp and lexicographically lower id.
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
        UnsignedEvent::new(
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        )
    }

    /// Assembles a signed event from its parts; only signing and
    /// deserialization can produce `Event`s.
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

    /// The borrowed view used by the canonical writer.
    pub(crate) fn parts(&self) -> EventParts<'_> {
        EventParts {
            pubkey: &self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
        }
    }

    /// Full NIP-01 verification: recomputes the id from the canonical
    /// serialization, then BIP-340-verifies `sig` over it. Allocates
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`Error::IdMismatch`] when the stored id does not match the
    /// recomputed id; [`Error::InvalidSignature`] when the public key is
    /// not on the curve or the signature is invalid.
    pub fn verify(&self) -> Result<()> {
        let computed = {
            let mut hasher = Sha256::new();
            canonical::write_event(&self.parts(), &mut hasher);
            EventId::from_bytes(hasher.finalize().into())
        };
        if computed != self.id {
            return Err(Error::IdMismatch);
        }
        self.sig
            .verify(&self.id, &self.pubkey)
            .map_err(|source| Error::InvalidSignature { source })
    }

    /// The wire JSON object: `id`, `pubkey`, `created_at`, `kind`, `tags`,
    /// `content`, `sig` in canonical field order and escaping.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        canonical::write_signed(self, &mut out);
        out
    }

    /// Constructs an event from its wire fields. Shape-valid by
    /// construction — like [`Self::from_json`], this does not verify the id
    /// or the signature; call [`Self::verify`] when that matters.
    #[must_use]
    pub const fn new(
        id: EventId,
        pubkey: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: Tags,
        content: String,
        sig: Signature,
    ) -> Self {
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        }
    }

    /// Parses the wire JSON object.
    ///
    /// # Errors
    ///
    /// [`JsonError`] on any malformed input; the message names the
    /// offending field.
    pub fn from_json(json: &str) -> json::Result<Self> {
        serde_json::from_str(json).map_err(JsonError::from)
    }

    /// NIP-01 newest-first order: `created_at` descending, `id` ascending
    /// as the tie-break. Usable as `sort_by(Event::cmp_newest_first)`.
    #[must_use]
    pub fn cmp_newest_first(a: &Self, b: &Self) -> Ordering {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    }

    /// Negentropy item order: `created_at` ascending, `id` ascending as the
    /// tie-break — the same id direction as [`Self::cmp_newest_first`].
    #[must_use]
    pub fn cmp_oldest_first(a: &Self, b: &Self) -> Ordering {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
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
    /// Strict wire rules: every key must be unique; `id`/`pubkey`/`sig`
    /// are exact-length lowercase hex, `created_at` a plain integer below
    /// `2^53`, `kind` an integer in `0..=65535`, `content` a string, `tags`
    /// an array of non-empty string arrays. Unknown fields are ignored.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EventVisitor;

        impl<'de> Visitor<'de> for EventVisitor {
            type Value = Event;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a signed NIP-01 event object")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a strict visitor is a loop over tagged fields"
            )]
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Event, M::Error> {
                let mut seen = Vec::new();
                let mut id = None;
                let mut pubkey = None;
                let mut created_at = None;
                let mut kind = None;
                let mut tags = None;
                let mut content = None;
                let mut sig = None;
                while let Some(key) = json::next_key(&mut map, &mut seen)? {
                    match key.as_ref() {
                        "id" => id = Some(map.next_value::<WireHex<32, true>>()?.0),
                        "pubkey" => pubkey = Some(map.next_value::<WireHex<32, true>>()?.0),
                        "created_at" => {
                            created_at = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0);
                        }
                        "kind" => {
                            kind = Some(map.next_value::<WireInt<{ u16::MAX as u64 }>>()?.0);
                        }
                        "tags" => tags = Some(map.next_value::<WireTags>()?.0),
                        "content" => content = Some(map.next_value::<String>()?),
                        "sig" => sig = Some(map.next_value::<WireHex<64, true>>()?.0),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Event {
                    id: EventId::from_bytes(json::required(id, "id")?),
                    pubkey: PublicKey::from_bytes(json::required(pubkey, "pubkey")?),
                    created_at: Timestamp::from_secs(json::required(created_at, "created_at")?),
                    kind: Kind::new(
                        u16::try_from(json::required(kind, "kind")?)
                            .map_err(serde::de::Error::custom)?,
                    ),
                    tags: json::required(tags, "tags")?,
                    content: json::required(content, "content")?,
                    sig: Signature::from_bytes(json::required(sig, "sig")?),
                })
            }
        }

        deserializer.deserialize_map(EventVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::{String, ToString};

    use super::*;
    use crate::event::tag::Tag;

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
    fn new_round_trips_wire_json() {
        let sig = "ab".repeat(64);
        let json = alloc::format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":1700000000,"kind":1,"tags":[["t","smoke"]],"content":"hello","sig":"{sig}"}}"#,
            "cd".repeat(32),
            PK,
        );
        let original = signed(&json);
        let rebuilt = Event::new(
            original.id(),
            original.pubkey(),
            original.created_at(),
            original.kind(),
            original.tags().clone(),
            alloc::string::String::from(original.content()),
            original.sig(),
        );
        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.to_json(), original.to_json());
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
        assert_eq!(Event::cmp_newest_first(&a, &b), Ordering::Less);
        assert_eq!(Event::cmp_oldest_first(&a, &b), Ordering::Greater);
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
        // Duplicate keys are rejected — even of unknown fields.
        let dup = alloc::format!(
            "{{\"id\":\"{}\",\"id\":\"{}\",\"pubkey\":\"{PK}\",\"created_at\":1700000000,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(32),
            "cd".repeat(64),
        );
        assert!(serde_json::from_str::<Event>(&dup).is_err());
        assert!(serde_json::from_str::<Event>(&base(",\"extra\":1,\"extra\":2")).is_err());
        // Non-canonical integer spellings are rejected.
        for (field, spelling) in [("created_at", "1e3"), ("created_at", "-0"), ("kind", "1.0")] {
            let raw = base("").replace(
                &alloc::format!("\"{field}\":1700000000"),
                &alloc::format!("\"{field}\":{spelling}"),
            );
            let raw = if field == "created_at" {
                raw
            } else {
                base("").replace("\"kind\":1,", &alloc::format!("\"kind\":{spelling},"))
            };
            assert!(serde_json::from_str::<Event>(&raw).is_err(), "{raw}");
        }
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
        assert!(matches!(event.verify().unwrap_err(), Error::IdMismatch));
    }

    #[test]
    fn verify_rejects_a_bad_signature() {
        let mut value = serde_json::to_value(valid_event()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("sig".into(), "ff".repeat(64).into());
        let event: Event = serde_json::from_value(value).unwrap();
        assert!(matches!(
            event.verify().unwrap_err(),
            Error::InvalidSignature { .. }
        ));
    }

    #[test]
    fn signature_verify_rejects_an_off_curve_pubkey() {
        let event = valid_event();
        let off_curve = PublicKey::from_bytes([0xff; 32]);
        assert!(matches!(
            event.sig().verify(&event.id(), &off_curve).unwrap_err(),
            crate::key::Error::InvalidPublicKey
        ));
    }

    #[test]
    fn signature_verify_rejects_a_wrong_message() {
        let event = valid_event();
        let other_id = EventId::from_bytes([0u8; 32]);
        assert!(matches!(
            event.sig().verify(&other_id, &event.pubkey()).unwrap_err(),
            crate::key::Error::InvalidSignature
        ));
    }

    #[test]
    fn event_id_glue() {
        let id = EventId::from_bytes([0xab; 32]);
        assert_eq!(EventId::from_slice(id.as_bytes()).unwrap(), id);
        assert!(matches!(
            EventId::from_slice(&[0u8; 31]).unwrap_err(),
            Error::InvalidLength {
                expected: 32,
                found: 31
            }
        ));
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
        assert!(matches!(
            Signature::from_slice(&[0u8; 63]).unwrap_err(),
            crate::key::Error::InvalidLength {
                expected: 64,
                found: 63
            }
        ));
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
