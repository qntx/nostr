//! The unsigned event: `pubkey`, `created_at`, `kind`, `tags`, `content`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::id::EventId;
use super::kind::Kind;
use super::tag::Tags;
use super::{EventParts, canonical};
use crate::json::{self, JsonError, WireHex, WireInt, WireTags};
use crate::key::PublicKey;
use crate::limits::MAX_SAFE_INTEGER;
use crate::time::Timestamp;

/// An unsigned event: `pubkey`, `created_at`, `kind`, `tags`, `content`.
///
/// Constructed directly or via [`super::EventBuilder`]; signing turns it
/// into an [`super::Event`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnsignedEvent {
    pub(crate) pubkey: PublicKey,
    pub(crate) created_at: Timestamp,
    pub(crate) kind: Kind,
    pub(crate) tags: Tags,
    pub(crate) content: String,
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

    /// The canonical NIP-01 serialization `[0,pubkey,created_at,kind,tags,content]`
    /// — the byte-exact preimage whose SHA-256 is the event id.
    #[must_use]
    pub fn id_preimage(&self) -> String {
        let mut out = String::new();
        canonical::write_event(&self.parts(), &mut out);
        out
    }

    /// The wire JSON object: `pubkey`, `created_at`, `kind`, `tags`,
    /// `content` in canonical field order and escaping.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        canonical::write_unsigned(self, &mut out);
        out
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

    /// The event id: SHA-256 over the canonical serialization, written
    /// straight into the hasher with no intermediate string.
    #[must_use]
    pub fn id(&self) -> EventId {
        let mut hasher = Sha256::new();
        canonical::write_event(&self.parts(), &mut hasher);
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
    /// Strict wire rules: keys are unique; `pubkey` is 64-char lowercase
    /// hex, `created_at` a plain integer below `2^53`, `kind` an integer in
    /// `0..=65535`, `content` a string, `tags` an array of non-empty string
    /// arrays. Unknown fields are ignored.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnsignedVisitor;

        impl<'de> Visitor<'de> for UnsignedVisitor {
            type Value = UnsignedEvent;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an unsigned NIP-01 event object")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a strict visitor is a loop over tagged fields"
            )]
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<UnsignedEvent, M::Error> {
                let mut seen = Vec::new();
                let mut pubkey = None;
                let mut created_at = None;
                let mut kind = None;
                let mut tags = None;
                let mut content = None;
                while let Some(key) = json::next_key(&mut map, &mut seen)? {
                    match key.as_ref() {
                        "pubkey" => pubkey = Some(map.next_value::<WireHex<32, true>>()?.0),
                        "created_at" => {
                            created_at = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0);
                        }
                        "kind" => {
                            kind = Some(map.next_value::<WireInt<{ u16::MAX as u64 }>>()?.0);
                        }
                        "tags" => tags = Some(map.next_value::<WireTags>()?.0),
                        "content" => content = Some(map.next_value::<String>()?),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(UnsignedEvent {
                    pubkey: PublicKey::from_bytes(json::required(pubkey, "pubkey")?),
                    created_at: Timestamp::from_secs(json::required(created_at, "created_at")?),
                    kind: Kind::new(
                        u16::try_from(json::required(kind, "kind")?)
                            .map_err(serde::de::Error::custom)?,
                    ),
                    tags: json::required(tags, "tags")?,
                    content: json::required(content, "content")?,
                })
            }
        }

        deserializer.deserialize_map(UnsignedVisitor)
    }
}
