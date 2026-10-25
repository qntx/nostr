//! NIP-05 (Mapping Nostr keys to DNS identifiers) — the codec half of
//! `nips/nip05.ts`: the `local@domain` grammar, the `nostr.json`
//! document parser, and lookup. Transport lives in `nk`'s `http`
//! module.
//!
//! `names`/`relays` entries are applied in document order (a serde
//! visitor, not a sorted map) so case-folding collisions resolve the
//! way `Object.entries` does.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/05.md>

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::Deserialize;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde_json::Value;
use url::form_urlencoded::Serializer;

use crate::JsonError;
use crate::PublicKey;
use crate::nips::nip19::ProfilePointer;
use crate::nips::util::trim_js;

/// The root local part — `domain` alone resolves to `_`.
pub const ROOT_LOCAL: &str = "_";

/// Errors produced by NIP-05 address parsing and document decoding.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The identifier does not match the `local@domain` grammar.
    #[error("invalid NIP-05 identifier")]
    InvalidAddress,
    /// The input is not valid JSON.
    #[error("invalid NIP-05 JSON")]
    InvalidJson {
        /// The parser failure.
        #[source]
        source: JsonError,
    },
    /// The document is not a JSON object.
    #[error("NIP-05 document is not a JSON object")]
    NotAnObject,
    /// The document lacks an object `names` map.
    #[error("NIP-05 document missing names map")]
    MissingNames,
}

/// A parsed NIP-05 identifier — `<local>@<domain>`, both ASCII-
/// lowercased, with `_` for a bare domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nip05Address {
    local: String,
    domain: String,
}

/// `[A-Za-z0-9._-]` — the local-part charset.
const fn is_local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')
}

/// `[A-Za-z0-9-]` — one domain label's charset.
const fn is_label_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

impl FromStr for Nip05Address {
    type Err = Error;

    /// Parses `name@domain`, `_@domain`, or bare `domain` (the local
    /// becomes `_`). JS-trims, ASCII-only per the TS regex, both parts
    /// lowercased; the input is never echoed in the error.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] on any deviation from the grammar.
    fn from_str(input: &str) -> Result<Self, Error> {
        let input = trim_js(input);
        let (local, domain) = match input.split_once('@') {
            Some((local, domain)) => {
                if local.is_empty() || !local.bytes().all(is_local_char) {
                    return Err(Error::InvalidAddress);
                }
                (local, domain)
            }
            None => (ROOT_LOCAL, input),
        };
        let valid_domain = !domain.is_empty()
            && domain
                .split('.')
                .all(|l| !l.is_empty() && l.bytes().all(is_label_char))
            && domain.contains('.');
        if !valid_domain {
            return Err(Error::InvalidAddress);
        }
        // Both parts are validated ASCII, so ASCII folding is exact.
        Ok(Self {
            local: local.to_ascii_lowercase(),
            domain: domain.to_ascii_lowercase(),
        })
    }
}

impl fmt::Display for Nip05Address {
    /// `local@domain`; a root local prints as bare `domain`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.local == ROOT_LOCAL {
            write!(f, "{}", self.domain)
        } else {
            write!(f, "{}@{}", self.local, self.domain)
        }
    }
}

impl Nip05Address {
    /// The local part — `_` for a domain-only identifier.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// `https://<domain>/.well-known/nostr.json?name=<local>` — the
    /// form-urlencoded query, byte-identical to TS `wellKnownUrl`.
    #[must_use]
    pub fn well_known_url(&self) -> String {
        let mut query = Serializer::new(String::new());
        query.append_pair("name", &self.local);
        alloc::format!(
            "https://{}/.well-known/nostr.json?{}",
            self.domain,
            query.finish()
        )
    }
}

/// The `nip46` block — 46.md appendix discovery metadata
/// (`{relays, nostrconnect_url}`), not a bunker pointer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nip46Discovery {
    /// `relays` — string entries only.
    pub relays: Option<Vec<String>>,
    /// `nostrconnect_url`.
    pub nostrconnect_url: Option<String>,
}

/// Ordered JSON-object entries; a non-object value decodes as `None`.
struct OrderedEntries(Option<Vec<(String, Value)>>);

impl<'de> Deserialize<'de> for OrderedEntries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(EntriesVisitor)
    }
}

struct EntriesVisitor;

impl<'de> Visitor<'de> for EntriesVisitor {
    type Value = OrderedEntries;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((k, v)) = map.next_entry::<String, Value>()? {
            entries.push((k, v));
        }
        Ok(OrderedEntries(Some(entries)))
    }

    /// Every non-object value — scalar or array — decodes as `None`,
    /// matching TS `isRecord` failing.
    fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(OrderedEntries(None))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(OrderedEntries(None))
    }
}

/// The raw wire shape: entries stay in document order.
struct RawDocument {
    is_object: bool,
    names: Option<Vec<(String, Value)>>,
    relays: Option<Vec<(String, Value)>>,
    nip46: Option<Value>,
}

impl RawDocument {
    const NOT_OBJECT: Self = Self {
        is_object: false,
        names: None,
        relays: None,
        nip46: None,
    };
}

impl<'de> Deserialize<'de> for RawDocument {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DocumentVisitor)
    }
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = RawDocument;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a NIP-05 document object")
    }

    /// Every scalar/array input means "not a NIP-05 document".
    fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(RawDocument::NOT_OBJECT)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut names = None;
        let mut relays = None;
        let mut nip46 = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "names" => {
                    names = map.next_value::<OrderedEntries>()?.0;
                }
                "relays" => {
                    relays = map.next_value::<OrderedEntries>()?.0;
                }
                "nip46" => {
                    nip46 = Some(map.next_value::<Value>()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(RawDocument {
            is_object: true,
            names,
            relays,
            nip46,
        })
    }
}

/// A parsed `/.well-known/nostr.json` document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nip05Document {
    names: BTreeMap<String, PublicKey>,
    relays: Option<BTreeMap<PublicKey, Vec<String>>>,
    nip46: Option<Nip46Discovery>,
}

/// A non-empty string value.
fn nonempty_string(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    if s.is_empty() {
        None
    } else {
        Some(String::from(s))
    }
}

/// Non-empty string items only — TS `stringUrls`.
fn string_urls(list: &[Value]) -> Vec<String> {
    list.iter().filter_map(nonempty_string).collect()
}

/// One `relays` entry: a 64-hex key and a non-empty string list.
fn relay_entry(key: &str, value: &Value) -> Option<(PublicKey, Vec<String>)> {
    let pk = PublicKey::from_wire_hex(key).ok()?;
    let urls = string_urls(value.as_array()?);
    if urls.is_empty() {
        None
    } else {
        Some((pk, urls))
    }
}

/// The `nip46` block — TS `parseNip05Nip46`: present only when at
/// least one usable field survives.
fn nip46_discovery(v: &Value) -> Option<Nip46Discovery> {
    let object = v.as_object()?;
    let relays = object
        .get("relays")
        .and_then(Value::as_array)
        .map(|list| string_urls(list));
    let nostrconnect_url = object
        .get("nostrconnect_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if relays.is_none() && nostrconnect_url.is_none() {
        None
    } else {
        Some(Nip46Discovery {
            relays,
            nostrconnect_url,
        })
    }
}

impl Nip05Document {
    /// Parses a `nostr.json` body with the TS rules: `names` keys and
    /// values lowercase, non-hex and non-string entries skipped,
    /// `relays` keeps only hex keys with non-empty string lists,
    /// `nip46` survives only when it carries a usable field. Entries
    /// apply in document order — a `names` case-fold collision resolves
    /// to the later entry.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON;
    /// [`Error::NotAnObject`] on a non-object document;
    /// [`Error::MissingNames`] when `names` is absent or not an object.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let raw: RawDocument =
            serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })?;
        if !raw.is_object {
            return Err(Error::NotAnObject);
        }
        let names = raw.names.ok_or(Error::MissingNames)?;
        let mut doc = Self::default();
        for (key, value) in names {
            let Some(hex) = value.as_str() else {
                continue;
            };
            let Ok(pk) = PublicKey::from_wire_hex(hex) else {
                continue;
            };
            doc.names.insert(key.to_lowercase(), pk);
        }
        if let Some(entries) = raw.relays {
            doc.relays = Some(
                entries
                    .into_iter()
                    .filter_map(|(k, v)| relay_entry(&k, &v))
                    .collect(),
            );
        }
        doc.nip46 = raw.nip46.as_ref().and_then(nip46_discovery);
        Ok(doc)
    }

    /// The `names` map — lowercased local part to public key.
    #[must_use]
    pub const fn names(&self) -> &BTreeMap<String, PublicKey> {
        &self.names
    }

    /// The `relays` map — public key to relay URL strings. `None` when
    /// `relays` was absent or not an object.
    #[must_use]
    pub const fn relays(&self) -> Option<&BTreeMap<PublicKey, Vec<String>>> {
        self.relays.as_ref()
    }

    /// The `nip46` discovery block, when present.
    #[must_use]
    pub const fn nip46(&self) -> Option<&Nip46Discovery> {
        self.nip46.as_ref()
    }

    /// Resolves `address` inside this document — TS
    /// `lookupFromDocument`: a `names` hit plus any relay hints.
    #[must_use]
    pub fn profile(&self, address: &Nip05Address) -> Option<ProfilePointer> {
        let pubkey = *self.names.get(&address.local)?;
        let relays = self
            .relays
            .as_ref()
            .and_then(|r| r.get(&pubkey))
            .cloned()
            .unwrap_or_default();
        Some(ProfilePointer { pubkey, relays })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::string::ToString as _;

    use super::*;

    const PK: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn address_display_round_trips() {
        let named = "Bob@Example.COM".parse::<Nip05Address>().unwrap();
        assert_eq!(named.local(), "bob");
        assert_eq!(named.domain(), "example.com");
        assert_eq!(named.to_string(), "bob@example.com");
        let root = "example.com".parse::<Nip05Address>().unwrap();
        assert_eq!(root.local(), "_");
        assert_eq!(root.to_string(), "example.com");
        assert_eq!("_@example.com".parse::<Nip05Address>().unwrap(), root);
    }

    #[test]
    fn well_known_url() {
        let address = "bob@example.com".parse::<Nip05Address>().unwrap();
        assert_eq!(
            address.well_known_url(),
            "https://example.com/.well-known/nostr.json?name=bob"
        );
    }

    #[test]
    fn document_error_kinds() {
        assert!(matches!(
            Nip05Document::from_json("{"),
            Err(Error::InvalidJson { .. })
        ));
        assert!(matches!(
            Nip05Document::from_json("[1]"),
            Err(Error::NotAnObject)
        ));
        assert!(matches!(
            Nip05Document::from_json("{}"),
            Err(Error::MissingNames)
        ));
        assert!(matches!(
            Nip05Document::from_json(r#"{"names":[]}"#),
            Err(Error::MissingNames)
        ));
    }

    #[test]
    fn profile_lookup() {
        let doc = Nip05Document::from_json(&alloc::format!(
            r#"{{"names":{{"alice":"{PK}"}},"relays":{{"{PK}":["wss://a.example"]}}}}"#
        ))
        .unwrap();
        let address = "alice@example.com".parse::<Nip05Address>().unwrap();
        let profile = doc.profile(&address).unwrap();
        assert_eq!(profile.relays, ["wss://a.example"]);
    }
}
