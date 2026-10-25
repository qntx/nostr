//! NIP-11 (Relay Information Document) — the codec half of
//! `nips/nip11.ts`. Transport lives in the `nk` crate's `http` module;
//! this module is the pure parser plus the ws→http URL splice.
//!
//! The parser is lenient like TS: wrong-typed fields are dropped, never
//! fatal — only a non-object document errors.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/11.md>

use alloc::string::String;
use alloc::vec::Vec;

use crate::{JsonError, PublicKey, RelayUrl};

/// Errors produced by [`RelayInformation::from_json`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not valid JSON.
    #[error("invalid relay information JSON")]
    InvalidJson {
        /// The parser failure.
        #[source]
        source: JsonError,
    },
    /// The document is not a JSON object.
    #[error("relay information document is not a JSON object")]
    NotAnObject,
}

/// The `limitation` block — the ten numbers and three booleans a relay
/// advertises. Every entry is optional and present only when the
/// document carried a correctly-typed value.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limitation {
    /// `max_message_length`.
    pub max_message_length: Option<u64>,
    /// `max_subscriptions`.
    pub max_subscriptions: Option<u64>,
    /// `max_limit`.
    pub max_limit: Option<u64>,
    /// `max_subid_length`.
    pub max_subid_length: Option<u64>,
    /// `max_event_tags`.
    pub max_event_tags: Option<u64>,
    /// `max_content_length`.
    pub max_content_length: Option<u64>,
    /// `min_pow_difficulty`.
    pub min_pow_difficulty: Option<u64>,
    /// `created_at_lower_limit`.
    pub created_at_lower_limit: Option<u64>,
    /// `created_at_upper_limit`.
    pub created_at_upper_limit: Option<u64>,
    /// `default_limit`.
    pub default_limit: Option<u64>,
    /// `auth_required`.
    pub auth_required: Option<bool>,
    /// `payment_required`.
    pub payment_required: Option<bool>,
    /// `restricted_writes`.
    pub restricted_writes: Option<bool>,
}

/// A parsed NIP-11 relay information document. Fields are `None` when
/// absent or wrong-typed in the source; `pubkey`/`self_pubkey` are kept
/// only when they are 64-hex.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayInformation {
    /// `name`.
    pub name: Option<String>,
    /// `description`.
    pub description: Option<String>,
    /// `banner`.
    pub banner: Option<String>,
    /// `icon`.
    pub icon: Option<String>,
    /// `pubkey` — the relay operator's public key.
    pub pubkey: Option<PublicKey>,
    /// `self` — the relay's own public key (wire name `self`).
    pub self_pubkey: Option<PublicKey>,
    /// `contact`.
    pub contact: Option<String>,
    /// `supported_nips` — non-negative integers only.
    pub supported_nips: Option<Vec<u64>>,
    /// `software`.
    pub software: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `limitation` — absent when every entry was wrong-typed.
    pub limitation: Option<Limitation>,
    /// `payments_url`.
    pub payments_url: Option<String>,
    /// `terms_of_service`.
    pub terms_of_service: Option<String>,
}

type StringField = fn(&mut RelayInformation) -> &mut Option<String>;
type NumberField = fn(&mut Limitation) -> &mut Option<u64>;
type BoolField = fn(&mut Limitation) -> &mut Option<bool>;
type KeyField = fn(&mut RelayInformation) -> &mut Option<PublicKey>;

const STRING_FIELDS: [(&str, StringField); 9] = [
    ("name", |i| &mut i.name),
    ("description", |i| &mut i.description),
    ("banner", |i| &mut i.banner),
    ("icon", |i| &mut i.icon),
    ("contact", |i| &mut i.contact),
    ("software", |i| &mut i.software),
    ("version", |i| &mut i.version),
    ("payments_url", |i| &mut i.payments_url),
    ("terms_of_service", |i| &mut i.terms_of_service),
];

const LIMITATION_NUMBERS: [(&str, NumberField); 10] = [
    ("max_message_length", |l| &mut l.max_message_length),
    ("max_subscriptions", |l| &mut l.max_subscriptions),
    ("max_limit", |l| &mut l.max_limit),
    ("max_subid_length", |l| &mut l.max_subid_length),
    ("max_event_tags", |l| &mut l.max_event_tags),
    ("max_content_length", |l| &mut l.max_content_length),
    ("min_pow_difficulty", |l| &mut l.min_pow_difficulty),
    ("created_at_lower_limit", |l| &mut l.created_at_lower_limit),
    ("created_at_upper_limit", |l| &mut l.created_at_upper_limit),
    ("default_limit", |l| &mut l.default_limit),
];

const LIMITATION_BOOLEANS: [(&str, BoolField); 3] = [
    ("auth_required", |l| &mut l.auth_required),
    ("payment_required", |l| &mut l.payment_required),
    ("restricted_writes", |l| &mut l.restricted_writes),
];

impl RelayInformation {
    /// Parses a relay information document, lenient like TS
    /// `parseRelayInformation`: string fields drop on wrong type,
    /// `supported_nips` keeps only non-negative integers, `limitation`
    /// drops entirely when it carries no valid entry, and
    /// `pubkey`/`self` survive only as 64-hex.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON;
    /// [`Error::NotAnObject`] when the document is not a JSON object.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })?;
        let object = value.as_object().ok_or(Error::NotAnObject)?;
        let mut info = Self::default();
        for (key, field) in STRING_FIELDS {
            if let Some(v) = object.get(key).and_then(serde_json::Value::as_str) {
                *field(&mut info) = Some(String::from(v));
            }
        }
        let key_fields: [(&str, KeyField); 2] = [
            ("pubkey", |i| &mut i.pubkey),
            ("self", |i| &mut i.self_pubkey),
        ];
        for (key, field) in key_fields {
            if let Some(pk) = object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| PublicKey::from_hex(s).ok())
            {
                *field(&mut info) = Some(pk);
            }
        }
        if let Some(nips) = object
            .get("supported_nips")
            .and_then(serde_json::Value::as_array)
        {
            info.supported_nips = Some(nips.iter().filter_map(serde_json::Value::as_u64).collect());
        }
        if let Some(raw) = object
            .get("limitation")
            .and_then(serde_json::Value::as_object)
        {
            info.limitation = limitation_of(raw);
        }
        Ok(info)
    }

    /// The HTTP URL that serves this relay's NIP-11 document:
    /// `wss://`→`https://`, `ws://`→`http://`. A [`RelayUrl`] is always
    /// normalized `ws(s)://`, so only the scheme changes.
    #[must_use]
    pub fn url(relay: &RelayUrl) -> String {
        match relay.as_str().split_once("://") {
            Some(("wss", rest)) => alloc::format!("https://{rest}"),
            Some(("ws", rest)) => alloc::format!("http://{rest}"),
            _ => String::from(relay.as_str()),
        }
    }
}

/// The `limitation` block — `None` when no entry survived typing.
fn limitation_of(raw: &serde_json::Map<String, serde_json::Value>) -> Option<Limitation> {
    let mut limitation = Limitation::default();
    let mut any = false;
    for (key, field) in LIMITATION_NUMBERS {
        if let Some(v) = raw.get(key).and_then(serde_json::Value::as_u64) {
            *field(&mut limitation) = Some(v);
            any = true;
        }
    }
    for (key, field) in LIMITATION_BOOLEANS {
        if let Some(v) = raw.get(key).and_then(serde_json::Value::as_bool) {
            *field(&mut limitation) = Some(v);
            any = true;
        }
    }
    if any { Some(limitation) } else { None }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use super::*;

    #[test]
    fn url_splices_both_schemes() {
        assert_eq!(
            RelayInformation::url(&RelayUrl::parse("wss://a.example/").unwrap()),
            "https://a.example/"
        );
        assert_eq!(
            RelayInformation::url(&RelayUrl::parse("ws://a.example:8080/x?y=1").unwrap()),
            "http://a.example:8080/x?y=1"
        );
    }

    #[test]
    fn non_object_is_error() {
        assert!(matches!(
            RelayInformation::from_json("42"),
            Err(Error::NotAnObject)
        ));
        assert!(matches!(
            RelayInformation::from_json("{"),
            Err(Error::InvalidJson { .. })
        ));
    }
}
