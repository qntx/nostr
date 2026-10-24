//! Strict wire-JSON helpers shared by the event, filter and message
//! visitors, plus the public [`JsonError`] wrapper.
//!
//! The wire profile (ADR-0007 rule 4): integers are plain JSON integers in
//! `0..=2^53-1` (`1e3`, `1.0`, `-0` and negative spellings are rejected —
//! `serde_json` itself reports them as floats or negatives), object keys
//! are unique, and unknown fields are ignored.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::event::{Tag, Tags};
use crate::limits::MAX_SAFE_INTEGER;

/// A `serde_json` parse/validation failure, wrapped so no `serde_json`
/// type leaks into the public API.
///
/// `Display` and [`core::error::Error::source`] both render the underlying
/// parser message, which names the offending field.
#[derive(Debug)]
pub struct JsonError(serde_json::Error);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for JsonError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<serde_json::Error> for JsonError {
    fn from(error: serde_json::Error) -> Self {
        Self(error)
    }
}

/// The result type for `from_json` entry points.
pub(crate) type Result<T> = core::result::Result<T, JsonError>;

/// Records `key` in `seen`, failing on a duplicate object key — known and
/// unknown keys share the one set (objects have unique keys).
pub(crate) fn unique_key<'de, E: DeError>(
    seen: &mut Vec<Cow<'de, str>>,
    key: Cow<'de, str>,
) -> core::result::Result<(), E> {
    if seen.contains(&key) {
        return Err(E::custom(alloc::format!("duplicate key `{key}`")));
    }
    seen.push(key);
    Ok(())
}

/// Finalizes a required field: `None` → `missing_field`.
pub(crate) fn required<T, E: DeError>(
    slot: Option<T>,
    field: &'static str,
) -> core::result::Result<T, E> {
    slot.ok_or_else(|| E::missing_field(field))
}

/// A wire integer in `0..=MAX`: only a plain non-negative JSON integer is
/// accepted (`visit_u64`); floats, exponents, negatives and other types are
/// deserialization errors.
#[derive(Debug)]
pub(crate) struct WireInt<const MAX: u64>(pub u64);

struct IntVisitor {
    max: u64,
}

impl Visitor<'_> for IntVisitor {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a non-negative integer of at most {}", self.max)
    }

    fn visit_u64<E: DeError>(self, value: u64) -> core::result::Result<u64, E> {
        if value <= self.max {
            Ok(value)
        } else {
            Err(E::custom("integer out of range"))
        }
    }
}

impl<'de, const MAX: u64> Deserialize<'de> for WireInt<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer
            .deserialize_any(IntVisitor { max: MAX })
            .map(Self)
    }
}

/// Deserializes a `0..=MAX_SAFE_INTEGER` wire integer for `Deserialize`
/// field attributes.
pub(crate) fn de_safe_int<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<u64, D::Error> {
    deserializer.deserialize_any(IntVisitor {
        max: MAX_SAFE_INTEGER,
    })
}

/// A strict-lowercase wire hex string decoded into `N` bytes (events'
/// `id`/`pubkey`/`sig`); `STRICT == false` accepts any case (filter
/// `ids`/`authors`).
#[derive(Debug)]
pub(crate) struct WireHex<const N: usize, const STRICT: bool>(pub [u8; N]);

struct HexVisitor<const N: usize, const STRICT: bool>;

impl<const N: usize, const STRICT: bool> Visitor<'_> for HexVisitor<N, STRICT> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {}-character hex string", N * 2)
    }

    fn visit_str<E: DeError>(self, v: &str) -> core::result::Result<Self::Value, E> {
        let decoded = if STRICT {
            crate::hex::decode_wire::<N>(v)
        } else {
            crate::hex::decode_caller::<N>(v)
        };
        decoded.map_err(|_| E::custom("invalid hex"))
    }
}

impl<'de, const N: usize, const STRICT: bool> Deserialize<'de> for WireHex<N, STRICT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer
            .deserialize_any(HexVisitor::<N, STRICT>)
            .map(Self)
    }
}

/// A list of `N`-byte hex strings (`ids`, `authors`).
#[derive(Debug)]
pub(crate) struct WireHexList<const N: usize, const STRICT: bool>(pub Vec<[u8; N]>);

impl<'de, const N: usize, const STRICT: bool> Deserialize<'de> for WireHexList<N, STRICT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        Vec::<WireHex<N, STRICT>>::deserialize(deserializer)
            .map(|items| Self(items.into_iter().map(|item| item.0).collect()))
    }
}

/// A `kinds` list (`0..=65535` elements).
#[derive(Debug)]
pub(crate) struct WireU16List(pub Vec<u16>);

impl<'de> Deserialize<'de> for WireU16List {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        Vec::<WireInt<{ u16::MAX as u64 }>>::deserialize(deserializer).and_then(|items| {
            items
                .into_iter()
                .map(|item| {
                    u16::try_from(item.0).map_err(|_| D::Error::custom("kind out of range"))
                })
                .collect::<core::result::Result<Vec<u16>, D::Error>>()
                .map(Self)
        })
    }
}

/// A `tags` field: a sequence of non-empty string sequences.
#[derive(Debug)]
pub(crate) struct WireTags(pub Tags);

impl<'de> Deserialize<'de> for WireTags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        Vec::<Tag>::deserialize(deserializer).map(|tags| Self(tags.into_iter().collect()))
    }
}

/// Reads the next map key and rejects it as a duplicate before the value
/// is read (unique keys only; the error fires on the key, not the value).
pub(crate) fn next_key<'de, M: MapAccess<'de>>(
    map: &mut M,
    seen: &mut Vec<Cow<'de, str>>,
) -> core::result::Result<Option<Cow<'de, str>>, M::Error> {
    match map.next_key::<Cow<'de, str>>()? {
        Some(key) => {
            unique_key::<M::Error>(seen, Cow::clone(&key))?;
            Ok(Some(key))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn wire_int_accepts_only_plain_integers() {
        assert_eq!(serde_json::from_str::<WireInt<5>>("5").unwrap().0, 5);
        for bad in ["6", "-1", "-0", "1.0", "1e3", "\"5\"", "null", "true", "[]"] {
            assert!(serde_json::from_str::<WireInt<5>>(bad).is_err(), "{bad}");
        }
        assert_eq!(
            serde_json::from_str::<WireInt<{ MAX_SAFE_INTEGER }>>("9007199254740991")
                .unwrap()
                .0,
            MAX_SAFE_INTEGER
        );
        assert!(serde_json::from_str::<WireInt<{ MAX_SAFE_INTEGER }>>("9007199254740992").is_err());
    }

    #[test]
    fn wire_hex_respects_case_mode() {
        assert_eq!(
            serde_json::from_str::<WireHex<2, true>>("\"00ff\"")
                .unwrap()
                .0,
            [0x00, 0xff]
        );
        assert!(serde_json::from_str::<WireHex<2, true>>("\"00FF\"").is_err());
        assert_eq!(
            serde_json::from_str::<WireHex<2, false>>("\"00FF\"")
                .unwrap()
                .0,
            [0x00, 0xff]
        );
        assert!(serde_json::from_str::<WireHex<2, true>>("5").is_err());
    }

    #[test]
    fn json_error_displays_and_sources_serde() {
        let error = serde_json::from_str::<u64>("\"x\"")
            .map_err(JsonError)
            .unwrap_err();
        let text = error.to_string();
        assert_ne!(text.len(), 0);
        assert!(core::error::Error::source(&error).is_some());
    }
}
