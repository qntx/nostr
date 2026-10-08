//! Wire JSON deserialization helpers shared by the event and filter map
//! visitors (NK-ADR-012 rulings 7–9).
//!
//! Ruling 7 gives duplicate keys `JSON.parse` semantics: the *last* value
//! wins, even when an earlier duplicate would fail typed validation. That
//! rules out deserializing fields eagerly — an early error aborts the map.
//! Instead each known field reads through a lenient [`Captured`] wrapper:
//! it accepts any JSON value, converts the wanted shape, and records
//! `Invalid(reason)` for everything else, so a later duplicate simply
//! overwrites it. Unknown keys drain through `IgnoredAny`; no `Value` tree
//! is built and nothing here depends on `serde_json`.
//!
//! Rulings 8–9: a JSON number counts as an integer whenever its *value* is
//! integral — `u64`, a non-negative `i64` (including `-0`), or an `f64`
//! that round-trips exactly — bounded by `Number.MAX_SAFE_INTEGER`. Above
//! that bound TS has already lost precision after `JSON.parse`.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::tag::{Tag, Tags};

/// `Number.MAX_SAFE_INTEGER` — the inclusive upper bound for wire integers.
pub(crate) const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// The outcome of leniently reading one wire field: converted content, or a
/// reason the value was unusable — which surfaces only when no later
/// duplicate replaces the slot (NK-ADR-012 ruling 7).
#[derive(Debug)]
pub(crate) enum Captured<T> {
    Valid(T),
    Invalid(&'static str),
}

/// `"invalid {field}: {reason}"` for `Error::custom`.
struct FieldError<'a> {
    field: &'a str,
    reason: &'static str,
}

impl fmt::Display for FieldError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

/// Finalizes a required field: absent → `missing_field`, invalid →
/// `custom`, valid → the converted value.
pub(crate) fn finish<T, E: DeError>(
    slot: Option<Captured<T>>,
    field: &'static str,
) -> Result<T, E> {
    match slot {
        None => Err(E::missing_field(field)),
        Some(Captured::Invalid(reason)) => Err(E::custom(FieldError { field, reason })),
        Some(Captured::Valid(v)) => Ok(v),
    }
}

/// Finalizes an optional field (filters have no required keys).
pub(crate) fn finish_opt<T, E: DeError>(slot: Captured<T>, field: &str) -> Result<T, E> {
    match slot {
        Captured::Invalid(reason) => Err(E::custom(FieldError { field, reason })),
        Captured::Valid(v) => Ok(v),
    }
}

/// Drains the remainder of a rejected sequence.
fn drain_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
    while seq.next_element::<IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Drains the remainder of a rejected map.
fn drain_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Emits the requested `visit_*` rejection arms for a lenient capture: each
/// turns a non-matching JSON type into `Invalid` instead of a
/// deserialization error, draining containers so the map stays in sync.
/// `visit_some` forwards to the inner value.
macro_rules! reject {
    (@arm $value:ty, $reason:expr, visit_some) => {
        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<$value, D::Error> {
            d.deserialize_any(self)
        }
    };
    (@arm $value:ty, $reason:expr, visit_seq) => {
        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<$value, A::Error> {
            drain_seq(seq)?;
            Ok(Captured::Invalid($reason))
        }
    };
    (@arm $value:ty, $reason:expr, visit_map) => {
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<$value, A::Error> {
            drain_map(map)?;
            Ok(Captured::Invalid($reason))
        }
    };
    (@arm $value:ty, $reason:expr, $method:ident) => {
        fn $method<E: DeError>(self) -> Result<$value, E> {
            Ok(Captured::Invalid($reason))
        }
    };
    (@arm $value:ty, $reason:expr, $method:ident ($arg:ty)) => {
        fn $method<E: DeError>(self, _v: $arg) -> Result<$value, E> {
            Ok(Captured::Invalid($reason))
        }
    };
    ($value:ty, $reason:expr => $($method:ident $(($arg:ty))?),* $(,)?) => {
        $(
            reject!(@arm $value, $reason, $method $(($arg))?);
        )*
    };
}

/// Captures a string field; any other JSON type yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireStr(pub(crate) Captured<String>);

struct StrVisitor;

impl<'de> Visitor<'de> for StrVisitor {
    type Value = Captured<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Captured<String>, E> {
        Ok(Captured::Valid(v.into()))
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Captured<String>, E> {
        Ok(Captured::Valid(v))
    }

    reject!(Captured<String>, "not a string" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_unit, visit_none, visit_some,
        visit_bytes(&[u8]), visit_byte_buf(Vec<u8>), visit_seq, visit_map);
}

impl<'de> Deserialize<'de> for WireStr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrVisitor).map(Self)
    }
}

/// Captures a string field as `Cow`, borrowing the input when it needs no
/// unescaping — hex fields validate against the borrowed text without an
/// intermediate `String`.
#[derive(Debug)]
pub(crate) struct WireCow<'de>(pub(crate) Captured<Cow<'de, str>>);

struct CowVisitor;

impl<'de> Visitor<'de> for CowVisitor {
    type Value = Captured<Cow<'de, str>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_borrowed_str<E: DeError>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(Captured::Valid(Cow::Borrowed(v)))
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Captured::Valid(Cow::Owned(v.into())))
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        Ok(Captured::Valid(Cow::Owned(v)))
    }

    reject!(Captured<Cow<'de, str>>, "not a string" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_unit, visit_none, visit_some,
        visit_bytes(&[u8]), visit_byte_buf(Vec<u8>), visit_seq, visit_map);
}

impl<'de> Deserialize<'de> for WireCow<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CowVisitor).map(Self)
    }
}

/// Captures a `0..=MAX` integer field (rulings 8–9); any other shape or an
/// out-of-range/non-integral number yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireInt<const MAX: u64>(pub(crate) Captured<u64>);

#[derive(Debug)]
struct IntVisitor {
    max: u64,
}

impl<'de> Visitor<'de> for IntVisitor {
    type Value = Captured<u64>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a non-negative integer of at most {}", self.max)
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Captured<u64>, E> {
        if value <= self.max {
            Ok(Captured::Valid(value))
        } else {
            Ok(Captured::Invalid("integer out of range"))
        }
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Captured<u64>, E> {
        u64::try_from(value).map_or_else(
            |_| Ok(Captured::Invalid("integer must not be negative")),
            |value| self.visit_u64(value),
        )
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::float_cmp,
        reason = "range-checked first: -0.0 <= value <= max; the exact i64 \
                  round-trip *is* the integrality test (integers up to 2^53 \
                  are exact in f64)"
    )]
    fn visit_f64<E: DeError>(self, value: f64) -> Result<Captured<u64>, E> {
        // `f64::fract` is std-only; a value <= 2^53-1 is integral iff it
        // round-trips through i64 (`-0.0` becomes `0`).
        let int = value as i64;
        if value >= 0.0 && value <= self.max as f64 && int as f64 == value {
            Ok(Captured::Valid(int as u64))
        } else {
            Ok(Captured::Invalid("not an integer in range"))
        }
    }

    reject!(Captured<u64>, "not a number" =>
        visit_bool(bool), visit_char(char), visit_str(&str),
        visit_string(String), visit_unit, visit_none, visit_some,
        visit_bytes(&[u8]), visit_byte_buf(Vec<u8>), visit_seq, visit_map);
}

impl<'de, const MAX: u64> Deserialize<'de> for WireInt<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(IntVisitor { max: MAX })
            .map(Self)
    }
}

/// Captures a string-list field (`ids`, `authors`, `#<letter>` values);
/// a non-array or non-string element yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireStrList(pub(crate) Captured<Vec<String>>);

struct StrListVisitor;

impl<'de> Visitor<'de> for StrListVisitor {
    type Value = Captured<Vec<String>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of strings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        let mut bad = None;
        while let Some(el) = seq.next_element::<WireStr>()? {
            if bad.is_none() {
                match el.0 {
                    Captured::Valid(v) => items.push(v),
                    Captured::Invalid(reason) => bad = Some(reason),
                }
            }
        }
        Ok(bad.map_or(Captured::Valid(items), Captured::Invalid))
    }

    reject!(Captured<Vec<String>>, "not an array" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_str(&str), visit_string(String),
        visit_unit, visit_none, visit_some, visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>), visit_map);
}

/// Captures a hex string into a fixed-size byte array; `STRICT` selects
/// wire lowercase hex (events) vs any-case hex (filter `ids`/`authors`,
/// ruling 4). Any non-string or non-hex value yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireHex<const N: usize, const STRICT: bool>(pub(crate) Captured<[u8; N]>);

struct HexVisitor<const N: usize, const STRICT: bool>;

impl<'de, const N: usize, const STRICT: bool> Visitor<'de> for HexVisitor<N, STRICT> {
    type Value = Captured<[u8; N]>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {}-character hex string", N * 2)
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        let decoded = if STRICT {
            crate::hex::decode_wire::<N>(v)
        } else {
            crate::hex::decode_caller::<N>(v)
        };
        decoded.map_or_else(
            |_| Ok(Captured::Invalid("invalid hex")),
            |bytes| Ok(Captured::Valid(bytes)),
        )
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }

    reject!(Captured<[u8; N]>, "not a string" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_unit, visit_none, visit_some,
        visit_bytes(&[u8]), visit_byte_buf(Vec<u8>), visit_seq, visit_map);
}

impl<'de, const N: usize, const STRICT: bool> Deserialize<'de> for WireHex<N, STRICT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(HexVisitor::<N, STRICT>)
            .map(Self)
    }
}

/// Captures a list of `N`-byte hex strings (`ids`, `authors`); a non-array
/// or bad element yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireHexList<const N: usize, const STRICT: bool>(
    pub(crate) Captured<Vec<[u8; N]>>,
);

struct HexListVisitor<const N: usize, const STRICT: bool>;

impl<'de, const N: usize, const STRICT: bool> Visitor<'de> for HexListVisitor<N, STRICT> {
    type Value = Captured<Vec<[u8; N]>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "an array of {}-character hex strings", N * 2)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        let mut bad = None;
        while let Some(el) = seq.next_element::<WireHex<N, STRICT>>()? {
            if bad.is_none() {
                match el.0 {
                    Captured::Valid(v) => items.push(v),
                    Captured::Invalid(reason) => bad = Some(reason),
                }
            }
        }
        Ok(bad.map_or(Captured::Valid(items), Captured::Invalid))
    }

    reject!(Captured<Vec<[u8; N]>>, "not an array" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_str(&str), visit_string(String),
        visit_unit, visit_none, visit_some, visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>), visit_map);
}

impl<'de, const N: usize, const STRICT: bool> Deserialize<'de> for WireHexList<N, STRICT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(HexListVisitor::<N, STRICT>)
            .map(Self)
    }
}

impl<'de> Deserialize<'de> for WireStrList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrListVisitor).map(Self)
    }
}

/// Captures a `kinds` list (`0..=65535` elements); a non-array or a
/// non-integer/out-of-range element yields `Invalid`.
#[derive(Debug)]
pub(crate) struct WireU16List(pub(crate) Captured<Vec<u16>>);

/// Pushes a captured kind; a `u64` above `u16::MAX` (unreachable through
/// `WireInt<65535>` but kept total) marks the field invalid.
fn push_kind(items: &mut Vec<u16>, bad: &mut Option<&'static str>, value: u64) {
    match u16::try_from(value) {
        Ok(value) => items.push(value),
        Err(_) => *bad = Some("kind out of range"),
    }
}

struct U16ListVisitor;

impl<'de> Visitor<'de> for U16ListVisitor {
    type Value = Captured<Vec<u16>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of kinds")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        let mut bad = None;
        while let Some(el) = seq.next_element::<WireInt<{ u16::MAX as u64 }>>()? {
            if bad.is_none() {
                match el.0 {
                    Captured::Valid(v) => push_kind(&mut items, &mut bad, v),
                    Captured::Invalid(reason) => bad = Some(reason),
                }
            }
        }
        Ok(bad.map_or(Captured::Valid(items), Captured::Invalid))
    }

    reject!(Captured<Vec<u16>>, "not an array" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_str(&str), visit_string(String),
        visit_unit, visit_none, visit_some, visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>), visit_map);
}

impl<'de> Deserialize<'de> for WireU16List {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(U16ListVisitor).map(Self)
    }
}

/// Captures a `tags` field: a sequence of non-empty string sequences. The
/// first wrong element marks the field `Invalid`; the rest still drains so
/// the map stays in sync and a later duplicate can win.
#[derive(Debug)]
pub(crate) struct WireTags(pub(crate) Captured<Tags>);

struct TagsVisitor;

impl<'de> Visitor<'de> for TagsVisitor {
    type Value = Captured<Tags>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of tag arrays")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut tags = Tags::new();
        let mut bad = None;
        while let Some(el) = seq.next_element::<WireStrList>()? {
            if bad.is_none() {
                match el.0 {
                    Captured::Valid(items) => match Tag::new(items) {
                        Ok(tag) => tags.push(tag),
                        Err(_) => bad = Some("tag must be a non-empty string array"),
                    },
                    Captured::Invalid(reason) => bad = Some(reason),
                }
            }
        }
        Ok(bad.map_or(Captured::Valid(tags), Captured::Invalid))
    }

    reject!(Captured<Tags>, "not an array" =>
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64),
        visit_char(char), visit_str(&str), visit_string(String),
        visit_unit, visit_none, visit_some, visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>), visit_map);
}

impl<'de> Deserialize<'de> for WireTags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TagsVisitor).map(Self)
    }
}

/// Deserializes a `0..=MAX_SAFE_INTEGER` wire integer for `Deserialize`
/// field attributes (e.g. a `serde_json::Value`-driven `count`).
pub(crate) fn de_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    match deserializer.deserialize_any(IntVisitor {
        max: MAX_SAFE_INTEGER,
    })? {
        Captured::Valid(v) => Ok(v),
        Captured::Invalid(reason) => Err(D::Error::custom(reason)),
    }
}

/// Deserializes a `0..=u16::MAX` wire integer (`kind`, `kinds` items).
pub(crate) fn de_u16<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    match deserializer.deserialize_any(IntVisitor {
        max: u64::from(u16::MAX),
    })? {
        Captured::Valid(v) => {
            let Ok(v) = u16::try_from(v) else {
                return Err(D::Error::custom("kind out of range"));
            };
            Ok(v)
        }
        Captured::Invalid(reason) => Err(D::Error::custom(reason)),
    }
}
