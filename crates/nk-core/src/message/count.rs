//! NIP-45 `COUNT` payloads: the result object and the `HyperLogLog` sketch.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::de::{Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Error, Result};
use crate::hex;
use crate::json::{self, WireInt};
use crate::limits::MAX_SAFE_INTEGER;

/// A NIP-45 `HyperLogLog` sketch: 256 registers as a 512-char lowercase hex
/// string on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hll(pub(crate) [u8; 256]);

impl Hll {
    /// The all-zero sketch (merge identity).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0; 256])
    }

    /// Register-wise maximum of `self` and `other` (NIP-45 sketch merge).
    pub fn merge(&mut self, other: &Self) {
        for (slot, byte) in self.0.iter_mut().zip(other.0) {
            *slot = (*slot).max(byte);
        }
    }
}

impl FromStr for Hll {
    type Err = Error;

    /// Parses a 512-char hex string of any case (lowercase on display).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHll`] when `s` is not 512 hex characters.
    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 512 {
            return Err(Error::InvalidHll);
        }
        hex::decode_caller::<256>(s)
            .map(Self)
            .map_err(|_| Error::InvalidHll)
    }
}

impl fmt::Display for Hll {
    /// The lowercase 512-char hex form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl Serialize for Hll {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&alloc::format!("{self}"))
    }
}

impl<'de> Deserialize<'de> for Hll {
    /// Deserializes a 512-char lowercase hex string (protocol text).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.len() != 512 {
            return Err(serde::de::Error::custom(Error::InvalidHll));
        }
        hex::decode_wire::<256>(&raw)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A relay `COUNT` reply payload (NIP-45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountResult {
    /// The reported count.
    pub count: u64,
    /// `true` when the count is an estimate (ignored on parse when not a bool).
    pub approximate: Option<bool>,
    /// The optional HLL sketch (ignored on parse when not 512-hex).
    pub hll: Option<Hll>,
}

impl Serialize for CountResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut len = 1;
        len += usize::from(self.approximate.is_some());
        len += usize::from(self.hll.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("count", &self.count)?;
        if let Some(approximate) = self.approximate {
            map.serialize_entry("approximate", &approximate)?;
        }
        if let Some(hll) = &self.hll {
            map.serialize_entry("hll", hll)?;
        }
        map.end()
    }
}

/// `visit_*` arms that drain a container or ignore a scalar, producing
/// `None` — used by the lenient `approximate`/`hll` fields, where a wrong
/// shape is ignored rather than an error.
macro_rules! opt_out {
    ($($method:ident $(($arg:ty))?),* $(,)?) => {$(
        fn $method<E: DeError>(self $(, _: $arg)?) -> Result<Self::Value, E> {
            Ok(None)
        }
    )*};
}

/// A `bool` or `None` for any other JSON value.
#[derive(Default)]
struct OptBool;

impl<'de> Visitor<'de> for OptBool {
    type Value = Option<bool>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bool")
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Some(v))
    }

    opt_out!(
        visit_i64(i64),
        visit_u64(u64),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_string(String),
        visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>),
        visit_unit,
        visit_none
    );

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    #[allow(
        clippy::excessive_nesting,
        reason = "a strict visitor is a loop over tagged fields"
    )]
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

/// A parsed [`Hll`] or `None` for any other JSON value.
#[derive(Default)]
struct OptHll;

impl<'de> Visitor<'de> for OptHll {
    type Value = Option<Hll>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 512-char hex string")
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(hex::decode_wire::<256>(v).ok().map(Hll))
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }

    opt_out!(
        visit_bool(bool),
        visit_i64(i64),
        visit_u64(u64),
        visit_f64(f64),
        visit_char(char),
        visit_bytes(&[u8]),
        visit_byte_buf(Vec<u8>),
        visit_unit,
        visit_none
    );

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    #[allow(
        clippy::excessive_nesting,
        reason = "a strict visitor is a loop over tagged fields"
    )]
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

impl<'de> Deserialize<'de> for CountResult {
    /// `count` must be a plain integer in `0..=2^53-1`; keys are unique; a
    /// non-bool `approximate` and a non-512-hex `hll` are ignored rather
    /// than failing.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CountVisitor;

        impl<'de> Visitor<'de> for CountVisitor {
            type Value = CountResult;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a NIP-45 count object")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a strict visitor is a loop over tagged fields"
            )]
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<CountResult, M::Error> {
                let mut seen = Vec::new();
                let mut count = None;
                let mut approximate = None;
                let mut hll = None;
                while let Some(key) = json::next_key(&mut map, &mut seen)? {
                    match key.as_ref() {
                        "count" => {
                            count = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0);
                        }
                        "approximate" => {
                            approximate = map.next_value::<OptBoolDe>()?.0;
                        }
                        "hll" => {
                            hll = map.next_value::<OptHllDe>()?.0;
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(CountResult {
                    count: json::required(count, "count")?,
                    approximate,
                    hll,
                })
            }
        }

        deserializer.deserialize_map(CountVisitor)
    }
}

/// `Deserialize` wrapper for [`OptBool`].
struct OptBoolDe(Option<bool>);

impl<'de> Deserialize<'de> for OptBoolDe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OptBool).map(Self)
    }
}

/// `Deserialize` wrapper for [`OptHll`].
struct OptHllDe(Option<Hll>);

impl<'de> Deserialize<'de> for OptHllDe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OptHll).map(Self)
    }
}
