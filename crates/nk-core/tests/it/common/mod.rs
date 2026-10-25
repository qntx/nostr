//! Helpers shared by the vector tests: hex codecs and value comparison.
//! There is no divergence registry: every case must pass as written.
//! A case with `"nonCanonicalJson": true` must be *rejected* by the strict
//! parser (TypeScript accepts it because `JSON.parse` erases the spelling).

#![allow(dead_code, reason = "each test module uses a subset")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of,
    reason = "a malformed fixture file must fail the test loudly"
)]

/// `true` when two JSON texts are semantically equal (key order is not
/// semantic); falls back to string equality on unparseable input.
pub(crate) fn json_eq(a: &str, b: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(a),
        serde_json::from_str::<serde_json::Value>(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

use nk_core::{EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};

/// Decodes hex of any case into a byte vector.
pub(crate) fn unhex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Decodes hex into a fixed-size array.
pub(crate) fn unhex_arr<const N: usize>(input: &str) -> Option<[u8; N]> {
    let bytes = unhex(input)?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// A `TryCryptoRng` that answers `try_fill_bytes` with `aux` (the BIP-340
/// auxiliary randomness draw of `sign_event`/`sign_id`).
pub(crate) struct AuxRng(pub(crate) [u8; 32]);

impl rand_core::TryRng for AuxRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        dest.copy_from_slice(&self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for AuxRng {}

/// A `TryCryptoRng` that answers `try_fill_bytes` from a scripted entropy
/// stream, consumed in draw order.
pub(crate) struct BytesRng(pub(crate) Vec<u8>);

impl rand_core::TryRng for BytesRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let n = dest.len();
        let take = self.0.drain(..n.min(self.0.len()));
        dest.copy_from_slice(&take.collect::<Vec<u8>>());
        Ok(())
    }
}

impl rand_core::TryCryptoRng for BytesRng {}

/// Lowercase hex of `bytes`.
pub(crate) fn hex_str(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4).into(), 16).unwrap());
        out.push(char::from_digit((b & 0x0f).into(), 16).unwrap());
    }
    out
}

#[cfg(feature = "os-rng")]
use std::future::Future;

/// Drives a future to completion — the `it` binary is std, no executor
/// dependency needed.
#[cfg(feature = "os-rng")]
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => return v,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct HasDup(bool);

impl<'de> serde::Deserialize<'de> for HasDup {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::Deserialize as _;
        use serde::de::{MapAccess, SeqAccess, Visitor};
        use std::collections::HashSet;

        struct Scan;
        impl<'de> Visitor<'de> for Scan {
            type Value = HasDup;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<HasDup, A::Error> {
                let mut seen = HashSet::new();
                let mut dup = false;
                // The map must be fully drained — an early return leaves
                // `Deserializer` mid-object and `from_str` reports a
                // trailing-comma error, hiding the duplicate.
                while let Some((key, HasDup(sub))) = map.next_entry::<String, HasDup>()? {
                    dup |= !seen.insert(key) || sub;
                }
                Ok(HasDup(dup))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<HasDup, A::Error> {
                let mut dup = false;
                while let Some(HasDup(sub)) = seq.next_element::<HasDup>()? {
                    dup |= sub;
                }
                Ok(HasDup(dup))
            }
            fn visit_bool<E>(self, _: bool) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_i64<E>(self, _: i64) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_u64<E>(self, _: u64) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_f64<E>(self, _: f64) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_str<E>(self, _: &str) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_bytes<E>(self, _: &[u8]) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_none<E>(self) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
            fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<HasDup, D::Error> {
                HasDup::deserialize(d)
            }
            fn visit_unit<E>(self) -> Result<HasDup, E> {
                Ok(HasDup(false))
            }
        }
        d.deserialize_any(Scan)
    }
}

/// `true` when any object in `json` repeats a key — `serde_json::Value`
/// merges duplicates silently, so the check runs on the raw text.
pub(crate) fn has_duplicate_keys(json: &str) -> bool {
    serde_json::from_str::<HasDup>(json).is_ok_and(|h| h.0)
}

/// `true` when a `Number` in `v` uses a non-integral spelling `JSON.parse`
/// accepts but the canonical profile rejects (`1e3`, `1.0`, `1700000000.0`,
/// `-0`) — all deserialize as floats.
fn is_noncanonical(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Number(n) => n.is_f64(),
        serde_json::Value::Array(a) => a.iter().any(is_noncanonical),
        serde_json::Value::Object(m) => m.values().any(is_noncanonical),
        _ => false,
    }
}

/// Raw-text form of [`caller_filter`]: rejects duplicate keys
/// (`nonCanonicalJson`), then builds the caller-side filter.
pub(crate) fn caller_filter_raw(raw: &str) -> Result<Filter, String> {
    if has_duplicate_keys(raw) {
        return Err(String::from("duplicate keys"));
    }
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    caller_filter(&v)
}

/// Caller-input filter parse — vector `input`/`filter` values are
/// developer-supplied Filter objects (the `canonicalizeFilter`/`matchFilter`
/// arguments); hex fields normalize at the boundary via the typed decoders
/// and `Filter::tag`'s `#e`/`#p` lowercasing.
pub(crate) fn caller_filter(v: &serde_json::Value) -> Result<Filter, String> {
    if is_noncanonical(v) {
        return Err(String::from("nonCanonicalJson"));
    }
    let err = |m: &str| String::from(m);
    let object = v.as_object().ok_or_else(|| err("not an object"))?;
    let str_list = |v: &serde_json::Value| -> Result<Vec<String>, String> {
        v.as_array()
            .ok_or_else(|| err("not an array"))?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(String::from)
                    .ok_or_else(|| err("non-string item"))
            })
            .collect()
    };
    let mut filter = Filter::default();
    for (key, value) in object {
        match key.as_str() {
            "ids" => {
                let mut list = Vec::new();
                for hex in str_list(value)? {
                    list.push(EventId::from_hex(&hex).map_err(|e| e.to_string())?);
                }
                filter = filter.ids(list);
            }
            "authors" => {
                let mut list = Vec::new();
                for hex in str_list(value)? {
                    list.push(PublicKey::from_hex(&hex).map_err(|e| e.to_string())?);
                }
                filter = filter.authors(list);
            }
            "kinds" => {
                let mut list = Vec::new();
                for item in value.as_array().ok_or_else(|| err("not an array"))? {
                    list.push(Kind::new(
                        item.as_u64()
                            .ok_or_else(|| err("non-integer kind"))
                            .and_then(|v| u16::try_from(v).map_err(|_| err("kind range")))?,
                    ));
                }
                filter = filter.kinds(list);
            }
            "since" => {
                filter = filter.since(Timestamp::from_secs(
                    value.as_u64().ok_or_else(|| err("non-integer since"))?,
                ));
            }
            "until" => {
                filter = filter.until(Timestamp::from_secs(
                    value.as_u64().ok_or_else(|| err("non-integer until"))?,
                ));
            }
            "limit" => {
                filter = filter.limit(value.as_u64().ok_or_else(|| err("non-integer limit"))?);
            }
            "search" => {
                filter = filter.search(value.as_str().ok_or_else(|| err("non-string search"))?);
            }
            _ => {
                if let Some(letter) = key
                    .strip_prefix('#')
                    .and_then(|c| SingleLetterTag::new(c.chars().next()?))
                    .filter(|_| key.chars().count() == 2)
                {
                    filter = filter.tag(letter, str_list(value)?);
                }
            }
        }
    }
    Ok(filter)
}
