//! [`RelayUrl`]: a WHATWG-normalized relay URL, the typed counterpart of the
//! TS `normalizeURL`/`normalizeRelayUrls` in `@qntx/nostr`'s `core/util.ts`.
//! Normalization is byte-for-byte identical to the TS side.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::error::{Error, ErrorKind, Result};

/// A normalized relay URL (`ws://` or `wss://`).
///
/// Construction goes through [`RelayUrl::parse`], so a value is always in the
/// canonical form: lowercase scheme and host, `http:`/`https:` rewritten to
/// `ws:`/`wss:` (a bare host is prefixed `wss://`), default port removed,
/// duplicate path slashes collapsed, query pairs sorted by name, fragment
/// removed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayUrl(String);

impl RelayUrl {
    /// Parses and normalizes `input` exactly like the TS `normalizeURL`.
    ///
    /// # Errors
    ///
    /// `ErrorKind::Url` when `input` is not a valid WHATWG URL or its scheme
    /// is not `http`/`https`/`ws`/`wss`.
    pub fn parse(input: &str) -> Result<Self> {
        let prefixed;
        let input = if input.contains("://") {
            input
        } else {
            prefixed = alloc::format!("wss://{input}");
            prefixed.as_str()
        };
        let mut url = Url::parse(input)
            .map_err(|error| Error::with_source(ErrorKind::Url, "invalid URL", error))?;
        let rewrite = match url.scheme() {
            "http" => Some("ws"),
            "https" => Some("wss"),
            "ws" | "wss" => None,
            scheme => {
                return Err(Error::new(
                    ErrorKind::Url,
                    alloc::format!("unsupported relay URL scheme: {scheme}:"),
                ));
            }
        };
        if let Some(target) = rewrite {
            url.set_scheme(target)
                .map_err(|()| Error::new(ErrorKind::Url, "could not rewrite scheme"))?;
        }
        url.set_path(&collapse_path(url.path()));
        sort_query(&mut url);
        url.set_fragment(None);
        Ok(Self(url.into()))
    }

    /// The normalized URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Like the TS `normalizeRelayUrls`: each entry is normalized, empty or
    /// invalid entries are skipped, and results are deduplicated in
    /// first-seen order.
    #[must_use]
    pub fn normalize_all<I, S>(inputs: I) -> Vec<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out: Vec<Self> = Vec::new();
        for input in inputs {
            let input = input.as_ref();
            if input.is_empty() {
                continue;
            }
            if let Ok(url) = Self::parse(input)
                && !out.iter().any(|seen| seen.0 == url.0)
            {
                out.push(url);
            }
        }
        out
    }
}

/// Collapses runs of `/` into one and strips a single trailing `/` unless the
/// path is the bare root. Mirrors `p.pathname.replaceAll(/\/+/g, "/")` plus
/// the one-slash trim in the TS implementation.
fn collapse_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut at_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !at_slash {
                out.push('/');
            }
            at_slash = true;
        } else {
            out.push(c);
            at_slash = false;
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Stable-sorts decoded query pairs by name compared as UTF-16 code units
/// (`URLSearchParams.sort()`), then re-serializes in
/// `application/x-www-form-urlencoded` form; an empty result drops the `?`.
fn sort_query(url: &mut Url) {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    pairs.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    if pairs.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(
            pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
    }
}

impl FromStr for RelayUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for RelayUrl {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RelayUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for RelayUrl {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelayUrl {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn deserialize_accepts_escaped_strings() {
        let url: RelayUrl = serde_json::from_str("\"wss://a.example/\\u00e9\"").unwrap();
        assert_eq!(url.as_str(), "wss://a.example/%C3%A9");
    }

    #[test]
    fn deserialize_accepts_owned_values() {
        let url: RelayUrl =
            serde_json::from_value(serde_json::Value::String(String::from("relay.example")))
                .unwrap();
        assert_eq!(url.as_str(), "wss://relay.example/");
    }

    #[test]
    fn deserialize_rejects_other_schemes() {
        let error = serde_json::from_str::<RelayUrl>("\"gopher://a.example\"").unwrap_err();
        assert!(
            !error.to_string().is_empty(),
            "serde error must carry the cause"
        );
    }
}
