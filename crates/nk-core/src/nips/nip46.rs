//! NIP-46 (Nostr Connect) URI and RPC JSON codecs — the protocol half of
//! `nips/nip46.ts`. Transport, signing, and the NIP-44 channel live in the
//! signer layer; this module is the pure codec.
//!
//! [`BunkerUri`] is the `bunker://` pointer a remote signer publishes;
//! [`NostrConnectUri`] is the client-initiated `nostrconnect://` URI. Both are
//! parsed through the WHATWG [`url`] crate — the same spec as JS `URL` — and
//! query pairs go through its `form_urlencoded` (`URLSearchParams`). The RPC
//! payloads are [`Request`]/[`Response`] over `serde_json`; lone-surrogate
//! escapes are rejected at parse like `serde_json` does, and errors never
//! echo the input.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/46.md>

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;
use url::form_urlencoded::Serializer;

use crate::nips::util::trim_js;

/// Errors produced by NIP-46 URI parsing and RPC JSON decoding.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not a parseable URI.
    #[error("invalid URI")]
    InvalidUri {
        /// The URL parser failure.
        #[source]
        source: url::ParseError,
    },
    /// The URI uses a different scheme than the type requires.
    #[error("expected a {expected}: URI")]
    UnexpectedScheme {
        /// The required scheme.
        expected: &'static str,
    },
    /// The URI authority is not a 64-hex public key.
    #[error("invalid public key in URI")]
    InvalidPublicKey,
    /// The `secret` query parameter is absent or empty.
    #[error("missing secret in URI")]
    MissingSecret,
    /// No `relay` query parameters are present.
    #[error("missing relays in URI")]
    MissingRelays,
    /// The RPC JSON is malformed or fails the wire shape checks.
    #[error("invalid NIP-46 JSON")]
    InvalidJson {
        /// The serde error describing the offending field.
        #[source]
        source: crate::JsonError,
    },
}

/// `url.hostname || url.pathname.replace(/^\/*/, "")` — the non-special-scheme
/// authority, falling back to the path with its leading slashes stripped.
fn authority_or_path(url: &Url) -> &str {
    match url.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => url.path().trim_start_matches('/'),
    }
}

/// `url.searchParams.get(name)` — the first `name` pair's decoded value.
fn query_get<'a>(pairs: &'a [(Cow<'a, str>, Cow<'a, str>)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_ref())
}

/// `url.searchParams.getAll(name)` — every `name` pair's decoded value.
fn query_get_all<'a>(pairs: &[(Cow<'a, str>, Cow<'a, str>)], name: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
        .collect()
}

/// A `bunker://` pointer — the remote signer's public key, its relays, and an
/// optional secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BunkerUri {
    /// Remote signer / bunker public key.
    pub remote_signer: PublicKey,
    /// `relay` query values, decoded and in order.
    pub relays: Vec<String>,
    /// `secret` query value (`None` when absent; a present-but-empty
    /// `secret=` stays `Some("")` like `URLSearchParams.get`).
    pub secret: Option<String>,
}

impl FromStr for BunkerUri {
    type Err = Error;

    /// Parses a `bunker://` URI.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUri`] when the input is not a URI,
    /// [`Error::UnexpectedScheme`] for other schemes (including NIP-05
    /// identifiers), and [`Error::InvalidPublicKey`] when the authority is
    /// not a 64-hex public key.
    fn from_str(input: &str) -> Result<Self, Error> {
        let url = Url::parse(trim_js(input)).map_err(|e| Error::InvalidUri { source: e })?;
        if url.scheme() != "bunker" {
            return Err(Error::UnexpectedScheme { expected: "bunker" });
        }
        // Any-case 64-hex is accepted.
        let remote_signer =
            PublicKey::from_hex(authority_or_path(&url)).map_err(|_| Error::InvalidPublicKey)?;
        let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = url.query_pairs().collect();
        Ok(Self {
            remote_signer,
            relays: query_get_all(&pairs, "relay"),
            secret: query_get(&pairs, "secret").map(String::from),
        })
    }
}

impl fmt::Display for BunkerUri {
    /// `bunker://<lowercase pubkey>` plus the `relay` pairs in order and a
    /// non-empty `secret`, application/x-www-form-urlencoded.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut serializer = Serializer::new(String::new());
        for relay in &self.relays {
            serializer.append_pair("relay", relay);
        }
        if let Some(secret) = self.secret.as_deref().filter(|s| !s.is_empty()) {
            serializer.append_pair("secret", secret);
        }
        let query = serializer.finish();
        if query.is_empty() {
            write!(f, "bunker://{}", self.remote_signer)
        } else {
            write!(f, "bunker://{}?{query}", self.remote_signer)
        }
    }
}

/// A `nostrconnect://` URI — the client's public key, its relays, the
/// handshake secret, and optional metadata.
///
/// Constructed values always hold a non-empty `secret` and at least one
/// relay, so `Display` cannot fail.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NostrConnectUri {
    client: PublicKey,
    relays: Vec<String>,
    secret: String,
    perms: Vec<String>,
    name: Option<String>,
    url: Option<String>,
    image: Option<String>,
}

impl NostrConnectUri {
    /// Creates a `nostrconnect://` URI with the required fields.
    ///
    /// # Errors
    ///
    /// [`Error::MissingSecret`] when `secret` is empty;
    /// [`Error::MissingRelays`] when `relays` is empty.
    pub fn new(client: PublicKey, relays: Vec<String>, secret: String) -> Result<Self, Error> {
        if secret.is_empty() {
            return Err(Error::MissingSecret);
        }
        if relays.is_empty() {
            return Err(Error::MissingRelays);
        }
        Ok(Self {
            client,
            relays,
            secret,
            perms: Vec::new(),
            name: None,
            url: None,
            image: None,
        })
    }

    /// Sets the `perms` the client advertises, serialized joined on `,`.
    #[must_use]
    pub fn with_perms<I, S>(mut self, perms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.perms = perms.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the client metadata `name`.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the client metadata `url`.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the client metadata `image`.
    #[must_use]
    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    /// The client's public key.
    #[must_use]
    pub const fn client(&self) -> PublicKey {
        self.client
    }

    /// The `relay` query values, in order.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// The handshake secret — guaranteed non-empty.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The advertised `perms`.
    #[must_use]
    pub fn perms(&self) -> &[String] {
        &self.perms
    }

    /// The client metadata `name`, when present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The client metadata `url`, when present.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// The client metadata `image`, when present.
    #[must_use]
    pub fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }
}

impl FromStr for NostrConnectUri {
    type Err = Error;

    /// Parses a `nostrconnect://` URI. The input is never echoed (N11).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUri`] when the input is not a URI,
    /// [`Error::UnexpectedScheme`] for other schemes,
    /// [`Error::InvalidPublicKey`] when the authority is not 64-hex,
    /// [`Error::MissingSecret`] for an absent or empty `secret`, and
    /// [`Error::MissingRelays`] for zero `relay` pairs.
    fn from_str(uri: &str) -> Result<Self, Error> {
        let url = Url::parse(uri).map_err(|e| Error::InvalidUri { source: e })?;
        if url.scheme() != "nostrconnect" {
            return Err(Error::UnexpectedScheme {
                expected: "nostrconnect",
            });
        }
        let client =
            PublicKey::from_hex(authority_or_path(&url)).map_err(|_| Error::InvalidPublicKey)?;
        let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = url.query_pairs().collect();
        let secret = query_get(&pairs, "secret")
            .filter(|s| !s.is_empty())
            .ok_or(Error::MissingSecret)?;
        let relays = query_get_all(&pairs, "relay");
        if relays.is_empty() {
            return Err(Error::MissingRelays);
        }
        let perms = match query_get(&pairs, "perms") {
            Some(raw) if !raw.is_empty() => raw
                .split(',')
                .filter(|perm| !perm.is_empty())
                .map(String::from)
                .collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            client,
            relays,
            secret: String::from(secret),
            perms,
            name: query_get(&pairs, "name").map(String::from),
            url: query_get(&pairs, "url").map(String::from),
            image: query_get(&pairs, "image").map(String::from),
        })
    }
}

impl fmt::Display for NostrConnectUri {
    /// `nostrconnect://<client>?…` — absent-or-empty `name`/`url`/`image`
    /// and an empty `perms` are omitted; `perms` are re-joined on `,`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut serializer = Serializer::new(String::new());
        for relay in &self.relays {
            serializer.append_pair("relay", relay);
        }
        serializer.append_pair("secret", &self.secret);
        if !self.perms.is_empty() {
            serializer.append_pair("perms", &self.perms.join(","));
        }
        for (key, value) in [
            ("name", self.name.as_deref()),
            ("url", self.url.as_deref()),
            ("image", self.image.as_deref()),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                serializer.append_pair(key, value);
            }
        }
        write!(f, "nostrconnect://{}?{}", self.client, serializer.finish())
    }
}

/// A NIP-46 RPC method name, serialized as its wire string
/// (`"connect"`, `"sign_event"`, …). Unknown names round-trip through
/// [`Method::Other`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// `connect`.
    Connect,
    /// `get_public_key`.
    GetPublicKey,
    /// `sign_event`.
    SignEvent,
    /// `ping`.
    Ping,
    /// `nip04_encrypt`.
    Nip04Encrypt,
    /// `nip04_decrypt`.
    Nip04Decrypt,
    /// `nip44_encrypt`.
    Nip44Encrypt,
    /// `nip44_decrypt`.
    Nip44Decrypt,
    /// Any other method name, preserved verbatim.
    Other(String),
}

impl Method {
    /// The wire method name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Connect => "connect",
            Self::GetPublicKey => "get_public_key",
            Self::SignEvent => "sign_event",
            Self::Ping => "ping",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Other(name) => name,
        }
    }
}

impl From<String> for Method {
    fn from(name: String) -> Self {
        match name.as_str() {
            "connect" => Self::Connect,
            "get_public_key" => Self::GetPublicKey,
            "sign_event" => Self::SignEvent,
            "ping" => Self::Ping,
            "nip04_encrypt" => Self::Nip04Encrypt,
            "nip04_decrypt" => Self::Nip04Decrypt,
            "nip44_encrypt" => Self::Nip44Encrypt,
            "nip44_decrypt" => Self::Nip44Decrypt,
            _ => Self::Other(name),
        }
    }
}

impl Serialize for Method {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// A NIP-46 RPC request — `{id, method, params}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Request {
    /// The request id the response correlates to.
    pub id: String,
    /// The RPC method.
    pub method: Method,
    /// The method arguments.
    pub params: Vec<String>,
}

impl Request {
    /// Decodes a `{id, method, params}` JSON object.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON or a wrong wire shape.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })
    }

    /// `{"id":…,"method":…,"params":…}` in field order.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A NIP-46 RPC response — `{id, result?, error?}`. Explicit JSON `null`s
/// decode as absent fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Response {
    /// The request id this answers.
    pub id: String,
    /// The result payload, when the call succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The error payload, when the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// Decodes an `{id, result?, error?}` JSON object; explicit `null`s are
    /// absent fields.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON or a wrong wire shape.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })
    }

    /// `{"id":…,"result":…,"error":…}` in field order — absent options are
    /// omitted, never `null`.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::format;
    use alloc::vec;
    use core::error::Error as _;

    use super::*;

    const PK: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn pubkey() -> PublicKey {
        PublicKey::from_hex(PK).unwrap()
    }

    #[test]
    fn bunker_uri_round_trip() {
        let uri = BunkerUri {
            remote_signer: pubkey(),
            relays: vec![
                String::from("wss://relay.one"),
                String::from("wss://relay.two/path?x=1"),
            ],
            secret: Some(String::from("s e c r e t")),
        };
        let encoded = uri.to_string();
        assert_eq!(
            encoded,
            "bunker://3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d?\
relay=wss%3A%2F%2Frelay.one&relay=wss%3A%2F%2Frelay.two%2Fpath%3Fx%3D1&secret=s+e+c+r+e+t"
        );
        assert_eq!(encoded.parse::<BunkerUri>().unwrap(), uri);
    }

    #[test]
    fn bunker_parse_variants() {
        // Uppercase hex, empty-secret pair, and whitespace padding.
        let upper = PK.to_uppercase();
        let parsed = format!("  bunker://{upper}?secret=  ")
            .parse::<BunkerUri>()
            .unwrap();
        assert_eq!(
            parsed,
            BunkerUri {
                remote_signer: pubkey(),
                relays: Vec::new(),
                secret: Some(String::new()),
            }
        );
        // Non-bunker schemes and malformed input.
        assert!(matches!(
            "nostrconnect://x".parse::<BunkerUri>(),
            Err(Error::UnexpectedScheme { expected: "bunker" })
        ));
        assert!(matches!(
            "alice@example.com".parse::<BunkerUri>(),
            Err(Error::InvalidUri { .. })
        ));
        assert!(matches!(
            format!("bunker://{PK}@evil").parse::<BunkerUri>(),
            Err(Error::InvalidPublicKey)
        ));
        // Opaque-path fallback: `bunker://` without an authority.
        let path_form = format!("bunker:{PK}");
        assert!(path_form.parse::<BunkerUri>().is_ok());
    }

    #[test]
    fn nostrconnect_uri_round_trip() {
        let uri = NostrConnectUri::new(
            pubkey(),
            vec![String::from("wss://relay.damus.io")],
            String::from("hunter2"),
        )
        .unwrap()
        .with_perms([String::from("nip44_encrypt"), String::from("sign_event")])
        .with_name("My App")
        .with_url("https://my.app/");
        let encoded = uri.to_string();
        assert_eq!(
            encoded,
            "nostrconnect://3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d?\
relay=wss%3A%2F%2Frelay.damus.io&secret=hunter2&perms=nip44_encrypt%2Csign_event&name=My+App&url=https%3A%2F%2Fmy.app%2F"
        );
        let parsed = encoded.parse::<NostrConnectUri>().unwrap();
        assert_eq!(parsed, uri);
        assert_eq!(parsed.client(), pubkey());
        assert_eq!(parsed.secret(), "hunter2");
        assert_eq!(parsed.name(), Some("My App"));
        assert_eq!(parsed.url(), Some("https://my.app/"));
        assert_eq!(parsed.image(), None);
    }

    #[test]
    fn nostrconnect_new_rejects_empty_invariants() {
        assert!(matches!(
            NostrConnectUri::new(pubkey(), vec![String::from("wss://r")], String::new()),
            Err(Error::MissingSecret)
        ));
        assert!(matches!(
            NostrConnectUri::new(pubkey(), Vec::new(), String::from("s")),
            Err(Error::MissingRelays)
        ));
    }

    #[test]
    fn nostrconnect_parse_errors() {
        let base = |tail: &str| format!("nostrconnect://{PK}?{tail}");
        let inputs = [
            "not a uri",
            "https://x",
            "nostrconnect://xyz?secret=s&relay=r",
            &base("relay=r"),
            &base("secret=&relay=r"),
            &base("secret=s"),
        ];
        let checks: [fn(&Error) -> bool; 6] = [
            |e| matches!(e, Error::InvalidUri { .. }),
            |e| {
                matches!(
                    e,
                    Error::UnexpectedScheme {
                        expected: "nostrconnect"
                    }
                )
            },
            |e| matches!(e, Error::InvalidPublicKey),
            |e| matches!(e, Error::MissingSecret),
            |e| matches!(e, Error::MissingSecret),
            |e| matches!(e, Error::MissingRelays),
        ];
        for (input, check) in inputs.iter().zip(checks) {
            let err = input.parse::<NostrConnectUri>().unwrap_err();
            assert!(check(&err), "{input}: {err}");
            // N11: the URI (which may carry the secret) is never echoed.
            let text = err.to_string();
            assert!(
                !text.contains("not a uri") && !text.contains("hunter"),
                "{input} leaked into the error"
            );
        }
        let err = "not a uri".parse::<NostrConnectUri>().unwrap_err();
        assert!(err.source().is_some());
    }

    #[test]
    fn nostrconnect_perms_and_metadata() {
        // `perms=` and `perms=,` both decode to an empty list; `a,,b` drops
        // the empty entry; present-but-empty `name` stays Some("").
        let uri: NostrConnectUri =
            format!("nostrconnect://{PK}?relay=r&secret=s&perms=a%2C%2Cb&name=")
                .parse()
                .unwrap();
        assert_eq!(uri.perms(), ["a", "b"]);
        assert_eq!(uri.name(), Some(""));
        assert_eq!(uri.url(), None);
        assert_eq!(uri.image(), None);
        let empty: NostrConnectUri = format!("nostrconnect://{PK}?relay=r&secret=s&perms=%2C")
            .parse()
            .unwrap();
        assert_eq!(empty.perms(), Vec::<String>::new());
    }

    #[test]
    fn method_wire_strings() {
        let cases = [
            (Method::Connect, "connect"),
            (Method::GetPublicKey, "get_public_key"),
            (Method::SignEvent, "sign_event"),
            (Method::Ping, "ping"),
            (Method::Nip04Encrypt, "nip04_encrypt"),
            (Method::Nip04Decrypt, "nip04_decrypt"),
            (Method::Nip44Encrypt, "nip44_encrypt"),
            (Method::Nip44Decrypt, "nip44_decrypt"),
        ];
        for (method, name) in cases {
            assert_eq!(method.as_str(), name);
            let json = serde_json::to_string(&method).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            let decoded: Method = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, method);
        }
        // Unknown names round-trip through `Other`.
        let decoded: Method = serde_json::from_str("\"weird\"").unwrap();
        assert_eq!(decoded, Method::Other(String::from("weird")));
        assert_eq!(
            serde_json::to_string(&Method::Other(String::from("weird"))).unwrap(),
            "\"weird\""
        );
    }

    #[test]
    fn request_json_round_trip() {
        let request = Request {
            id: String::from("1"),
            method: Method::SignEvent,
            params: vec![String::from("{\"kind\":1}")],
        };
        let json = request.to_json();
        assert_eq!(
            json,
            r#"{"id":"1","method":"sign_event","params":["{\"kind\":1}"]}"#
        );
        assert_eq!(Request::from_json(&json).unwrap(), request);
        // Unknown methods decode through `Other`.
        let weird = Request::from_json(r#"{"id":"2","method":"weird","params":[]}"#).unwrap();
        assert_eq!(weird.method, Method::Other(String::from("weird")));
    }

    #[test]
    fn request_json_errors() {
        let cases = [
            "{",
            // serde_json rejects lone-surrogate escapes; that is a strict-JSON difference.
            r#"{"id":"\ud800","method":"m","params":[]}"#,
            "[]",
            r#"{"id":1,"method":"m","params":[]}"#,
            r#"{"id":"i","method":"m"}"#,
            r#"{"id":"i","method":"m","params":[1]}"#,
        ];
        for input in cases {
            let err = Request::from_json(input).unwrap_err();
            assert!(matches!(err, Error::InvalidJson { .. }), "{input}");
            assert!(err.source().is_some(), "{input}");
        }
    }

    #[test]
    fn response_json_round_trip_and_nulls() {
        // Explicit nulls decode as absent; to_json omits absent fields.
        let response = Response::from_json(r#"{"id":"r","result":null,"error":null}"#).unwrap();
        assert_eq!(
            response,
            Response {
                id: String::from("r"),
                result: None,
                error: None,
            }
        );
        assert_eq!(response.to_json(), r#"{"id":"r"}"#);
        let err = Response::from_json(r#"{"id":"r","error":"denied"}"#).unwrap();
        assert_eq!(err.to_json(), r#"{"id":"r","error":"denied"}"#);
        let ok = Response::from_json(r#"{"id":"r","result":"sig"}"#).unwrap();
        assert_eq!(ok.to_json(), r#"{"id":"r","result":"sig"}"#);
    }

    #[test]
    fn response_json_errors() {
        let cases = [
            "{",
            r#"{"id":"\udfffr"}"#,
            "42",
            r#"{"id":1}"#,
            r#"{"id":"r","result":{}}"#,
            r#"{"id":"r","error":true}"#,
        ];
        for input in cases {
            let err = Response::from_json(input).unwrap_err();
            assert!(matches!(err, Error::InvalidJson { .. }), "{input}");
            assert!(err.source().is_some(), "{input}");
        }
    }
}
