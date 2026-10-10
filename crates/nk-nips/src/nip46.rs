//! NIP-46 (Nostr Connect) URI and RPC JSON codecs — the protocol half of
//! `nips/nip46.ts`. Transport, signing, and the NIP-44 channel live in the
//! signer layer (nk-signer); this module is the pure codec.
//!
//! [`BunkerUri`] is the `bunker://` pointer a remote signer publishes;
//! [`NostrConnectUri`] is the client-initiated `nostrconnect://` URI. Both are
//! parsed through the WHATWG [`url`] crate — the same spec as JS `URL` — and
//! query pairs go through its `form_urlencoded` (`URLSearchParams`). The RPC
//! payloads are [`Request`]/[`Response`] over `serde_json`; lone-surrogate
//! escapes are rejected at parse like `serde_json` does (N10), and errors
//! never echo the input (N11).
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/46.md>

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use nk_core::PublicKey;
use serde::Serialize;
use url::Url;
use url::form_urlencoded::Serializer;

use crate::error::{Error, ErrorKind, Result};
use crate::util::trim_js;

fn nip46(message: impl Into<Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Nip46, message)
}

fn nip46_source(
    message: &'static str,
    source: impl core::error::Error + Send + Sync + 'static,
) -> Error {
    Error::with_source(ErrorKind::Nip46, message, source)
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
    pub pubkey: PublicKey,
    /// `relay` query values, decoded and in order.
    pub relays: Vec<String>,
    /// `secret` query value (`None` when absent; a present-but-empty
    /// `secret=` stays `Some("")` like `URLSearchParams.get`).
    pub secret: Option<String>,
}

impl BunkerUri {
    /// Parses a `bunker://` URI — TS `parseBunkerURL`. `None` when the input
    /// is not a bunker URI (including NIP-05 identifiers) or the authority is
    /// not a 64-hex public key.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let url = Url::parse(trim_js(input)).ok()?;
        if url.scheme() != "bunker" {
            return None;
        }
        // isHex32(pubkey.toLowerCase()) — any-case 64-hex is accepted.
        let pubkey = PublicKey::from_hex(authority_or_path(&url)).ok()?;
        let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = url.query_pairs().collect();
        Some(Self {
            pubkey,
            relays: query_get_all(&pairs, "relay"),
            secret: query_get(&pairs, "secret").map(String::from),
        })
    }
}

impl fmt::Display for BunkerUri {
    /// TS `toBunkerURL`: `bunker://<lowercase pubkey>` plus the `relay` pairs
    /// in order and a non-empty `secret`, application/x-www-form-urlencoded.
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
            write!(f, "bunker://{}", self.pubkey)
        } else {
            write!(f, "bunker://{}?{query}", self.pubkey)
        }
    }
}

/// A `nostrconnect://` URI — the client's public key, its relays, the
/// handshake secret, and optional metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NostrConnectUri {
    /// The client's public key.
    pub client_pubkey: PublicKey,
    /// `relay` query values, decoded and in order.
    pub relays: Vec<String>,
    /// The handshake `secret` — required and non-empty.
    pub secret: String,
    /// `perms` split on `,` with empty entries dropped; absent and
    /// `perms=`/`perms=,` all decode to `[]`.
    pub perms: Vec<String>,
    /// Client metadata `name` (kept verbatim when present, even empty).
    pub name: Option<String>,
    /// Client metadata `url`.
    pub url: Option<String>,
    /// Client metadata `image`.
    pub image: Option<String>,
}

impl NostrConnectUri {
    /// Parses a `nostrconnect://` URI — TS `parseNostrConnectURI`, same error
    /// messages. The input is never echoed (N11).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip46`]: `invalid nostrconnect URI` when the URL does not
    /// parse, `expected nostrconnect: scheme, got <scheme>` on another
    /// scheme, `invalid client pubkey in nostrconnect URI` when the authority
    /// is not 64-hex, `missing secret in nostrconnect URI` for an absent or
    /// empty `secret`, and `missing relays in nostrconnect URI` for zero
    /// `relay` pairs.
    pub fn parse(uri: &str) -> Result<Self> {
        let url = Url::parse(uri).map_err(|e| nip46_source("invalid nostrconnect URI", e))?;
        if url.scheme() != "nostrconnect" {
            return Err(nip46(alloc::format!(
                "expected nostrconnect: scheme, got {}:",
                url.scheme()
            )));
        }
        let client_pubkey = PublicKey::from_hex(authority_or_path(&url))
            .map_err(|_| nip46("invalid client pubkey in nostrconnect URI"))?;
        let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = url.query_pairs().collect();
        let secret = query_get(&pairs, "secret").filter(|s| !s.is_empty());
        let Some(secret) = secret else {
            return Err(nip46("missing secret in nostrconnect URI"));
        };
        let relays = query_get_all(&pairs, "relay");
        if relays.is_empty() {
            return Err(nip46("missing relays in nostrconnect URI"));
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
            client_pubkey,
            relays,
            secret: String::from(secret),
            perms,
            name: query_get(&pairs, "name").map(String::from),
            url: query_get(&pairs, "url").map(String::from),
            image: query_get(&pairs, "image").map(String::from),
        })
    }

    /// Serializes back to a `nostrconnect://` URI — TS `createNostrConnectURI`
    /// over a typed value. Absent-or-empty `name`/`url`/`image` and an empty
    /// `perms` are omitted; `perms` are re-joined on `,`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip46`]: `nostrconnect secret is required` for an empty
    /// secret, `at least one relay is required` for empty relays.
    pub fn to_uri(&self) -> Result<String> {
        if self.secret.is_empty() {
            return Err(nip46("nostrconnect secret is required"));
        }
        if self.relays.is_empty() {
            return Err(nip46("at least one relay is required"));
        }
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
        Ok(alloc::format!(
            "nostrconnect://{}?{}",
            self.client_pubkey,
            serializer.finish()
        ))
    }
}

/// A NIP-46 RPC request — `{id, method, params}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The request id the response correlates to.
    pub id: String,
    /// The RPC method (`connect`, `sign_event`, …).
    pub method: String,
    /// The method arguments.
    pub params: Vec<String>,
}

impl Request {
    /// `JSON.stringify({id, method, params})` in field order.
    #[must_use]
    pub fn to_json(&self) -> String {
        /// Field order is the wire order — serde emits declared order.
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            method: &'a str,
            params: &'a [String],
        }
        serde_json::to_string(&Wire {
            id: &self.id,
            method: &self.method,
            params: &self.params,
        })
        .unwrap_or_default()
    }

    /// `JSON.parse` plus the TS shape checks — `serde_json` also rejects the
    /// lone-surrogate escapes `JSON.parse` accepts (N10).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip46`]: `invalid NIP-46 request JSON` on malformed JSON,
    /// `invalid NIP-46 request shape` when the value is not an object with
    /// string `id`/`method`, `invalid NIP-46 request params` when `params` is
    /// not an array of strings.
    pub fn from_json(json: &str) -> Result<Self> {
        let data: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| nip46_source("invalid NIP-46 request JSON", e))?;
        let Some(object) = data.as_object() else {
            return Err(nip46("invalid NIP-46 request shape"));
        };
        let (Some(id), Some(method)) = (
            object.get("id").and_then(serde_json::Value::as_str),
            object.get("method").and_then(serde_json::Value::as_str),
        ) else {
            return Err(nip46("invalid NIP-46 request shape"));
        };
        let Some(params) = object.get("params").and_then(serde_json::Value::as_array) else {
            return Err(nip46("invalid NIP-46 request params"));
        };
        let mut strings = Vec::with_capacity(params.len());
        for param in params {
            let Some(param) = param.as_str() else {
                return Err(nip46("invalid NIP-46 request params"));
            };
            strings.push(String::from(param));
        }
        Ok(Self {
            id: String::from(id),
            method: String::from(method),
            params: strings,
        })
    }
}

/// A NIP-46 RPC response — `{id, result?, error?}`. Explicit JSON `null`s are
/// absent fields, matching TS `decodeNip46Response`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Response {
    /// The request id this answers.
    pub id: String,
    /// The result payload, when the call succeeded.
    pub result: Option<String>,
    /// The error payload, when the call failed.
    pub error: Option<String>,
}

impl Response {
    /// `JSON.stringify` of `{id, result?, error?}` in field order — absent
    /// options are omitted, never `null`.
    #[must_use]
    pub fn to_json(&self) -> String {
        /// Field order is the wire order — serde emits declared order.
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            result: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<&'a str>,
        }
        serde_json::to_string(&Wire {
            id: &self.id,
            result: self.result.as_deref(),
            error: self.error.as_deref(),
        })
        .unwrap_or_default()
    }

    /// `JSON.parse` plus the TS shape checks — explicit `null` result/error
    /// decode as absent (N10: lone surrogates reject at the parse stage).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip46`]: `invalid NIP-46 response JSON` on malformed JSON,
    /// `invalid NIP-46 response shape` when the value is not an object with a
    /// string `id`, `invalid NIP-46 response result`/`… error` when present
    /// fields are neither strings nor `null`.
    pub fn from_json(json: &str) -> Result<Self> {
        let data: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| nip46_source("invalid NIP-46 response JSON", e))?;
        let Some(object) = data.as_object() else {
            return Err(nip46("invalid NIP-46 response shape"));
        };
        let Some(id) = object.get("id").and_then(serde_json::Value::as_str) else {
            return Err(nip46("invalid NIP-46 response shape"));
        };
        let result = response_field(object, "result")?;
        let error = response_field(object, "error")?;
        Ok(Self {
            id: String::from(id),
            result,
            error,
        })
    }
}

/// One optional `result`/`error` field: absent or `null` → `None`, a string →
/// `Some`, anything else → `invalid NIP-46 response <field>`.
fn response_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(nip46(alloc::format!("invalid NIP-46 response {field}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn nip46_err(result: Result<impl Sized>) -> Error {
        result.err().expect("expected a NIP-46 error")
    }

    #[test]
    fn bunker_uri_round_trip() {
        let uri = BunkerUri {
            pubkey: PublicKey::from_hex(PK).unwrap(),
            relays: alloc::vec![
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
        assert_eq!(BunkerUri::parse(&encoded), Some(uri));
    }

    #[test]
    fn bunker_parse_variants() {
        // Uppercase hex, empty-secret pair, and whitespace padding — `trim()`
        // and the `toLowerCase`/`isHex32` gate.
        let upper = PK.to_uppercase();
        assert_eq!(
            BunkerUri::parse(&alloc::format!("  bunker://{upper}?secret=  ")),
            Some(BunkerUri {
                pubkey: PublicKey::from_hex(PK).unwrap(),
                relays: Vec::new(),
                secret: Some(String::new()),
            })
        );
        // Non-bunker schemes and NIP-05 identifiers are not bunker URIs.
        assert_eq!(BunkerUri::parse("nostrconnect://x"), None);
        assert_eq!(BunkerUri::parse("alice@example.com"), None);
        assert_eq!(
            BunkerUri::parse(&alloc::format!("bunker://{PK}@evil")),
            None
        );
        // Opaque-path fallback: `bunker://` without an authority.
        let path_form = alloc::format!("bunker:{PK}");
        assert!(BunkerUri::parse(&path_form).is_some());
    }

    #[test]
    fn nostrconnect_uri_round_trip() {
        let uri = NostrConnectUri {
            client_pubkey: PublicKey::from_hex(PK).unwrap(),
            relays: alloc::vec![String::from("wss://relay.damus.io")],
            secret: String::from("hunter2"),
            perms: alloc::vec![String::from("nip44_encrypt"), String::from("sign_event")],
            name: Some(String::from("My App")),
            url: Some(String::from("https://my.app/")),
            image: None,
        };
        let encoded = uri.to_uri().unwrap();
        assert_eq!(
            encoded,
            "nostrconnect://3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d?\
relay=wss%3A%2F%2Frelay.damus.io&secret=hunter2&perms=nip44_encrypt%2Csign_event&name=My+App&url=https%3A%2F%2Fmy.app%2F"
        );
        assert_eq!(NostrConnectUri::parse(&encoded).unwrap(), uri);
    }

    #[test]
    fn nostrconnect_parse_errors() {
        let base = |tail: &str| alloc::format!("nostrconnect://{PK}?{tail}");
        let cases = [
            ("not a uri", "invalid nostrconnect URI"),
            ("https://x", "expected nostrconnect: scheme, got https:"),
            (
                "nostrconnect://xyz?secret=s&relay=r",
                "invalid client pubkey in nostrconnect URI",
            ),
            (&base("relay=r"), "missing secret in nostrconnect URI"),
            (
                &base("secret=&relay=r"),
                "missing secret in nostrconnect URI",
            ),
            (&base("secret=s"), "missing relays in nostrconnect URI"),
        ];
        for (input, message) in cases {
            let error = nip46_err(NostrConnectUri::parse(input));
            assert_eq!(error.kind(), ErrorKind::Nip46);
            assert_eq!(
                error.to_string(),
                alloc::format!("nip46: {message}"),
                "{input}"
            );
            // N11: the URI (which may carry the secret) is never echoed.
            assert!(
                !error.to_string().contains("not a uri"),
                "{input} leaked into the error"
            );
        }
    }

    #[test]
    fn nostrconnect_perms_and_metadata() {
        // `perms=` and `perms=,` both decode to an empty list; `a,,b` drops
        // the empty entry; present-but-empty `name` stays Some("").
        let uri = NostrConnectUri::parse(&alloc::format!(
            "nostrconnect://{PK}?relay=r&secret=s&perms=a%2C%2Cb&name="
        ))
        .unwrap();
        assert_eq!(uri.perms, alloc::vec![String::from("a"), String::from("b")]);
        assert_eq!(uri.name, Some(String::new()));
        assert_eq!(uri.url, None);
        assert_eq!(uri.image, None);
        let empty = NostrConnectUri::parse(&alloc::format!(
            "nostrconnect://{PK}?relay=r&secret=s&perms=%2C"
        ))
        .unwrap();
        assert_eq!(empty.perms, Vec::<String>::new());
    }

    #[test]
    fn request_json_round_trip() {
        let request = Request {
            id: String::from("1"),
            method: String::from("sign_event"),
            params: alloc::vec![String::from("{\"kind\":1}")],
        };
        let json = request.to_json();
        assert_eq!(
            json,
            r#"{"id":"1","method":"sign_event","params":["{\"kind\":1}"]}"#
        );
        assert_eq!(Request::from_json(&json).unwrap(), request);
    }

    #[test]
    fn request_json_errors() {
        let cases = [
            ("{", "invalid NIP-46 request JSON"),
            // serde_json rejects the lone-surrogate escapes JSON.parse takes.
            (
                r#"{"id":"\ud800","method":"m","params":[]}"#,
                "invalid NIP-46 request JSON",
            ),
            ("[]", "invalid NIP-46 request shape"),
            (
                r#"{"id":1,"method":"m","params":[]}"#,
                "invalid NIP-46 request shape",
            ),
            (
                r#"{"id":"i","method":"m"}"#,
                "invalid NIP-46 request params",
            ),
            (
                r#"{"id":"i","method":"m","params":[1]}"#,
                "invalid NIP-46 request params",
            ),
        ];
        for (input, message) in cases {
            let error = nip46_err(Request::from_json(input));
            assert_eq!(error.kind(), ErrorKind::Nip46);
            assert_eq!(
                error.to_string(),
                alloc::format!("nip46: {message}"),
                "{input}"
            );
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
            ("{", "invalid NIP-46 response JSON"),
            (r#"{"id":"\udfffr"}"#, "invalid NIP-46 response JSON"),
            ("42", "invalid NIP-46 response shape"),
            (r#"{"id":1}"#, "invalid NIP-46 response shape"),
            (
                r#"{"id":"r","result":{}}"#,
                "invalid NIP-46 response result",
            ),
            (
                r#"{"id":"r","error":true}"#,
                "invalid NIP-46 response error",
            ),
        ];
        for (input, message) in cases {
            let error = nip46_err(Response::from_json(input));
            assert_eq!(error.kind(), ErrorKind::Nip46);
            assert_eq!(
                error.to_string(),
                alloc::format!("nip46: {message}"),
                "{input}"
            );
        }
    }
}
