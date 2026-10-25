//! Blossom (BUD-01/02/04/06 + NIP-B7) codecs — `nips/blossom.ts`'s
//! sans-IO half. Transport lives in `nk`'s `http` module.
//!
//! Blob hashes, normalized server URLs, auth templates (kind `24242`,
//! not NIP-98), the `Nostr `+base64url authorization header, blob
//! descriptors and kind `10063` server lists.
//!
//! @see <https://github.com/hzrd149/blossom>

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use sha2::Digest;

use crate::event::{Event, EventBuilder, Kind, Tag, Tags};
use crate::hex;
use crate::nips::util::trim_js;
use crate::{JsonError, Timestamp};

/// Errors produced by the Blossom codecs.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[allow(
    variant_size_differences,
    reason = "the JsonError source is a cold error path"
)]
pub enum Error {
    /// The input is not 64 hex characters.
    #[error("invalid blob sha256")]
    InvalidHash,
    /// The string is not an `http(s)` URL.
    #[error("invalid blossom server URL")]
    InvalidServer,
    /// The auth message is empty or whitespace-only.
    #[error("blossom auth message must not be empty")]
    EmptyMessage,
    /// No usable `http(s)` server URL was given.
    #[error("server list requires at least one valid http(s) URL")]
    NoServers,
    /// A server-list event carries the wrong kind.
    #[error("expected kind {expected}, got {found}")]
    WrongKind {
        /// The expected kind.
        expected: u16,
        /// The kind actually present.
        found: u16,
    },
    /// The input is not valid JSON.
    #[error("invalid blossom JSON")]
    InvalidJson {
        /// The parser failure.
        #[source]
        source: JsonError,
    },
    /// The descriptor is not a JSON object.
    #[error("invalid blob descriptor")]
    NotAnObject,
    /// The descriptor's `url` is absent or empty.
    #[error("blob descriptor missing url")]
    MissingUrl,
    /// The descriptor's `sha256` is absent or not 64-hex.
    #[error("blob descriptor missing sha256")]
    MissingHash,
    /// The descriptor's `size` is absent or not a non-negative integer.
    #[error("blob descriptor missing size")]
    MissingSize,
    /// A list response is not a JSON array.
    #[error("blossom list response must be a JSON array")]
    NotAnArray,
}

/// A blob's SHA-256 — the `x` tag's value and the last 64-hex run of a
/// blob URL.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobHash([u8; 32]);

impl BlobHash {
    /// SHA-256 of `data`.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        Self(sha2::Sha256::digest(data).into())
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The last 64-hex run of `url`'s path, lowercased — TS
    /// `getHashFromURL`. `None` when `url` does not parse or carries
    /// no hash (query strings do not count).
    #[must_use]
    pub fn from_url(url: &str) -> Option<Self> {
        let parsed = url::Url::parse(url).ok()?;
        let mut last = None;
        // Regex `[0-9a-f]{64}` semantics: non-overlapping matches from
        // each run's start — a run contributes its last complete
        // 64-char block.
        for run in parsed.path().split(|b: char| !b.is_ascii_hexdigit()) {
            let Some(last_block) = (run.len() / 64).checked_sub(1).map(|n| n * 64) else {
                continue;
            };
            if let Some(block) = run.get(last_block..last_block + 64) {
                last = Self::from_str(block).ok();
            }
        }
        last
    }
}

impl FromStr for BlobHash {
    type Err = Error;

    /// 64-char hex, any case.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHash`] on any other shape.
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(Self(hex::decode_caller(s).map_err(|_| Error::InvalidHash)?))
    }
}

impl fmt::Display for BlobHash {
    /// Lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// A normalized Blossom server base URL: `http(s)://host[:port][/path]`
/// with trailing slashes stripped — TS `parseHttpUrl`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Server(String);

impl Server {
    /// The normalized base.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `base + path` — TS `blossomUrl`. A `path` prefix on the base is
    /// kept (`/api/upload`).
    #[must_use]
    pub fn endpoint(&self, path: &str) -> String {
        alloc::format!("{}/{}", self.0, path.strip_prefix('/').unwrap_or(path))
    }

    /// `{base}/{hash}{extension}` — the blob's fetch URL.
    #[must_use]
    pub fn blob_url(&self, hash: &BlobHash, extension: &str) -> String {
        alloc::format!("{}/{}{}", self.0, hash, extension)
    }
}

impl FromStr for Server {
    type Err = Error;

    /// `http`/`https` URL → `origin + path` without trailing slashes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidServer`] when `raw` does not parse or carries a
    /// non-HTTP scheme.
    fn from_str(raw: &str) -> Result<Self, Error> {
        let url = url::Url::parse(raw).map_err(|_| Error::InvalidServer)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::InvalidServer);
        }
        let mut base = url.origin().ascii_serialization();
        base.push_str(url.path().trim_end_matches('/'));
        Ok(Self(base))
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// BUD-11 `t` verbs. Mirror reuses `upload`; there is no `t=mirror`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthVerb {
    /// `upload`.
    Upload,
    /// `delete`.
    Delete,
    /// `list`.
    List,
    /// `get`.
    Get,
    /// `media`.
    Media,
}

impl AuthVerb {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Get => "get",
            Self::Media => "media",
        }
    }

    /// BUD-11's default human-readable content.
    #[must_use]
    pub const fn default_message(self) -> &'static str {
        match self {
            Self::Upload => "Upload Blob",
            Self::Delete => "Delete Blob",
            Self::List => "List Blobs",
            Self::Get => "Get Blob",
            Self::Media => "Upload Media",
        }
    }
}

/// A kind `24242` auth template (draft — pubkey comes from the signer).
/// The expiration is explicit: nk-core has no clock.
#[derive(Clone, Debug)]
pub struct Authorization {
    verb: AuthVerb,
    expiration: Timestamp,
    blob: Option<BlobHash>,
    message: Option<String>,
    servers: Vec<String>,
}

/// Hostname for a BUD-11 `server` tag: full URL or bare domain,
/// lowercased — TS `serverHostname`.
fn server_hostname(raw: &str) -> Option<String> {
    let owned;
    let raw = if raw.contains("://") {
        raw
    } else {
        owned = alloc::format!("https://{raw}");
        owned.as_str()
    };
    let url = url::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let hostname = url.host_str()?.to_lowercase();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

impl Authorization {
    /// A template for `verb` expiring at `expiration` (unix seconds).
    #[must_use]
    pub const fn new(verb: AuthVerb, expiration: Timestamp) -> Self {
        Self {
            verb,
            expiration,
            blob: None,
            message: None,
            servers: Vec::new(),
        }
    }

    /// Adds the `x` tag for `hash`.
    #[must_use]
    pub const fn blob(mut self, hash: BlobHash) -> Self {
        self.blob = Some(hash);
        self
    }

    /// Overrides the default human-readable content.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyMessage`] when `message` is empty or whitespace.
    pub fn message(mut self, message: impl Into<String>) -> Result<Self, Error> {
        let message = message.into();
        if trim_js(&message).is_empty() {
            return Err(Error::EmptyMessage);
        }
        self.message = Some(message);
        Ok(self)
    }

    /// Adds `server` tags: each entry's lowercase hostname (a full URL
    /// or a bare domain), first-seen deduped, invalid entries skipped.
    #[must_use]
    pub fn servers<S: AsRef<str>>(mut self, servers: impl IntoIterator<Item = S>) -> Self {
        let mut seen: BTreeSet<String> = self.servers.iter().cloned().collect();
        for raw in servers {
            if let Some(hostname) = server_hostname(raw.as_ref())
                && seen.insert(hostname.clone())
            {
                self.servers.push(hostname);
            }
        }
        self
    }
}

impl From<Authorization> for EventBuilder {
    /// The kind `24242` template: `t`, `expiration`, optional `x`,
    /// `server`×n in TS order; content is the message or the verb's
    /// default.
    fn from(auth: Authorization) -> Self {
        let mut tags = alloc::vec![
            Tag::custom("t", [auth.verb.as_str()]),
            Tag::custom("expiration", [auth.expiration.as_secs().to_string()]),
        ];
        if let Some(hash) = auth.blob {
            tags.push(Tag::custom("x", [hash.to_string()]));
        }
        for server in &auth.servers {
            tags.push(Tag::custom("server", [server.as_str()]));
        }
        let content = auth
            .message
            .unwrap_or_else(|| String::from(auth.verb.default_message()));
        Self::new(Kind::BLOBS_AUTH, content).tags(tags)
    }
}

/// The `Nostr ` authorization header of a signed event: `Nostr ` +
/// base64url **without padding** of the event JSON — BUD-02, not
/// NIP-98's standard base64.
#[must_use]
pub fn authorization_header(event: &Event) -> String {
    alloc::format!(
        "Nostr {}",
        Base64UrlUnpadded::encode_string(event.to_json().as_bytes())
    )
}

/// A BUD-01/02/04 blob descriptor — one server's record of a blob.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobDescriptor {
    /// Where the blob is served.
    pub url: String,
    /// The blob's SHA-256.
    pub sha256: BlobHash,
    /// Size in bytes.
    pub size: u64,
    /// The blob's MIME `type`, when present.
    pub mime_type: Option<String>,
    /// Upload time, when present.
    pub uploaded: Option<Timestamp>,
}

impl BlobDescriptor {
    /// Parses one descriptor with the TS rules: `url`, `sha256`,
    /// `size` are required; wrong-typed `type`/`uploaded` are dropped.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON;
    /// [`Error::NotAnObject`], [`Error::MissingUrl`],
    /// [`Error::MissingHash`], [`Error::MissingSize`] on the required
    /// fields.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let value: Value =
            serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })?;
        Self::from_value(&value)
    }

    /// A `list` response body: a JSON array where **every** element is
    /// a descriptor — TS `listBlobs`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on malformed JSON;
    /// [`Error::NotAnArray`] on a non-array top level; the descriptor
    /// errors on any element.
    pub fn list_from_json(json: &str) -> Result<Vec<Self>, Error> {
        let value: Value =
            serde_json::from_str(json).map_err(|e| Error::InvalidJson { source: e.into() })?;
        let items = value.as_array().ok_or(Error::NotAnArray)?;
        items.iter().map(Self::from_value).collect()
    }

    /// BUD-04 mirror request body: `{"url":…}`.
    #[must_use]
    pub fn mirror_body(&self) -> String {
        serde_json::json!({ "url": self.url }).to_string()
    }

    /// One JSON value → descriptor (the shared validation).
    fn from_value(value: &Value) -> Result<Self, Error> {
        let object = value.as_object().ok_or(Error::NotAnObject)?;
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(Error::MissingUrl)?;
        let sha256 = object
            .get("sha256")
            .and_then(Value::as_str)
            .and_then(|s| BlobHash::from_str(s).ok())
            .ok_or(Error::MissingHash)?;
        let size = object
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(Error::MissingSize)?;
        let mime_type = object.get("type").and_then(Value::as_str).map(String::from);
        let uploaded = object
            .get("uploaded")
            .and_then(Value::as_u64)
            .map(Timestamp::from_secs);
        Ok(Self {
            url: String::from(url),
            sha256,
            size,
            mime_type,
            uploaded,
        })
    }
}

/// A parsed NIP-B7 kind `10063` server list — normalized `http(s)`
/// base URLs, first-seen deduplicated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ServerList {
    servers: Vec<Server>,
}

impl ServerList {
    /// Builds a list from raw strings: each is normalized like
    /// [`Server::from_str`], invalid entries skipped, results
    /// first-seen deduplicated — TS `blossomServerListEventBuilder`.
    ///
    /// # Errors
    ///
    /// [`Error::NoServers`] when nothing valid remains.
    pub fn new<S: AsRef<str>>(servers: impl IntoIterator<Item = S>) -> Result<Self, Error> {
        let mut list = Self::default();
        for raw in servers {
            if let Ok(server) = Server::from_str(raw.as_ref())
                && !list.servers.contains(&server)
            {
                list.servers.push(server);
            }
        }
        if list.servers.is_empty() {
            return Err(Error::NoServers);
        }
        Ok(list)
    }

    /// The normalized servers, first-seen order.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }
}

impl TryFrom<&Event> for ServerList {
    type Error = Error;

    /// Parses a kind `10063` event: each `["server", <url>]` tag's
    /// value is normalized like [`Server::from_str`] (invalid or empty
    /// entries skipped, first-seen dedup).
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] — the event is not a server list.
    fn try_from(event: &Event) -> Result<Self, Error> {
        if event.kind() != Kind::BLOSSOM_SERVER_LIST {
            return Err(Error::WrongKind {
                expected: Kind::BLOSSOM_SERVER_LIST.as_u16(),
                found: event.kind().as_u16(),
            });
        }
        let mut list = Self::default();
        for tag in event.tags() {
            let Some(value) = tag
                .value()
                .filter(|v| tag.name() == "server" && !v.is_empty())
            else {
                continue;
            };
            if let Ok(server) = Server::from_str(value)
                && !list.servers.contains(&server)
            {
                list.servers.push(server);
            }
        }
        Ok(list)
    }
}

impl From<ServerList> for EventBuilder {
    /// Builds an unsigned kind `10063` template — one `server` tag per
    /// entry.
    fn from(list: ServerList) -> Self {
        let tags: Tags = list
            .servers
            .iter()
            .map(|s| Tag::custom("server", [s.as_str()]))
            .collect();
        Self::new(Kind::BLOSSOM_SERVER_LIST, "").tags(tags)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use super::*;

    const PK: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn hash_display_round_trips() {
        let hash = BlobHash::from_str(&PK.to_uppercase()).unwrap();
        assert_eq!(hash.to_string(), PK);
        assert_eq!(
            BlobHash::of(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn from_url_last_run_wins() {
        let hash = BlobHash::from_url(&alloc::format!("https://x/aaa/{PK}.png")).unwrap();
        assert_eq!(hash.to_string(), PK);
        assert!(BlobHash::from_url("not a url").is_none());
        assert!(BlobHash::from_url("https://x/nohash").is_none());
    }

    #[test]
    fn server_normalizes() {
        let server = "https://cdn.example.com/api/".parse::<Server>().unwrap();
        assert_eq!(server.as_str(), "https://cdn.example.com/api");
        assert_eq!(
            server.endpoint("/upload"),
            "https://cdn.example.com/api/upload"
        );
        assert!("wss://x.example".parse::<Server>().is_err());
    }

    #[test]
    fn auth_template_ts_order() {
        let auth = Authorization::new(AuthVerb::Upload, Timestamp::from_secs(1_700_000_000))
            .blob(BlobHash::from_str(PK).unwrap())
            .servers(["https://a.example.com", "A.EXAMPLE.COM", "ftp://b.com"]);
        let template = EventBuilder::from(auth);
        // t, expiration, x, server — TS order.
        let unsigned = template.build_at(
            crate::PublicKey::from_hex(PK).unwrap(),
            Timestamp::from_secs(1_700_000_000),
        );
        let names: Vec<&str> = unsigned.tags().iter().map(Tag::name).collect();
        assert_eq!(names, ["t", "expiration", "x", "server"]);
    }

    #[test]
    fn auth_message_validation() {
        let auth = Authorization::new(AuthVerb::Get, Timestamp::from_secs(0));
        assert!(matches!(
            auth.clone().message("   "),
            Err(Error::EmptyMessage)
        ));
        assert!(auth.message("hey").is_ok());
    }
}
