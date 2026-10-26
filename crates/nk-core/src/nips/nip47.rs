//! NIP-47 Nostr Wallet Connect, client side: `nostr+walletconnect://` URI parsing, kind-13194
//! info event parsing, and response-payload validation. The wallet-service side is out of scope.

use alloc::string::String;
use alloc::vec::Vec;

/// NIP-47 info event kind.
pub const INFO_KIND: u16 = 13194;
/// NIP-47 request kind.
pub const REQUEST_KIND: u16 = 23194;
/// NIP-47 response kind.
pub const RESPONSE_KIND: u16 = 23195;

/// `encryption` tag value for NIP-44 v2.
pub const ENCRYPTION_NIP44: &str = "nip44_v2";

/// The NWC client operation failed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The connection URI is malformed: bad scheme, key, secret, or relay list.
    Uri,
    /// The event is not a valid NIP-47 artifact (wrong kind or missing fields).
    Event,
    /// The decrypted payload fails validation (shape, `result_type`, amounts).
    Response,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Uri => "invalid NWC connection URI",
            Self::Event => "invalid NIP-47 event",
            Self::Response => "invalid NIP-47 response",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// `nip47` result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// A parsed `nostr+walletconnect://` connection URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwcConnection {
    /// 64-hex wallet service pubkey.
    pub wallet_pubkey: String,
    /// Relay URLs, all `wss://` (or `ws://localhost`/`127.0.0.1` for tests).
    pub relays: Vec<String>,
    /// 32-byte client secret.
    pub secret: [u8; 32],
    /// Optional lightning address.
    pub lud16: Option<String>,
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let (chunks, []) = text.as_bytes().as_chunks::<2>() else {
        return Err(Error::Uri);
    };
    if chunks.len() != 32 {
        return Err(Error::Uri);
    }
    let mut out = [0u8; 32];
    for (dst, [hi, lo]) in out.iter_mut().zip(chunks) {
        match (hex_nibble(*hi), hex_nibble(*lo)) {
            (Some(h), Some(l)) => *dst = (h << 4) | l,
            _ => return Err(Error::Uri),
        }
    }
    Ok(out)
}

/// Percent-decode a query-string value (percent-triplets only; `+` is kept — the spec's URIs
/// percent-encode every reserved character, and `+` never appears in its fields).
fn pct_decode(text: &str) -> Result<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes.next().and_then(hex_nibble).ok_or(Error::Uri)?;
            let lo = bytes.next().and_then(hex_nibble).ok_or(Error::Uri)?;
            out.push((hi << 4) | lo);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).map_err(|_| Error::Uri)
}

fn is_loopback_ws(url: &str) -> bool {
    url.starts_with("ws://localhost") || url.starts_with("ws://127.0.0.1")
}

/// Parse `nostr+walletconnect://<pubkey>?relay=wss://…&secret=<64hex>[&lud16=…]`.
///
/// # Errors
/// [`Error::Uri`] on a bad scheme, a non-64-hex pubkey/secret, an empty relay list, or a
/// relay that is neither `wss://` nor loopback `ws://`.
pub fn parse_connection_uri(uri: &str) -> Result<NwcConnection> {
    let rest = uri
        .strip_prefix("nostr+walletconnect://")
        .ok_or(Error::Uri)?;
    let (host, query) = rest.split_once('?').ok_or(Error::Uri)?;
    let wallet_pubkey = pct_decode(host)?.to_lowercase();
    hex32(&wallet_pubkey)?;
    let mut relays = Vec::new();
    let mut secret = None;
    let mut lud16 = None;
    for part in query.split('&') {
        let (key, raw) = part.split_once('=').ok_or(Error::Uri)?;
        let value = pct_decode(raw)?;
        match key {
            "relay" => {
                if !value.starts_with("wss://") && !is_loopback_ws(&value) {
                    return Err(Error::Uri);
                }
                relays.push(value);
            }
            "secret" => secret = Some(hex32(&value)?),
            "lud16" => lud16 = Some(value),
            _ => {}
        }
    }
    if relays.is_empty() {
        return Err(Error::Uri);
    }
    Ok(NwcConnection {
        wallet_pubkey,
        relays,
        secret: secret.ok_or(Error::Uri)?,
        lud16,
    })
}

/// A parsed kind-13194 info event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwcInfo {
    /// Supported method names.
    pub methods: Vec<String>,
    /// `encryption` tag entries (empty = nip04-only per spec).
    pub encryptions: Vec<String>,
    /// `extensions` tag entries.
    pub extensions: Vec<String>,
    /// Whether `nip44_v2` is offered — required by a NIP-44-only client.
    pub nip44: bool,
}

/// Parse an info event: kind must be 13194; content is the space-separated method list; the
/// `encryption` and `extensions` tags carry space-separated identifiers.
///
/// # Errors
/// [`Error::Event`] when `kind` is not 13194.
pub fn parse_info_event(kind: u16, content: &str, tags: &[(String, String)]) -> Result<NwcInfo> {
    if kind != INFO_KIND {
        return Err(Error::Event);
    }
    let split = |s: &str| -> Vec<String> { s.split_whitespace().map(String::from).collect() };
    let mut encryptions = Vec::new();
    let mut extensions = Vec::new();
    for (k, v) in tags {
        match k.as_str() {
            "encryption" => encryptions = split(v),
            "extensions" => extensions = split(v),
            _ => {}
        }
    }
    Ok(NwcInfo {
        methods: split(content),
        nip44: encryptions.iter().any(|entry| entry == ENCRYPTION_NIP44),
        encryptions,
        extensions,
    })
}

/// A decoded response outcome: success carries the `result` object, failure the error code.
///
/// Field validation checks method matching, result/error exclusivity, listed NIP-47 error
/// codes, and that msat amounts are non-negative safe integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NwcOutcome {
    /// `result` present, `error` absent — carries the result object.
    Ok(serde_json::Value),
    /// `error` present, `result` absent — carries the NIP-47 code.
    Err(String),
}

fn is_msat(value: &serde_json::Value) -> bool {
    // `as_u64` rejects floats and negatives — a `1.0`-spelled integer is non-canonical
    // JSON for amounts and is rejected, matching the vector `nonCanonicalJson` class.
    value.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991)
}

/// Validate a decrypted kind-23195 payload against its request method.
///
/// `result_type` must equal `method`, exactly one of `result`/`error` must be present,
/// `error.code` must be a listed NIP-47 code, and every `amount`/`balance`/`fees_paid`
/// field must be a non-negative safe integer.
///
/// # Errors
/// [`Error::Response`] on any violation.
pub fn decode_response_payload(method: &str, json: &str) -> Result<NwcOutcome> {
    const CODES: &[&str] = &[
        "RATE_LIMITED",
        "NOT_IMPLEMENTED",
        "INSUFFICIENT_BALANCE",
        "QUOTA_EXCEEDED",
        "RESTRICTED",
        "UNAUTHORIZED",
        "INTERNAL",
        "UNSUPPORTED_ENCRYPTION",
        "OTHER",
        "PAYMENT_FAILED",
        "NOT_FOUND",
    ];
    let doc: serde_json::Value = serde_json::from_str(json).map_err(|_| Error::Response)?;
    let obj = doc.as_object().ok_or(Error::Response)?;
    if obj.get("result_type").and_then(|v| v.as_str()) != Some(method) {
        return Err(Error::Response);
    }
    let result = obj.get("result").filter(|v| !v.is_null());
    let error = obj.get("error").filter(|v| !v.is_null());
    match (result, error) {
        (Some(r), None) => {
            for key in ["amount", "balance", "fees_paid"] {
                if let Some(v) = r.get(key).filter(|v| !is_msat(v)) {
                    let _ = v;
                    return Err(Error::Response);
                }
            }
            Ok(NwcOutcome::Ok(r.clone()))
        }
        (None, Some(e)) => {
            let code = e
                .get("code")
                .and_then(|c| c.as_str())
                .ok_or(Error::Response)?;
            if !CODES.contains(&code) {
                return Err(Error::Response);
            }
            if !e.get("message").is_some_and(serde_json::Value::is_string) {
                return Err(Error::Response);
            }
            Ok(NwcOutcome::Err(String::from(code)))
        }
        _ => Err(Error::Response),
    }
}
