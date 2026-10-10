//! NIP-98 HTTP auth (kind 27235).
//!
//! [`auth_event`] builds the unsigned auth-event template the caller signs;
//! [`token`] and [`authorization_header`] encode a signed event as the
//! standard-base64 `Nostr` bearer token; [`unpack_token`] reverses it;
//! [`validate_auth_event`] checks a decoded event against the request.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/98.md>

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Event, EventBuilder, Kind, Tag, Timestamp};
use base64ct::{Base64, Encoding};
use core::fmt::Write as _;
use sha2::{Digest, Sha256};

use crate::nips::Result;
use crate::nips::error::{Error, ErrorKind};
use crate::nips::util::is_js_whitespace;

/// Default `|now − created_at|` window for [`validate_auth_event`] (TS
/// `DEFAULT_MAX_SKEW_SEC`).
pub const DEFAULT_MAX_SKEW_SECS: u64 = 60;

/// Lowercase hex of SHA-256(`payload`) — the `payload` tag value.
fn payload_hash(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    digest.iter().fold(String::with_capacity(64), |mut out, b| {
        out.write_fmt(format_args!("{b:02x}")).ok();
        out
    })
}

/// `/^nostr\s+/i`: case-insensitive `nostr` followed by one or more JS `\s`.
fn strip_scheme(token: &str) -> &str {
    let Some(head) = token.get(..5) else {
        return token;
    };
    if !head.eq_ignore_ascii_case("nostr") {
        return token;
    }
    let rest = &token[5..];
    if rest.starts_with(is_js_whitespace) {
        rest.trim_start_matches(is_js_whitespace)
    } else {
        token
    }
}

/// Standard base64 accepting missing padding: TS pads to a multiple of 4 and
/// decodes with `@scure/base`; `base64ct::Base64` rejects the same shapes —
/// including length mod 4 == 1, whose `===` padding is non-canonical.
fn decode_padded(encoded: &str) -> Result<Vec<u8>> {
    let rem = encoded.len() % 4;
    let mut padded = String::with_capacity(encoded.len() + 3);
    let encoded = if rem == 0 {
        encoded
    } else {
        padded.push_str(encoded);
        for _ in rem..4 {
            padded.push('=');
        }
        padded.as_str()
    };
    Base64::decode_vec(encoded)
        .map_err(|e| Error::with_source(ErrorKind::Nip98, "invalid token encoding", e))
}

/// An unsigned NIP-98 HTTP-auth event template.
///
/// Kind 27235 with `["u", url]`, `["method", method]`, and — when `payload` is
/// `Some` — `["payload", sha256_hex(payload)]`; `created_at` is fixed by
/// [`EventBuilder::build`] (`clock` feature) or [`EventBuilder::build_at`].
/// `payload` is the raw request body; TS object payloads (`JSON.stringify`)
/// are TS-only — pass the serialized bytes instead.
pub fn auth_event(url: &str, method: &str, payload: Option<&[u8]>, content: &str) -> EventBuilder {
    let mut builder = EventBuilder::new(Kind::HTTP_AUTH, content)
        .tags([Tag::custom("u", [url]), Tag::custom("method", [method])]);
    if let Some(payload) = payload {
        builder = builder.tag(Tag::custom("payload", [payload_hash(payload)]));
    }
    builder
}

/// The NIP-98 token of a signed event: standard padded base64 of the event
/// wire JSON — byte-identical to `JSON.stringify(signed)` (field order `id`,
/// `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`).
#[must_use]
pub fn token(event: &Event) -> String {
    // `Event::serialize` never fails; `serde_json`'s `Result` is a trait
    // obligation, so the empty-string fallback is unreachable.
    let json = serde_json::to_string(event).unwrap_or_default();
    Base64::encode_string(json.as_bytes())
}

/// The `Authorization` header value: `"Nostr " + token(event)`.
#[must_use]
pub fn authorization_header(event: &Event) -> String {
    let mut header = String::with_capacity(6 + token(event).len());
    header.push_str("Nostr ");
    header.push_str(&token(event));
    header
}

/// Decodes a NIP-98 token back into the signed event.
///
/// With or without the `Nostr ` scheme. Error messages mirror the TS
/// `unpackEventFromToken`: `missing token`, `invalid token encoding`,
/// `invalid token`, `invalid token JSON`, `token is not a signed event`.
///
/// # Errors
///
/// `ErrorKind::Nip98` for a missing token, malformed base64, non-object JSON,
/// invalid JSON, or JSON that is not a signed event.
pub fn unpack_token(token: &str) -> Result<Event> {
    if token.is_empty() {
        return Err(Error::new(ErrorKind::Nip98, "missing token"));
    }
    let encoded = strip_scheme(token);

    let bytes = decode_padded(encoded)?;
    let json = String::from_utf8_lossy(&bytes);
    if !json.starts_with('{') {
        return Err(Error::new(ErrorKind::Nip98, "invalid token"));
    }
    serde_json::from_str(&json).map_err(|e| {
        let message = match e.classify() {
            // Malformed JSON — the inputs `JSON.parse` rejects.
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                "invalid token JSON"
            }
            // Well-formed JSON that is not a signed event — TS
            // `validateSignedEvent` fails on the parsed object.
            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                "token is not a signed event"
            }
        };
        Error::with_source(ErrorKind::Nip98, message, e)
    })
}

/// Whether `event` is a valid NIP-98 auth event for `url` + `method`.
///
/// TS `validateAuthEvent` order: signature, kind 27235, `|now − created_at|`
/// within `max_skew_secs`, first `u` tag equal to `url` exactly, first
/// `method` tag equal case-insensitively (Unicode `toLowerCase`), and — when
/// `payload` is `Some` — first `payload` tag equal to its SHA-256 hex.
#[must_use]
pub fn validate_auth_event(
    event: &Event,
    url: &str,
    method: &str,
    payload: Option<&[u8]>,
    now: Timestamp,
    max_skew_secs: u64,
) -> bool {
    if event.verify().is_err() {
        return false;
    }
    if event.kind() != Kind::HTTP_AUTH {
        return false;
    }
    if now.as_secs().abs_diff(event.created_at().as_secs()) > max_skew_secs {
        return false;
    }
    if event.tags().first_value("u") != Some(url) {
        return false;
    }
    let Some(m) = event.tags().first_value("method") else {
        return false;
    };
    if m.to_lowercase() != method.to_lowercase() {
        return false;
    }
    if let Some(payload) = payload
        && event.tags().first_value("payload") != Some(payload_hash(payload).as_str())
    {
        return false;
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]
mod tests {
    use alloc::string::ToString;

    use crate::{Keys, SecretKey};

    use super::*;

    const SECRET: &str = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";

    fn keys() -> Keys {
        Keys::new(SecretKey::from_hex(SECRET).unwrap())
    }

    fn signed_auth(url: &str, method: &str, payload: Option<&[u8]>, now: u64) -> Event {
        let keys = keys();
        let unsigned = auth_event(url, method, payload, "")
            .build_at(keys.public_key(), Timestamp::from_secs(now));
        keys.sign_event_with_aux(unsigned, &[0x42; 32]).unwrap()
    }

    #[test]
    fn auth_event_shape() {
        let event = auth_event(
            "https://api.example.com/upload",
            "POST",
            Some(b"body".as_slice()),
            "",
        )
        .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000));
        assert_eq!(event.kind(), Kind::HTTP_AUTH);
        assert_eq!(event.content(), "");
        let tags: Vec<_> = event.tags().iter().map(Tag::as_slice).collect();
        assert_eq!(
            tags,
            [
                ["u", "https://api.example.com/upload"].as_slice(),
                ["method", "POST"].as_slice(),
                [
                    "payload",
                    "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5"
                ]
                .as_slice(),
            ]
        );
        // No payload argument → no payload tag.
        let without = auth_event("https://a", "GET", None, "content")
            .build_at(keys().public_key(), Timestamp::from_secs(0));
        assert_eq!(without.tags().len(), 2);
        assert_eq!(without.content(), "content");
    }

    #[test]
    fn token_round_trip() {
        let event = signed_auth("https://api.example.com/", "GET", None, 1_700_000_000);
        let token = token(&event);
        assert_eq!(unpack_token(&token).unwrap(), event);
        let header = authorization_header(&event);
        assert!(header.starts_with("Nostr "));
        assert_eq!(unpack_token(&header).unwrap(), event);
    }

    #[test]
    fn unpack_token_scheme_variants() {
        let event = signed_auth("https://a/", "GET", None, 1_700_000_000);
        let token = token(&event);
        for prefix in ["Nostr ", "nostr\t", "NOSTR  ", "nOsTr\n", "nostr\u{feff}"] {
            let mut t = String::from(prefix);
            t.push_str(&token);
            assert_eq!(unpack_token(&t).unwrap(), event, "prefix {prefix:?}");
        }
        // U+0085 is Unicode White_Space but NOT JS `\s` — no strip; the
        // non-base64 byte fails the encoding step.
        let mut t = String::from("nostr\u{85}");
        t.push_str(&token);
        let err = unpack_token(&t).unwrap_err();
        assert_eq!(err.to_string(), "nip98: invalid token encoding");
    }

    #[test]
    fn unpack_token_errors() {
        assert_eq!(
            unpack_token("").unwrap_err().to_string(),
            "nip98: missing token"
        );
        assert_eq!(
            unpack_token("!!!").unwrap_err().to_string(),
            "nip98: invalid token encoding"
        );
        // Valid base64 that does not start with "{".
        assert_eq!(
            unpack_token("aGVsbG8=").unwrap_err().to_string(),
            "nip98: invalid token"
        );
        // "{x" — malformed JSON.
        assert_eq!(
            unpack_token(&Base64::encode_string(b"{x"))
                .unwrap_err()
                .to_string(),
            "nip98: invalid token JSON"
        );
        // "{}", "[]"-shaped valid JSON that is not a signed event — and the
        // unsigned form of a real event.
        assert_eq!(
            unpack_token("e30=").unwrap_err().to_string(),
            "nip98: token is not a signed event"
        );
        let unsigned_json =
            serde_json::to_string(&signed_auth("https://a/", "GET", None, 0).into_unsigned())
                .unwrap();
        assert_eq!(
            unpack_token(&Base64::encode_string(unsigned_json.as_bytes()))
                .unwrap_err()
                .to_string(),
            "nip98: token is not a signed event"
        );
    }

    #[test]
    fn unpack_token_accepts_unpadded_base64() {
        let event = signed_auth("https://a/", "GET", None, 1_700_000_000);
        let token = token(&event);
        let stripped = token.trim_end_matches('=');
        assert_eq!(unpack_token(stripped).unwrap(), event);
    }

    #[test]
    fn validate_auth_event_checks() {
        let now = 1_700_000_000;
        let url = "https://api.example.com/upload";
        let event = signed_auth(url, "POST", Some(b"body"), now);
        let now = Timestamp::from_secs(now);

        assert!(validate_auth_event(
            &event,
            url,
            "post",
            Some(b"body"),
            now,
            DEFAULT_MAX_SKEW_SECS
        ));
        // Skew boundaries: exactly ±60 ok, ±61 rejected.
        assert!(validate_auth_event(
            &event,
            url,
            "POST",
            None,
            Timestamp::from_secs(now.as_secs() + 60),
            DEFAULT_MAX_SKEW_SECS
        ));
        assert!(!validate_auth_event(
            &event,
            url,
            "POST",
            None,
            Timestamp::from_secs(now.as_secs() + 61),
            DEFAULT_MAX_SKEW_SECS
        ));
        assert!(!validate_auth_event(
            &event,
            "https://other.example.com/",
            "POST",
            None,
            now,
            DEFAULT_MAX_SKEW_SECS
        ));
        assert!(!validate_auth_event(
            &event,
            url,
            "POST",
            Some(b"other"),
            now,
            DEFAULT_MAX_SKEW_SECS
        ));
        // Payload tag absent → a Some(payload) check fails.
        let no_payload = signed_auth(url, "POST", None, now.as_secs());
        assert!(!validate_auth_event(
            &no_payload,
            url,
            "POST",
            Some(b"body"),
            now,
            DEFAULT_MAX_SKEW_SECS
        ));
        // Custom skew window.
        assert!(!validate_auth_event(
            &event,
            url,
            "POST",
            None,
            Timestamp::from_secs(now.as_secs() + 5),
            4
        ));
    }

    #[test]
    fn validate_rejects_wrong_kind_and_bad_sig() {
        let now = 1_700_000_000;
        let keys = keys();
        let unsigned = EventBuilder::new(Kind::TEXT_NOTE, "")
            .tag(Tag::custom("u", ["https://a/"]))
            .tag(Tag::custom("method", ["GET"]))
            .build_at(keys.public_key(), Timestamp::from_secs(now));
        let wrong_kind = keys.sign_event_with_aux(unsigned, &[0x42; 32]).unwrap();
        assert!(!validate_auth_event(
            &wrong_kind,
            "https://a/",
            "GET",
            None,
            Timestamp::from_secs(now),
            DEFAULT_MAX_SKEW_SECS
        ));
        // Tamper the content → the id/signature no longer match.
        let tampered_json = serde_json::to_string(&signed_auth("https://a/", "GET", None, now))
            .unwrap()
            .replace("\"content\":\"\"", "\"content\":\"x\"");
        let tampered: Event = serde_json::from_str(&tampered_json).unwrap();
        assert!(!validate_auth_event(
            &tampered,
            "https://a/",
            "GET",
            None,
            Timestamp::from_secs(now),
            DEFAULT_MAX_SKEW_SECS
        ));
    }

    #[test]
    fn strip_scheme_edge_cases() {
        assert_eq!(strip_scheme("nostr"), "nostr");
        assert_eq!(strip_scheme("nostri"), "nostri");
        assert_eq!(strip_scheme(""), "");
        // Non-ASCII first bytes: no panic on the byte-5 slice boundary.
        assert_eq!(strip_scheme("énostr x"), "énostr x");
    }
}
