//! NIP-21 `nostr:` URI scheme.
//!
//! The scheme is case-insensitive and the remainder must be a bech32 entity as
//! defined by NIP-19 (`npub`, `note`, `nprofile`, `nevent`, `naddr` — `nsec` is
//! excluded by NIP-21). The charset check is done by hand; no regex.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/21.md>

use alloc::string::String;

use core::fmt;
use core::str::FromStr;

use crate::nips::nip19;

/// Errors produced by parsing a `nostr:` URI.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URI does not start with the `nostr:` scheme or does not match
    /// the NIP-21 shape `nostr:<hrp>1<bech32 data>`.
    #[error("missing or malformed nostr: scheme")]
    MissingScheme,
    /// `nsec` entities are excluded from `nostr:` URIs by NIP-21.
    #[error("nostr: URIs must not contain an nsec entity")]
    SecretKey,
    /// The entity part is not a valid NIP-19 bech32 entity.
    #[error(transparent)]
    Nip19(#[from] nip19::Error),
}

const SCHEME: &str = "nostr:";
const NSEC: &str = "nsec1";

const fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Bech32 data-part charset (excludes `1`, `b`, `i`, `o`), case-insensitive.
const fn is_data_char(b: u8) -> bool {
    matches!(
        b.to_ascii_lowercase(),
        b'0' | b'2'..=b'9' | b'a' | b'c'..=b'h' | b'j'..=b'n' | b'p'..=b'z'
    )
}

fn is_nsec(entity: &str) -> bool {
    entity.len() >= NSEC.len() && entity[..NSEC.len()].eq_ignore_ascii_case(NSEC)
}

/// Returns the entity part of `uri` when it matches the NIP-21 shape
/// `nostr:[a-z0-9]+1[02-9ac-hj-np-z]+` (case-insensitive). `1` never appears in
/// the bech32 data charset, so the separator can only be the last `1`.
fn uri_entity(uri: &str) -> Option<&str> {
    if uri.len() <= SCHEME.len() || !uri.get(..SCHEME.len())?.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let entity = &uri[SCHEME.len()..];
    let sep = entity.rfind('1')?;
    let hrp = entity.get(..sep)?;
    let data = entity.get(sep + 1..)?;
    if hrp.is_empty() || !hrp.bytes().all(is_scheme_char) {
        return None;
    }
    if data.is_empty() || !data.bytes().all(is_data_char) {
        return None;
    }
    Some(entity)
}

/// A parsed `nostr:` URI (NIP-21). `nsec` URIs are rejected.
#[derive(Clone, Debug)]
pub struct NostrUri {
    /// The bech32 entity without the `nostr:` prefix, as written in the URI.
    value: String,
    entity: nip19::Entity,
}

impl NostrUri {
    /// Parses a `nostr:<bech32>` URI.
    ///
    /// # Errors
    ///
    /// [`Error::MissingScheme`] on a malformed URI, [`Error::SecretKey`] on
    /// an `nsec` entity, and [`Error::Nip19`] on a well-shaped but
    /// undecodable entity.
    pub fn parse(uri: &str) -> Result<Self, Error> {
        let Some(entity) = uri_entity(uri) else {
            return Err(Error::MissingScheme);
        };
        if is_nsec(entity) {
            return Err(Error::SecretKey);
        }
        let decoded = nip19::Entity::from_bech32(entity)?;
        Ok(Self {
            value: entity.into(),
            entity: decoded,
        })
    }

    /// The bech32 entity without the `nostr:` prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The decoded NIP-19 entity.
    #[must_use]
    pub const fn entity(&self) -> &nip19::Entity {
        &self.entity
    }

    /// Consumes the URI and returns the decoded NIP-19 entity.
    #[must_use]
    pub fn into_entity(self) -> nip19::Entity {
        self.entity
    }
}

impl fmt::Display for NostrUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.value)
    }
}

impl FromStr for NostrUri {
    type Err = Error;

    /// Parses a `nostr:<bech32>` URI — identical to [`NostrUri::parse`].
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::format;
    use alloc::string::ToString;

    use core::error::Error as _;

    use super::*;

    const NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    #[test]
    fn parse_round_trip() {
        let uri = NostrUri::parse(&format!("nostr:{NPUB}")).unwrap();
        assert_eq!(uri.as_str(), NPUB);
        assert_eq!(uri.to_string(), format!("nostr:{NPUB}"));
        assert!(matches!(uri.entity(), nip19::Entity::Public(_)));
        assert!(matches!(uri.into_entity(), nip19::Entity::Public(_)));
        assert!(format!("nostr:{NPUB}").parse::<NostrUri>().is_ok());
    }

    #[test]
    fn accepts_case_insensitive_scheme_and_upper_entity() {
        assert!(NostrUri::parse(&format!("NOSTR:{NPUB}")).is_ok());
        assert!(NostrUri::parse(&format!("nostr:{}", NPUB.to_uppercase())).is_ok());
    }

    #[test]
    fn rejects_nsec() {
        let err = NostrUri::parse(&format!("nostr:{NSEC}")).unwrap_err();
        assert!(matches!(err, Error::SecretKey));
        // Also when only the shape matches (uppercase prefix).
        assert!(matches!(
            NostrUri::parse(&format!("nostr:{}", NSEC.to_uppercase())),
            Err(Error::SecretKey)
        ));
    }

    #[test]
    fn rejects_malformed_and_wrong_scheme() {
        for input in [
            "",
            "npub180cvv07",
            "http://x",
            "nostr:",
            "nostr:abc",
            "nostr://abc",
            "nostr:npub1bad!chars",
        ] {
            assert!(
                matches!(NostrUri::parse(input), Err(Error::MissingScheme)),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_undecodable_entity_with_nip19_source() {
        // Shape is valid but the checksum is wrong.
        let mut code = String::from(NPUB);
        let last = code.pop().unwrap();
        code.push(if last == 'q' { 'p' } else { 'q' });
        let err = NostrUri::parse(&format!("nostr:{code}")).unwrap_err();
        assert!(matches!(err, Error::Nip19(_)));
        assert!(err.source().is_some());
    }
}
