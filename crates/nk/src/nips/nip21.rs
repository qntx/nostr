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
use crate::nips::{Error, ErrorKind, Result};

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

/// True when `value` has the `nostr:` URI shape and is not an `nsec`; the
/// entity is not decoded (TS `isNostrURI`).
#[must_use]
pub fn is_nostr_uri(value: &str) -> bool {
    uri_entity(value).is_some_and(|entity| !is_nsec(entity))
}

/// A parsed `nostr:` URI (NIP-21). `nsec` URIs are rejected.
#[derive(Clone, Debug)]
pub struct NostrUri {
    /// The bech32 entity without the `nostr:` prefix, as written in the URI.
    value: String,
    entity: nip19::Entity,
}

impl NostrUri {
    /// Parses a `nostr:<bech32>` URI (TS `parseNostrURI`).
    ///
    /// Shape violations and `nsec` URIs produce [`ErrorKind::Nip21`]; a
    /// well-shaped but undecodable entity also produces [`ErrorKind::Nip21`]
    /// with the NIP-19 error as `source`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip21`] on a malformed URI, an `nsec` entity, or a NIP-19
    /// decode failure.
    pub fn parse(uri: &str) -> Result<Self> {
        let Some(entity) = uri_entity(uri) else {
            return Err(Error::new(ErrorKind::Nip21, "invalid nostr URI"));
        };
        if is_nsec(entity) {
            return Err(Error::new(
                ErrorKind::Nip21,
                "NIP-21 identifiers exclude nsec",
            ));
        }
        let decoded = nip19::decode(entity)
            .map_err(|error| Error::with_source(ErrorKind::Nip21, "invalid nostr URI", error))?;
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

    fn from_str(s: &str) -> Result<Self> {
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
    fn parses_a_valid_uri() {
        let uri = NostrUri::parse(&format!("nostr:{NPUB}")).unwrap();
        assert_eq!(uri.as_str(), NPUB);
        assert!(matches!(uri.entity(), nip19::Entity::Public(_)));
        assert_eq!(uri.to_string(), format!("nostr:{NPUB}"));
        let via_from_str: NostrUri = format!("nostr:{NPUB}").parse().unwrap();
        assert_eq!(via_from_str.as_str(), NPUB);
        assert!(matches!(uri.into_entity(), nip19::Entity::Public(_)));
    }

    #[test]
    fn scheme_is_case_insensitive() {
        assert_eq!(
            NostrUri::parse(&format!("NOSTR:{NPUB}")).unwrap().as_str(),
            NPUB
        );
        assert!(is_nostr_uri(&format!("NoStR:{NPUB}")));
        assert!(is_nostr_uri(&format!("nostr:{}", NPUB.to_uppercase())));
        assert!(NostrUri::parse(&format!("nostr:{}", NPUB.to_uppercase())).is_ok());
    }

    #[test]
    fn nsec_is_rejected() {
        let uri = format!("nostr:{NSEC}");
        assert!(!is_nostr_uri(&uri));
        let error = NostrUri::parse(&uri).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Nip21);
        let upper = format!("nostr:{}", NSEC.to_uppercase());
        assert!(!is_nostr_uri(&upper));
        assert_eq!(
            NostrUri::parse(&upper).unwrap_err().kind(),
            ErrorKind::Nip21
        );
    }

    #[test]
    fn malformed_inputs_reject() {
        for uri in [
            "",
            "nostr:",
            NPUB,
            "nostr:npub",
            "nostr:npub1abc!",
            "nostr:npub1 ab",
            "https://npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            "nostr1npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
        ] {
            assert!(!is_nostr_uri(uri), "{uri}");
            assert_eq!(
                NostrUri::parse(uri).unwrap_err().kind(),
                ErrorKind::Nip21,
                "{uri}"
            );
        }
        // Shape-valid but undecodable: bad checksum and mixed case.
        let bad_checksum = format!("nostr:{}x", &NPUB[..NPUB.len() - 1]);
        let mixed =
            String::from("nostr:nPuB180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6");
        for uri in [bad_checksum, mixed] {
            assert!(is_nostr_uri(&uri), "{uri}");
            let error = NostrUri::parse(&uri).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Nip21, "{uri}");
            assert!(
                error.source().is_some_and(|s| {
                    s.downcast_ref::<Error>()
                        .is_some_and(|e| e.kind() == ErrorKind::Nip19)
                }),
                "{uri}: the NIP-19 error must be the source"
            );
        }
    }
}
