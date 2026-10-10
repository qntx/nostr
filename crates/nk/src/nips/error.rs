//! The `nk::nips` error type, kept separate from the crate-root error
//! and `ErrorKind`; errors from lower crates travel upward via `source`.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use core::fmt;

/// Machine-readable category of an [`Error`].
///
/// Variants are added as the producers of each kind land; matching on the
/// enum always needs a wildcard arm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Hex decoding failed (bad character, wrong length, case on the wire).
    Hex,
    /// Key validation, signing, or encryption failed.
    Crypto,
    /// An event or event-like input failed structural validation.
    EventValidation,
    /// NIP-13 proof-of-work check failed.
    Nip13,
    /// A NIP-17 gift-wrap operation failed.
    Nip17,
    /// A NIP-19 bech32 entity failed encoding or decoding.
    Nip19,
    /// A NIP-21 `nostr:` URI failed parsing or was an `nsec`.
    Nip21,
    /// A NIP-46 URI or RPC payload failed parsing or validation.
    Nip46,
    /// A NIP-49 `ncryptsec` operation failed.
    Nip49,
    /// A NIP-59 seal/gift-wrap operation failed.
    Nip59,
    /// A NIP-98 HTTP-auth operation failed.
    Nip98,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex => f.write_str("hex"),
            Self::Crypto => f.write_str("crypto"),
            Self::EventValidation => f.write_str("event validation"),
            Self::Nip13 => f.write_str("nip13"),
            Self::Nip17 => f.write_str("nip17"),
            Self::Nip19 => f.write_str("nip19"),
            Self::Nip21 => f.write_str("nip21"),
            Self::Nip46 => f.write_str("nip46"),
            Self::Nip49 => f.write_str("nip49"),
            Self::Nip59 => f.write_str("nip59"),
            Self::Nip98 => f.write_str("nip98"),
        }
    }
}

/// The error type returned by `nk::nips` APIs.
///
/// The representation is private; inspect [`Error::kind`] for the category.
/// `Display` renders `"<kind>: <message>"` in lowercase without a trailing
/// period and never contains secrets.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: Cow<'static, str>,
    source: Option<Box<dyn core::error::Error + Send + Sync + 'static>>,
}

#[allow(
    dead_code,
    reason = "the constructors are used by feature-gated NIP modules"
)]
impl Error {
    /// Creates an error without an underlying source.
    pub(crate) fn new(kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Creates an error carrying the underlying library error as `source`.
    pub(crate) fn with_source(
        kind: ErrorKind,
        message: impl Into<Cow<'static, str>>,
        source: impl core::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// The error category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| -> &(dyn core::error::Error + 'static) { source })
    }
}

/// Result type alias used across the workspace.
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use core::error::Error as _;

    use super::*;

    #[test]
    fn error_kind_display_names() {
        assert_eq!(ErrorKind::Hex.to_string(), "hex");
        assert_eq!(ErrorKind::Crypto.to_string(), "crypto");
        assert_eq!(ErrorKind::EventValidation.to_string(), "event validation");
        assert_eq!(ErrorKind::Nip13.to_string(), "nip13");
        assert_eq!(ErrorKind::Nip17.to_string(), "nip17");
        assert_eq!(ErrorKind::Nip19.to_string(), "nip19");
        assert_eq!(ErrorKind::Nip21.to_string(), "nip21");
        assert_eq!(ErrorKind::Nip46.to_string(), "nip46");
        assert_eq!(ErrorKind::Nip49.to_string(), "nip49");
        assert_eq!(ErrorKind::Nip59.to_string(), "nip59");
        assert_eq!(ErrorKind::Nip98.to_string(), "nip98");
    }

    #[test]
    fn display_renders_kind_and_message() {
        let error = Error::new(ErrorKind::Nip19, "bad bech32");
        assert_eq!(error.to_string(), "nip19: bad bech32");
        assert_eq!(error.kind(), ErrorKind::Nip19);
    }

    #[test]
    fn source_is_absent_for_flat_errors() {
        let flat = Error::new(ErrorKind::Nip21, "nostr uri rejected");
        assert!(flat.source().is_none());
    }

    #[test]
    fn source_carries_the_lower_level_error() {
        let lower = crate::EventId::from_slice(&[0u8; 4]).unwrap_err();
        let wrapped = Error::with_source(ErrorKind::Nip19, "invalid payload", lower);
        assert_eq!(wrapped.kind(), ErrorKind::Nip19);
        let source = wrapped.source().unwrap();
        assert_eq!(source.to_string(), "hex: invalid event id length");
    }
}
