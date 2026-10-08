//! nk-core's error type. Each `nk-*` crate defines its own opaque `Error`
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
    /// Relay URL parsing or normalization failed.
    Url,
    /// An event, tag, or event address failed structural validation.
    EventValidation,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex => f.write_str("hex"),
            Self::Url => f.write_str("url"),
            Self::EventValidation => f.write_str("event validation"),
        }
    }
}

/// The error type returned by nk-core APIs.
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
