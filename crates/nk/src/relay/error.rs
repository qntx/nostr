//! The relay module's failure type.

use std::fmt;

/// Why a relay operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `subscribe`/`fetch` got an empty filter list.
    #[error("filters must not be empty")]
    InvalidFilters,
    /// The operation did not finish inside its deadline.
    #[error("the relay did not answer in time")]
    Timeout,
    /// The connection is down and the operation could not queue.
    #[error("the relay is disconnected")]
    Disconnected,
    /// `Relay::close` has run; the relay is terminal.
    #[error("the relay is closed")]
    Closed,
    /// The WebSocket transport failed.
    #[error("transport failure")]
    Transport(#[source] TransportError),
    /// The relay URL is not a `ws://`/`wss://` endpoint.
    #[error("invalid relay URL")]
    InvalidUrl,
}

/// A type-erased transport failure.
#[derive(Debug)]
pub struct TransportError(Box<dyn std::error::Error + Send + Sync>);

impl TransportError {
    /// Wraps any backend error.
    pub(crate) fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;
