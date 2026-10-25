//! The relay module's failure type.

/// Why a relay operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `subscribe`/`fetch`/`count` got an empty filter list.
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
    /// The relay `CLOSED` a request with a reason (NIP-45 `COUNT`, and
    /// any `auth-required:` that could not be answered).
    #[error("the relay refused with reason: {0}")]
    Refused(String),
    /// The WebSocket transport failed.
    #[error("transport failure")]
    Transport(#[source] TransportError),
    /// A NIP-77 sync failed inside the negentropy codec.
    #[error("negentropy failure")]
    Negentropy(#[source] NegentropyError),
    /// The relay URL is not a `ws://`/`wss://` endpoint.
    #[error("invalid relay URL")]
    InvalidUrl,
}

erased_error!(
    TransportError,
    "A type-erased transport failure.",
    "Wraps any backend error."
);
erased_error!(
    NegentropyError,
    "A type-erased NIP-77 sync failure.",
    "Wraps any negentropy error."
);

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;
