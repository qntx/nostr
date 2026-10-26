//! Error type for `nk-store` operations.

/// The error type returned by store operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A stored row failed to decode back into the shape it was written as.
    /// The message names what failed (the table column or encoding).
    #[error("corrupt stored data: {0}")]
    Corrupt(&'static str),
    /// A backend operation failed (I/O or driver error). The backend failure
    /// is wrapped in an opaque newtype so no driver type leaks into the API.
    #[error("backend failure")]
    Backend(#[source] BackendError),
}

/// An opaque wrapper for backend driver failures (e.g. SQLite). The
/// underlying error is private — no driver type appears in the public API.
///
/// The source is type-erased on purpose: [`EventStore`](crate::EventStore)
/// can be implemented outside this crate, and such backends report their own
/// driver errors through [`BackendError::new`], like `std::io::Error::other`.
#[derive(Debug)]
pub struct BackendError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl BackendError {
    /// Wraps any backend error.
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Result type for store operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
