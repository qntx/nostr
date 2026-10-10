//! Private `#[source]` wrappers for the module error enums, so no
//! third-party error type appears in a public variant field. The module is
//! `#[doc(hidden)]` and not part of the stable API.

use core::fmt;

/// The underlying `base16ct` decode failure, carried as a `#[source]`.
#[derive(Debug)]
pub struct HexSource(pub(crate) base16ct::Error);

impl fmt::Display for HexSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for HexSource {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The underlying `serde_json` parse failure, carried as a `#[source]`.
#[derive(Debug)]
pub struct JsonSource(pub(crate) serde_json::Error);

impl fmt::Display for JsonSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for JsonSource {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The underlying `url` parse failure, carried as a `#[source]`.
#[derive(Debug, Clone, Copy)]
pub struct UrlSource(pub(crate) url::ParseError);

impl fmt::Display for UrlSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for UrlSource {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}
