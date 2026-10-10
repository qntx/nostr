//! Unix-timestamp newtype (seconds since the epoch).

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::json;

/// Seconds since the Unix epoch, serialized as a bare JSON number (the
/// NIP-01 `created_at` representation).
#[cfg_attr(not(feature = "clock"), doc = "```compile_fail")]
#[cfg_attr(not(feature = "clock"), doc = "let _ = nk::Timestamp::now();")]
#[cfg_attr(not(feature = "clock"), doc = "```")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl<'de> Deserialize<'de> for Timestamp {
    /// Accepts any integer-valued JSON number (`1e3`, `1.0`, `-0`) up to
    /// `2^53-1`; output is always a plain integer (NK-ADR-012 rulings 8–9).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        json::de_u64(deserializer).map(Self)
    }
}

impl Timestamp {
    /// Wraps a seconds count.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// The wrapped seconds count.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// The current wall-clock time. Requires the `clock` feature (absent on
    /// platforms without a wall clock, e.g. bare `wasm32-unknown-unknown`).
    #[must_use]
    #[cfg(feature = "clock")]
    pub fn now() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }
}

impl From<u64> for Timestamp {
    fn from(secs: u64) -> Self {
        Self(secs)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn conversion_display_and_serde() {
        let ts = Timestamp::from(1_700_000_000);
        assert_eq!(ts.as_secs(), 1_700_000_000);
        assert_eq!(ts.to_string(), "1700000000");
        assert_eq!(serde_json::to_string(&ts).expect("ser"), "1700000000");
        // Rulings 8–9: every integer spelling up to 2^53-1 parses.
        for (raw, secs) in [
            ("1000", 1000),
            ("1e3", 1000),
            ("1.0", 1),
            ("-0", 0),
            ("9007199254740991.0", 9_007_199_254_740_991),
        ] {
            assert_eq!(
                serde_json::from_str::<Timestamp>(raw).expect(raw),
                Timestamp::from_secs(secs),
                "{raw}"
            );
        }
        for bad in ["-1", "1.5", "9007199254740992", "\"x\"", "null"] {
            assert!(serde_json::from_str::<Timestamp>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    #[cfg(feature = "clock")]
    fn now_is_sane() {
        assert!(Timestamp::now().as_secs() > 1_700_000_000);
    }
}
