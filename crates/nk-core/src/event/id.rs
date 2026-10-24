//! The NIP-01 event id: the SHA-256 digest of the canonical serialization.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::{Error, Result};
use crate::hex;

/// An event id: the SHA-256 digest of the canonical serialization (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Wraps 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copies a byte slice into an id.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] when `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength {
            expected: 32,
            found: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Parses 64-character hex of any case.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHex`] when the input is not 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        hex::decode_caller(hex)
            .map(Self)
            .map_err(|_| Error::InvalidHex)
    }

    /// SHA-256 of `canonical` — the preimage bytes of an event id.
    #[must_use]
    pub fn hash(canonical: &[u8]) -> Self {
        Self(Sha256::digest(canonical).into())
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical lowercase hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({})", self.to_hex())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for EventId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EventId {
    /// Wire form: 64-character lowercase hex.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(
            hex::decode_wire(&raw).map_err(serde::de::Error::custom)?,
        ))
    }
}
