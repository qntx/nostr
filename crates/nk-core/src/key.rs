//! Public keys. Secret keys and signing arrive with `secp256k1` in NK1-03.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, ErrorKind, Result};
use crate::hex;

/// An x-only public key (32 bytes).
///
/// The `from_*` constructors check shape only: whether the bytes are a valid
/// curve point is decided at signature verification, not here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps 32 bytes without a curve check.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copies a byte slice into a key.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Hex, "invalid public key length"))?;
        Ok(Self(array))
    }

    /// Parses 64-character hex of any case; the key stores bytes only, so the
    /// canonical output is always lowercase.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when the input is not 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(hex::decode_caller(hex)?))
    }

    /// The raw key bytes.
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

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(
            hex::decode_wire(&raw).map_err(serde::de::Error::custom)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    const HEX: &str = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";

    #[test]
    fn from_hex_accepts_mixed_case() {
        let key = PublicKey::from_hex(&HEX.to_uppercase()).unwrap();
        assert_eq!(key.to_hex(), HEX);
    }

    #[test]
    fn wire_deserialize_rejects_uppercase() {
        assert!(
            serde_json::from_str::<PublicKey>(&alloc::format!("\"{}\"", HEX.to_uppercase()))
                .is_err()
        );
    }

    #[test]
    fn wire_deserialize_accepts_lowercase() {
        let key: PublicKey = serde_json::from_str(&alloc::format!("\"{HEX}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&key).unwrap(),
            alloc::format!("\"{HEX}\"")
        );
    }

    #[test]
    fn from_slice_checks_length() {
        PublicKey::from_slice(&[0u8; 31]).unwrap_err();
        PublicKey::from_slice(&[0u8; 32]).unwrap();
    }

    #[test]
    fn display_and_debug_use_lowercase_hex() {
        let key = PublicKey::from_hex(HEX).unwrap();
        assert_eq!(key.to_string(), HEX);
        assert_eq!(
            alloc::format!("{key:?}"),
            alloc::format!("PublicKey({HEX})")
        );
    }
}
