//! The NIP-01 subscription id.

use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Error, Result};
use crate::hex;
use crate::limits::SUBSCRIPTION_ID_MAX_CHARS;

/// A NIP-01 subscription id: 1..=64 Unicode scalar values.
#[cfg_attr(not(feature = "os-rng"), doc = "```compile_fail")]
#[cfg_attr(
    not(feature = "os-rng"),
    doc = "let _ = nk_core::SubscriptionId::generate();"
)]
#[cfg_attr(not(feature = "os-rng"), doc = "```")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Validates `id`; fails when empty or longer than 64 scalar values.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSubscriptionId`] when the length is outside `1..=64`.
    pub fn new<S>(id: S) -> Result<Self>
    where
        S: Into<String>,
    {
        let id = id.into();
        let len = id.chars().count();
        if len == 0 || len > SUBSCRIPTION_ID_MAX_CHARS {
            return Err(Error::InvalidSubscriptionId { len });
        }
        Ok(Self(id))
    }

    /// A random 16-hex-char subscription id drawn from `rng`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when `rng` fails.
    pub fn from_rng<R>(rng: &mut R) -> Result<Self>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut bytes = [0u8; 8];
        rng.try_fill_bytes(&mut bytes).map_err(|_| Error::Rng)?;
        Ok(Self(hex::encode(&bytes)))
    }

    /// A random subscription id from the OS RNG.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when the OS entropy source fails. Requires the
    /// `os-rng` feature.
    #[cfg(feature = "os-rng")]
    pub fn generate() -> Result<Self> {
        Self::from_rng(&mut getrandom::SysRng)
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for SubscriptionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for SubscriptionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubscriptionId {
    /// Deserializes a string and validates the 1..=64 scalar-value bound.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}
