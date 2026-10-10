//! Protocol byte/character limits shared by the wire types.

/// Byte length of a NIP-01 event id (SHA-256).
pub const EVENT_ID_BYTES: usize = 32;

/// Byte length of a BIP-340 x-only public key.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Byte length of a secret key.
pub const SECRET_KEY_BYTES: usize = 32;

/// Byte length of a BIP-340 Schnorr signature.
pub const SIGNATURE_BYTES: usize = 64;

/// Maximum length of a subscription id in characters (NIP-01: 1–64 chars).
pub const SUBSCRIPTION_ID_MAX_CHARS: usize = 64;
