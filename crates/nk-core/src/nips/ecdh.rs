//! secp256k1 ECDH shared by the NIP-04 and NIP-44 key derivation paths.

use crate::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

/// The ECDH computation failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `peer`'s bytes do not lift to a curve point.
    InvalidPeerKey,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPeerKey => f.write_str("peer key is not on the curve"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The ECDH computation failed.
pub type Result<T> = core::result::Result<T, Error>;

/// Returns the x coordinate of the ECDH shared point.
///
/// `peer` is lifted to an even-parity x-only key — TS
/// `secp256k1.getSharedSecret(secret, 02 || peer).slice(1, 33)`; the temporary
/// `secp256k1::SecretKey` and the shared point are erased.
///
/// # Errors
///
/// [`Error::InvalidPeerKey`] when `peer`'s bytes do not lift to a curve point.
pub fn shared_x(secret: &SecretKey, peer: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    secret.with_secret_bytes(|bytes| {
        // nk's `SecretKey` already validated the scalar.
        let Ok(mut sec) = secp256k1::SecretKey::from_secret_bytes(*bytes) else {
            return Err(Error::InvalidPeerKey);
        };
        let Ok(peer_x) = secp256k1::XOnlyPublicKey::from_byte_array(*peer.as_bytes()) else {
            sec.non_secure_erase();
            return Err(Error::InvalidPeerKey);
        };
        let peer_point =
            secp256k1::PublicKey::from_x_only_public_key(peer_x, secp256k1::Parity::Even);
        let mut point = secp256k1::ecdh::shared_secret_point(&peer_point, &sec);
        sec.non_secure_erase();
        let mut shared_x = Zeroizing::new([0u8; 32]);
        shared_x.copy_from_slice(point.split_at(32).0);
        point.zeroize();
        Ok(shared_x)
    })
}
