//! secp256k1 ECDH shared by the NIP-04 and NIP-44 key derivation paths.

use nk_core::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, ErrorKind, Result};

/// Returns the x coordinate of `secp256k1::ecdh::shared_secret_point` between
/// `secret` and `peer` lifted to an even-parity x-only key (TS
/// `secp256k1.getSharedSecret(secret, 02 || peer).slice(1, 33)`). The
/// temporary `secp256k1::SecretKey` and the shared point are erased.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] when `peer`'s bytes do not lift to a curve point.
pub(crate) fn shared_secret_x(secret: &SecretKey, peer: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    secret.with_secret_bytes(|bytes| {
        // nk-core's `SecretKey` already validated the scalar.
        let Ok(mut sec) = secp256k1::SecretKey::from_secret_bytes(*bytes) else {
            return Err(Error::new(ErrorKind::Crypto, "invalid secret key"));
        };
        let Ok(peer_x) = secp256k1::XOnlyPublicKey::from_byte_array(*peer.as_bytes()) else {
            sec.non_secure_erase();
            return Err(Error::new(ErrorKind::Crypto, "invalid public key"));
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
