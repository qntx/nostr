//! NIP-04 legacy encrypted direct messages. Prefer NIP-44
//! ([`crate::nips::nip44`]) for new applications.
//!
//! The payload is `<base64(ciphertext)>?iv=<base64(iv)>`: AES-256-CBC keyed
//! with the unhashed ECDH x coordinate, PKCS#7 padding, and UTF-8 lossy
//! decoding of the plaintext. The padded standard-alphabet base64
//! (`base64ct::Base64`) matches `@scure/base`'s strictness.
//!
//! Secret material is zeroized on drop.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/04.md>

use alloc::string::String;
use alloc::vec::Vec;

use crate::{PublicKey, SecretKey};
use base64ct::{Base64, Encoding};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{Block, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const BLOCK: usize = 16;
const IV_LEN: usize = 16;

/// NIP-04 errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The peer public key does not lift to a curve point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The payload does not split into a non-empty ciphertext and IV on
    /// `?iv=`.
    #[error("missing iv")]
    MissingIv,
    /// Bad base64, a wrong IV length, or bad padding — like TS there is no
    /// padding-oracle distinction.
    #[error("invalid payload")]
    InvalidPayload,
}

/// The 32-byte ECDH x coordinate shared with a peer (TS `sharedX` —
/// `secp256k1.getSharedSecret(...).slice(1, 33)`). NIP-04 AES-CBC keys this
/// value directly, without hashing.
///
/// No `PartialEq`, `Display`, or serde: secret material is never compared in
/// non-constant time or formatted into logs.
#[derive(Clone)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Derives the shared secret from our `secret` and the peer's `peer`
    /// public key via `secp256k1::ecdh::shared_secret_point` with the peer
    /// lifted to an even-parity x-only key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] when `peer`'s bytes do not lift to a
    /// curve point.
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self, Error> {
        crate::nips::ecdh::shared_secret_x(secret, peer)
            .map(|x| Self(*x))
            .ok_or(Error::InvalidPublicKey)
    }

    /// Wraps a raw ECDH x coordinate produced by an external key holder (TS
    /// `encryptWithSharedSecret` / `decryptWithSharedSecret`, #223).
    #[must_use]
    pub const fn from_bytes(shared_x: [u8; 32]) -> Self {
        Self(shared_x)
    }

    /// Encrypts `plaintext` with an explicit `iv` — the deterministic form used
    /// by shared test vectors.
    #[must_use]
    pub fn encrypt_with_iv(&self, plaintext: &str, iv: &[u8; IV_LEN]) -> String {
        let plaintext = plaintext.as_bytes();
        // PKCS#7: append 1..=16 bytes, each holding the pad length.
        let pad_len = u8::try_from(BLOCK - plaintext.len() % BLOCK).unwrap_or_default();
        // `buf` holds the plaintext until encryption overwrites it in place.
        let mut buf = Zeroizing::new(Vec::with_capacity(plaintext.len() + usize::from(pad_len)));
        buf.extend_from_slice(plaintext);
        buf.resize(plaintext.len() + usize::from(pad_len), pad_len);
        let mut cipher = Aes256CbcEnc::new((&self.0).into(), iv.into());
        cipher.encrypt_blocks(Block::<Aes256CbcEnc>::cast_slice_from_core_mut(
            buf.as_chunks_mut::<BLOCK>().0,
        ));
        let mut payload = Base64::encode_string(&buf);
        payload.push_str("?iv=");
        payload.push_str(&Base64::encode_string(iv));
        payload
    }

    /// Encrypts `plaintext` with an IV drawn from `rng`.
    #[must_use]
    pub fn encrypt_with_rng<R>(&self, plaintext: &str, rng: &mut R) -> String
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        let mut iv = Zeroizing::new([0u8; IV_LEN]);
        rng.fill_bytes(iv.as_mut_slice());
        self.encrypt_with_iv(plaintext, &iv)
    }

    /// Encrypts `plaintext` with an OS-entropy IV.
    ///
    /// # Panics
    ///
    /// When the OS entropy source fails — the same contract as
    /// [`crate::SecretKey::generate`].
    #[cfg(feature = "os-rng")]
    #[must_use]
    pub fn encrypt(&self, plaintext: &str) -> String {
        self.encrypt_with_rng(plaintext, &mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// Decrypts a NIP-04 `<base64(ct)>?iv=<base64(iv)>` payload. Plaintext is
    /// UTF-8 lossy-decoded like `TextDecoder`.
    ///
    /// # Errors
    ///
    /// [`Error::MissingIv`] when the payload does not split into exactly two
    /// non-empty parts on `?iv=`; [`Error::InvalidPayload`] for every other
    /// failure.
    pub fn decrypt(&self, payload: &str) -> Result<String, Error> {
        let mut parts = payload.split("?iv=");
        let (Some(ciphertext_b64), Some(iv_b64), None) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::MissingIv);
        };
        if ciphertext_b64.is_empty() || iv_b64.is_empty() {
            return Err(Error::MissingIv);
        }
        let iv = Base64::decode_vec(iv_b64).map_err(|_| Error::InvalidPayload)?;
        let mut buf =
            Zeroizing::new(Base64::decode_vec(ciphertext_b64).map_err(|_| Error::InvalidPayload)?);
        let Ok(iv) = <&[u8; IV_LEN]>::try_from(iv.as_slice()) else {
            return Err(Error::InvalidPayload);
        };
        let cipher = Aes256CbcDec::new((&self.0).into(), iv.into());
        let plaintext = cipher
            .decrypt_padded::<Pkcs7>(buf.as_mut_slice())
            .map_err(|_| Error::InvalidPayload)?;
        Ok(String::from_utf8_lossy(plaintext).into_owned())
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(..)")
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests fail by panicking"
    )]

    use alloc::format;
    use alloc::vec::Vec;

    use super::*;

    const SEC1: &str = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
    const PUB2: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    // Vector values from vectors/nip04/codec.json (plaintext "hi").
    const SHARED: &str = "d5f1424c2796acf26048369b21aa426ea9908cbae8fafed428dc6d16f0aac669";
    const IV: [u8; 16] = [0xaa; 16];
    const PAYLOAD: &str = "GaqpqgDySizH9H4RBmRQ2g==?iv=qqqqqqqqqqqqqqqqqqqqqg==";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn shared() -> SharedSecret {
        SharedSecret::from_bytes(unhex(SHARED).try_into().unwrap())
    }

    #[test]
    fn derive_and_encrypt_match_the_vector() {
        let secret = SecretKey::from_hex(SEC1).unwrap();
        let peer = PublicKey::from_hex(PUB2).unwrap();
        let derived = SharedSecret::derive(&secret, &peer).unwrap();
        for key in [derived, shared()] {
            assert_eq!(key.encrypt_with_iv("hi", &IV), PAYLOAD);
            assert_eq!(key.decrypt(PAYLOAD).unwrap(), "hi");
        }
        assert_eq!(format!("{:?}", shared()), "SharedSecret(..)");
    }

    /// Deterministic rng emitting iv 00..0f — `rand_core` exposes no canned
    /// test rng.
    struct Seq(u8);
    impl rand_core::TryRng for Seq {
        type Error = rand_core::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut out = [0u8; 4];
            self.try_fill_bytes(&mut out)?;
            Ok(u32::from_le_bytes(out))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut out = [0u8; 8];
            self.try_fill_bytes(&mut out)?;
            Ok(u64::from_le_bytes(out))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Seq {}

    #[test]
    fn encrypt_with_rng_uses_the_rng() {
        assert_eq!(
            shared().encrypt_with_rng("hi", &mut Seq(0)),
            shared().encrypt_with_iv(
                "hi",
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
    }

    #[test]
    fn decrypt_error_shapes() {
        let key = shared();
        // Missing iv: no separator, empty side, or a second separator.
        for payload in ["abc", "?iv=abc", "abc?iv=", "abc?iv=def?iv=ghi", ""] {
            assert!(matches!(key.decrypt(payload), Err(Error::MissingIv)));
        }
        // Everything else reports the generic variant.
        for payload in [
            "!!!?iv=AAAAAAAAAAAAAAAAAAAAAA==",      // bad ct base64
            "aGVsbG8=?iv=!!!",                      // bad iv base64
            "aGVsbG8=?iv=AAAA",                     // 2-byte iv
            "aGVsbG8=?iv=AAAAAAAAAAAAAAAAAAAAAA==", // ct not a block multiple
            "FBcOBdVOrSZCvx8l6/hzpw==?iv=qqqqqqqqqqqqqqqqqqqqqg==", // bad padding
        ] {
            assert!(matches!(key.decrypt(payload), Err(Error::InvalidPayload)));
        }
    }
}
