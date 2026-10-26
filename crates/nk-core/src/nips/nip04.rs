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

use crate::nips::ecdh;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const BLOCK: usize = 16;
const IV_LEN: usize = 16;

/// The error type returned by NIP-04 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The peer's bytes do not lift to a curve point.
    #[error("invalid public key")]
    Derive,
    /// `rng` failed to fill the initialization vector.
    #[error("rng failed")]
    Rng,
    /// The payload does not split into exactly two non-empty parts on
    /// `?iv=`.
    #[error("invalid NIP-04 payload: missing iv")]
    MissingIv,
    /// Any other payload failure: bad base64, wrong IV length, or bad
    /// padding (like TS there is no padding-oracle distinction).
    #[error("invalid NIP-04 payload")]
    InvalidPayload,
}

/// Result type for NIP-04 operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The 32-byte ECDH x coordinate shared with a peer (
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
    /// [`Error::Derive`] when `peer`'s bytes do not lift to a curve point.
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self> {
        ecdh::shared_secret_x(secret, peer)
            .map(|x| Self(*x))
            .ok_or(Error::Derive)
    }

    /// Wraps a raw ECDH x coordinate produced by an external key holder (TS
    /// `encryptWithSharedSecret` / `decryptWithSharedSecret`, #223).
    #[cfg(test)]
    pub(crate) const fn from_bytes(shared_x: [u8; 32]) -> Self {
        Self(shared_x)
    }

    /// Encrypts `text` under this shared secret with an IV drawn from `rng`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when `rng` fails.
    pub fn encrypt<R>(&self, text: &str, rng: &mut R) -> Result<String>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut iv = Zeroizing::new([0u8; IV_LEN]);
        rng.try_fill_bytes(iv.as_mut_slice())
            .map_err(|_| Error::Rng)?;
        Ok(encrypt_with_iv(self, text, &iv))
    }

    /// Decrypts a NIP-04 `<base64(ct)>?iv=<base64(iv)>` payload under this
    /// shared secret. Plaintext is UTF-8 lossy-decoded like `TextDecoder`.
    ///
    /// # Errors
    ///
    /// [`Error::MissingIv`] when the payload does not split into exactly
    /// two non-empty parts on `?iv=`; [`Error::InvalidPayload`] for every
    /// other failure (bad base64, wrong IV length, bad padding).
    pub fn decrypt(&self, data: &str) -> Result<String> {
        let mut parts = data.split("?iv=");
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

/// Encrypts `text` under `key` with an explicit `iv` — the deterministic
/// form used by shared test vectors.
pub(crate) fn encrypt_with_iv(key: &SharedSecret, text: &str, iv: &[u8; IV_LEN]) -> String {
    let plaintext = text.as_bytes();
    // PKCS#7: append 1..=16 bytes, each holding the pad length.
    let pad_len = u8::try_from(BLOCK - plaintext.len() % BLOCK).unwrap_or_default();
    // `buf` holds the plaintext until encryption overwrites it in place.
    let mut buf = Zeroizing::new(Vec::with_capacity(plaintext.len() + usize::from(pad_len)));
    buf.extend_from_slice(plaintext);
    buf.resize(plaintext.len() + usize::from(pad_len), pad_len);
    let mut cipher = Aes256CbcEnc::new((&key.0).into(), iv.into());
    cipher.encrypt_blocks(Block::<Aes256CbcEnc>::cast_slice_from_core_mut(
        buf.as_chunks_mut::<BLOCK>().0,
    ));
    let mut payload = Base64::encode_string(&buf);
    payload.push_str("?iv=");
    payload.push_str(&Base64::encode_string(iv));
    payload
}

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

    use serde::Deserialize;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `vectors/nip04/codec.json`: `derive`/`encrypt_with_iv`/`decrypt` are all
    /// internals, so the capability runs as an in-crate test.
    #[test]
    fn codec_vectors() {
        #[derive(Deserialize)]
        struct Case {
            sec1: String,
            pub2: String,
            iv: String,
            plaintext: String,
            payload: String,
        }
        #[derive(Deserialize)]
        struct Vec_ {
            cases: Vec<Case>,
        }
        let v: Vec_ = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/nip04/codec.json"
        )))
        .unwrap();
        for (i, c) in v.cases.iter().enumerate() {
            let secret = SecretKey::from_hex(&c.sec1).unwrap();
            let peer = PublicKey::from_hex(&c.pub2).unwrap();
            let shared = SharedSecret::derive(&secret, &peer).unwrap();
            let iv: [u8; 16] = unhex(&c.iv).try_into().unwrap();
            let payload = encrypt_with_iv(&shared, &c.plaintext, &iv);
            assert_eq!(payload, c.payload, "case {i}: encrypt");
            assert_eq!(
                shared.decrypt(&c.payload).unwrap(),
                c.plaintext,
                "case {i}: decrypt"
            );
        }
    }

    #[test]
    fn encrypt_rng_uses_the_rng() {
        struct Seq(u8);
        impl rand_core::TryRng for Seq {
            type Error = rand_core::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                let next = self.0;
                dest.iter_mut()
                    .zip(0u8..)
                    .for_each(|(byte, n)| *byte = next.wrapping_add(n));
                self.0 = next.wrapping_add(u8::try_from(dest.len()).unwrap_or(u8::MAX));
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Seq {}

        let shared = SharedSecret::from_bytes([7; 32]);
        assert_eq!(
            shared.encrypt("hi", &mut Seq(0)).unwrap(),
            encrypt_with_iv(
                &shared,
                "hi",
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
    }

    #[test]
    fn decrypt_error_shapes() {
        let key = SharedSecret::from_bytes([7; 32]);
        for payload in ["abc", "?iv=abc", "abc?iv=", "abc?iv=def?iv=ghi", ""] {
            assert!(matches!(
                key.decrypt(payload).unwrap_err(),
                Error::MissingIv
            ));
        }
        for payload in [
            "!!!?iv=AAAAAAAAAAAAAAAAAAAAAA==",
            "aGVsbG8=?iv=!!!",
            "aGVsbG8=?iv=AAAA",
            "aGVsbG8=?iv=AAAAAAAAAAAAAAAAAAAAAA==",
            "FBcOBdVOrSZCvx8l6/hzpw==?iv=qqqqqqqqqqqqqqqqqqqqqg==",
        ] {
            assert!(matches!(
                key.decrypt(payload).unwrap_err(),
                Error::InvalidPayload
            ));
        }
        assert_eq!(format!("{key:?}"), "SharedSecret(..)");
    }
}
