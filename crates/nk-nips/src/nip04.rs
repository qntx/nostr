//! NIP-04 legacy encrypted direct messages. Prefer NIP-44
//! ([`crate::nip44`]) for new applications.
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

use base64ct::{Base64, Encoding};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{Block, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use nk_core::{PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, ErrorKind, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const BLOCK: usize = 16;
const IV_LEN: usize = 16;

fn crypto_error(message: &'static str) -> Error {
    Error::new(ErrorKind::Crypto, message)
}

fn missing_iv() -> Error {
    crypto_error("invalid NIP-04 payload: missing iv")
}

fn invalid() -> Error {
    crypto_error("invalid NIP-04 payload")
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
    /// [`ErrorKind::Crypto`] when `peer`'s bytes do not lift to a curve
    /// point.
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self> {
        crate::ecdh::shared_secret_x(secret, peer).map(|x| Self(*x))
    }

    /// Wraps a raw ECDH x coordinate produced by an external key holder (TS
    /// `encryptWithSharedSecret` / `decryptWithSharedSecret`, #223).
    #[must_use]
    pub const fn from_bytes(shared_x: [u8; 32]) -> Self {
        Self(shared_x)
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
#[must_use]
pub fn encrypt_with_iv(key: &SharedSecret, text: &str, iv: &[u8; IV_LEN]) -> String {
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

/// Encrypts `text` under `key` with an IV drawn from `rng`.
#[must_use]
pub fn encrypt_with_rng<R>(key: &SharedSecret, text: &str, rng: &mut R) -> String
where
    R: rand_core::CryptoRng + ?Sized,
{
    let mut iv = Zeroizing::new([0u8; IV_LEN]);
    rng.fill_bytes(iv.as_mut_slice());
    encrypt_with_iv(key, text, &iv)
}

/// Encrypts `text` under `key` with an OS-entropy IV.
///
/// # Panics
///
/// When the OS entropy source fails — the same contract as
/// [`nk_core::SecretKey::generate`].
#[cfg(feature = "os-rng")]
#[must_use]
pub fn encrypt(key: &SharedSecret, text: &str) -> String {
    encrypt_with_rng(key, text, &mut rand_core::UnwrapErr(getrandom::SysRng))
}

/// Decrypts a NIP-04 `<base64(ct)>?iv=<base64(iv)>` payload under `key`.
/// Plaintext is UTF-8 lossy-decoded like `TextDecoder`.
///
/// # Errors
///
/// [`ErrorKind::Crypto`]: `"missing iv"` when the payload does not split
/// into exactly two non-empty parts on `?iv=`, and `"invalid NIP-04
/// payload"` for every other failure (bad base64, wrong IV length, bad
/// padding) — like TS there is no padding-oracle distinction.
pub fn decrypt(key: &SharedSecret, data: &str) -> Result<String> {
    let mut parts = data.split("?iv=");
    let (Some(ciphertext_b64), Some(iv_b64), None) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(missing_iv());
    };
    if ciphertext_b64.is_empty() || iv_b64.is_empty() {
        return Err(missing_iv());
    }
    let iv = Base64::decode_vec(iv_b64).map_err(|_| invalid())?;
    let mut buf = Zeroizing::new(Base64::decode_vec(ciphertext_b64).map_err(|_| invalid())?);
    let Ok(iv) = <&[u8; IV_LEN]>::try_from(iv.as_slice()) else {
        return Err(invalid());
    };
    let cipher = Aes256CbcDec::new((&key.0).into(), iv.into());
    let plaintext = cipher
        .decrypt_padded::<Pkcs7>(buf.as_mut_slice())
        .map_err(|_| invalid())?;
    Ok(String::from_utf8_lossy(plaintext).into_owned())
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
    use alloc::string::ToString;
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
            assert_eq!(encrypt_with_iv(&key, "hi", &IV), PAYLOAD);
            assert_eq!(decrypt(&key, PAYLOAD).unwrap(), "hi");
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
            encrypt_with_rng(&shared(), "hi", &mut Seq(0)),
            encrypt_with_iv(
                &shared(),
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
            let err = decrypt(&key, payload).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Crypto);
            assert_eq!(
                err.to_string(),
                "crypto: invalid NIP-04 payload: missing iv"
            );
        }
        // Everything else reports the generic message.
        for payload in [
            "!!!?iv=AAAAAAAAAAAAAAAAAAAAAA==",      // bad ct base64
            "aGVsbG8=?iv=!!!",                      // bad iv base64
            "aGVsbG8=?iv=AAAA",                     // 2-byte iv
            "aGVsbG8=?iv=AAAAAAAAAAAAAAAAAAAAAA==", // ct not a block multiple
            "FBcOBdVOrSZCvx8l6/hzpw==?iv=qqqqqqqqqqqqqqqqqqqqqg==", // bad padding
        ] {
            let err = decrypt(&key, payload).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Crypto);
            assert_eq!(err.to_string(), "crypto: invalid NIP-04 payload");
        }
    }
}
