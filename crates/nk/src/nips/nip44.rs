//! NIP-44 v2 authenticated payload encryption.
//!
//! The payload is `base64(version || nonce || ciphertext || mac)`: the
//! conversation key is `HKDF-extract(SHA-256, salt = "nip44-v2", ecdh.x)`, the
//! per-message keys are `HKDF-expand(conversation_key, nonce)` (76 bytes split
//! 32/12/32), the cipher is raw `ChaCha20`, and `mac` is
//! `HMAC-SHA256(hmac_key, nonce || ciphertext)` verified in constant time
//! before decryption. The padded standard-alphabet base64 (`base64ct::Base64`)
//! matches `@scure/base`'s strictness: padding required; whitespace, URL-safe
//! characters, and non-canonical trailing bits rejected.
//!
//! All key material and intermediate buffers are zeroized on drop.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/44.md>

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::{PublicKey, SecretKey};
use base64ct::{Base64, Encoding};
use chacha20::cipher::StreamCipher;
use chacha20::{ChaCha20, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::nips::{Error, ErrorKind, Result};

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 2;
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
const MIN_PLAINTEXT_LEN: usize = 1;
const MAX_PLAINTEXT_LEN: usize = u32::MAX as usize;
const EXTENDED_PREFIX_THRESHOLD: usize = 0x1_0000;
const SHORT_PREFIX_LEN: usize = 2;
const EXTENDED_PREFIX_LEN: usize = 6;
/// Shortest decoded payload: version + nonce + 2-byte prefix + 32-byte padded
/// minimum + mac.
const MIN_DATA_LEN: usize = 1 + NONCE_LEN + SHORT_PREFIX_LEN + 32 + MAC_LEN;
/// Shortest base64 payload (132 chars for 99 bytes, padded).
const MIN_PAYLOAD_CHARS: usize = 132;

fn crypto_error(message: impl Into<alloc::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Crypto, message)
}

/// Builds an `HMAC-SHA256` for a 32-byte key. `KeyInit::new` takes a
/// block-size key; a 32-byte key zero-padded to 64 bytes is exactly what
/// `new_from_slice` produces internally for a sub-block key, and it cannot
/// fail.
fn hmac_sha256(key: &[u8; 32]) -> HmacSha256 {
    let mut block = Zeroizing::new([0u8; 64]);
    block.split_at_mut(32).0.copy_from_slice(key);
    HmacSha256::new((&*block).into())
}

fn hmac_sha256_tag(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = hmac_sha256(key);
    for part in parts {
        mac.update(part);
    }
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Same constant as TS `DEFAULT_MAX_PAYLOAD_CHARS`: the base64 length of a
/// payload carrying exactly 1 MiB (`0x100000` bytes) of plaintext — version(1)
/// + nonce(32) + extended prefix(6) + `calc_padded_len`(1 MiB) + mac(32).
pub const DEFAULT_MAX_PAYLOAD_CHARS: usize =
    (1 + NONCE_LEN + EXTENDED_PREFIX_LEN + 0x10_0000 + MAC_LEN).div_ceil(3) * 4;

/// `HKDF-extract(SHA-256, salt = "nip44-v2", shared_x)` — the conversation key
/// shared with a peer (TS `getConversationKey` /
/// `getConversationKeyFromSharedSecret`).
///
/// No `PartialEq`, `Display`, `FromStr`, or serde: secret material is never
/// compared in non-constant time or formatted into logs.
#[derive(Clone)]
pub struct ConversationKey([u8; 32]);

impl ConversationKey {
    /// Derives the key from our `secret` and the peer's `peer` public key:
    /// `secp256k1::ecdh::shared_secret_point` with the peer lifted to an
    /// even-parity x-only key, then [`Self::from_shared_secret`] on the x
    /// coordinate. The temporary `secp256k1::SecretKey` and shared point are
    /// erased before returning.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `peer`'s bytes do not lift to a curve point.
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self> {
        crate::nips::ecdh::shared_secret_x(secret, peer)
            .map(|shared_x| Self::from_shared_secret(&shared_x))
    }

    /// HKDF-extracts a conversation key from a raw ECDH x coordinate (TS
    /// `getConversationKeyFromSharedSecret`).
    #[must_use]
    pub fn from_shared_secret(shared_x: &[u8; 32]) -> Self {
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared_x);
        let mut key = [0u8; 32];
        key.copy_from_slice(&prk);
        // `prk` and the `Hkdf` struct both retain the pseudorandom key —
        // wipe what is reachable.
        prk.as_mut_slice().zeroize();
        drop(hkdf);
        Self(key)
    }

    /// Wraps already-derived key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A copy of the 32 key bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConversationKey(..)")
    }
}

impl Drop for ConversationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ConversationKey {}

/// Per-message keys expanded from the conversation key and nonce (TS
/// `getMessageKeys`): `HKDF-expand(conversation_key, nonce, 76)` split into
/// `chacha_key` (32) / `chacha_nonce` (12) / `hmac_key` (32).
#[derive(Clone)]
pub struct MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

impl MessageKeys {
    /// `HKDF-expand(PRK = key, info = nonce, L = 76)`: three 32-byte
    /// `HMAC-SHA256` blocks, the last truncated to 12 bytes. All inputs are
    /// fixed-size, so every HMAC is infallible.
    #[must_use]
    pub fn derive(key: &ConversationKey, nonce: &[u8; 32]) -> Self {
        let block = |prev: &[u8], counter: u8| -> [u8; 32] {
            hmac_sha256_tag(&key.0, &[prev, nonce, &[counter]])
        };
        let t1 = block(&[], 1);
        let t2 = Zeroizing::new(block(&t1, 2));
        let t3 = Zeroizing::new(block(&*t2, 3));
        let (t2_head, t2_tail) = t2.split_at(12);
        let (t3_head, _) = t3.split_at(12);
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce.copy_from_slice(t2_head);
        let mut hmac_key = [0u8; 32];
        let (hmac_a, hmac_b) = hmac_key.split_at_mut(20);
        hmac_a.copy_from_slice(t2_tail);
        hmac_b.copy_from_slice(t3_head);
        Self {
            chacha_key: t1,
            chacha_nonce,
            hmac_key,
        }
    }

    /// The 32-byte `ChaCha20` key.
    #[must_use]
    pub const fn chacha_key(&self) -> &[u8; 32] {
        &self.chacha_key
    }

    /// The 12-byte `ChaCha20` nonce.
    #[must_use]
    pub const fn chacha_nonce(&self) -> &[u8; 12] {
        &self.chacha_nonce
    }

    /// The 32-byte `HMAC-SHA256` key.
    #[must_use]
    pub const fn hmac_key(&self) -> &[u8; 32] {
        &self.hmac_key
    }
}

impl core::fmt::Debug for MessageKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MessageKeys(..)")
    }
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.chacha_key.zeroize();
        self.chacha_nonce.zeroize();
        self.hmac_key.zeroize();
    }
}

impl ZeroizeOnDrop for MessageKeys {}

/// The padded plaintext length for `len` (TS `calcPaddedLen`): 32-byte chunks
/// up to a 256-byte power of two, then eighths of the next power of two.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] when `len` is zero or exceeds the `u32` maximum
/// (TS also rejects non-integers and negatives — unrepresentable in
/// `usize`), or when the padded length does not fit `usize` (32-bit
/// targets: NIP-44 padded lengths reach `2^32`).
pub fn calc_padded_len(len: usize) -> Result<usize> {
    let len = u64::try_from(len).map_err(|_| crypto_error("invalid plaintext size"))?;
    usize::try_from(padded_len(len)?)
        .map_err(|_| crypto_error("padded length exceeds the platform's address space"))
}

/// `calc_padded_len` computed in `u64` so the `2^32` padded-length ceiling
/// exists on 32-bit targets instead of overflowing `usize`.
fn padded_len(len: u64) -> Result<u64> {
    if !(1..=u64::from(u32::MAX)).contains(&len) {
        return Err(crypto_error(
            "invalid plaintext size: must be between 1 and 4294967295 bytes",
        ));
    }
    if len <= 32 {
        return Ok(32);
    }
    // TS computes `2 ** (floor(log2(len - 1)) + 1)` — the smallest power of
    // two strictly greater than `len - 1`, which is `next_power_of_two(len)`.
    let next_power = len.next_power_of_two();
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    // `len <= u32::MAX` and `chunk` is a power of two, so the product is at
    // most `2^32 + 2^28` and cannot overflow `u64`.
    Ok(chunk * ((len - 1) / chunk + 1))
}

fn pad(plaintext: &str) -> Result<Zeroizing<Vec<u8>>> {
    let unpadded = plaintext.as_bytes();
    let len = unpadded.len();
    if !(MIN_PLAINTEXT_LEN..=MAX_PLAINTEXT_LEN).contains(&len) {
        return Err(crypto_error(
            "invalid plaintext size: must be between 1 and 4294967295 bytes",
        ));
    }
    let padded_len = calc_padded_len(len)?;
    let prefix_len = if len >= EXTENDED_PREFIX_THRESHOLD {
        EXTENDED_PREFIX_LEN
    } else {
        SHORT_PREFIX_LEN
    };
    let Some(total) = prefix_len.checked_add(padded_len) else {
        return Err(crypto_error(
            "padded length exceeds the platform's address space",
        ));
    };
    let mut padded = Zeroizing::new(Vec::with_capacity(total));
    if len >= EXTENDED_PREFIX_THRESHOLD {
        // `len <= u32::MAX` is guaranteed by the range check above.
        let len32 =
            u32::try_from(len).map_err(|_| crypto_error("invalid plaintext size: too large"))?;
        padded.extend_from_slice(&[0, 0]);
        padded.extend_from_slice(&len32.to_be_bytes());
    } else {
        // `len < 65536` here, so the conversion cannot fail.
        let len16 = u16::try_from(len).map_err(|_| crypto_error("invalid plaintext size"))?;
        padded.extend_from_slice(&len16.to_be_bytes());
    }
    padded.extend_from_slice(unpadded);
    padded.resize(total, 0);
    Ok(padded)
}

fn unpad(padded: &[u8]) -> Result<String> {
    fn invalid<T>() -> Result<T> {
        Err(crypto_error("invalid padding"))
    }
    let Some(&prefix) = padded.first_chunk::<2>() else {
        return invalid();
    };
    let first_two = u16::from_be_bytes(prefix);
    let (unpadded_len, prefix_len) = if first_two == 0 {
        let Some(len_bytes) = padded
            .get(SHORT_PREFIX_LEN..EXTENDED_PREFIX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
        else {
            return invalid();
        };
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len < EXTENDED_PREFIX_THRESHOLD {
            return invalid();
        }
        (len, EXTENDED_PREFIX_LEN)
    } else {
        (usize::from(first_two), SHORT_PREFIX_LEN)
    };
    if !(MIN_PLAINTEXT_LEN..=MAX_PLAINTEXT_LEN).contains(&unpadded_len) {
        return invalid();
    }
    let Some(end) = prefix_len.checked_add(unpadded_len) else {
        return invalid();
    };
    let Some(unpadded) = padded.get(prefix_len..end) else {
        return invalid();
    };
    if padded.len() != prefix_len + calc_padded_len(unpadded_len)? {
        return invalid();
    }
    Ok(String::from_utf8_lossy(unpadded).into_owned())
}

/// `HMAC-SHA256(hmac_key, nonce || message)` — the payload MAC.
fn hmac_aad(key: &[u8; 32], message: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    hmac_sha256_tag(key, &[nonce, message])
}

/// Splits a decoded payload body into `(nonce, ciphertext, mac)`; `data` has
/// already passed the minimum-length and version checks, so the splits cannot
/// fail.
fn split_payload(data: &[u8]) -> Option<(&[u8; 32], &[u8], &[u8; 32])> {
    let (_, rest) = data.split_first()?;
    let (nonce, rest) = rest.split_first_chunk::<NONCE_LEN>()?;
    let (ciphertext, mac) = rest.split_last_chunk::<MAC_LEN>()?;
    Some((nonce, ciphertext, mac))
}

/// Encrypts `plaintext` with a caller-supplied `nonce` (TS
/// `nip44.encrypt(plaintext, key, nonce)`).
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on an out-of-range plaintext size.
pub fn encrypt_with_nonce(
    plaintext: &str,
    key: &ConversationKey,
    nonce: &[u8; 32],
) -> Result<String> {
    let keys = MessageKeys::derive(key, nonce);
    let mut data = pad(plaintext)?;
    ChaCha20::new(keys.chacha_key().into(), keys.chacha_nonce().into())
        .apply_keystream(data.as_mut_slice());
    let mac = hmac_aad(keys.hmac_key(), data.as_slice(), nonce);
    let mut payload = Vec::with_capacity(1 + NONCE_LEN + data.len() + MAC_LEN);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(data.as_slice());
    payload.extend_from_slice(&mac);
    Ok(Base64::encode_string(&payload))
}

/// Encrypts `plaintext` with a nonce drawn from `rng`.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on an out-of-range plaintext size.
pub fn encrypt_with_rng<R>(plaintext: &str, key: &ConversationKey, rng: &mut R) -> Result<String>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce.as_mut_slice());
    encrypt_with_nonce(plaintext, key, &nonce)
}

/// Encrypts `plaintext` with an OS-entropy nonce.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on an out-of-range plaintext size.
///
/// # Panics
///
/// When the OS entropy source fails — the same contract as
/// [`crate::SecretKey::generate`].
#[cfg(feature = "os-rng")]
pub fn encrypt(plaintext: &str, key: &ConversationKey) -> Result<String> {
    encrypt_with_rng(plaintext, key, &mut rand_core::UnwrapErr(getrandom::SysRng))
}

/// Decrypts a NIP-44 `payload` under [`DEFAULT_MAX_PAYLOAD_CHARS`].
///
/// # Errors
///
/// [`ErrorKind::Crypto`] — see [`decrypt_with_max_len`].
pub fn decrypt(payload: &str, key: &ConversationKey) -> Result<String> {
    decrypt_with_max_len(payload, key, DEFAULT_MAX_PAYLOAD_CHARS)
}

/// Decrypts a NIP-44 `payload`, rejecting payloads longer than
/// `max_payload_chars` base64 characters.
///
/// The order matches TS and the spec: `#`/length/version checks first, then a
/// constant-time MAC verify (`verify_slice` — decryption does not run on MAC
/// failure), then padding validation. Plaintext is UTF-8 lossy-decoded like
/// `TextDecoder`.
///
/// # Errors
///
/// [`ErrorKind::Crypto`] on a bad length, unknown version, bad base64, MAC
/// mismatch, or invalid padding.
pub fn decrypt_with_max_len(
    payload: &str,
    key: &ConversationKey,
    max_payload_chars: usize,
) -> Result<String> {
    if payload.starts_with('#') {
        return Err(crypto_error("unknown encryption version"));
    }
    if payload.len() < MIN_PAYLOAD_CHARS || payload.len() > max_payload_chars {
        return Err(crypto_error("invalid payload length"));
    }
    let mut buf = Zeroizing::new(vec![0u8; payload.len()]);
    let data = Base64::decode(payload.as_bytes(), buf.as_mut_slice())
        .map_err(|_| crypto_error("invalid base64"))?;
    if data.len() < MIN_DATA_LEN {
        return Err(crypto_error("invalid data length"));
    }
    if data.first() != Some(&VERSION) {
        return Err(crypto_error("unknown encryption version"));
    }
    let Some((nonce, ciphertext, mac)) = split_payload(data) else {
        return Err(crypto_error("invalid data length"));
    };
    let keys = MessageKeys::derive(key, nonce);
    hmac_sha256(keys.hmac_key())
        .chain_update(nonce)
        .chain_update(ciphertext)
        .verify_slice(mac)
        .map_err(|_| crypto_error("invalid MAC"))?;
    let mut padded = Zeroizing::new(ciphertext.to_vec());
    ChaCha20::new(keys.chacha_key().into(), keys.chacha_nonce().into())
        .apply_keystream(padded.as_mut_slice());
    unpad(padded.as_slice())
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
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const SEC1: &str = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
    const PUB2: &str = "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133";
    const NONCE: &[u8; 32] = &[0x0b; 32];

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").expect("writing to a String is infallible");
            out
        })
    }

    fn conversation_key() -> ConversationKey {
        let secret = SecretKey::from_hex(SEC1).unwrap();
        let peer = PublicKey::from_hex(PUB2).unwrap();
        ConversationKey::derive(&secret, &peer).unwrap()
    }

    #[test]
    fn derive_matches_the_official_vector() {
        let key = conversation_key();
        assert_eq!(
            hex(&key.to_bytes()),
            "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"
        );
        assert_eq!(format!("{key:?}"), "ConversationKey(..)");
    }

    #[test]
    fn from_shared_secret_matches_derive() {
        // The ECDH x-coordinate of the first shared-secret vector case.
        let shared = unhex("5ad01c0fc57ed5f92a0518b6440ca876eb1f247ddbb237ba1caaabbf4cebbdce");
        let shared: [u8; 32] = shared.try_into().unwrap();
        assert_eq!(
            hex(&ConversationKey::from_shared_secret(&shared).to_bytes()),
            "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"
        );
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn message_keys_match_the_official_vector() {
        let key = ConversationKey::from_bytes(
            unhex("a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54")
                .try_into()
                .unwrap(),
        );
        let keys = MessageKeys::derive(
            &key,
            &unhex("e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72")
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            hex(keys.chacha_key()),
            "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76"
        );
        assert_eq!(hex(keys.chacha_nonce()), "c4ad129bb01180c0933a160c");
        assert_eq!(
            hex(keys.hmac_key()),
            "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4"
        );
        assert_eq!(format!("{keys:?}"), "MessageKeys(..)");
    }

    #[test]
    fn calc_padded_len_boundaries() {
        assert_eq!(calc_padded_len(0).unwrap_err().kind(), ErrorKind::Crypto);
        assert_eq!(calc_padded_len(1).unwrap(), 32);
        assert_eq!(calc_padded_len(32).unwrap(), 32);
        assert_eq!(calc_padded_len(33).unwrap(), 64);
        assert_eq!(calc_padded_len(250).unwrap(), 256);
        assert_eq!(calc_padded_len(320).unwrap(), 320);
        assert_eq!(calc_padded_len(515).unwrap(), 640);
        assert_eq!(calc_padded_len(65535).unwrap(), 65536);
        assert_eq!(calc_padded_len(65536).unwrap(), 65536);
        // len - 1 is exactly 2^16: the bucket switches to the 2^17 table.
        assert_eq!(calc_padded_len(65537).unwrap(), 81920);
    }

    #[test]
    fn calc_padded_len_uses_64_bit_math() {
        // The spec ceiling: the u32 length prefix allows plaintexts up to
        // 0xFFFF_FFFF, whose padded length is exactly 2^32 — past `usize::MAX`
        // on 32-bit targets, so the helper is exercised directly.
        assert_eq!(padded_len(u64::from(u32::MAX)).unwrap(), 0x1_0000_0000);
        assert_eq!(
            padded_len(u64::from(u32::MAX) + 1).unwrap_err().kind(),
            ErrorKind::Crypto
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(calc_padded_len(u32::MAX as usize).unwrap(), 0x1_0000_0000);
            assert_eq!(
                calc_padded_len(u32::MAX as usize + 1).unwrap_err().kind(),
                ErrorKind::Crypto
            );
        }
    }

    #[test]
    fn encrypt_matches_the_official_vector() {
        let key = ConversationKey::from_bytes(
            unhex("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
                .try_into()
                .unwrap(),
        );
        let mut nonce = [0u8; 32];
        *nonce.last_mut().unwrap() = 1;
        let payload = encrypt_with_nonce("a", &key, &nonce).unwrap();
        assert_eq!(
            payload,
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
        );
    }

    #[test]
    fn round_trip() {
        let key = conversation_key();
        let payload = encrypt_with_nonce("hi", &key, NONCE).unwrap();
        assert_eq!(decrypt(&payload, &key).unwrap(), "hi");
        assert_eq!(decrypt("#", &key).unwrap_err().kind(), ErrorKind::Crypto);
        assert_eq!(
            decrypt_with_max_len(&payload, &key, payload.len() - 1)
                .unwrap_err()
                .kind(),
            ErrorKind::Crypto
        );
        let mut corrupted = payload;
        let at = corrupted.len() - 5;
        corrupted.replace_range(at..=at, "A");
        assert_eq!(
            decrypt(&corrupted, &key).unwrap_err().kind(),
            ErrorKind::Crypto
        );
    }

    #[test]
    fn base64_strictness_matches_scure() {
        let key = conversation_key();
        // A 33-byte plaintext pads to 34 + 32 + 66 + 32 = 131 decoded bytes,
        // which base64-encodes with a trailing `=` to exercise the
        // unpadded/extra-padding rejections.
        let payload = encrypt_with_nonce(&"a".repeat(33), &key, NONCE).unwrap();
        assert!(payload.ends_with('='));
        let mut rejects = vec![
            String::from(payload.trim_end_matches('=')),
            format!("{payload} "),
            format!(" {payload}"),
            format!("{payload}\n"),
            format!("{payload}="),
        ];
        // URL-safe alphabet substitutions only diverge when present.
        if payload.contains('+') {
            rejects.push(payload.replace('+', "-"));
        }
        if payload.contains('/') {
            rejects.push(payload.replace('/', "_"));
        }
        for bad in rejects {
            assert_eq!(
                decrypt(&bad, &key).unwrap_err().kind(),
                ErrorKind::Crypto,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn plaintext_size_limits() {
        let key = conversation_key();
        assert_eq!(
            encrypt_with_nonce("", &key, NONCE).unwrap_err().kind(),
            ErrorKind::Crypto
        );
        assert!(encrypt_with_nonce("a", &key, NONCE).is_ok());
        // 65536 uses the extended u32 prefix; 65535 stays on u16.
        assert!(encrypt_with_nonce(&"a".repeat(65536), &key, NONCE).is_ok());
        assert_eq!(
            decrypt(
                &encrypt_with_nonce(&"a".repeat(65536), &key, NONCE).unwrap(),
                &key
            )
            .unwrap()
            .len(),
            65536
        );
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn encrypt_draws_an_os_nonce() {
        let key = conversation_key();
        let payload = encrypt("os-rng round trip", &key).unwrap();
        assert_eq!(decrypt(&payload, &key).unwrap(), "os-rng round trip");
    }
}
