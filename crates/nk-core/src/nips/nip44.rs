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

use crate::nips::ecdh;

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

/// The error type returned by NIP-44 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The peer's bytes do not lift to a curve point.
    #[error("invalid public key")]
    Derive,
    /// `rng` failed to fill the nonce.
    #[error("rng failed")]
    Rng,
    /// The plaintext is empty or exceeds the `u32` length prefix.
    #[error("invalid plaintext size: must be between 1 and 4294967295 bytes")]
    PlaintextSize,
    /// The padded length does not fit `usize` (32-bit targets).
    #[error("padded length exceeds the platform's address space")]
    PaddedOverflow,
    /// The payload is outside the allowed base64 length window.
    #[error("invalid payload length")]
    PayloadLength,
    /// The payload version is not 2 (or starts with `#`).
    #[error("unknown encryption version")]
    UnknownVersion,
    /// The payload is not padded standard-alphabet base64.
    #[error("invalid base64")]
    InvalidBase64,
    /// The decoded payload is too short for version + nonce + mac.
    #[error("invalid data length")]
    DataLength,
    /// The payload MAC did not verify in constant time.
    #[error("invalid MAC")]
    Mac,
    /// The decrypted padding block is malformed.
    #[error("invalid padding")]
    Padding,
}

/// Result type for NIP-44 operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

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

/// The default payload cap: the base64 length of a
/// payload carrying exactly 1 MiB (`0x100000` bytes) of plaintext — version(1)
/// + nonce(32) + extended prefix(6) + `calc_padded_len`(1 MiB) + mac(32).
pub const DEFAULT_MAX_PAYLOAD_CHARS: usize =
    (1 + NONCE_LEN + EXTENDED_PREFIX_LEN + 0x10_0000 + MAC_LEN).div_ceil(3) * 4;

/// `HKDF-extract(SHA-256, salt = "nip44-v2", shared_x)` — the conversation key
/// shared with a peer (NIP-44 `getConversationKey` equivalent /
/// `getConversationKeyFromSharedSecret`).
///
/// No `PartialEq`, `Display`, `FromStr`, or serde: secret material is never
/// compared in non-constant time or formatted into logs.
#[derive(Clone)]
pub struct ConversationKey([u8; 32]);

impl ConversationKey {
    /// Derives the key from our `secret` and the peer's `peer` public key:
    /// `secp256k1::ecdh::shared_secret_point` with the peer lifted to an
    /// even-parity x-only key, then HKDF-extract on the x coordinate. The
    /// temporary `secp256k1::SecretKey` and shared point are erased before
    /// returning.
    ///
    /// # Errors
    ///
    /// [`Error::Derive`] when `peer`'s bytes do not lift to a curve point.
    ///
    /// # Examples
    ///
    /// ```
    /// use nk_core::nips::nip44::ConversationKey;
    /// use nk_core::{SecretKey, Keys};
    ///
    /// let alice = SecretKey::from_bytes([1; 32]).unwrap();
    /// let bob = SecretKey::from_bytes([2; 32]).unwrap();
    /// let key = ConversationKey::derive(&alice, &bob.public_key())?;
    /// # #[cfg(feature = "os-rng")]
    /// # {
    /// let payload = key.encrypt("hi", &mut nk_core::SysRng)?;
    /// assert_eq!(key.decrypt(&payload)?, "hi");
    /// # }
    /// # Ok::<(), nk_core::nips::nip44::Error>(())
    /// ```
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self> {
        ecdh::shared_secret_x(secret, peer)
            .map(|shared_x| Self::from_shared_secret(&shared_x))
            .ok_or(Error::Derive)
    }

    /// HKDF-extracts a conversation key from a raw ECDH x coordinate (TS
    /// `getConversationKeyFromSharedSecret`).
    pub(crate) fn from_shared_secret(shared_x: &[u8; 32]) -> Self {
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
    #[cfg(test)]
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A copy of the 32 key bytes.
    #[cfg(test)]
    pub(crate) const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Encrypts `plaintext` with a nonce drawn from `rng` (TS
    /// `nip44.encrypt`).
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when `rng` fails; [`Error::PlaintextSize`] or
    /// [`Error::PaddedOverflow`] on an out-of-range plaintext size.
    pub fn encrypt<R>(&self, plaintext: &str, rng: &mut R) -> Result<String>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
        rng.try_fill_bytes(nonce.as_mut_slice())
            .map_err(|_| Error::Rng)?;
        self.encrypt_with_nonce(plaintext, &nonce)
    }

    /// Encrypts `plaintext` with a caller-supplied `nonce` — the
    /// deterministic form used by shared test vectors.
    ///
    /// # Errors
    ///
    /// [`Error::PlaintextSize`] or [`Error::PaddedOverflow`] on an
    /// out-of-range plaintext size.
    pub(crate) fn encrypt_with_nonce(&self, plaintext: &str, nonce: &[u8; 32]) -> Result<String> {
        let keys = MessageKeys::derive(self, nonce);
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

    /// Decrypts a NIP-44 `payload` under [`DEFAULT_MAX_PAYLOAD_CHARS`].
    ///
    /// For a different cap use [`ConversationKey::decrypt_with_limit`].
    ///
    /// The order matches TS and the spec: `#`/length/version checks first,
    /// then a constant-time MAC verify (decryption does not run on MAC
    /// failure), then padding validation. Plaintext is UTF-8 lossy-decoded
    /// like `TextDecoder`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownVersion`], [`Error::PayloadLength`],
    /// [`Error::InvalidBase64`], [`Error::DataLength`], [`Error::Mac`], or
    /// [`Error::Padding`].
    pub fn decrypt(&self, payload: &str) -> Result<String> {
        self.decrypt_with_limit(payload, DEFAULT_MAX_PAYLOAD_CHARS)
    }

    /// [`Self::decrypt`] rejecting payloads longer than `max_payload_chars`
    /// base64 characters.
    /// Decrypts `payload`, rejecting ciphertexts longer than
    /// `max_payload_len` characters, overriding the default
    /// option. Pass [`DEFAULT_MAX_PAYLOAD_CHARS`] for the spec default.
    ///
    /// # Errors
    ///
    /// The same conditions as [`ConversationKey::decrypt`].
    pub fn decrypt_with_limit(&self, payload: &str, max_payload_chars: usize) -> Result<String> {
        if payload.starts_with('#') {
            return Err(Error::UnknownVersion);
        }
        if payload.len() < MIN_PAYLOAD_CHARS || payload.len() > max_payload_chars {
            return Err(Error::PayloadLength);
        }
        let mut buf = Zeroizing::new(vec![0u8; payload.len()]);
        let data = Base64::decode(payload.as_bytes(), buf.as_mut_slice())
            .map_err(|_| Error::InvalidBase64)?;
        if data.len() < MIN_DATA_LEN {
            return Err(Error::DataLength);
        }
        if data.first() != Some(&VERSION) {
            return Err(Error::UnknownVersion);
        }
        let Some((nonce, ciphertext, mac)) = split_payload(data) else {
            return Err(Error::DataLength);
        };
        let keys = MessageKeys::derive(self, nonce);
        hmac_sha256(keys.hmac_key())
            .chain_update(nonce)
            .chain_update(ciphertext)
            .verify_slice(mac)
            .map_err(|_| Error::Mac)?;
        let mut padded = Zeroizing::new(ciphertext.to_vec());
        ChaCha20::new(keys.chacha_key().into(), keys.chacha_nonce().into())
            .apply_keystream(padded.as_mut_slice());
        unpad(padded.as_slice())
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
pub(crate) struct MessageKeys {
    chacha_key: [u8; 32],
    chacha_nonce: [u8; 12],
    hmac_key: [u8; 32],
}

impl MessageKeys {
    /// `HKDF-expand(PRK = key, info = nonce, L = 76)`: three 32-byte
    /// `HMAC-SHA256` blocks, the last truncated to 12 bytes. All inputs are
    /// fixed-size, so every HMAC is infallible.
    pub(crate) fn derive(key: &ConversationKey, nonce: &[u8; 32]) -> Self {
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

    pub(crate) const fn chacha_key(&self) -> &[u8; 32] {
        &self.chacha_key
    }

    pub(crate) const fn chacha_nonce(&self) -> &[u8; 12] {
        &self.chacha_nonce
    }

    pub(crate) const fn hmac_key(&self) -> &[u8; 32] {
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

/// The padded plaintext length for `len`: 32-byte chunks
/// up to a 256-byte power of two, then eighths of the next power of two.
///
/// # Errors
///
/// [`Error::PlaintextSize`] when `len` is zero or exceeds the `u32` maximum,
/// [`Error::PaddedOverflow`] when the padded length does not fit `usize`
/// (32-bit targets: NIP-44 padded lengths reach `2^32`).
pub(crate) fn calc_padded_len(len: usize) -> Result<usize> {
    let len = u64::try_from(len).map_err(|_| Error::PlaintextSize)?;
    usize::try_from(padded_len(len)?).map_err(|_| Error::PaddedOverflow)
}

/// `calc_padded_len` computed in `u64` so the `2^32` padded-length ceiling
/// exists on 32-bit targets instead of overflowing `usize`.
fn padded_len(len: u64) -> Result<u64> {
    if !(1..=u64::from(u32::MAX)).contains(&len) {
        return Err(Error::PlaintextSize);
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
        return Err(Error::PlaintextSize);
    }
    let padded_len = calc_padded_len(len)?;
    let prefix_len = if len >= EXTENDED_PREFIX_THRESHOLD {
        EXTENDED_PREFIX_LEN
    } else {
        SHORT_PREFIX_LEN
    };
    let total = prefix_len
        .checked_add(padded_len)
        .ok_or(Error::PaddedOverflow)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(total));
    if len >= EXTENDED_PREFIX_THRESHOLD {
        // `len <= u32::MAX` is guaranteed by the range check above.
        let len32 = u32::try_from(len).map_err(|_| Error::PlaintextSize)?;
        padded.extend_from_slice(&[0, 0]);
        padded.extend_from_slice(&len32.to_be_bytes());
    } else {
        // `len < 65536` here, so the conversion cannot fail.
        let len16 = u16::try_from(len).map_err(|_| Error::PlaintextSize)?;
        padded.extend_from_slice(&len16.to_be_bytes());
    }
    padded.extend_from_slice(unpadded);
    padded.resize(total, 0);
    Ok(padded)
}

fn unpad(padded: &[u8]) -> Result<String> {
    let Some(&prefix) = padded.first_chunk::<2>() else {
        return Err(Error::Padding);
    };
    let first_two = u16::from_be_bytes(prefix);
    let (unpadded_len, prefix_len) = if first_two == 0 {
        let Some(len_bytes) = padded
            .get(SHORT_PREFIX_LEN..EXTENDED_PREFIX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
        else {
            return Err(Error::Padding);
        };
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len < EXTENDED_PREFIX_THRESHOLD {
            return Err(Error::Padding);
        }
        (len, EXTENDED_PREFIX_LEN)
    } else {
        (usize::from(first_two), SHORT_PREFIX_LEN)
    };
    if !(MIN_PLAINTEXT_LEN..=MAX_PLAINTEXT_LEN).contains(&unpadded_len) {
        return Err(Error::Padding);
    }
    let Some(end) = prefix_len.checked_add(unpadded_len) else {
        return Err(Error::Padding);
    };
    let Some(unpadded) = padded.get(prefix_len..end) else {
        return Err(Error::Padding);
    };
    if padded.len() != prefix_len + calc_padded_len(unpadded_len).map_err(|_| Error::Padding)? {
        return Err(Error::Padding);
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::excessive_nesting,
        clippy::missing_assert_message,
        clippy::option_if_let_else,
        clippy::or_fun_call,
        clippy::str_to_string,
        reason = "tests fail by panicking"
    )]

    use alloc::format;
    use alloc::vec::Vec;

    use serde::Deserialize;
    use sha2::Digest;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_arr<const N: usize>(s: &str) -> Option<[u8; N]> {
        crate::hex::decode_caller::<N>(s).ok()
    }

    fn unhex_arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().expect("hex length")
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").expect("writing to a String is infallible");
            out
        })
    }

    const OFFICIAL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip44/official.json"
    ));
    const EXTENDED: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip44/extended.json"
    ));
    const SHARED_SECRET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip44/shared-secret.json"
    ));

    #[test]
    fn official_valid() {
        #[derive(Deserialize)]
        struct CkCase {
            sec1: String,
            pub2: String,
            conversation_key: String,
        }
        #[derive(Deserialize)]
        struct MkNonce {
            nonce: String,
            chacha_key: String,
            chacha_nonce: String,
            hmac_key: String,
        }
        #[derive(Deserialize)]
        struct MkCase {
            conversation_key: String,
            keys: Vec<MkNonce>,
        }
        #[derive(Deserialize)]
        struct EdCase {
            conversation_key: String,
            nonce: String,
            plaintext: String,
            payload: String,
        }
        #[derive(Deserialize)]
        struct LongCase {
            conversation_key: String,
            nonce: String,
            pattern: String,
            repeat: usize,
            plaintext_sha256: String,
            payload_sha256: String,
        }
        #[derive(Deserialize)]
        struct Valid {
            get_conversation_key: Vec<CkCase>,
            get_message_keys: MkCase,
            calc_padded_len: Vec<[usize; 2]>,
            encrypt_decrypt: Vec<EdCase>,
            encrypt_decrypt_long_msg: Vec<LongCase>,
        }
        #[derive(Deserialize)]
        struct V2 {
            valid: Valid,
        }
        #[derive(Deserialize)]
        struct Doc {
            v2: V2,
        }
        let doc: Doc = serde_json::from_str(OFFICIAL).unwrap();

        for (i, c) in doc.v2.valid.get_conversation_key.iter().enumerate() {
            let secret = SecretKey::from_hex(&c.sec1).unwrap();
            let peer = PublicKey::from_hex(&c.pub2).unwrap();
            let key = ConversationKey::derive(&secret, &peer).unwrap();
            assert_eq!(hex(&key.to_bytes()), c.conversation_key, "ck case {i}");
        }

        {
            let c = &doc.v2.valid.get_message_keys;
            let ck = ConversationKey::from_bytes(unhex_arr(&c.conversation_key));
            for (j, n) in c.keys.iter().enumerate() {
                let keys = MessageKeys::derive(&ck, &unhex_arr(&n.nonce));
                assert_eq!(hex(keys.chacha_key()), n.chacha_key, "mk {j} chacha_key");
                assert_eq!(
                    hex(keys.chacha_nonce()),
                    n.chacha_nonce,
                    "mk {j} chacha_nonce"
                );
                assert_eq!(hex(keys.hmac_key()), n.hmac_key, "mk {j} hmac_key");
            }
        }

        for [input, expected] in &doc.v2.valid.calc_padded_len {
            assert_eq!(calc_padded_len(*input).unwrap(), *expected, "pad {input}");
        }

        for (i, c) in doc.v2.valid.encrypt_decrypt.iter().enumerate() {
            let ck = ConversationKey::from_bytes(unhex_arr(&c.conversation_key));
            let payload = ck
                .encrypt_with_nonce(&c.plaintext, &unhex_arr(&c.nonce))
                .unwrap();
            assert_eq!(payload, c.payload, "ed case {i}: encrypt");
            assert_eq!(
                ck.decrypt(&c.payload).unwrap(),
                c.plaintext,
                "ed case {i}: decrypt"
            );
        }

        for (i, c) in doc.v2.valid.encrypt_decrypt_long_msg.iter().enumerate() {
            let ck = ConversationKey::from_bytes(unhex_arr(&c.conversation_key));
            let plaintext = c.pattern.repeat(c.repeat);
            assert_eq!(
                hex(&Sha256::digest(plaintext.as_bytes())),
                c.plaintext_sha256,
                "long {i}: plaintext sha"
            );
            let payload = ck
                .encrypt_with_nonce(&plaintext, &unhex_arr(&c.nonce))
                .unwrap();
            assert_eq!(
                hex(&Sha256::digest(payload.as_bytes())),
                c.payload_sha256,
                "long {i}: payload sha"
            );
            assert_eq!(
                ck.decrypt(&payload).unwrap(),
                plaintext,
                "long {i}: decrypt"
            );
        }
    }

    #[test]
    fn official_invalid() {
        #[derive(Deserialize)]
        struct DecCase {
            conversation_key: String,
            payload: String,
        }
        #[derive(Deserialize)]
        struct CkCase {
            sec1: String,
            pub2: String,
        }
        #[derive(Deserialize)]
        struct Invalid {
            encrypt_msg_lengths: Vec<usize>,
            get_conversation_key: Vec<CkCase>,
            decrypt: Vec<DecCase>,
        }
        #[derive(Deserialize)]
        struct V2 {
            invalid: Invalid,
        }
        #[derive(Deserialize)]
        struct Doc {
            v2: V2,
        }
        let doc: Doc = serde_json::from_str(OFFICIAL).unwrap();

        let key = ConversationKey::from_bytes([7; 32]);
        for len in &doc.v2.invalid.encrypt_msg_lengths {
            let plaintext = "a".repeat(*len);
            // Mirrors packages/nostr/tests/nip44.test.ts: only 0 must fail —
            // the extended u32 prefix (3rdparty/nips/44.md) makes 65536+
            // encryptable; entries over 1 MiB are skipped like the TS test.
            if *len == 0 {
                assert!(
                    key.encrypt_with_nonce(&plaintext, &[0; 32]).is_err(),
                    "encrypt must reject length {len}"
                );
            } else if *len <= 0x10_0000 {
                assert!(
                    key.encrypt_with_nonce(&plaintext, &[0; 32]).is_ok(),
                    "encrypt must accept length {len}"
                );
            }
        }

        for (i, c) in doc.v2.invalid.get_conversation_key.iter().enumerate() {
            let secret = SecretKey::from_hex(&c.sec1);
            let peer = PublicKey::from_hex(&c.pub2);
            // The invalid scalar/xonly inputs are rejected at parsing.
            if let (Ok(secret), Ok(peer)) = (secret, peer) {
                assert!(
                    ConversationKey::derive(&secret, &peer).is_err(),
                    "ck invalid {i}"
                );
            }
        }

        for (i, c) in doc.v2.invalid.decrypt.iter().enumerate() {
            let ck = ConversationKey::from_bytes(unhex_arr(&c.conversation_key));
            assert!(ck.decrypt(&c.payload).is_err(), "decrypt invalid {i}");
        }
    }

    #[test]
    fn extended_round_trips() {
        #[derive(Deserialize)]
        struct Case {
            pattern: String,
            repeat: usize,
            conversation_key: String,
            nonce: String,
            plaintext_sha256: String,
            payload_sha256: String,
        }
        #[derive(Deserialize)]
        struct Vec_ {
            cases: Vec<Case>,
        }
        let v: Vec_ = serde_json::from_str(EXTENDED).unwrap();
        for (i, c) in v.cases.iter().enumerate() {
            let ck = ConversationKey::from_bytes(unhex_arr(&c.conversation_key));
            let plaintext = c.pattern.repeat(c.repeat);
            assert_eq!(
                hex(&Sha256::digest(plaintext.as_bytes())),
                c.plaintext_sha256,
                "ext {i}: plaintext sha"
            );
            let payload = ck
                .encrypt_with_nonce(&plaintext, &unhex_arr(&c.nonce))
                .unwrap();
            assert_eq!(
                hex(&Sha256::digest(payload.as_bytes())),
                c.payload_sha256,
                "ext {i}: payload sha"
            );
            assert_eq!(ck.decrypt(&payload).unwrap(), plaintext, "ext {i}: decrypt");
        }
    }

    #[test]
    fn shared_secret_vectors() {
        #[derive(Deserialize)]
        struct Case {
            sec1: String,
            pub2: String,
            shared_secret: String,
            conversation_key: String,
        }
        #[derive(Deserialize)]
        struct Vec_ {
            cases: Vec<Case>,
        }
        let v: Vec_ = serde_json::from_str(SHARED_SECRET).unwrap();
        for (i, c) in v.cases.iter().enumerate() {
            let secret = SecretKey::from_hex(&c.sec1).unwrap();
            let peer = PublicKey::from_hex(&c.pub2).unwrap();
            let derived = ConversationKey::derive(&secret, &peer).unwrap();
            let from_shared = ConversationKey::from_shared_secret(&unhex_arr(&c.shared_secret));
            assert_eq!(
                hex(&derived.to_bytes()),
                c.conversation_key,
                "shared {i}: derive"
            );
            assert_eq!(
                hex(&from_shared.to_bytes()),
                c.conversation_key,
                "shared {i}: from_shared_secret"
            );
        }
    }

    #[test]
    fn calc_padded_len_uses_64_bit_math() {
        assert_eq!(padded_len(u64::from(u32::MAX)).unwrap(), 0x1_0000_0000);
        assert!(matches!(
            padded_len(u64::from(u32::MAX) + 1),
            Err(Error::PlaintextSize)
        ));
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(calc_padded_len(u32::MAX as usize).unwrap(), 0x1_0000_0000);
            assert!(matches!(
                calc_padded_len(u32::MAX as usize + 1),
                Err(Error::PlaintextSize)
            ));
        }
    }

    #[test]
    fn decrypt_error_shapes() {
        let secret = SecretKey::from_bytes([1; 32]).unwrap();
        let peer =
            PublicKey::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let key = ConversationKey::derive(&secret, &peer).unwrap();
        let payload = key
            .encrypt_with_nonce(&"a".repeat(33), &[0x0b; 32])
            .unwrap();
        assert_eq!(key.decrypt(&payload).unwrap(), "a".repeat(33));
        assert!(matches!(
            key.decrypt("#"),
            Err(Error::PayloadLength | Error::UnknownVersion)
        ));
        assert!(matches!(
            key.decrypt_with_limit(&payload, payload.len() - 1),
            Err(Error::PayloadLength)
        ));
        let mut corrupted = payload.clone();
        let at = corrupted.len() - 20;
        let replacement = if corrupted.as_bytes().get(at) == Some(&b'A') {
            "B"
        } else {
            "A"
        };
        corrupted.replace_range(at..=at, replacement);
        assert!(matches!(key.decrypt(&corrupted), Err(Error::Mac)));

        // Base64 strictness: unpadded, whitespace, extra padding.
        assert!(payload.ends_with('='));
        for bad in [
            String::from(payload.trim_end_matches('=')),
            format!("{payload} "),
            format!(" {payload}"),
            format!("{payload}\n"),
            format!("{payload}="),
        ] {
            assert!(
                matches!(
                    key.decrypt(&bad),
                    Err(Error::InvalidBase64 | Error::PayloadLength)
                ),
                "{bad:?}"
            );
        }
        assert_eq!(format!("{key:?}"), "ConversationKey(..)");
    }

    /// Replays the `nip44.v2` differential stream (`NK_DIFF_DIR`) — the
    /// `encrypt`/`decrypt` ops take explicit `conversation_key`/`nonce`, so
    /// the replay needs the crate-internal helpers.
    #[test]
    #[ignore = "requires NK_DIFF_DIR"]
    fn diff_stream() {
        use alloc::string::ToString;
        use std::path::PathBuf;

        use serde_json::Value;

        let dir = std::env::var("NK_DIFF_DIR")
            .expect("NK_DIFF_DIR is not set — run `bun packages/nostr/scripts/parity/diff.ts`");
        assert!(!dir.is_empty(), "NK_DIFF_DIR must not be empty");
        let text = std::fs::read_to_string(PathBuf::from(dir).join("nip44.v2.jsonl")).unwrap();
        let mut lines = text.lines();
        assert_eq!(
            serde_json::from_str::<Value>(lines.next().unwrap()).unwrap()["capability"],
            "nip44.v2"
        );
        let mut samples: Vec<String> = Vec::new();
        let mut mismatches = 0usize;
        for line in lines {
            let case: Value = serde_json::from_str(line).unwrap();
            let i = case["i"].as_u64().unwrap_or(0);
            let input: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
            let got: core::result::Result<String, ()> = match input["op"].as_str() {
                Some("encrypt") => {
                    match (
                        hex_arr::<32>(input["conversation_key"].as_str().unwrap_or("")),
                        hex_arr::<32>(input["nonce"].as_str().unwrap_or("")),
                    ) {
                        (Some(key), Some(nonce)) => ConversationKey::from_bytes(key)
                            .encrypt_with_nonce(input["plaintext"].as_str().unwrap_or(""), &nonce)
                            .map_err(|_| ()),
                        _ => Err(()),
                    }
                }
                Some("decrypt") => {
                    match hex_arr::<32>(input["conversation_key"].as_str().unwrap_or("")) {
                        Some(a) => ConversationKey::from_bytes(a)
                            .decrypt(input["payload"].as_str().unwrap_or(""))
                            .map_err(|_| ()),
                        None => Err(()),
                    }
                }
                _ => Err(()),
            };
            let want = case["out"].clone();
            let got_v = got.ok().map(Value::String);
            if got_v
                != (if want.is_null() {
                    None
                } else {
                    Some(want.clone())
                })
            {
                mismatches += 1;
                if samples.len() < 10 {
                    samples.push(format!(
                        "  i={i}: input={}\n    got:  {}\n    want: {}",
                        case["input"],
                        got_v
                            .as_ref()
                            .map_or("<err>".to_string(), ToString::to_string),
                        want,
                    ));
                }
            }
        }
        assert_eq!(
            mismatches,
            0,
            "nip44.v2: {mismatches} mismatches\n{}",
            samples.join("\n")
        );
    }
}
