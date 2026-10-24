//! NIP-49 `ncryptsec` secret-key encryption.
//!
//! The payload is a 91-byte record bech32-encoded under the `ncryptsec`
//! hrp (long NIP-19 checksum): version `0x02`, the scrypt `log_n` work
//! factor, a 16-byte salt, a 24-byte nonce, the key-security byte, and
//! 48 bytes of XChaCha20-Poly1305 ciphertext. scrypt (`r = 8`, `p = 1`,
//! `dkLen = 32`) derives the cipher key from the NFKC-normalized UTF-8
//! password; the key-security byte is the AEAD's associated data.
//!
//! [`EncryptedSecretKey::decrypt`] takes an explicit `max_log_n` ceiling:
//! scrypt needs `128 * r * 2^log_n` bytes of memory (4 GiB at
//! `log_n = 22`), so a crafted `ncryptsec` could exhaust the caller.
//! Payloads above the ceiling are rejected before scrypt runs.
//!
//! Secret material — the NFKC password bytes, the scrypt output, and
//! every intermediate buffer — is zeroized after use.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/49.md>

use alloc::borrow::ToOwned;
use alloc::string::String;

use core::fmt;
use core::str::FromStr;

use crate::SecretKey;
use bech32::Hrp;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Default scrypt `log2(N)` work factor for new `ncryptsec` payloads.
pub const DEFAULT_LOG_N: u8 = 16;

const VERSION: u8 = 0x02;
const LOG_N_MIN: u8 = 1;
const LOG_N_MAX: u8 = 22;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KSB_INDEX: usize = 2 + SALT_LEN + NONCE_LEN;
const CIPHERTEXT_INDEX: usize = KSB_INDEX + 1;
const PAYLOAD_LEN: usize = CIPHERTEXT_INDEX + SECRET_LEN + TAG_LEN;

const HRP_NCRYPTSEC: Hrp = Hrp::parse_unchecked("ncryptsec");

/// Errors produced by `ncryptsec` parsing, encryption, and decryption.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The string is not valid bech32.
    #[error("invalid bech32")]
    Bech32 {
        /// The decode failure.
        #[source]
        source: crate::nips::nip19::DecodeError,
    },
    /// The human-readable prefix is not `ncryptsec`.
    #[error("unexpected prefix {found}: expected ncryptsec")]
    UnexpectedPrefix {
        /// The prefix that was found.
        found: String,
    },
    /// The decoded payload is not the 91-byte NIP-49 record.
    #[error("invalid ncryptsec length: {found} bytes")]
    InvalidLength {
        /// The decoded payload length.
        found: usize,
    },
    /// The payload version byte is not `0x02`.
    #[error("unsupported ncryptsec version {version:#04x}")]
    UnsupportedVersion {
        /// The version byte that was found.
        version: u8,
    },
    /// The key-security byte is not 0x00, 0x01, or 0x02.
    #[error("invalid key security byte {byte:#04x}")]
    InvalidKeySecurity {
        /// The byte that was found.
        byte: u8,
    },
    /// `rng` failed to fill the salt or nonce.
    #[error("rng failed")]
    Rng,
    /// A `log_n` argument is outside `1..=22`.
    #[error("invalid log_n {log_n}: expected 1-22")]
    InvalidLogN {
        /// The out-of-range value.
        log_n: u8,
    },
    /// The payload's `log_n` exceeds the caller's `max_log_n` ceiling.
    #[error("log_n {log_n} exceeds the maximum {max}")]
    LogNTooLarge {
        /// The payload's work factor.
        log_n: u8,
        /// The caller's ceiling.
        max: u8,
    },
    /// Decryption failed — wrong password or tampered payload; the two
    /// are intentionally indistinguishable.
    #[error("failed to decrypt")]
    Decryption,
    /// The decrypted bytes are not a valid secp256k1 secret scalar.
    #[error("invalid secret key")]
    InvalidSecretKey,
}

/// The key-security byte recorded in an `ncryptsec` payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeySecurity {
    /// 0x00 — the key is known to have been handled insecurely.
    Insecure = 0x00,
    /// 0x01 — the key is handled in exclusive/secure storage.
    Secure = 0x01,
    /// 0x02 — the key's handling is unknown or unverified.
    Unknown = 0x02,
}

fn check_log_n(log_n: u8) -> Result<(), Error> {
    if !(LOG_N_MIN..=LOG_N_MAX).contains(&log_n) {
        return Err(Error::InvalidLogN { log_n });
    }
    Ok(())
}

/// scrypt(`r = 8`, `p = 1`, `dkLen = 32`) over the NFKC-normalized UTF-8
/// password. Both the password bytes and the derived key are zeroized
/// after use.
fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    log_n: u8,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = scrypt::Params::new(log_n, 8, 1).map_err(|_| Error::InvalidLogN { log_n })?;
    let password_nfkc = Zeroizing::new(password.nfkc().collect::<String>().into_bytes());
    let mut key = Zeroizing::new([0u8; SECRET_LEN]);
    scrypt::scrypt(&password_nfkc, salt, &params, key.as_mut()).map_err(|_| Error::Decryption)?;
    Ok(key)
}

/// A parsed `ncryptsec`: the encrypted secret key plus the scrypt
/// parameters and key-security byte recorded in the payload.
#[derive(Clone, Copy, Debug)]
pub struct EncryptedSecretKey {
    log_n: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    key_security: KeySecurity,
    /// The 32-byte ciphertext plus 16-byte Poly1305 tag.
    ciphertext: [u8; SECRET_LEN + TAG_LEN],
}

impl EncryptedSecretKey {
    /// Encrypts `secret` with the given `salt` and `nonce` — the
    /// deterministic form used by the shared vectors.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLogN`] when `log_n` is outside `1..=22`.
    pub(crate) fn encrypt_with(
        secret: &SecretKey,
        password: &str,
        log_n: u8,
        key_security: KeySecurity,
        salt: &[u8; SALT_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, Error> {
        check_log_n(log_n)?;
        let key = derive_key(password, salt, log_n)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Decryption)?;
        let ksb = key_security as u8;
        // The plaintext section holds `secret`'s bytes until encryption
        // overwrites them in place — the guard wipes the whole buffer.
        let mut plaintext_guard = Zeroizing::new([0u8; SECRET_LEN]);
        secret.with_secret_bytes(|bytes| {
            plaintext_guard.copy_from_slice(bytes);
        });
        let mut ciphertext = [0u8; SECRET_LEN + TAG_LEN];
        ciphertext[..SECRET_LEN].copy_from_slice(&*plaintext_guard);
        let tag = cipher
            .encrypt_inout_detached(
                &XNonce::from(*nonce),
                &[ksb],
                ciphertext[..SECRET_LEN].as_mut().into(),
            )
            .map_err(|_| Error::Decryption)?;
        ciphertext[SECRET_LEN..].copy_from_slice(tag.as_slice());
        Ok(Self {
            log_n,
            salt: *salt,
            nonce: *nonce,
            key_security,
            ciphertext,
        })
    }

    /// Encrypts `secret`, drawing a 16-byte salt and 24-byte nonce from
    /// `rng` in that order.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when `rng` fails; [`Error::InvalidLogN`] on the same
    /// conditions as `encrypt_with`.
    pub fn encrypt<R>(
        secret: &SecretKey,
        password: &str,
        log_n: u8,
        key_security: KeySecurity,
        rng: &mut R,
    ) -> Result<Self, Error>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        check_log_n(log_n)?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rng.try_fill_bytes(&mut salt).map_err(|_| Error::Rng)?;
        rng.try_fill_bytes(&mut nonce).map_err(|_| Error::Rng)?;
        Self::encrypt_with(secret, password, log_n, key_security, &salt, &nonce)
    }

    /// The scrypt `log2(N)` work factor recorded in the payload.
    #[must_use]
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    /// The key-security byte recorded in the payload.
    #[must_use]
    pub const fn key_security(&self) -> KeySecurity {
        self.key_security
    }

    /// Decrypts the payload, rejecting `log_n` values above `max_log_n`
    /// **before** scrypt runs.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLogN`] when `max_log_n` is outside `1..=22`,
    /// [`Error::LogNTooLarge`] when the payload's `log_n` exceeds
    /// `max_log_n`, [`Error::Decryption`] on a wrong password or tampered
    /// payload (indistinguishable), and [`Error::InvalidSecretKey`] when
    /// the decrypted bytes are not a valid secret scalar.
    pub fn decrypt(&self, password: &str, max_log_n: u8) -> Result<SecretKey, Error> {
        check_log_n(max_log_n)?;
        if self.log_n > max_log_n {
            return Err(Error::LogNTooLarge {
                log_n: self.log_n,
                max: max_log_n,
            });
        }
        let key = derive_key(password, &self.salt, self.log_n)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| Error::Decryption)?;
        let ksb = self.key_security as u8;
        // The guard wipes the decrypted scalar on every path.
        let mut secret_guard = Zeroizing::new([0u8; SECRET_LEN]);
        secret_guard.copy_from_slice(&self.ciphertext[..SECRET_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.ciphertext[SECRET_LEN..]);
        let secret = &mut *secret_guard;
        if cipher
            .decrypt_inout_detached(
                &XNonce::from(self.nonce),
                &[ksb],
                secret.as_mut_slice().into(),
                &tag.into(),
            )
            .is_err()
        {
            return Err(Error::Decryption);
        }
        // `from_bytes` gets its own copy; the guard wipes the local on drop.
        SecretKey::from_bytes(*secret).map_err(|_| Error::InvalidSecretKey)
    }
}

impl FromStr for EncryptedSecretKey {
    type Err = Error;

    /// Parses an `ncryptsec` string — checks the bech32 checksum, the hrp,
    /// the payload length, the version byte, and the key-security byte.
    /// The ciphertext is not authenticated until [`Self::decrypt`].
    ///
    /// # Errors
    ///
    /// [`Error::Bech32`], [`Error::UnexpectedPrefix`],
    /// [`Error::InvalidLength`], [`Error::UnsupportedVersion`], and
    /// [`Error::InvalidKeySecurity`].
    fn from_str(ncryptsec: &str) -> Result<Self, Error> {
        let (hrp, payload) = crate::nips::nip19::decode_bech32(ncryptsec)
            .map_err(|e| Error::Bech32 { source: e })?;
        if hrp != HRP_NCRYPTSEC {
            return Err(Error::UnexpectedPrefix {
                found: hrp.as_str().to_owned(),
            });
        }
        let record: [u8; PAYLOAD_LEN] =
            payload
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidLength {
                    found: payload.len(),
                })?;
        let version = record[0];
        if version != VERSION {
            return Err(Error::UnsupportedVersion { version });
        }
        let byte = record[KSB_INDEX];
        let key_security = match byte {
            0x00 => KeySecurity::Insecure,
            0x01 => KeySecurity::Secure,
            0x02 => KeySecurity::Unknown,
            _ => return Err(Error::InvalidKeySecurity { byte }),
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&record[2..2 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&record[2 + SALT_LEN..KSB_INDEX]);
        let mut ciphertext = [0u8; SECRET_LEN + TAG_LEN];
        ciphertext.copy_from_slice(&record[CIPHERTEXT_INDEX..]);
        Ok(Self {
            log_n: record[1],
            salt,
            nonce,
            key_security,
            ciphertext,
        })
    }
}

impl fmt::Display for EncryptedSecretKey {
    /// Re-encodes the payload as an `ncryptsec1…` string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = VERSION;
        payload[1] = self.log_n;
        payload[2..2 + SALT_LEN].copy_from_slice(&self.salt);
        payload[2 + SALT_LEN..KSB_INDEX].copy_from_slice(&self.nonce);
        payload[KSB_INDEX] = self.key_security as u8;
        payload[CIPHERTEXT_INDEX..].copy_from_slice(&self.ciphertext);
        f.write_str(&crate::nips::nip19::encode_bech32(HRP_NCRYPTSEC, &payload))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use core::error::Error as _;

    use super::*;

    const SALT: [u8; SALT_LEN] = [0x42; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];

    fn secret() -> SecretKey {
        SecretKey::from_bytes([0x33; 32]).unwrap()
    }

    fn encrypted() -> EncryptedSecretKey {
        EncryptedSecretKey::encrypt_with(
            &secret(),
            "hunter2",
            LOG_N_MIN,
            KeySecurity::Secure,
            &SALT,
            &NONCE,
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let key = encrypted();
        assert_eq!(key.log_n(), LOG_N_MIN);
        assert_eq!(key.key_security(), KeySecurity::Secure);
        let code = key.to_string();
        assert!(code.starts_with("ncryptsec1"));
        let parsed = code.parse::<EncryptedSecretKey>().unwrap();
        assert_eq!(parsed.log_n(), LOG_N_MIN);
        assert_eq!(parsed.key_security(), KeySecurity::Secure);
        let decrypted = parsed.decrypt("hunter2", LOG_N_MAX).unwrap();
        assert_eq!(decrypted.with_secret_bytes(|b| *b), [0x33; 32]);
    }

    #[test]
    fn deterministic_output_matches_payload_layout() {
        let key = EncryptedSecretKey::encrypt_with(
            &secret(),
            "hunter2",
            DEFAULT_LOG_N,
            KeySecurity::Unknown,
            &SALT,
            &NONCE,
        )
        .unwrap();
        let (hrp, payload) = crate::nips::nip19::decode_bech32(&key.to_string()).unwrap();
        assert_eq!(hrp, HRP_NCRYPTSEC);
        assert_eq!(payload.first(), Some(&VERSION));
        assert_eq!(payload.get(1), Some(&DEFAULT_LOG_N));
        assert_eq!(payload.get(KSB_INDEX), Some(&(KeySecurity::Unknown as u8)));
    }

    #[test]
    fn encrypt_rejects_out_of_range_log_n() {
        for log_n in [0, 23, u8::MAX] {
            assert!(matches!(
                EncryptedSecretKey::encrypt_with(
                    &secret(),
                    "pw",
                    log_n,
                    KeySecurity::Unknown,
                    &SALT,
                    &NONCE
                ),
                Err(Error::InvalidLogN { .. })
            ));
        }
    }

    #[test]
    fn parse_rejects_malformed_input() {
        // Not bech32.
        let err = "not-ncryptsec".parse::<EncryptedSecretKey>().unwrap_err();
        assert!(matches!(err, Error::Bech32 { .. }));
        assert!(err.source().is_some());
        // Wrong hrp — a valid npub string.
        let npub = crate::nips::nip19::encode_bech32(Hrp::parse_unchecked("npub"), &[0x11; 32]);
        assert!(matches!(
            npub.parse::<EncryptedSecretKey>(),
            Err(Error::UnexpectedPrefix { .. })
        ));
        // Wrong payload length.
        let short = crate::nips::nip19::encode_bech32(HRP_NCRYPTSEC, &[0x02; 10]);
        assert!(matches!(
            short.parse::<EncryptedSecretKey>(),
            Err(Error::InvalidLength { found: 10 })
        ));
        // Wrong version.
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = 0x01;
        let bad_version = crate::nips::nip19::encode_bech32(HRP_NCRYPTSEC, &payload);
        assert!(matches!(
            bad_version.parse::<EncryptedSecretKey>(),
            Err(Error::UnsupportedVersion { version: 0x01 })
        ));
        // Bad key-security byte.
        payload[0] = VERSION;
        payload[KSB_INDEX] = 0x07;
        let bad_ksb = crate::nips::nip19::encode_bech32(HRP_NCRYPTSEC, &payload);
        assert!(matches!(
            bad_ksb.parse::<EncryptedSecretKey>(),
            Err(Error::InvalidKeySecurity { byte: 0x07 })
        ));
    }

    #[test]
    fn decrypt_rejects_max_log_n_before_scrypt() {
        let key = encrypted();
        assert!(matches!(
            key.decrypt("hunter2", 0),
            Err(Error::InvalidLogN { log_n: 0 })
        ));
        // The payload carries LOG_N_MIN; a zero ceiling is still checked
        // first, so max_log_n must be >= the payload's.
        assert!(matches!(
            key.decrypt("hunter2", 23),
            Err(Error::InvalidLogN { log_n: 23 })
        ));
        // Payload log_n above the caller ceiling fails before scrypt.
        let high = EncryptedSecretKey::encrypt_with(
            &secret(),
            "hunter2",
            LOG_N_MIN + 1,
            KeySecurity::Secure,
            &SALT,
            &NONCE,
        )
        .unwrap();
        assert!(matches!(
            high.decrypt("hunter2", LOG_N_MIN),
            Err(Error::LogNTooLarge {
                log_n: _,
                max: LOG_N_MIN
            })
        ));
    }

    #[test]
    fn decrypt_wrong_password_is_indistinguishable() {
        let key = encrypted();
        assert!(matches!(
            key.decrypt("wrong", LOG_N_MAX),
            Err(Error::Decryption)
        ));
        // A tampered tag fails the same way.
        let mut tampered = key;
        tampered.ciphertext[SECRET_LEN] ^= 0x01;
        assert!(matches!(
            tampered.decrypt("hunter2", LOG_N_MAX),
            Err(Error::Decryption)
        ));
    }

    #[test]
    fn nfkc_passwords_agree() {
        // U+212B U+2126 U+1E9B U+0323 (the spec's example) vs its NFKC form.
        let decomposed = "\u{212b}\u{2126}\u{1e9b}\u{0323}";
        let composed = decomposed.nfkc().collect::<String>();
        assert_ne!(decomposed, composed);
        let a = EncryptedSecretKey::encrypt_with(
            &secret(),
            decomposed,
            LOG_N_MIN,
            KeySecurity::Unknown,
            &SALT,
            &NONCE,
        )
        .unwrap();
        let b = EncryptedSecretKey::encrypt_with(
            &secret(),
            &composed,
            LOG_N_MIN,
            KeySecurity::Unknown,
            &SALT,
            &NONCE,
        )
        .unwrap();
        assert_eq!(a.to_string(), b.to_string());
        // Unicode passwords beyond ASCII work too.
        let key = EncryptedSecretKey::encrypt_with(
            &secret(),
            "päss wörd",
            LOG_N_MIN,
            KeySecurity::Insecure,
            &SALT,
            &NONCE,
        )
        .unwrap();
        let decrypted = key.decrypt("päss wörd", LOG_N_MAX).unwrap();
        decrypted.with_secret_bytes(|bytes| assert_eq!(&[0x33; 32], bytes));
    }

    #[test]
    fn decrypt_rejects_invalid_scalar() {
        // A payload whose plaintext is the all-zero scalar: AEAD succeeds,
        // the scalar check must fail.
        let key = derive_key("pw", &SALT, LOG_N_MIN).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).unwrap();
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = VERSION;
        payload[1] = LOG_N_MIN;
        payload[2..2 + SALT_LEN].copy_from_slice(&SALT);
        payload[2 + SALT_LEN..KSB_INDEX].copy_from_slice(&NONCE);
        payload[KSB_INDEX] = KeySecurity::Unknown as u8;
        let tag = cipher
            .encrypt_inout_detached(
                &XNonce::from(NONCE),
                &[KeySecurity::Unknown as u8],
                payload[CIPHERTEXT_INDEX..CIPHERTEXT_INDEX + SECRET_LEN]
                    .as_mut()
                    .into(),
            )
            .unwrap();
        payload[PAYLOAD_LEN - TAG_LEN..].copy_from_slice(tag.as_slice());
        let code = crate::nips::nip19::encode_bech32(HRP_NCRYPTSEC, &payload);
        let parsed = code.parse::<EncryptedSecretKey>().unwrap();
        assert!(matches!(
            parsed.decrypt("pw", LOG_N_MAX),
            Err(Error::InvalidSecretKey)
        ));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "tests exercise fixed vectors by panicking"
)]
mod vectors {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use serde_json::Value;

    use crate::SecretKey;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    fn unhex_arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn vector_codec() {
        let doc: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/nip49/codec.json"
        )))
        .unwrap();
        for case in doc["cases"].as_array().unwrap() {
            if let (
                Some(secret),
                Some(password),
                Some(log_n),
                Some(ks),
                Some(salt),
                Some(nonce),
                Some(out),
            ) = (
                case["secret"].as_str(),
                case["password"].as_str(),
                case["log_n"].as_u64(),
                case["key_security"].as_u64(),
                case["salt"].as_str(),
                case["nonce"].as_str(),
                case["ncryptsec"].as_str(),
            ) {
                let secret = SecretKey::from_bytes(unhex_arr(secret)).unwrap();
                let key_security = match ks {
                    0 => KeySecurity::Insecure,
                    1 => KeySecurity::Secure,
                    _ => KeySecurity::Unknown,
                };
                let esk = EncryptedSecretKey::encrypt_with(
                    &secret,
                    password,
                    log_n as u8,
                    key_security,
                    &unhex_arr(salt),
                    &unhex_arr(nonce),
                )
                .unwrap();
                assert_eq!(esk.to_string(), out);
                let back = EncryptedSecretKey::from_str(out).unwrap();
                assert_eq!(back.to_string(), out);
                assert_eq!(
                    back.decrypt(password, 22).unwrap().public_key().to_hex(),
                    secret.public_key().to_hex()
                );
            }
            // cases with `error`/`err` are covered by the official suite.
        }
    }

    #[test]
    fn vector_official() {
        let doc: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/nip49/official.json"
        )))
        .unwrap();
        for case in doc["cases"].as_array().unwrap() {
            let esk = EncryptedSecretKey::from_str(case["ncryptsec"].as_str().unwrap()).unwrap();
            let secret = esk
                .decrypt(
                    case["password"].as_str().unwrap(),
                    case["max_log_n"].as_u64().unwrap() as u8,
                )
                .unwrap();
            if let Some(nsec) = case.get("nsec").and_then(Value::as_str) {
                assert_eq!(secret.to_bech32(), nsec);
            } else if let Some(hex_want) = case.get("secret").and_then(Value::as_str) {
                assert_eq!(secret.with_secret_bytes(|b| hex(b)), hex_want);
            }
        }
    }

    #[test]
    fn vector_max_logn() {
        let doc: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/nip49/max-logn.json"
        )))
        .unwrap();
        for case in doc["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let r = input.parse::<EncryptedSecretKey>();
            match (&case["error"], r) {
                (Value::Null, Ok(esk)) if case.get("secret").and_then(Value::as_str).is_some() => {
                    let want = case["secret"].as_str().unwrap();
                    let s = esk
                        .decrypt(
                            case["password"].as_str().unwrap_or(""),
                            case["maxLogN"].as_u64().unwrap_or(22) as u8,
                        )
                        .unwrap_or_else(|e| panic!("decrypt failed: {e}"));
                    assert_eq!(s.with_secret_bytes(|b| hex(b)), want);
                }
                (Value::Null, Err(e)) => panic!("parse failed: {e}"),
                _ => {}
            }
        }
    }
    fn hex(b: &[u8]) -> String {
        b.iter()
            .fold(String::with_capacity(b.len() * 2), |mut out, x| {
                const H: &[u8; 16] = b"0123456789abcdef";
                out.push(char::from(H[usize::from(x >> 4)]));
                out.push(char::from(H[usize::from(x & 0xf)]));
                out
            })
    }
}
