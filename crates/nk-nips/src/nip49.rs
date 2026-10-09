//! NIP-49 `ncryptsec` secret-key encryption.
//!
//! The payload is a 91-byte record bech32-encoded under the `ncryptsec`
//! hrp (long NIP-19 checksum): version `0x02`, the scrypt `log_n` work
//! factor, a 16-byte salt, a 24-byte nonce, the key-security byte, and
//! 48 bytes of XChaCha20-Poly1305 ciphertext. scrypt (`r = 8`, `p = 1`,
//! `dkLen = 32`) derives the cipher key from the NFKC-normalized UTF-8
//! password; the key-security byte is the AEAD's associated data.
//!
//! [`decrypt`] takes an explicit `max_log_n` ceiling: scrypt needs
//! `128 * r * 2^log_n` bytes of memory (4 GiB at `log_n = 22`), so a
//! crafted `ncryptsec` could exhaust the caller. Payloads above the
//! ceiling are rejected before scrypt runs.
//!
//! Secret material — the NFKC password bytes, the scrypt output, and
//! every intermediate buffer — is zeroized after use.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/49.md>

use alloc::format;
use alloc::string::String;

use bech32::Hrp;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use nk_core::SecretKey;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, ErrorKind, Result};

const VERSION: u8 = 0x02;
const LOG_N_MIN: u8 = 1;
const LOG_N_MAX: u8 = 22;
const LOG_N_DEFAULT: u8 = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KSB_INDEX: usize = 2 + SALT_LEN + NONCE_LEN;
const CIPHERTEXT_INDEX: usize = KSB_INDEX + 1;
const PAYLOAD_LEN: usize = CIPHERTEXT_INDEX + SECRET_LEN + TAG_LEN;

const HRP_NCRYPTSEC: Hrp = Hrp::parse_unchecked("ncryptsec");

fn nip49(message: impl Into<alloc::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Nip49, message)
}

/// The key-security byte recorded in an `ncryptsec` payload (TS
/// `KeySecurityByte`).
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

/// Options for [`encrypt_with`], [`encrypt_with_rng`], and [`encrypt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptOptions {
    log_n: u8,
    key_security: KeySecurity,
}

impl EncryptOptions {
    /// Defaults: `log_n` 16, [`KeySecurity::Unknown`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            log_n: LOG_N_DEFAULT,
            key_security: KeySecurity::Unknown,
        }
    }

    /// Sets the scrypt `log2(N)` work factor.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip49`] when `log_n` is outside `1..=22`.
    pub fn log_n(self, log_n: u8) -> Result<Self> {
        if !(LOG_N_MIN..=LOG_N_MAX).contains(&log_n) {
            return Err(nip49(format!(
                "invalid logn {log_n}, expected integer {LOG_N_MIN}..{LOG_N_MAX}"
            )));
        }
        Ok(Self { log_n, ..self })
    }

    /// Sets the key-security byte recorded in the payload.
    #[must_use]
    pub const fn key_security(self, ksb: KeySecurity) -> Self {
        Self {
            key_security: ksb,
            ..self
        }
    }

    /// The scrypt `log2(N)` work factor.
    #[must_use]
    pub const fn log_n_value(self) -> u8 {
        self.log_n
    }

    /// The key-security byte.
    #[must_use]
    pub const fn key_security_byte(self) -> KeySecurity {
        self.key_security
    }
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// scrypt(`r = 8`, `p = 1`, `dkLen = 32`) over the NFKC-normalized UTF-8
/// password. Both the password bytes and the derived key are zeroized
/// after use.
fn derive_key(password: &str, salt: &[u8; SALT_LEN], log_n: u8) -> Result<Zeroizing<[u8; 32]>> {
    let params =
        scrypt::Params::new(log_n, 8, 1).map_err(|_| nip49("invalid scrypt parameters"))?;
    let password_nfkc = Zeroizing::new(password.nfkc().collect::<String>().into_bytes());
    let mut key = Zeroizing::new([0u8; SECRET_LEN]);
    scrypt::scrypt(&password_nfkc, salt, &params, key.as_mut())
        .map_err(|_| nip49("scrypt failed"))?;
    Ok(key)
}

/// Encrypts `secret` to an `ncryptsec` string with the given `salt` and
/// `nonce` — the deterministic form used by the shared vectors.
///
/// # Errors
///
/// [`ErrorKind::Nip49`] when the scrypt parameters or the AEAD fail
/// (unreachable with the fixed NIP-49 layout).
pub fn encrypt_with(
    secret: &SecretKey,
    password: &str,
    options: EncryptOptions,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<String> {
    let log_n = options.log_n;
    let key = derive_key(password, salt, log_n)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| nip49("invalid cipher key"))?;
    let ksb = options.key_security as u8;
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0] = VERSION;
    payload[1] = log_n;
    payload[2..2 + SALT_LEN].copy_from_slice(salt);
    payload[2 + SALT_LEN..KSB_INDEX].copy_from_slice(nonce);
    payload[KSB_INDEX] = ksb;
    secret.with_secret_bytes(|bytes| {
        payload[CIPHERTEXT_INDEX..CIPHERTEXT_INDEX + SECRET_LEN].copy_from_slice(bytes);
    });
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(*nonce),
            &[ksb],
            payload[CIPHERTEXT_INDEX..CIPHERTEXT_INDEX + SECRET_LEN]
                .as_mut()
                .into(),
        )
        .map_err(|_| nip49("encryption failed"))?;
    payload[PAYLOAD_LEN - TAG_LEN..].copy_from_slice(tag.as_slice());
    let code = crate::nip19::encode_bech32(HRP_NCRYPTSEC, &payload);
    payload.zeroize();
    Ok(code)
}

/// Encrypts `secret`, drawing a 16-byte salt and 24-byte nonce from
/// `rng` in that order.
///
/// # Errors
///
/// [`ErrorKind::Nip49`] on the same conditions as [`encrypt_with`].
pub fn encrypt_with_rng<R>(
    secret: &SecretKey,
    password: &str,
    options: EncryptOptions,
    rng: &mut R,
) -> Result<String>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    encrypt_with(secret, password, options, &salt, &nonce)
}

/// Encrypts `secret` with OS entropy.
///
/// When the OS entropy source fails — the same contract as
/// [`nk_core::SecretKey::generate`].
///
/// # Errors
///
/// [`ErrorKind::Nip49`] on the same conditions as [`encrypt_with`];
/// panics if the OS RNG fails (see `getrandom::SysRng`).
#[cfg(feature = "os-rng")]
pub fn encrypt(secret: &SecretKey, password: &str, options: EncryptOptions) -> Result<String> {
    encrypt_with_rng(
        secret,
        password,
        options,
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// A decrypted `ncryptsec`: the secret key plus the key-security byte
/// recorded in the payload.
#[derive(Debug)]
pub struct Decrypted {
    /// The recovered secret key.
    pub secret_key: SecretKey,
    /// The payload's key-security byte.
    pub key_security: KeySecurity,
}

/// Decrypts an `ncryptsec` string, rejecting payloads whose `log_n`
/// exceeds `max_log_n` **before** scrypt runs.
///
/// # Errors
///
/// [`ErrorKind::Nip49`] on `max_log_n` outside `1..=22`, malformed
/// bech32, a wrong hrp/length/version, `log_n > max_log_n`, a
/// key-security byte other than 0/1/2, a wrong password (AEAD
/// authentication), or a decrypted value that is not a valid secret
/// scalar — the latter carries the `nk_core` crypto error as `source`
/// (ruling N3).
pub fn decrypt(ncryptsec: &str, password: &str, max_log_n: u8) -> Result<Decrypted> {
    if !(LOG_N_MIN..=LOG_N_MAX).contains(&max_log_n) {
        return Err(nip49(format!(
            "invalid maxLogN {max_log_n}, expected integer {LOG_N_MIN}..{LOG_N_MAX}"
        )));
    }
    let (hrp, mut payload) =
        crate::nip19::decode_bech32(ncryptsec).ok_or_else(|| nip49("invalid ncryptsec"))?;
    if hrp != HRP_NCRYPTSEC {
        payload.zeroize();
        return Err(nip49(format!("invalid prefix {hrp}, expected 'ncryptsec'")));
    }
    if payload.len() != PAYLOAD_LEN {
        payload.zeroize();
        return Err(nip49("invalid ncryptsec length"));
    }
    // The length is fixed from here on: parse a stack record the compiler
    // can bounds-check statically.
    let mut record = [0u8; PAYLOAD_LEN];
    record.copy_from_slice(&payload);
    payload.zeroize();
    let version = record[0];
    if version != VERSION {
        record.zeroize();
        return Err(nip49(format!("invalid version {version}, expected 0x02")));
    }
    let log_n = record[1];
    if log_n > max_log_n {
        record.zeroize();
        return Err(nip49(format!("logn {log_n} exceeds maxLogN {max_log_n}")));
    }
    let ksb = record[KSB_INDEX];
    let key_security = match ksb {
        0x00 => KeySecurity::Insecure,
        0x01 => KeySecurity::Secure,
        0x02 => KeySecurity::Unknown,
        other => {
            record.zeroize();
            return Err(nip49(format!(
                "invalid key security byte {other}, expected 0x00, 0x01, or 0x02"
            )));
        }
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&record[2..2 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&record[2 + SALT_LEN..KSB_INDEX]);
    let key = derive_key(password, &salt, log_n)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| nip49("invalid cipher key"))?;
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&record[CIPHERTEXT_INDEX..CIPHERTEXT_INDEX + SECRET_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&record[PAYLOAD_LEN - TAG_LEN..]);
    record.zeroize();
    if cipher
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            &[ksb],
            secret.as_mut_slice().into(),
            &tag.into(),
        )
        .is_err()
    {
        secret.zeroize();
        return Err(nip49("failed to decrypt"));
    }
    let secret_key = SecretKey::from_bytes(secret)
        .map_err(|e| Error::with_source(ErrorKind::Nip49, "invalid secret key", e))?;
    Ok(Decrypted {
        secret_key,
        key_security,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests fail by panicking"
    )]

    use core::error::Error as _;

    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];
    const SALT: [u8; 16] = [1u8; 16];
    const NONCE: [u8; 24] = [2u8; 24];

    fn secret() -> SecretKey {
        SecretKey::from_bytes(SECRET).unwrap()
    }

    #[test]
    fn encrypt_options_bounds() {
        assert!(EncryptOptions::new().log_n(0).is_err());
        assert!(EncryptOptions::new().log_n(23).is_err());
        let options = EncryptOptions::new()
            .log_n(2)
            .unwrap()
            .key_security(KeySecurity::Secure);
        assert_eq!(options.log_n_value(), 2);
        assert_eq!(options.key_security_byte(), KeySecurity::Secure);
        assert_eq!(EncryptOptions::new().log_n_value(), 16, "TS default logn");
        assert_eq!(
            EncryptOptions::new().key_security_byte(),
            KeySecurity::Unknown,
            "TS default ksb"
        );
    }

    #[test]
    fn encrypt_with_roundtrips() {
        let options = EncryptOptions::new()
            .log_n(2)
            .unwrap()
            .key_security(KeySecurity::Insecure);
        let code = encrypt_with(&secret(), "päss wörd", options, &SALT, &NONCE).unwrap();
        assert!(code.starts_with("ncryptsec1"));
        let out = decrypt(&code, "päss wörd", 22).unwrap();
        out.secret_key
            .with_secret_bytes(|bytes| assert_eq!(&SECRET, bytes));
        assert_eq!(out.key_security, KeySecurity::Insecure);
    }

    #[test]
    fn nfkc_passwords_agree() {
        // U+212B U+2126 U+1E9B U+0323 (the spec's example) vs its NFKC form.
        let decomposed = "\u{212b}\u{2126}\u{1e9b}\u{0323}";
        let composed = decomposed.nfkc().collect::<String>();
        assert_ne!(decomposed, composed);
        let options = EncryptOptions::new().log_n(1).unwrap();
        let a = encrypt_with(&secret(), decomposed, options, &SALT, &NONCE).unwrap();
        let b = encrypt_with(&secret(), &composed, options, &SALT, &NONCE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn decrypt_bounds_and_shape() {
        let options = EncryptOptions::new().log_n(2).unwrap();
        let code = encrypt_with(&secret(), "pw", options, &SALT, &NONCE).unwrap();
        for max_log_n in [0u8, 23] {
            let err = decrypt(&code, "pw", max_log_n).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Nip49);
        }
        // log_n 2 > ceiling 1: rejected before scrypt.
        assert_eq!(
            decrypt(&code, "pw", 1).unwrap_err().kind(),
            ErrorKind::Nip49
        );
        // Wrong password fails AEAD authentication.
        assert_eq!(
            decrypt(&code, "wrong", 22).unwrap_err().kind(),
            ErrorKind::Nip49
        );
        // Not bech32 / wrong hrp.
        for input in [
            "garbage",
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2",
        ] {
            assert_eq!(
                decrypt(input, "pw", 22).unwrap_err().kind(),
                ErrorKind::Nip49
            );
        }
    }

    #[test]
    fn decrypt_rejects_invalid_scalar_with_source() {
        // A payload whose plaintext is the all-zero scalar: AEAD succeeds,
        // the scalar check must fail with the nk-core error as source (N3).
        let key = derive_key("pw", &SALT, 2).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).unwrap();
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = VERSION;
        payload[1] = 2;
        payload[2..2 + SALT_LEN].copy_from_slice(&SALT);
        payload[2 + SALT_LEN..KSB_INDEX].copy_from_slice(&NONCE);
        payload[KSB_INDEX] = 0x02;
        let tag = cipher
            .encrypt_inout_detached(
                &XNonce::from(NONCE),
                &[0x02],
                payload[CIPHERTEXT_INDEX..CIPHERTEXT_INDEX + SECRET_LEN]
                    .as_mut()
                    .into(),
            )
            .unwrap();
        payload[PAYLOAD_LEN - TAG_LEN..].copy_from_slice(tag.as_slice());
        let code = crate::nip19::encode_bech32(HRP_NCRYPTSEC, &payload);
        payload.zeroize();
        let err = decrypt(&code, "pw", 22).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Nip49);
        assert!(err.source().is_some(), "N3 carries the scalar error");
    }
}
