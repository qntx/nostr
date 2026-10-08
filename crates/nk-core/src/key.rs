//! Keys: x-only public keys, secret scalars, and BIP-340 signing — the
//! counterpart of `@qntx/nostr`'s `core/key.ts`.
//!
//! Context management is delegated to `secp256k1`'s internal global-context
//! machinery: a thread-local context under `std`, a self-contained
//! stack-allocated context per call under `no_std`. No public `_with_ctx`
//! variants exist.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result};
use crate::event::{Event, EventId, Signature, UnsignedEvent};
use crate::hex;

/// An x-only public key (32 bytes).
///
/// The `from_*` constructors check shape only: whether the bytes are a valid
/// curve point is decided at signature verification, not here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps 32 bytes without a curve check.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copies a byte slice into a key.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Hex, "invalid public key length"))?;
        Ok(Self(array))
    }

    /// Parses 64-character hex of any case; the key stores bytes only, so the
    /// canonical output is always lowercase.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when the input is not 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(hex::decode_caller(hex)?))
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The canonical lowercase hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self(
            hex::decode_wire(&raw).map_err(serde::de::Error::custom)?,
        ))
    }
}

/// A secp256k1 secret scalar (32 bytes).
///
/// The scalar range is validated at construction, so every `SecretKey` is a
/// valid BIP-340 secret key. The bytes are wiped on drop via
/// [`secp256k1::SecretKey::non_secure_erase`]; like `zeroize` itself, that
/// erasure is best effort — the compiler may still have made copies.
///
/// No `PartialEq`, `Display`, `FromStr`, serde, `Hash`, or `Ord`: secret
/// material is never compared in non-constant time or formatted into logs.
/// Compare [`SecretKey::public_key`] instead; hex output belongs to nk-nips'
/// NIP-19 `nsec`.
#[cfg_attr(not(feature = "os-rng"), doc = "```compile_fail")]
#[cfg_attr(
    not(feature = "os-rng"),
    doc = "let _ = nk_core::SecretKey::generate();"
)]
#[cfg_attr(not(feature = "os-rng"), doc = "```")]
#[derive(Clone)]
pub struct SecretKey(secp256k1::SecretKey);

impl SecretKey {
    /// Wraps `bytes` after validating the scalar range.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `bytes` is not a valid secret scalar.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        secp256k1::SecretKey::from_secret_bytes(bytes)
            .map(Self)
            .map_err(|_| {
                let mut bytes = bytes;
                bytes.zeroize();
                Error::new(ErrorKind::Crypto, "invalid secret key")
            })
    }

    /// Copies a byte slice into a key.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `bytes` is not exactly 32 bytes long or is
    /// not a valid secret scalar.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut array = [0u8; 32];
        if bytes.len() != array.len() {
            return Err(Error::new(ErrorKind::Crypto, "invalid secret key length"));
        }
        array.copy_from_slice(bytes);
        Self::from_bytes(array)
    }

    /// Parses 64-character hex of any case; the decoded intermediate is wiped
    /// if the scalar is invalid.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Hex`] when the input is not 64 hex characters;
    /// [`ErrorKind::Crypto`] when it is not a valid secret scalar.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(hex::decode_caller(hex)?)
    }

    /// Draws 32-byte candidates from `rng` until one is a valid scalar.
    #[must_use]
    pub fn generate_with_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            match Self::from_bytes(bytes) {
                Ok(key) => return key,
                Err(_) => bytes.zeroize(),
            }
        }
    }

    /// Draws a key from the operating system's entropy source.
    ///
    /// # Panics
    ///
    /// When the OS entropy source fails — an unrecoverable environment
    /// failure, the same contract as `rand::rng()`. Callers that must handle
    /// entropy failure use [`Self::generate_with_rng`] with their own source.
    #[cfg(feature = "os-rng")]
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// The raw secret bytes.
    #[must_use]
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.0.to_secret_bytes()
    }

    /// The x-only BIP-340 public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.x_only_public_key().0.to_byte_array())
    }

    /// The keypair behind this key, for signing.
    fn keypair(&self) -> secp256k1::Keypair {
        // Infallible: the scalar was validated at construction.
        self.0.keypair()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl zeroize::ZeroizeOnDrop for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// A secret key with its derived public key — the signing handle.
#[cfg_attr(not(feature = "os-rng"), doc = "```compile_fail")]
#[cfg_attr(not(feature = "os-rng"), doc = "let _ = nk_core::Keys::generate();")]
#[cfg_attr(not(feature = "os-rng"), doc = "```")]
#[cfg_attr(not(feature = "os-rng"), doc = "```compile_fail")]
#[cfg_attr(
    not(feature = "os-rng"),
    doc = "fn call(keys: &nk_core::Keys, event: nk_core::UnsignedEvent) {"
)]
#[cfg_attr(not(feature = "os-rng"), doc = "    let _ = keys.sign_event(event);")]
#[cfg_attr(not(feature = "os-rng"), doc = "}")]
#[cfg_attr(not(feature = "os-rng"), doc = "```")]
#[derive(Clone)]
pub struct Keys {
    secret: SecretKey,
    public: PublicKey,
}

impl Keys {
    /// Wraps `secret` and derives its public key.
    #[must_use]
    pub fn new(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Draws a new key pair from `rng`.
    #[must_use]
    pub fn generate_with_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        Self::new(SecretKey::generate_with_rng(rng))
    }

    /// Draws a new key pair from the operating system's entropy source.
    ///
    /// # Panics
    ///
    /// When the OS entropy source fails — see [`SecretKey::generate`].
    #[cfg(feature = "os-rng")]
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// The x-only public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    /// The secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// BIP-340-signs the 32-byte `id` with `aux` as the auxiliary randomness
    /// (TS `schnorr.sign(id, secret, aux)`).
    #[must_use]
    pub fn sign_id_with_aux(&self, id: &EventId, aux: &[u8; 32]) -> Signature {
        let mut keypair = self.secret.keypair();
        let signature = secp256k1::schnorr::sign_with_aux_rand(id.as_bytes(), &keypair, aux);
        keypair.non_secure_erase();
        Signature::from_bytes(signature.to_byte_array())
    }

    /// Signs `unsigned` with `aux` as the auxiliary randomness.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `unsigned`'s pubkey differs from this key's
    /// public key (TS `signEvent` throws `CryptoError`).
    pub fn sign_event_with_aux(&self, unsigned: UnsignedEvent, aux: &[u8; 32]) -> Result<Event> {
        if unsigned.pubkey() != self.public {
            return Err(Error::new(
                ErrorKind::Crypto,
                "unsigned event pubkey does not match the signing key",
            ));
        }
        let id = unsigned.id();
        let signature = self.sign_id_with_aux(&id, aux);
        Ok(Event::new_signed(unsigned, id, signature))
    }

    /// Signs `unsigned`, drawing the auxiliary randomness from `rng`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `unsigned`'s pubkey differs from this key's
    /// public key.
    pub fn sign_event_with_rng<R>(&self, unsigned: UnsignedEvent, rng: &mut R) -> Result<Event>
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        let result = self.sign_event_with_aux(unsigned, &aux);
        aux.zeroize();
        result
    }

    /// Signs `unsigned`, drawing the auxiliary randomness from the operating
    /// system's entropy source.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Crypto`] when `unsigned`'s pubkey differs from this key's
    /// public key.
    ///
    /// # Panics
    ///
    /// When the OS entropy source fails — see [`SecretKey::generate`].
    #[cfg(feature = "os-rng")]
    pub fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event> {
        self.sign_event_with_rng(unsigned, &mut rand_core::UnwrapErr(getrandom::SysRng))
    }
}

impl fmt::Debug for Keys {
    /// The secret key is never formatted; only the public key is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("public_key", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;
    use crate::kind::Kind;
    use crate::tag::Tags;
    use crate::time::Timestamp;

    const HEX: &str = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";

    /// BIP-340 official vector index 0.
    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const SECRET_PUB: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const VECTOR0_SIG: &str = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0";

    /// Deterministic `CryptoRng` for tests: emits its counter in big-endian.
    struct CounterRng(u8);

    impl rand_core::TryRng for CounterRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(u32::from(self.0))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self.0.wrapping_add(1);
            Ok(u64::from(self.0))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dest.iter_mut() {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for CounterRng {}

    #[test]
    fn from_hex_accepts_mixed_case() {
        let key = PublicKey::from_hex(&HEX.to_uppercase()).unwrap();
        assert_eq!(key.to_hex(), HEX);
    }

    #[test]
    fn wire_deserialize_rejects_uppercase() {
        assert!(
            serde_json::from_str::<PublicKey>(&alloc::format!("\"{}\"", HEX.to_uppercase()))
                .is_err()
        );
    }

    #[test]
    fn wire_deserialize_accepts_lowercase() {
        let key: PublicKey = serde_json::from_str(&alloc::format!("\"{HEX}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&key).unwrap(),
            alloc::format!("\"{HEX}\"")
        );
    }

    #[test]
    fn from_slice_checks_length() {
        PublicKey::from_slice(&[0u8; 31]).unwrap_err();
        PublicKey::from_slice(&[0u8; 32]).unwrap();
    }

    #[test]
    fn display_and_debug_use_lowercase_hex() {
        let key = PublicKey::from_hex(HEX).unwrap();
        assert_eq!(key.to_string(), HEX);
        assert_eq!(
            alloc::format!("{key:?}"),
            alloc::format!("PublicKey({HEX})")
        );
    }

    #[test]
    fn secret_key_rejects_out_of_range_scalars() {
        for bytes in [[0u8; 32], [0xff; 32]] {
            let error = SecretKey::from_bytes(bytes).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Crypto);
        }
    }

    #[test]
    fn secret_key_from_slice_checks_length() {
        assert_eq!(
            SecretKey::from_slice(&[1u8; 31]).unwrap_err().kind(),
            ErrorKind::Crypto
        );
        SecretKey::from_slice(&[1u8; 32]).unwrap();
    }

    #[test]
    fn secret_key_from_hex_accepts_mixed_case() {
        let key = SecretKey::from_hex(&SECRET.to_uppercase()).unwrap();
        assert_eq!(key.public_key().to_hex(), SECRET_PUB);
    }

    #[test]
    fn secret_key_from_hex_reports_hex_errors() {
        assert_eq!(
            SecretKey::from_hex("zz").unwrap_err().kind(),
            ErrorKind::Hex
        );
        assert_eq!(
            SecretKey::from_hex(&"00".repeat(32)).unwrap_err().kind(),
            ErrorKind::Crypto
        );
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let key = SecretKey::from_hex(SECRET).unwrap();
        assert_eq!(
            SecretKey::from_bytes(key.to_secret_bytes())
                .unwrap()
                .public_key(),
            key.public_key()
        );
    }

    #[test]
    fn secret_key_debug_hides_the_scalar() {
        let key = SecretKey::from_hex(SECRET).unwrap();
        assert_eq!(alloc::format!("{key:?}"), "SecretKey(..)");
    }

    #[test]
    fn generate_with_rng_yields_valid_keys() {
        let key = SecretKey::generate_with_rng(&mut CounterRng(0));
        // A generated key always lands in range; signing roundtrips.
        let id = EventId::from_bytes([7u8; 32]);
        let keys = Keys::new(key);
        let signature = keys.sign_id_with_aux(&id, &[0u8; 32]);
        signature.verify(&id, &keys.public_key()).unwrap();
    }

    #[test]
    fn keys_new_derives_the_public_key() {
        let keys = Keys::new(SecretKey::from_hex(SECRET).unwrap());
        assert_eq!(keys.public_key().to_hex(), SECRET_PUB);
        assert_eq!(keys.secret_key().to_secret_bytes()[31], 3);
    }

    #[test]
    fn keys_debug_shows_only_the_public_key() {
        let secret = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
        let keys = Keys::new(SecretKey::from_hex(secret).unwrap());
        let debug = alloc::format!("{keys:?}");
        assert!(debug.contains(&keys.public_key().to_hex()));
        assert!(!debug.contains(secret));
    }

    #[test]
    fn sign_id_with_aux_matches_bip340_vector_zero() {
        let keys = Keys::new(SecretKey::from_hex(SECRET).unwrap());
        let signature = keys.sign_id_with_aux(&EventId::from_bytes([0u8; 32]), &[0u8; 32]);
        assert_eq!(signature.to_hex(), VECTOR0_SIG);
    }

    #[test]
    fn sign_event_with_aux_rejects_a_mismatching_pubkey() {
        let keys = Keys::new(SecretKey::from_hex(SECRET).unwrap());
        let unsigned = UnsignedEvent::new(
            PublicKey::from_hex(HEX).unwrap(),
            Timestamp::from_secs(1),
            Kind::TEXT_NOTE,
            Tags::new(),
            "gm",
        );
        let error = keys.sign_event_with_aux(unsigned, &[0u8; 32]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Crypto);
    }

    #[test]
    fn sign_event_with_rng_produces_a_verified_event() {
        let keys = Keys::new(SecretKey::from_hex(SECRET).unwrap());
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "gm",
        );
        let event = keys
            .sign_event_with_rng(unsigned.clone(), &mut CounterRng(9))
            .unwrap();
        assert!(event.matches_unsigned(&unsigned));
        event.verify().unwrap();
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn generate_and_sign_event_use_os_entropy() {
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "gm",
        );
        keys.sign_event(unsigned).unwrap().verify().unwrap();
    }
}
