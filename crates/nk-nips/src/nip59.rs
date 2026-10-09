//! NIP-59 gift wrap.
//!
//! Counterpart of `@qntx/nostr/nips/nip59` behind the `nip59` feature.
//!
//! TS drives the whole flow through the injected, asynchronous `Nip59Crypto`
//! (which may be a remote NIP-46 signer). This layer owns neither signers nor
//! async callbacks, so the implementation is split in two:
//!
//! - The local-key synchronous flow: [`seal`], [`gift_wrap`], [`wrap`], and
//!   [`unwrap`].
//! - The pure protocol steps: [`seal_template`], [`check_gift_wrap`],
//!   [`parse_seal`], [`open_rumor`], and [`Rumor::to_json`], which a signer
//!   layer composes into the same flow for remote signing.
//!
//! Errors are [`ErrorKind::Nip59`], mirroring TS `Nip59Error` (TS wraps
//! encryption/decryption failures into `Nip59Error` too, so decrypt errors are
//! `Nip59` here, not `Crypto`).

use alloc::string::{String, ToString};
use alloc::vec;

use nk_core::{
    Event, EventId, Keys, Kind, PublicKey, RelayUrl, Tag, Tags, Timestamp, UnsignedEvent,
};

use crate::Result;
use crate::error::{Error, ErrorKind};
use crate::nip44;

/// TS `TWO_DAYS_SECS` — the uniform random-offset window for `Random`
/// timestamps.
pub const TWO_DAYS_SECS: u64 = 172_800;

/// Whether `kind` is a NIP-59 gift wrap kind — `1059`, or `21059` for the
/// ephemeral variant (TS `isGiftWrapKind`).
#[must_use]
pub const fn is_gift_wrap_kind(kind: Kind) -> bool {
    kind.as_u16() == 1059 || kind.as_u16() == 21059
}

/// An unsigned event plus its computed id — the plaintext payload of a gift
/// wrap (TS `createRumor` / `rumorToJson` / `parseRumor`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rumor {
    unsigned: UnsignedEvent,
    id: EventId,
}

impl Rumor {
    /// Wraps `unsigned`, computing its id.
    #[must_use]
    pub fn new(unsigned: UnsignedEvent) -> Self {
        let id = unsigned.id();
        Self { unsigned, id }
    }

    /// The computed event id.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// The underlying unsigned event.
    #[must_use]
    pub const fn unsigned(&self) -> &UnsignedEvent {
        &self.unsigned
    }

    /// Returns the wrapped unsigned event.
    #[must_use]
    pub fn into_unsigned(self) -> UnsignedEvent {
        self.unsigned
    }

    /// TS `rumorToJson`: `id`, `pubkey`, `created_at`, `kind`, `tags`,
    /// `content` in that order.
    #[must_use]
    pub fn to_json(&self) -> String {
        // Field serializers on nk-core types and `serde_json`'s `Result` never
        // fail here, so `unwrap_or_default` is unreachable.
        let unsigned = self.unsigned();
        let mut json = alloc::format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{},\"kind\":{},\"tags\":",
            self.id().to_hex(),
            unsigned.pubkey().to_hex(),
            unsigned.created_at().as_secs(),
            unsigned.kind().as_u16(),
        );
        json.push_str(&serde_json::to_string(unsigned.tags()).unwrap_or_default());
        json.push_str(",\"content\":");
        json.push_str(&serde_json::to_string(unsigned.content()).unwrap_or_default());
        json.push('}');
        json
    }

    /// TS `parseRumor`.
    ///
    /// The parsed object must satisfy `validateEvent` for an unsigned event,
    /// must not carry a `sig` property, and when it carries a string `id` the
    /// value must equal the computed id ignoring case. A missing or
    /// non-string `id` is replaced by the computed id.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip59`] — `invalid JSON` (syntax), `rumor must be
    /// unsigned` (`sig` present), or `invalid rumor` (shape or id mismatch).
    pub fn from_json(json: &str) -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(json)
            .map_err(|e| nip59_error_source("invalid JSON", e))?;
        let object = value
            .as_object()
            .ok_or_else(|| nip59_error("invalid rumor"))?;
        if object.contains_key("sig") {
            return Err(nip59_error("rumor must be unsigned"));
        }
        let given_id = object.get("id").and_then(serde_json::Value::as_str);
        let unsigned = serde_json::from_value::<UnsignedEvent>(value.clone())
            .map_err(|e| nip59_error_source("invalid rumor", e))?;
        let rumor = Self::new(unsigned);
        if given_id.is_some_and(|id| !id.eq_ignore_ascii_case(&rumor.id().to_hex())) {
            return Err(nip59_error("invalid rumor"));
        }
        Ok(rumor)
    }
}

/// Timestamp strategy for [`seal`], [`gift_wrap`], and [`wrap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timestamps {
    /// TS default: `now` minus a uniformly random offset in
    /// `[0, TWO_DAYS_SECS)` seconds, drawn from `rng` by rejection sampling.
    Random {
        /// The timestamp the offset is subtracted from.
        now: Timestamp,
        /// Which layer(s) are randomized.
        scope: RandomScope,
    },
    /// TS `timestamps`: explicit per-layer timestamps, used by vectors and
    /// tests.
    Fixed {
        /// `created_at` of the seal.
        seal: Timestamp,
        /// `created_at` of the gift wrap.
        wrap: Timestamp,
    },
}

/// Which timestamp(s) [`Timestamps::Random`] randomizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RandomScope {
    /// TS `randomize: "seal+wrap"` (the default): both layers are
    /// randomized.
    SealAndWrap,
    /// TS `randomize: "wrap"`: the seal keeps the rumor's `created_at` and
    /// only the gift wrap is randomized.
    WrapOnly,
}

/// Options shared by [`seal`], [`gift_wrap`], and [`wrap`].
#[derive(Clone, Debug)]
pub struct WrapOptions {
    timestamps: Timestamps,
    relay_hint: Option<RelayUrl>,
    extra_tags: Tags,
    expiration: Option<Timestamp>,
    ephemeral: bool,
}

impl WrapOptions {
    /// Options with the given timestamp strategy.
    #[must_use]
    pub const fn new(timestamps: Timestamps) -> Self {
        Self {
            timestamps,
            relay_hint: None,
            extra_tags: Tags::new(),
            expiration: None,
            ephemeral: false,
        }
    }

    /// TS `relayHint`: relay hint embedded in the wrap's `p` tag.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// TS `extraTags`: appended to the wrap after `p` and `expiration`.
    #[must_use]
    pub fn extra_tags<I: IntoIterator<Item = Tag>>(mut self, tags: I) -> Self {
        self.extra_tags.extend(tags);
        self
    }

    /// TS `expiration`: an `["expiration", <unix secs>]` tag on both layers.
    #[must_use]
    pub const fn expiration(mut self, at: Timestamp) -> Self {
        self.expiration = Some(at);
        self
    }

    /// TS `ephemeral`: use kind `21059` instead of `1059` for the wrap.
    #[must_use]
    pub const fn ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    fn seal_created_at<R: rand_core::CryptoRng + ?Sized>(
        &self,
        rumor: &Rumor,
        rng: &mut R,
    ) -> Result<Timestamp> {
        match self.timestamps {
            Timestamps::Fixed { seal, .. } => Ok(seal),
            Timestamps::Random {
                scope: RandomScope::WrapOnly,
                ..
            } => Ok(rumor.unsigned.created_at()),
            Timestamps::Random { now, .. } => random_past(now, rng),
        }
    }

    fn wrap_created_at<R: rand_core::CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Timestamp> {
        match self.timestamps {
            Timestamps::Fixed { wrap, .. } => Ok(wrap),
            Timestamps::Random { now, .. } => random_past(now, rng),
        }
    }
}

/// Encrypts `rumor` to `recipient` and signs it as the kind `13` seal by
/// `author`.
///
/// `rng` consumption: the random offset (if the seal timestamp is
/// randomized), then the 32-byte NIP-44 nonce, then the 32-byte BIP-340
/// auxiliary randomness.
///
/// # Errors
///
/// [`ErrorKind::Nip59`] `failed to encrypt` — conversation key derivation or
/// NIP-44 encryption failed — and [`nk_core::Keys::sign_event_with_aux`]'s
/// errors for signing.
pub fn seal_with_rng<R>(
    rumor: &Rumor,
    author: &Keys,
    recipient: &PublicKey,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Event>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let created_at = options.seal_created_at(rumor, rng)?;
    let content = encrypt_layer(&rumor.to_json(), author, recipient, rng)?;
    let unsigned = seal_template(author.public_key(), content, created_at, options.expiration);
    sign(unsigned, author, rng)
}

/// [`seal_with_rng`] with the nonce and auxiliary randomness drawn from the
/// operating system.
///
/// # Errors
///
/// See [`seal_with_rng`].
///
/// # Panics
///
/// When the OS entropy source fails — the same contract as
/// [`nk_core::Keys::generate`].
#[cfg(feature = "os-rng")]
pub fn seal(
    rumor: &Rumor,
    author: &Keys,
    recipient: &PublicKey,
    options: &WrapOptions,
) -> Result<Event> {
    seal_with_rng(
        rumor,
        author,
        recipient,
        options,
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// Wraps `seal` for `recipient` under a fresh ephemeral key drawn from `rng`.
///
/// `rng` consumption: the ephemeral secret key (32-byte candidates, redrawn
/// while not a valid scalar — [`nk_core::Keys::generate_with_rng`]), then the
/// random offset (if the wrap timestamp is randomized), then the 32-byte
/// NIP-44 nonce, then the 32-byte BIP-340 auxiliary randomness.
///
/// # Errors
///
/// [`ErrorKind::Nip59`] `failed to encrypt` — conversation key derivation or
/// NIP-44 encryption failed — and [`nk_core::Keys::sign_event_with_aux`]'s
/// errors for signing.
pub fn gift_wrap_with_rng<R>(
    seal: &Event,
    recipient: &PublicKey,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Event>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let ephemeral = Keys::generate_with_rng(rng);
    let created_at = options.wrap_created_at(rng)?;
    // `Event::serialize` never fails; `serde_json`'s `Result` is a trait
    // obligation, not a reachable error. The wire order equals TS
    // `eventToJson`.
    let seal_json = serde_json::to_string(seal).unwrap_or_default();
    let content = encrypt_layer(&seal_json, &ephemeral, recipient, rng)?;
    let kind = if options.ephemeral {
        Kind::GIFT_WRAP_EPHEMERAL
    } else {
        Kind::GIFT_WRAP
    };
    let mut tags = vec![Tag::public_key(
        *recipient,
        options.relay_hint.as_ref(),
        None,
    )];
    if let Some(at) = options.expiration {
        tags.push(expiration_tag(at));
    }
    tags.extend(options.extra_tags.iter().cloned());
    let unsigned = UnsignedEvent::new(
        ephemeral.public_key(),
        created_at,
        kind,
        tags.into_iter().collect(),
        content,
    );
    sign(unsigned, &ephemeral, rng)
}

/// [`gift_wrap_with_rng`] with OS-entropy randomness.
///
/// # Errors
///
/// See [`gift_wrap_with_rng`].
///
/// # Panics
///
/// When the OS entropy source fails.
#[cfg(feature = "os-rng")]
pub fn gift_wrap(seal: &Event, recipient: &PublicKey, options: &WrapOptions) -> Result<Event> {
    gift_wrap_with_rng(
        seal,
        recipient,
        options,
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// The full gift wrap: [`seal_with_rng`] the rumor, then
/// [`gift_wrap_with_rng`] the seal (TS `wrap`).
///
/// `rng` consumption: the seal steps, then the gift-wrap steps — see those
/// functions for the exact order.
///
/// # Errors
///
/// See [`seal_with_rng`] and [`gift_wrap_with_rng`].
pub fn wrap_with_rng<R>(
    rumor: &Rumor,
    author: &Keys,
    recipient: &PublicKey,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Event>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let seal = seal_with_rng(rumor, author, recipient, options, rng)?;
    gift_wrap_with_rng(&seal, recipient, options, rng)
}

/// [`wrap_with_rng`] with OS-entropy randomness.
///
/// # Errors
///
/// See [`wrap_with_rng`].
///
/// # Panics
///
/// When the OS entropy source fails.
#[cfg(feature = "os-rng")]
pub fn wrap(
    rumor: &Rumor,
    author: &Keys,
    recipient: &PublicKey,
    options: &WrapOptions,
) -> Result<Event> {
    wrap_with_rng(
        rumor,
        author,
        recipient,
        options,
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// Opens `gift_wrap` for `recipient`.
///
/// Steps run in TS `unwrap` order:
///
/// 1. kind `1059`/`21059` → `expected gift wrap`
/// 2. wrap signature → `gift wrap signature`
/// 3. decrypt → `failed to decrypt`
/// 4. seal JSON → `invalid JSON`, seal shape and kind `13` → `expected seal`,
///    seal tag whitelist → `seal tags must be empty`, seal signature →
///    `seal signature`
/// 5. decrypt → `failed to decrypt`
/// 6. rumor JSON and rules via [`Rumor::from_json`]
/// 7. seal author == rumor author → `seal pubkey does not match rumor pubkey`
///
/// # Errors
///
/// [`ErrorKind::Nip59`] with the message of the failing step.
pub fn unwrap(gift_wrap: &Event, recipient: &Keys) -> Result<Rumor> {
    check_gift_wrap(gift_wrap)?;
    let seal_json = decrypt_layer(gift_wrap.content(), recipient, &gift_wrap.pubkey())?;
    let seal = parse_seal(&seal_json)?;
    let rumor_json = decrypt_layer(seal.content(), recipient, &seal.pubkey())?;
    open_rumor(&seal, &rumor_json)
}

/// The unsigned kind `13` seal: `encrypted_rumor` as content and, when given,
/// an `["expiration", <secs>]` tag — the only tag a seal may carry.
#[must_use]
pub fn seal_template(
    author: PublicKey,
    encrypted_rumor: String,
    created_at: Timestamp,
    expiration: Option<Timestamp>,
) -> UnsignedEvent {
    let mut tags = Tags::new();
    if let Some(at) = expiration {
        tags.push(expiration_tag(at));
    }
    UnsignedEvent::new(author, created_at, Kind::SEAL, tags, encrypted_rumor)
}

/// Checks `event` is a gift wrap and its signature verifies — steps 1–2 of
/// [`unwrap`].
///
/// # Errors
///
/// [`ErrorKind::Nip59`] — `expected gift wrap` or `gift wrap signature`.
pub fn check_gift_wrap(event: &Event) -> Result<()> {
    if !is_gift_wrap_kind(event.kind()) {
        return Err(nip59_error("expected gift wrap"));
    }
    if event.verify().is_err() {
        return Err(nip59_error("gift wrap signature"));
    }
    Ok(())
}

/// Parses a seal from its decrypted JSON — the seal half of [`unwrap`].
///
/// Signed-event shape and kind `13` → `expected seal`; every tag must be
/// `["expiration", <decimal digits>, …]` → `seal tags must be empty`;
/// signature → `seal signature`.
///
/// # Errors
///
/// [`ErrorKind::Nip59`] — `invalid JSON`, `expected seal`, `seal tags must be
/// empty`, or `seal signature`.
pub fn parse_seal(json: &str) -> Result<Event> {
    let seal = parse_event_json(json, "expected seal")?;
    if seal.kind() != Kind::SEAL {
        return Err(nip59_error("expected seal"));
    }
    let illegal = seal.tags().iter().any(|tag| {
        tag.name() != "expiration"
            || !tag
                .value()
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
    });
    if illegal {
        return Err(nip59_error("seal tags must be empty"));
    }
    if seal.verify().is_err() {
        return Err(nip59_error("seal signature"));
    }
    Ok(seal)
}

/// Opens a decrypted `rumor_json` against its `seal` — [`Rumor::from_json`]
/// plus the seal-author match (the rumor half of [`unwrap`]).
///
/// # Errors
///
/// [`ErrorKind::Nip59`] — [`Rumor::from_json`]'s errors or
/// `seal pubkey does not match rumor pubkey`.
pub fn open_rumor(seal: &Event, rumor_json: &str) -> Result<Rumor> {
    let rumor = Rumor::from_json(rumor_json)?;
    if seal.pubkey() != rumor.unsigned().pubkey() {
        return Err(nip59_error("seal pubkey does not match rumor pubkey"));
    }
    Ok(rumor)
}

/// TS `randomPastTimestamp(now, defaultRandomInt)`: a uniform integer in
/// `[0, TWO_DAYS_SECS)` drawn by rejection sampling over big-endian `u32`
/// draws (TS `defaultRandomInt` reads `getUint32(0)` big-endian and accepts
/// only values below `floor(2^32 / max) * max`), subtracted from `now`.
fn random_past<R: rand_core::CryptoRng + ?Sized>(now: Timestamp, rng: &mut R) -> Result<Timestamp> {
    const SPAN: u64 = u32::MAX as u64 + 1;
    const LIMIT: u64 = SPAN / TWO_DAYS_SECS * TWO_DAYS_SECS;
    loop {
        let mut bytes = [0u8; 4];
        rng.fill_bytes(&mut bytes);
        let draw = u64::from(u32::from_be_bytes(bytes));
        if draw < LIMIT {
            return now
                .as_secs()
                .checked_sub(draw % TWO_DAYS_SECS)
                .map(Timestamp::from_secs)
                // A negative `created_at` fails TS `validateEvent` at signing.
                .ok_or_else(|| {
                    Error::new(ErrorKind::EventValidation, "cannot sign invalid unsigned event")
                });
        }
    }
}

/// Conversation-key derivation + NIP-44 encryption with a `rng`-drawn nonce —
/// TS `nip44Encrypt`, whose failures surface as `failed to encrypt`.
fn encrypt_layer(
    plaintext: &str,
    keys: &Keys,
    peer: &PublicKey,
    rng: &mut (impl rand_core::CryptoRng + ?Sized),
) -> Result<String> {
    let conversation = nip44::ConversationKey::derive(keys.secret_key(), peer)
        .map_err(|e| nip59_error_source("failed to encrypt", e))?;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    nip44::encrypt_with_nonce(plaintext, &conversation, &nonce)
        .map_err(|e| nip59_error_source("failed to encrypt", e))
}

/// Signs `unsigned` with `rng`-drawn BIP-340 auxiliary randomness.
fn sign(
    unsigned: UnsignedEvent,
    keys: &Keys,
    rng: &mut (impl rand_core::CryptoRng + ?Sized),
) -> Result<Event> {
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    keys.sign_event_with_aux(unsigned, &aux).map_err(|e| {
        // A valid `UnsignedEvent` can only fail on a pubkey mismatch, which TS
        // `signEvent` surfaces as this `CryptoError`.
        Error::with_source(
            ErrorKind::Crypto,
            "unsigned event pubkey does not match secret key",
            e,
        )
    })
}

/// Conversation-key derivation + NIP-44 decryption — TS `decryptLayer`,
/// which wraps both into `failed to decrypt`.
fn decrypt_layer(ciphertext: &str, recipient: &Keys, peer: &PublicKey) -> Result<String> {
    let conversation = nip44::ConversationKey::derive(recipient.secret_key(), peer)
        .map_err(|e| nip59_error_source("failed to decrypt", e))?;
    nip44::decrypt(ciphertext, &conversation)
        .map_err(|e| nip59_error_source("failed to decrypt", e))
}

/// `serde_json` deserialization distinguishing malformed JSON (`invalid
/// JSON`, TS `JSON.parse` failure) from well-formed JSON of the wrong shape
/// (`shape_message`, TS `validateSignedEvent` failure) — the same split as
/// nip98.
fn parse_event_json(json: &str, shape_message: &'static str) -> Result<Event> {
    serde_json::from_str(json).map_err(|e| {
        let message = match e.classify() {
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                "invalid JSON"
            }
            serde_json::error::Category::Data | serde_json::error::Category::Io => shape_message,
        };
        nip59_error_source(message, e)
    })
}

fn expiration_tag(at: Timestamp) -> Tag {
    Tag::custom("expiration", [at.as_secs().to_string()])
}

fn nip59_error(message: &'static str) -> Error {
    Error::new(ErrorKind::Nip59, message)
}

fn nip59_error_source<E: core::error::Error + Send + Sync + 'static>(
    message: &'static str,
    source: E,
) -> Error {
    Error::with_source(ErrorKind::Nip59, message, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use nk_core::SecretKey;

    fn keys() -> Keys {
        // `1` is a valid secp256k1 scalar.
        Keys::new(SecretKey::from_bytes([1; 32]).unwrap())
    }

    fn peer() -> Keys {
        Keys::new(SecretKey::from_bytes([2; 32]).unwrap())
    }

    fn rumor() -> Rumor {
        Rumor::new(UnsignedEvent::new(
            keys().public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            Tags::new(),
            "hello",
        ))
    }

    /// A deterministic `rng` yielding an incrementing byte stream.
    struct CounterRng(u8);
    impl rand_core::TryRng for CounterRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut out = [0u8; 4];
            self.try_fill_bytes(&mut out)?;
            Ok(u32::from_le_bytes(out))
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut out = [0u8; 8];
            self.try_fill_bytes(&mut out)?;
            Ok(u64::from_le_bytes(out))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for CounterRng {}

    #[test]
    fn fixed_wrap_unwraps_round_trip() {
        let options = WrapOptions::new(Timestamps::Fixed {
            seal: Timestamp::from_secs(1_700_000_100),
            wrap: Timestamp::from_secs(1_700_000_200),
        });
        let wrap = wrap_with_rng(
            &rumor(),
            &keys(),
            &peer().public_key(),
            &options,
            &mut CounterRng(0),
        )
        .unwrap();
        assert_eq!(wrap.kind(), Kind::GIFT_WRAP);
        assert_eq!(wrap.created_at(), Timestamp::from_secs(1_700_000_200));
        let first = wrap.tags().iter().next().map(Tag::as_slice).unwrap();
        assert_eq!(first.first().map(String::as_str), Some("p"));
        let opened = unwrap(&wrap, &peer()).unwrap();
        assert_eq!(opened, rumor());
    }

    #[test]
    fn wrap_tag_order_and_ephemeral_kind() {
        let options = WrapOptions::new(Timestamps::Fixed {
            seal: Timestamp::from_secs(10),
            wrap: Timestamp::from_secs(20),
        })
        .relay_hint(RelayUrl::parse("wss://relay.example.com").unwrap())
        .expiration(Timestamp::from_secs(30))
        .extra_tags([Tag::custom("t", ["x"])])
        .ephemeral(true);
        let wrap = wrap_with_rng(
            &rumor(),
            &keys(),
            &peer().public_key(),
            &options,
            &mut CounterRng(9),
        )
        .unwrap();
        assert_eq!(wrap.kind(), Kind::GIFT_WRAP_EPHEMERAL);
        let names: Vec<&str> = wrap.tags().iter().map(Tag::name).collect();
        assert_eq!(names, ["p", "expiration", "t"]);
        let first = wrap.tags().iter().next().map(Tag::as_slice).unwrap();
        assert_eq!(
            first.get(2).map(String::as_str),
            Some("wss://relay.example.com/")
        );
    }

    #[test]
    fn seal_only_carries_expiration() {
        let options = WrapOptions::new(Timestamps::Fixed {
            seal: Timestamp::from_secs(10),
            wrap: Timestamp::from_secs(20),
        })
        .expiration(Timestamp::from_secs(30))
        .extra_tags([Tag::custom("t", ["x"])]);
        let seal = seal_with_rng(
            &rumor(),
            &keys(),
            &peer().public_key(),
            &options,
            &mut CounterRng(3),
        )
        .unwrap();
        assert_eq!(seal.kind(), Kind::SEAL);
        assert_eq!(seal.tags().len(), 1);
        assert_eq!(
            seal.tags().iter().next().map(Tag::as_slice).unwrap(),
            ["expiration", "30"]
        );
        let opened = parse_seal(&serde_json::to_string(&seal).unwrap());
        assert!(opened.is_ok());
    }

    #[test]
    fn wrap_only_scope_keeps_rumor_timestamp() {
        let options = WrapOptions::new(Timestamps::Random {
            now: Timestamp::from_secs(1_700_000_000),
            scope: RandomScope::WrapOnly,
        });
        let seal = seal_with_rng(
            &rumor(),
            &keys(),
            &peer().public_key(),
            &options,
            &mut CounterRng(1),
        )
        .unwrap();
        assert_eq!(seal.created_at(), rumor().unsigned().created_at());
    }

    #[test]
    fn unwrap_rejects_wrong_kind() {
        let event = keys()
            .sign_event_with_aux(
                UnsignedEvent::new(
                    keys().public_key(),
                    Timestamp::from_secs(1),
                    Kind::TEXT_NOTE,
                    Tags::new(),
                    "",
                ),
                &[7; 32],
            )
            .unwrap();
        let err = unwrap(&event, &peer()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Nip59);
        assert_eq!(err.to_string(), "nip59: expected gift wrap");
    }

    #[test]
    fn rumor_from_json_rejects_sig_and_bad_id() {
        let json = rumor().to_json();
        assert!(Rumor::from_json(&json).is_ok());
        let signed = json.replacen("\"id\":", "\"sig\":\"aa\",\"id\":", 1);
        assert!(Rumor::from_json(&signed).is_err());
        let bad = json.replacen(&rumor().id().to_hex(), &"f".repeat(64), 1);
        assert!(Rumor::from_json(&bad).is_err());
        let upper = json.replacen(
            &rumor().id().to_hex(),
            &rumor().id().to_hex().to_uppercase(),
            1,
        );
        assert!(Rumor::from_json(&upper).is_ok());
    }
}
