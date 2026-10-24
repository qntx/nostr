//! NIP-59 gift wrap.
//!
//! Counterpart of `@qntx/nostr/nips/nip59`.
//!
//! TS drives the whole flow through the injected, asynchronous `Nip59Crypto`
//! (which may be a remote NIP-46 signer). This layer owns neither signers nor
//! async callbacks, so the implementation is split in two:
//!
//! - The local-key synchronous flow: [`Rumor::wrap`] and
//!   [`Rumor::from_gift_wrap`].
//! - The pure protocol steps (`seal`, `gift_wrap`, `seal_template`,
//!   `check_gift_wrap`, `parse_seal`, `open_rumor`, [`Rumor::to_json`]) are
//!   `pub(crate)`: a signer layer composes them into the same flow for
//!   remote signing.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/59.md>

use alloc::string::{String, ToString};
use alloc::vec;

use crate::event::Error as EventError;
use crate::json::JsonError;
use crate::{Event, EventId, Keys, Kind, PublicKey, RelayUrl, Tag, Tags, Timestamp, UnsignedEvent};

use crate::nips::nip44;

/// TS `TWO_DAYS_SECS` — the uniform random-offset window for `Random`
/// timestamps.
pub const TWO_DAYS_SECS: u64 = 172_800;

/// The error type returned by NIP-59 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `rng` failed to fill a draw (random offset, NIP-44 nonce, or BIP-340
    /// auxiliary randomness).
    #[error("rng failed")]
    Rng,
    /// Conversation key derivation or NIP-44 encryption failed.
    #[error("failed to encrypt")]
    Encrypt(#[source] nip44::Error),
    /// Conversation key derivation or NIP-44 decryption failed.
    #[error("failed to decrypt")]
    Decrypt(#[source] nip44::Error),
    /// The ephemeral wrap key could not be generated.
    #[error("ephemeral key generation failed")]
    EphemeralKey(#[source] crate::key::Error),
    /// The unsigned event's pubkey does not match the signing key.
    #[error("unsigned event pubkey does not match secret key")]
    Sign(#[source] crate::key::Error),
    /// A JSON input was syntactically malformed (TS `JSON.parse` failure).
    #[error("invalid JSON")]
    Json(#[source] JsonError),
    /// Well-formed JSON that is not a valid seal/gift-wrap wire shape (TS
    /// `validateSignedEvent` failure), with the JSON error inside.
    #[error("{0}")]
    Shape(&'static str, #[source] JsonError),
    /// A rumor carried a `sig` property.
    #[error("rumor must be unsigned")]
    RumorSigned,
    /// The rumor failed shape validation or its `id` does not match the
    /// computed id.
    #[error("invalid rumor")]
    InvalidRumor,
    /// The input kind is not 1059 or 21059.
    #[error("expected gift wrap")]
    NotGiftWrap,
    /// The gift wrap's signature did not verify.
    #[error("gift wrap signature")]
    GiftWrapSignature(#[source] EventError),
    /// The seal's kind is not 13, carries illegal tags, or its signature did
    /// not verify.
    #[error("expected seal")]
    NotSeal,
    /// A seal tag other than `expiration` (with an all-digits value) was
    /// present.
    #[error("seal tags must be empty")]
    SealTags,
    /// The seal's signature did not verify.
    #[error("seal signature")]
    SealSignature(#[source] EventError),
    /// The seal author and the rumor author differ.
    #[error("seal pubkey does not match rumor pubkey")]
    PubkeyMismatch,
    /// The computed timestamp is out of range.
    #[error("cannot sign invalid unsigned event")]
    InvalidUnsignedEvent,
}

/// Result type for NIP-59 operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl Kind {
    /// Whether this kind is a NIP-59 gift wrap kind — `1059`, or `21059` for
    /// the ephemeral variant (TS `isGiftWrapKind`).
    #[must_use]
    pub const fn is_gift_wrap(self) -> bool {
        self.as_u16() == 1059 || self.as_u16() == 21059
    }
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
        // Field serializers on nk types and `serde_json`'s `Result` never
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
    /// [`Error::Json`] on malformed JSON, [`Error::RumorSigned`] when a `sig`
    /// is present, [`Error::InvalidRumor`] on shape or id mismatch.
    pub fn from_json(json: &str) -> Result<Self> {
        let value =
            serde_json::from_str::<serde_json::Value>(json).map_err(|e| Error::Json(e.into()))?;
        let object = value.as_object().ok_or(Error::InvalidRumor)?;
        if object.contains_key("sig") {
            return Err(Error::RumorSigned);
        }
        let given_id = object.get("id").and_then(serde_json::Value::as_str);
        let unsigned = serde_json::from_value::<UnsignedEvent>(value.clone())
            .map_err(|_| Error::InvalidRumor)?;
        let rumor = Self::new(unsigned);
        if given_id.is_some_and(|id| !id.eq_ignore_ascii_case(&rumor.id().to_hex())) {
            return Err(Error::InvalidRumor);
        }
        Ok(rumor)
    }

    /// Seals and gift-wraps this rumor for `recipient`, signed by `sender`
    /// (TS `wrap`). `rng` consumption: the random seal/wrap offsets (per
    /// [`WrapOptions`]' timestamp strategy), the ephemeral key draw, each
    /// NIP-44 nonce, then each BIP-340 auxiliary draw.
    ///
    /// # Errors
    ///
    /// Any [`Error`] from the `seal` and `gift_wrap` steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use nk_core::nips::nip59::{Rumor, Timestamps, WrapOptions};
    /// use nk_core::{Keys, Kind, SecretKey, Tags, Timestamp, UnsignedEvent};
    ///
    /// let alice = Keys::new(SecretKey::from_bytes([1; 32]).unwrap());
    /// let bob = Keys::new(SecretKey::from_bytes([2; 32]).unwrap());
    /// let unsigned = UnsignedEvent::new(
    ///     alice.public_key(),
    ///     Timestamp::from_secs(1_700_000_000),
    ///     Kind::PRIVATE_DIRECT_MESSAGE,
    ///     Tags::new(),
    ///     "hello bob",
    /// );
    /// let rumor = Rumor::new(unsigned);
    /// let options = WrapOptions::new(Timestamps::Fixed {
    ///     seal: Timestamp::from_secs(1_700_000_100),
    ///     wrap: Timestamp::from_secs(1_700_000_200),
    /// });
    /// let mut rng = nk_core::SysRng;
    /// let gift = rumor.wrap(&alice, &bob.public_key(), &options, &mut rng)?;
    /// let back = Rumor::from_gift_wrap(&gift, &bob)?;
    /// assert_eq!(back.unsigned().content(), "hello bob");
    /// # Ok::<(), nk_core::nips::nip59::Error>(())
    /// ```
    pub fn wrap<R>(
        &self,
        sender: &Keys,
        recipient: &PublicKey,
        options: &WrapOptions,
        rng: &mut R,
    ) -> Result<Event>
    where
        R: rand_core::TryCryptoRng + ?Sized,
    {
        let seal = seal(self, sender, recipient, options, rng)?;
        gift_wrap(&seal, recipient, options, rng)
    }

    /// Unwraps a NIP-59 gift wrap addressed to `recipient` (TS `unwrap`).
    ///
    /// # Errors
    ///
    /// [`Error::NotGiftWrap`]/[`Error::GiftWrapSignature`] on a malformed or
    /// badly-signed wrap, [`Error::Decrypt`] on a NIP-44 failure,
    /// [`Error::NotSeal`]/[`Error::SealTags`]/[`Error::SealSignature`] on a
    /// malformed seal, and the [`Rumor::from_json`] errors.
    pub fn from_gift_wrap(gift_wrap: &Event, recipient: &Keys) -> Result<Self> {
        check_gift_wrap(gift_wrap)?;
        let seal_json = decrypt_layer(gift_wrap.content(), recipient, &gift_wrap.pubkey())?;
        let seal = parse_seal(&seal_json)?;
        let rumor_json = decrypt_layer(seal.content(), recipient, &seal.pubkey())?;
        open_rumor(&seal, &rumor_json)
    }
}

/// Timestamp strategy for `seal`, `gift_wrap`, and [`Rumor::wrap`].
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

/// Options shared by the wrap layers.
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

    /// Per-recipient gift-wrap options for `nip17::wrap_direct_message`:
    /// same timestamps, expiration, and ephemeral flag, the target's relay
    /// hint, and no extra tags — TS `wrapDirectMessage` forwards only those.
    pub(crate) const fn dm_wrap(&self, relay_hint: Option<RelayUrl>) -> Self {
        Self {
            timestamps: self.timestamps,
            relay_hint,
            extra_tags: Tags::new(),
            expiration: self.expiration,
            ephemeral: self.ephemeral,
        }
    }

    fn seal_created_at<R: rand_core::TryCryptoRng + ?Sized>(
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

    fn wrap_created_at<R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<Timestamp> {
        match self.timestamps {
            Timestamps::Fixed { wrap, .. } => Ok(wrap),
            Timestamps::Random { now, .. } => random_past(now, rng),
        }
    }
}

/// `["expiration", <unix secs>]` — the tag both layers may carry.
fn expiration_tag(at: Timestamp) -> Tag {
    Tag::custom("expiration", [at.as_secs().to_string()])
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
/// [`Error::Encrypt`] — conversation key derivation or NIP-44 encryption
/// failed — [`Error::Rng`], and [`Error::Sign`] for signing.
pub(crate) fn seal<R>(
    rumor: &Rumor,
    author: &Keys,
    recipient: &PublicKey,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Event>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let created_at = options.seal_created_at(rumor, rng)?;
    let content = encrypt_layer(&rumor.to_json(), author, recipient, rng)?;
    let unsigned = seal_template(author.public_key(), content, created_at, options.expiration);
    sign(unsigned, author, rng)
}

/// Encrypts `seal` to `recipient` under a fresh ephemeral key (TS
/// `giftWrap`).
///
/// `rng` consumption: the ephemeral scalar, the random offset (if
/// randomized), the 32-byte NIP-44 nonce, then the BIP-340 auxiliary
/// randomness.
///
/// # Errors
///
/// [`Error::EphemeralKey`], [`Error::Encrypt`], [`Error::Rng`], and
/// [`Error::Sign`].
pub(crate) fn gift_wrap<R>(
    seal: &Event,
    recipient: &PublicKey,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Event>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let ephemeral = Keys::from_rng(rng).map_err(Error::EphemeralKey)?;
    let created_at = options.wrap_created_at(rng)?;
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

/// The kind-13 seal skeleton TS builds before signing.
pub(crate) fn seal_template(
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

/// TS `checkGiftWrap`: kind must be a gift wrap kind and the signature must
/// verify.
pub(crate) fn check_gift_wrap(event: &Event) -> Result<()> {
    if !event.kind().is_gift_wrap() {
        return Err(Error::NotGiftWrap);
    }
    event.verify().map_err(Error::GiftWrapSignature)?;
    Ok(())
}

/// TS `parseSeal`: a valid signed kind-13 event with no tags besides an
/// optional all-digits `expiration`.
pub(crate) fn parse_seal(json: &str) -> Result<Event> {
    let seal = parse_event_json(json, "expected seal")?;
    if seal.kind() != Kind::SEAL {
        return Err(Error::NotSeal);
    }
    let illegal = seal.tags().iter().any(|tag| {
        tag.name() != "expiration"
            || !tag
                .value()
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
    });
    if illegal {
        return Err(Error::SealTags);
    }
    seal.verify().map_err(Error::SealSignature)?;
    Ok(seal)
}

/// TS `openRumor`: the seal author must equal the rumor author.
pub(crate) fn open_rumor(seal: &Event, rumor_json: &str) -> Result<Rumor> {
    let rumor = Rumor::from_json(rumor_json)?;
    if seal.pubkey() != rumor.unsigned().pubkey() {
        return Err(Error::PubkeyMismatch);
    }
    Ok(rumor)
}

fn random_past<R: rand_core::TryCryptoRng + ?Sized>(
    now: Timestamp,
    rng: &mut R,
) -> Result<Timestamp> {
    const SPAN: u64 = u32::MAX as u64 + 1;
    const LIMIT: u64 = SPAN / TWO_DAYS_SECS * TWO_DAYS_SECS;
    loop {
        let mut bytes = [0u8; 4];
        rng.try_fill_bytes(&mut bytes).map_err(|_| Error::Rng)?;
        let draw = u64::from(u32::from_be_bytes(bytes));
        if draw < LIMIT {
            return now
                .as_secs()
                .checked_sub(draw % TWO_DAYS_SECS)
                .map(Timestamp::from_secs)
                .ok_or(Error::InvalidUnsignedEvent);
        }
    }
}

/// Conversation-key derivation + NIP-44 encryption with a `rng`-drawn nonce —
/// TS `nip44Encrypt`, whose failures surface as `failed to encrypt`.
fn encrypt_layer<R>(plaintext: &str, keys: &Keys, peer: &PublicKey, rng: &mut R) -> Result<String>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    let conversation =
        nip44::ConversationKey::derive(keys.secret_key(), peer).map_err(Error::Encrypt)?;
    conversation.encrypt(plaintext, rng).map_err(Error::Encrypt)
}

/// Signs `unsigned` with `rng`-drawn BIP-340 auxiliary randomness.
fn sign<R>(unsigned: UnsignedEvent, keys: &Keys, rng: &mut R) -> Result<Event>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    keys.sign_event(unsigned, rng).map_err(Error::Sign)
}

/// Conversation-key derivation + NIP-44 decryption — TS `decryptLayer`,
/// which wraps both into `failed to decrypt`.
fn decrypt_layer(ciphertext: &str, recipient: &Keys, peer: &PublicKey) -> Result<String> {
    let conversation =
        nip44::ConversationKey::derive(recipient.secret_key(), peer).map_err(Error::Decrypt)?;
    conversation.decrypt(ciphertext).map_err(Error::Decrypt)
}

/// `serde_json` deserialization distinguishing malformed JSON (`invalid
/// JSON`, TS `JSON.parse` failure) from well-formed JSON of the wrong shape
/// (TS `validateSignedEvent` failure) — the same split as nip98.
fn parse_event_json(json: &str, shape_message: &'static str) -> Result<Event> {
    serde_json::from_str(json).map_err(|e| {
        if matches!(
            e.classify(),
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof
        ) {
            Error::Json(e.into())
        } else {
            Error::Shape(shape_message, e.into())
        }
    })
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
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde_json::Value;

    use crate::{Event, Keys, RelayUrl, SecretKey, Tag, Timestamp, UnsignedEvent};

    use super::*;

    const JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip59/codec.json"
    ));

    /// A `TryCryptoRng` that serves a scripted entropy stream in draw order.
    struct BytesRng(Vec<u8>);
    impl rand_core::TryRng for BytesRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_be_bytes(b))
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_be_bytes(b))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
            let take: Vec<u8> = self.0.drain(..dest.len().min(self.0.len())).collect();
            dest.copy_from_slice(&take);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for BytesRng {}

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    fn unhex_arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }
    fn keys(s: &str) -> Keys {
        Keys::new(SecretKey::from_bytes(unhex_arr(s)).unwrap())
    }

    fn rumor(v: &Value) -> Rumor {
        let unsigned: UnsignedEvent = serde_json::from_value(v.clone()).unwrap();
        Rumor::new(unsigned)
    }

    fn options(v: &Value) -> WrapOptions {
        let mut o = WrapOptions::new(match &v["timestamps"] {
            Value::Null => Timestamps::Random {
                now: Timestamp::from_secs(v["now"].as_u64().unwrap_or(1_700_000_000)),
                scope: match v["randomize"].as_str().unwrap_or("seal+wrap") {
                    "wrap" => RandomScope::WrapOnly,
                    _ => RandomScope::SealAndWrap,
                },
            },
            t => Timestamps::Fixed {
                seal: Timestamp::from_secs(t["seal"].as_u64().unwrap()),
                wrap: Timestamp::from_secs(t["wrap"].as_u64().unwrap()),
            },
        });
        if let Some(h) = v.get("relay_hint").and_then(Value::as_str) {
            o = o.relay_hint(RelayUrl::parse(h).unwrap());
        }
        if let Some(tags) = v.get("extra_tags").and_then(Value::as_array) {
            o = o.extra_tags(tags.iter().filter_map(|t| {
                Tag::new(
                    t.as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|x| x.as_str().map(String::from)),
                )
                .ok()
            }));
        }
        if let Some(e) = v.get("expiration").and_then(Value::as_u64) {
            o = o.expiration(Timestamp::from_secs(e));
        }
        if let Some(ep) = v.get("ephemeral").and_then(Value::as_bool) {
            o = o.ephemeral(ep);
        }
        o
    }

    #[test]
    fn vector_wrap() {
        let doc: Value = serde_json::from_str(JSON).unwrap();
        for case in doc["wrap"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let sender = keys(case["secret_key"].as_str().unwrap());
            let recipient = keys(case["recipient_secret_key"].as_str().unwrap());
            let r = rumor(&case["rumor"]);
            let o = options(&case["options"]);
            let mut rng = BytesRng(unhex(case["entropy"].as_str().unwrap()));
            let wrap = r
                .wrap(&sender, &recipient.public_key(), &o, &mut rng)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let want: Event = serde_json::from_value(case["wrap"].clone()).unwrap();
            assert_eq!(wrap.to_json(), want.to_json(), "{name}");
        }
    }

    #[test]
    fn vector_seal() {
        let doc: Value = serde_json::from_str(JSON).unwrap();
        for case in doc["seal"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let sender = keys(case["secret_key"].as_str().unwrap());
            let recipient = keys(case["recipient_secret_key"].as_str().unwrap());
            let r = rumor(&case["rumor"]);
            let o = options(&case["options"]);
            let mut rng = BytesRng(unhex(case["entropy"].as_str().unwrap()));
            let s = seal(&r, &sender, &recipient.public_key(), &o, &mut rng)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let want: Event = serde_json::from_value(case["seal"].clone()).unwrap();
            assert_eq!(s.to_json(), want.to_json(), "{name}");
        }
    }

    #[test]
    fn vector_gift() {
        let doc: Value = serde_json::from_str(JSON).unwrap();
        for case in doc["gift"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let recipient = keys(case["recipient_secret_key"].as_str().unwrap());
            let s: Event = serde_json::from_value(case["seal"].clone()).unwrap();
            let o = options(&case["options"]);
            let mut rng = BytesRng(unhex(case["entropy"].as_str().unwrap()));
            let w = gift_wrap(&s, &recipient.public_key(), &o, &mut rng)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let want: Event = serde_json::from_value(case["wrap"].clone()).unwrap();
            assert_eq!(w.to_json(), want.to_json(), "{name}");
        }
    }

    #[test]
    fn vector_unwrap() {
        let doc: Value = serde_json::from_str(JSON).unwrap();
        for case in doc["unwrap"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let gw: Event = serde_json::from_value(case["gift_wrap"].clone()).unwrap();
            let recipient = keys(case["recipient_secret_key"].as_str().unwrap());
            match Rumor::from_gift_wrap(&gw, &recipient) {
                Ok(r) => {
                    let want: UnsignedEvent =
                        serde_json::from_value(case["rumor"].clone()).unwrap();
                    assert_eq!(r.unsigned().to_json(), want.to_json(), "{name}");
                }
                Err(_) => {
                    assert!(
                        case["rumor"].is_null() || case.get("error").is_some(),
                        "{name}"
                    );
                }
            }
        }
    }

    #[test]
    fn gift_wrap_kind_predicate() {
        assert!(Kind::GIFT_WRAP.is_gift_wrap());
        assert!(Kind::GIFT_WRAP_EPHEMERAL.is_gift_wrap());
        assert!(!Kind::SEAL.is_gift_wrap());
    }
}
