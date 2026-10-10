//! `vectors/nip59/codec.json` — NIP-59 `seal`/`gift_wrap`/`wrap`/`unwrap`
//! cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip59.test.ts`; regenerate with
//! `bun packages/nostr/scripts/parity/gen/all.ts`.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use nk::nips::nip59::{self, RandomScope, Rumor, Timestamps, WrapOptions};
use nk::{Event, Keys, PublicKey, RelayUrl, SecretKey, Tag, Timestamp, UnsignedEvent};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip59/codec.json"
));

/// Replays the recorded `entropy` bytes — the exact stream the TS
/// `randomBytes` seam and its `Nip59Crypto` wrapper consumed, in draw order.
struct StreamRng<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl StreamRng<'_> {
    fn new(hex: &str) -> Self {
        Self {
            bytes: Box::leak(hex_bytes(hex).into_boxed_slice()),
            pos: 0,
        }
    }

    const fn exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex in vector");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector hex"))
        .collect()
}

impl rand_core::TryRng for StreamRng<'_> {
    type Error = core::convert::Infallible;

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
        let end = self.pos + dest.len();
        dest.copy_from_slice(
            self.bytes
                .get(self.pos..end)
                .expect("vector entropy stream exhausted"),
        );
        self.pos = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for StreamRng<'_> {}

#[derive(Debug, Deserialize)]
struct FixedTimestamps {
    seal: u64,
    wrap: u64,
}

#[derive(Debug, Deserialize)]
struct VectorOptions {
    timestamps: Option<FixedTimestamps>,
    now: Option<u64>,
    randomize: Option<String>,
    relay_hint: Option<String>,
    extra_tags: Option<Vec<Vec<String>>>,
    expiration: Option<u64>,
    ephemeral: Option<bool>,
}

impl VectorOptions {
    fn options(&self) -> WrapOptions {
        let timestamps = match (self.timestamps.as_ref(), self.now) {
            (Some(fixed), _) => Timestamps::Fixed {
                seal: Timestamp::from_secs(fixed.seal),
                wrap: Timestamp::from_secs(fixed.wrap),
            },
            (None, Some(now)) => Timestamps::Random {
                now: Timestamp::from_secs(now),
                scope: match self.randomize.as_deref() {
                    Some("wrap") => RandomScope::WrapOnly,
                    _ => RandomScope::SealAndWrap,
                },
            },
            (None, None) => panic!("vector options need timestamps or now"),
        };
        let mut options = WrapOptions::new(timestamps);
        if let Some(hint) = &self.relay_hint {
            options = options.relay_hint(RelayUrl::parse(hint).expect("vector relay hint"));
        }
        if let Some(tags) = &self.extra_tags {
            options = options.extra_tags(
                tags.iter()
                    .map(|t| Tag::new(t.iter().cloned()).expect("vector tag")),
            );
        }
        if let Some(at) = self.expiration {
            options = options.expiration(Timestamp::from_secs(at));
        }
        if let Some(ephemeral) = self.ephemeral {
            options = options.ephemeral(ephemeral);
        }
        options
    }
}

fn rumor_of(input: &UnsignedEvent) -> Rumor {
    Rumor::new(UnsignedEvent::new(
        input.pubkey(),
        input.created_at(),
        input.kind(),
        input.tags().iter().cloned().collect(),
        input.content().to_owned(),
    ))
}

fn keys_of(secret_key: &str) -> Keys {
    Keys::new(SecretKey::from_hex(secret_key).expect("vector secret key"))
}

#[derive(Debug, Deserialize)]
struct WrapCase {
    name: String,
    secret_key: String,
    recipient_secret_key: String,
    rumor: UnsignedEvent,
    options: VectorOptions,
    entropy: String,
    wrap: Event,
}

#[derive(Debug, Deserialize)]
struct SealCase {
    name: String,
    secret_key: String,
    recipient_secret_key: String,
    rumor: UnsignedEvent,
    options: VectorOptions,
    entropy: String,
    seal: Event,
}

#[derive(Debug, Deserialize)]
struct GiftCase {
    name: String,
    recipient_secret_key: String,
    seal: Event,
    options: VectorOptions,
    entropy: String,
    wrap: Event,
}

/// Expected rumor keeps the `id` the TS rumor carried (computed when absent).
#[derive(Debug, Deserialize)]
struct ExpectedRumor {
    pubkey: PublicKey,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    id: String,
}

#[derive(Debug, Deserialize)]
struct UnwrapCase {
    name: String,
    gift_wrap: Event,
    recipient_secret_key: String,
    rumor: Option<ExpectedRumor>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    wrap: Vec<WrapCase>,
    seal: Vec<SealCase>,
    gift: Vec<GiftCase>,
    unwrap: Vec<UnwrapCase>,
}

#[test]
fn wrap_cases_replay() {
    let vector: Vector = serde_json::from_str(CODEC).expect("vector JSON");
    for case in &vector.wrap {
        let mut rng = StreamRng::new(&case.entropy);
        let recipient = keys_of(&case.recipient_secret_key).public_key();
        let event = nip59::wrap_with_rng(
            &rumor_of(&case.rumor),
            &keys_of(&case.secret_key),
            &recipient,
            &case.options.options(),
            &mut rng,
        )
        .unwrap_or_else(|e| panic!("wrap {} failed: {e}", case.name));
        assert_eq!(event, case.wrap, "wrap {}", case.name);
        assert!(rng.exhausted(), "wrap {} left entropy undrawn", case.name);
    }
}

#[test]
fn seal_cases_replay() {
    let vector: Vector = serde_json::from_str(CODEC).expect("vector JSON");
    for case in &vector.seal {
        let mut rng = StreamRng::new(&case.entropy);
        let recipient = keys_of(&case.recipient_secret_key).public_key();
        let event = nip59::seal_with_rng(
            &rumor_of(&case.rumor),
            &keys_of(&case.secret_key),
            &recipient,
            &case.options.options(),
            &mut rng,
        )
        .unwrap_or_else(|e| panic!("seal {} failed: {e}", case.name));
        assert_eq!(event, case.seal, "seal {}", case.name);
        assert!(rng.exhausted(), "seal {} left entropy undrawn", case.name);
    }
}

#[test]
fn gift_wrap_cases_replay() {
    let vector: Vector = serde_json::from_str(CODEC).expect("vector JSON");
    for case in &vector.gift {
        let mut rng = StreamRng::new(&case.entropy);
        let recipient = keys_of(&case.recipient_secret_key).public_key();
        let event =
            nip59::gift_wrap_with_rng(&case.seal, &recipient, &case.options.options(), &mut rng)
                .unwrap_or_else(|e| panic!("gift {} failed: {e}", case.name));
        assert_eq!(event, case.wrap, "gift {}", case.name);
        assert!(rng.exhausted(), "gift {} left entropy undrawn", case.name);
    }
}

#[test]
fn unwrap_cases_match() {
    let vector: Vector = serde_json::from_str(CODEC).expect("vector JSON");
    for case in &vector.unwrap {
        let result = nip59::unwrap(&case.gift_wrap, &keys_of(&case.recipient_secret_key));
        match (&case.rumor, &case.error) {
            (Some(expected), None) => {
                let rumor = result.unwrap_or_else(|e| panic!("unwrap {} failed: {e}", case.name));
                assert_eq!(rumor.id().to_hex(), expected.id, "unwrap {} id", case.name);
                let unsigned = rumor.unsigned();
                assert_eq!(
                    unsigned.pubkey(),
                    expected.pubkey,
                    "unwrap {} pubkey",
                    case.name
                );
                assert_eq!(
                    unsigned.created_at(),
                    Timestamp::from_secs(expected.created_at),
                    "unwrap {} created_at",
                    case.name
                );
                assert_eq!(
                    unsigned.kind().as_u16(),
                    expected.kind,
                    "unwrap {} kind",
                    case.name
                );
                assert_eq!(
                    unsigned
                        .tags()
                        .iter()
                        .map(Tag::as_slice)
                        .collect::<Vec<_>>(),
                    expected.tags.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    "unwrap {} tags",
                    case.name
                );
                assert_eq!(
                    unsigned.content(),
                    expected.content,
                    "unwrap {} content",
                    case.name
                );
            }
            (None, Some(message)) => {
                let err = result.unwrap_err();
                assert_eq!(
                    err.to_string(),
                    format!("nip59: {message}"),
                    "unwrap {}",
                    case.name
                );
            }
            _ => panic!("unwrap {} must set exactly one of rumor/error", case.name),
        }
    }
}
