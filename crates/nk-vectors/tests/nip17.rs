//! `vectors/nip17/codec.json` — NIP-17 `wrap_direct_message`,
//! `chat_message_rumor`, `normalize_recipients`, and DM-relay-list cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip17.test.ts`; regenerate with
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

use nk_core::{Event, Keys, PublicKey, RelayUrl, SecretKey, Tag, Tags, Timestamp, UnsignedEvent};
use nk_nips::nip17::{
    ChatMessageOptions, Recipient, ReplyTo, chat_message_rumor, dm_relay_list, dm_relay_list_tags,
    normalize_recipients, parse_dm_relay_list, wrap_direct_message_with_rng,
};
use nk_nips::nip59::{RandomScope, Rumor, Timestamps, WrapOptions};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip17/codec.json"
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
    type Error = rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.pos + dst.len();
        dst.copy_from_slice(
            self.bytes
                .get(self.pos..end)
                .expect("vector entropy stream exhausted"),
        );
        self.pos = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for StreamRng<'_> {}

fn keys_of(secret_key: &str) -> Keys {
    let bytes: [u8; 32] = hex_bytes(secret_key).try_into().expect("secret key length");
    Keys::new(SecretKey::from_bytes(bytes).expect("vector secret key"))
}

fn pubkey(hex: &str) -> PublicKey {
    // TS `assertHex32` lowercases caller input before validating.
    PublicKey::from_hex(&hex.to_lowercase()).expect("vector pubkey")
}

fn relay_url(s: &str) -> RelayUrl {
    RelayUrl::parse(s).expect("vector relay hint must be normalized")
}

#[derive(Deserialize)]
struct VectorRecipient {
    pubkey: String,
    relay_hint: Option<String>,
}

impl VectorRecipient {
    fn recipient(&self) -> Recipient {
        Recipient {
            pubkey: pubkey(&self.pubkey),
            relay_hint: self.relay_hint.as_deref().map(relay_url),
        }
    }
}

#[derive(Deserialize)]
struct VectorOptions {
    timestamps: Option<VectorTimestamps>,
    now: Option<u64>,
    randomize: Option<String>,
    expiration: Option<u64>,
    ephemeral: Option<bool>,
}

#[derive(Deserialize)]
struct VectorTimestamps {
    seal: u64,
    wrap: u64,
}

impl VectorOptions {
    fn options(&self) -> WrapOptions {
        let mut options = WrapOptions::new(self.timestamps.as_ref().map_or_else(
            || Timestamps::Random {
                now: Timestamp::from_secs(self.now.expect("random timestamps need now")),
                scope: match self.randomize.as_deref() {
                    None | Some("seal+wrap") => RandomScope::SealAndWrap,
                    Some("wrap") => RandomScope::WrapOnly,
                    Some(other) => panic!("unknown randomize scope {other}"),
                },
            },
            |t| Timestamps::Fixed {
                seal: Timestamp::from_secs(t.seal),
                wrap: Timestamp::from_secs(t.wrap),
            },
        ));
        if let Some(expiration) = self.expiration {
            options = options.expiration(Timestamp::from_secs(expiration));
        }
        if let Some(ephemeral) = self.ephemeral {
            options = options.ephemeral(ephemeral);
        }
        options
    }
}

#[derive(Deserialize)]
struct RumorInput {
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

impl RumorInput {
    fn rumor(&self) -> Rumor {
        let tags: Tags = self
            .tags
            .iter()
            .cloned()
            .map(|items| Tag::new(items).expect("vector tag"))
            .collect();
        Rumor::new(UnsignedEvent::new(
            pubkey(&self.pubkey),
            Timestamp::from_secs(self.created_at),
            nk_core::Kind::new(self.kind),
            tags,
            self.content.clone(),
        ))
    }
}

#[derive(Deserialize)]
struct WrapCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    sender_secret_key: String,
    recipients: Vec<VectorRecipient>,
    rumor: RumorInput,
    options: VectorOptions,
    entropy: String,
    output: Vec<WrapOutput>,
}

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct WrapOutput {
    recipient: String,
    wrap: Event,
}

#[derive(Deserialize)]
struct WrapErr {
    name: String,
    sender_secret_key: String,
    recipients: Vec<VectorRecipient>,
    rumor: RumorInput,
    options: VectorOptions,
    error: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WrapEntry {
    Case(WrapCase),
    Err(WrapErr),
}

#[derive(Deserialize)]
struct ChatCase {
    name: String,
    rust: bool,
    sender: String,
    recipients: Vec<VectorRecipient>,
    content: String,
    created_at: u64,
    options: ChatOptionsVector,
    rumor: Option<ChatRumor>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ChatOptionsVector {
    subject: Option<String>,
    reply_to: Option<VectorReplyTo>,
}

#[derive(Deserialize)]
struct VectorReplyTo {
    id: String,
    relay_hint: Option<String>,
}

#[derive(Deserialize)]
struct ChatRumor {
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    id: String,
}

impl ChatCase {
    fn chat_options(&self) -> ChatMessageOptions {
        ChatMessageOptions {
            subject: self.options.subject.clone(),
            reply_to: self.options.reply_to.as_ref().map(|reply| ReplyTo {
                id: nk_core::EventId::from_hex(&reply.id).expect("vector reply id"),
                relay_hint: reply.relay_hint.as_deref().map(relay_url),
            }),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NormalizeInput {
    Key(String),
    Recipient(VectorRecipient),
}

#[derive(Deserialize)]
struct NormalizeCase {
    name: String,
    input: Vec<NormalizeInput>,
    output: Vec<VectorRecipient>,
}

#[derive(Deserialize)]
struct RelayBuildCase {
    name: String,
    relays: Vec<String>,
    tags: Option<Vec<Vec<String>>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RelayParseCase {
    name: String,
    event: Event,
    relays: Option<Vec<String>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RelayList {
    build: Vec<RelayBuildCase>,
    parse: Vec<RelayParseCase>,
}

#[derive(Deserialize)]
struct Vector {
    wrap: Vec<WrapEntry>,
    chat: Vec<ChatCase>,
    normalize: Vec<NormalizeCase>,
    relay_list: RelayList,
}

#[test]
fn wrap_cases_replay() {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for entry in &vector.wrap {
        match entry {
            WrapEntry::Case(case) => {
                if !case.rust {
                    // TS writes relay hints verbatim; Rust carries a
                    // normalized RelayUrl — unnormalized hints are TS-only.
                    continue;
                }
                let mut rng = StreamRng::new(&case.entropy);
                let out = wrap_direct_message_with_rng(
                    &keys_of(&case.sender_secret_key),
                    &case
                        .recipients
                        .iter()
                        .map(VectorRecipient::recipient)
                        .collect::<Vec<_>>(),
                    &case.rumor.rumor(),
                    &case.options.options(),
                    &mut rng,
                )
                .unwrap_or_else(|e| panic!("wrap {} failed: {e}", case.name));
                let expected: Vec<(PublicKey, Event)> = case
                    .output
                    .iter()
                    .map(|o| (pubkey(&o.recipient), o.wrap.clone()))
                    .collect();
                assert_eq!(out, expected, "wrap {}", case.name);
                assert!(rng.exhausted(), "wrap {} left entropy undrawn", case.name);
            }
            WrapEntry::Err(case) => {
                let mut rng = StreamRng::new("00");
                let error = wrap_direct_message_with_rng(
                    &keys_of(&case.sender_secret_key),
                    &case
                        .recipients
                        .iter()
                        .map(VectorRecipient::recipient)
                        .collect::<Vec<_>>(),
                    &case.rumor.rumor(),
                    &case.options.options(),
                    &mut rng,
                )
                .unwrap_err();
                assert_eq!(
                    error.to_string(),
                    format!("nip17: {}", case.error),
                    "wrap {}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn chat_cases_match() {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.chat {
        if !case.rust {
            continue;
        }
        let recipients: Vec<Recipient> = case
            .recipients
            .iter()
            .map(VectorRecipient::recipient)
            .collect();
        let result = chat_message_rumor(
            pubkey(&case.sender),
            &recipients,
            &case.content,
            Timestamp::from_secs(case.created_at),
            &case.chat_options(),
        );
        if let Some(expected) = &case.rumor {
            let rumor = result.unwrap_or_else(|e| panic!("chat {} failed: {e}", case.name));
            assert_eq!(rumor.id().to_hex(), expected.id, "chat {} id", case.name);
            let unsigned = rumor.unsigned();
            assert_eq!(
                unsigned.pubkey(),
                pubkey(&expected.pubkey),
                "chat {} pubkey",
                case.name
            );
            assert_eq!(
                unsigned.created_at().as_secs(),
                expected.created_at,
                "chat {} created_at",
                case.name
            );
            assert_eq!(
                unsigned.kind().as_u16(),
                expected.kind,
                "chat {} kind",
                case.name
            );
            assert_eq!(
                unsigned
                    .tags()
                    .iter()
                    .map(Tag::as_slice)
                    .collect::<Vec<_>>(),
                expected.tags.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                "chat {} tags",
                case.name
            );
            assert_eq!(
                unsigned.content(),
                expected.content,
                "chat {} content",
                case.name
            );
        } else {
            let error = result.unwrap_err();
            let expected = case.error.as_deref().expect("chat error case");
            assert_eq!(
                error.to_string(),
                format!("nip17: {expected}"),
                "chat {}",
                case.name
            );
        }
    }
}

#[test]
fn normalize_cases_match() {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.normalize {
        let input: Vec<Recipient> = case
            .input
            .iter()
            .map(|item| match item {
                NormalizeInput::Key(key) => Recipient {
                    pubkey: pubkey(key),
                    relay_hint: None,
                },
                NormalizeInput::Recipient(r) => r.recipient(),
            })
            .collect();
        let expected: Vec<Recipient> = case.output.iter().map(VectorRecipient::recipient).collect();
        assert_eq!(
            normalize_recipients(input),
            expected,
            "normalize {}",
            case.name
        );
    }
}

#[test]
fn relay_list_cases_match() {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.relay_list.build {
        let built = dm_relay_list_tags(&case.relays);
        let tags: Vec<&[String]> = built.iter().map(Tag::as_slice).collect();
        if let Some(expected) = &case.tags {
            assert_eq!(
                tags,
                expected.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                "relay build {}",
                case.name
            );
            assert!(
                dm_relay_list(&case.relays).is_ok(),
                "relay build {} must not error",
                case.name
            );
        } else {
            let error = dm_relay_list(&case.relays).unwrap_err();
            let expected = case.error.as_deref().expect("build error case");
            assert_eq!(
                error.to_string(),
                format!("nip17: {expected}"),
                "relay build {}",
                case.name
            );
        }
    }
    for case in &vector.relay_list.parse {
        let result = parse_dm_relay_list(&case.event);
        if let Some(expected) = &case.relays {
            let urls: Vec<String> = result
                .unwrap_or_else(|e| panic!("relay parse {} failed: {e}", case.name))
                .iter()
                .map(|u| u.as_str().to_owned())
                .collect();
            assert_eq!(urls, *expected, "relay parse {}", case.name);
        } else {
            let error = result.unwrap_err();
            let expected = case.error.as_deref().expect("parse error case");
            assert_eq!(
                error.to_string(),
                format!("event validation: {expected}"),
                "relay parse {}",
                case.name
            );
        }
    }
}
