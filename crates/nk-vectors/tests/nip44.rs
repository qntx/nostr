//! `vectors/nip44/official.json`, `extended.json`, and `shared-secret.json` —
//! NIP-44 v2 payload-encryption vectors.
//!
//! `official.json` is the verbatim upstream vector file; `extended.json`
//! transcribes the spec-text u32-prefix boundary cases (checksummed payloads);
//! `shared-secret.json` is generated (`gen/nip44.ts`) and proves
//! `ConversationKey::from_shared_secret` reaches the official conversation
//! keys from the raw ECDH x-coordinate. The same files are replayed by
//! `packages/nostr/tests/nip44.test.ts`.

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

use nk::nips::ErrorKind;
use nk::nips::nip44::{self, ConversationKey, MessageKeys};
use nk::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use common::{hex, unhex};

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

fn bytes32(s: &str, label: &str) -> [u8; 32] {
    unhex(s)
        .unwrap_or_else(|| panic!("{label}: bad hex"))
        .try_into()
        .unwrap_or_else(|_| panic!("{label}: not 32 bytes"))
}

fn conversation_key(s: &str) -> ConversationKey {
    ConversationKey::from_bytes(bytes32(s, "conversation_key"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[derive(Debug, Deserialize)]
struct ConversationKeyCase {
    sec1: String,
    pub2: String,
    conversation_key: String,
}

#[derive(Debug, Deserialize)]
struct MessageKeyRow {
    nonce: String,
    chacha_key: String,
    chacha_nonce: String,
    hmac_key: String,
}

#[derive(Debug, Deserialize)]
struct MessageKeysVector {
    conversation_key: String,
    keys: Vec<MessageKeyRow>,
}

#[derive(Debug, Deserialize)]
struct EncryptDecryptCase {
    conversation_key: String,
    nonce: String,
    plaintext: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct LongMessageCase {
    conversation_key: String,
    nonce: String,
    pattern: String,
    repeat: usize,
    plaintext_sha256: String,
    payload_sha256: String,
}

#[derive(Debug, Deserialize)]
struct InvalidConversationKeyCase {
    sec1: String,
    pub2: String,
}

#[derive(Debug, Deserialize)]
struct InvalidDecryptCase {
    conversation_key: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct OfficialVectors {
    v2: OfficialV2,
}

#[derive(Debug, Deserialize)]
struct OfficialV2 {
    valid: OfficialValid,
    invalid: OfficialInvalid,
}

#[derive(Debug, Deserialize)]
struct OfficialValid {
    get_conversation_key: Vec<ConversationKeyCase>,
    get_message_keys: MessageKeysVector,
    calc_padded_len: Vec<(u64, u64)>,
    encrypt_decrypt: Vec<EncryptDecryptCase>,
    encrypt_decrypt_long_msg: Vec<LongMessageCase>,
}

#[derive(Debug, Deserialize)]
struct OfficialInvalid {
    encrypt_msg_lengths: Vec<u64>,
    get_conversation_key: Vec<InvalidConversationKeyCase>,
    decrypt: Vec<InvalidDecryptCase>,
}

#[derive(Debug, Deserialize)]
struct ExtendedVectors {
    cases: Vec<LongMessageCase>,
}

#[derive(Debug, Deserialize)]
struct SharedSecretVectors {
    cases: Vec<SharedSecretCase>,
}

#[derive(Debug, Deserialize)]
struct SharedSecretCase {
    sec1: String,
    pub2: String,
    shared_secret: String,
    conversation_key: String,
}

#[test]
fn official_get_conversation_key() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.valid.get_conversation_key.iter().enumerate() {
        let secret = SecretKey::from_hex(&case.sec1).expect("case sec1");
        let peer = PublicKey::from_hex(&case.pub2).expect("case pub2");
        let key = ConversationKey::derive(&secret, &peer)
            .unwrap_or_else(|e| panic!("case {i}: derive failed: {e}"));
        assert_eq!(
            hex(&key.to_bytes()),
            case.conversation_key,
            "case {i} conversation key"
        );
    }
}

#[test]
fn official_get_message_keys() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    let key = conversation_key(&vector.v2.valid.get_message_keys.conversation_key);
    for (i, row) in vector.v2.valid.get_message_keys.keys.iter().enumerate() {
        let keys = MessageKeys::derive(&key, &bytes32(&row.nonce, "nonce"));
        assert_eq!(
            hex(keys.chacha_key()),
            row.chacha_key,
            "case {i} chacha_key"
        );
        assert_eq!(
            hex(keys.chacha_nonce()),
            row.chacha_nonce,
            "case {i} chacha_nonce"
        );
        assert_eq!(hex(keys.hmac_key()), row.hmac_key, "case {i} hmac_key");
    }
}

#[test]
fn official_calc_padded_len() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, &(input, expected)) in vector.v2.valid.calc_padded_len.iter().enumerate() {
        let got = nip44::calc_padded_len(usize::try_from(input).expect("fits usize"))
            .unwrap_or_else(|e| panic!("case {i}: {input} rejected: {e}"));
        assert_eq!(got as u64, expected, "case {i}: calc_padded_len({input})");
    }
}

#[test]
fn official_encrypt_decrypt() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.valid.encrypt_decrypt.iter().enumerate() {
        let key = conversation_key(&case.conversation_key);
        let nonce = bytes32(&case.nonce, "nonce");
        let payload = nip44::encrypt_with_nonce(&case.plaintext, &key, &nonce)
            .unwrap_or_else(|e| panic!("case {i}: encrypt failed: {e}"));
        assert_eq!(payload, case.payload, "case {i}: payload");
        let plaintext = nip44::decrypt(&payload, &key)
            .unwrap_or_else(|e| panic!("case {i}: decrypt failed: {e}"));
        assert_eq!(plaintext, case.plaintext, "case {i}: plaintext");
    }
}

/// Shared runner for `official.json`'s `encrypt_decrypt_long_msg` and
/// `extended.json`: plaintexts/payloads are too large to inline, so the
/// vectors record `pattern.repeat(repeat)` plus SHA-256 checksums.
fn run_long_message(label: &str, cases: &[LongMessageCase]) {
    for (i, case) in cases.iter().enumerate() {
        let plaintext = case.pattern.repeat(case.repeat);
        assert_eq!(
            sha256_hex(plaintext.as_bytes()),
            case.plaintext_sha256,
            "{label} case {i}: plaintext checksum"
        );
        let key = conversation_key(&case.conversation_key);
        let nonce = bytes32(&case.nonce, "nonce");
        let payload = nip44::encrypt_with_nonce(&plaintext, &key, &nonce)
            .unwrap_or_else(|e| panic!("{label} case {i}: encrypt failed: {e}"));
        assert_eq!(
            sha256_hex(payload.as_bytes()),
            case.payload_sha256,
            "{label} case {i}: payload checksum"
        );
        let decrypted = nip44::decrypt_with_max_len(&payload, &key, payload.len())
            .unwrap_or_else(|e| panic!("{label} case {i}: decrypt failed: {e}"));
        assert_eq!(decrypted, plaintext, "{label} case {i}: plaintext");
    }
}

#[test]
fn official_encrypt_decrypt_long_msg() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    run_long_message("official", &vector.v2.valid.encrypt_decrypt_long_msg);
}

#[test]
fn extended_prefix_boundary() {
    let vector: ExtendedVectors = serde_json::from_str(EXTENDED).expect("valid JSON");
    run_long_message("extended", &vector.cases);
}

#[test]
fn official_invalid_get_conversation_key() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.invalid.get_conversation_key.iter().enumerate() {
        // A bad scalar fails at SecretKey construction; a bad x-only peer
        // fails inside `ConversationKey::derive` (`nk`'s PublicKey wraps
        // bytes without a curve check).
        let rejected = SecretKey::from_hex(&case.sec1).map_or(true, |secret| {
            PublicKey::from_hex(&case.pub2).map_or(true, |peer| {
                matches!(
                    ConversationKey::derive(&secret, &peer),
                    Err(ref e) if e.kind() == ErrorKind::Crypto
                )
            })
        });
        assert!(rejected, "case {i}: expected rejection");
    }
}

#[test]
fn official_invalid_decrypt() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.invalid.decrypt.iter().enumerate() {
        let key = conversation_key(&case.conversation_key);
        let err = nip44::decrypt(&case.payload, &key)
            .expect_err(&format!("case {i}: decrypt must fail ({})", case.payload));
        assert_eq!(
            err.kind(),
            ErrorKind::Crypto,
            "case {i}: expected ErrorKind::Crypto"
        );
    }
}

/// The vector list predates the extended u32 length prefix: under the current
/// spec only the sub-minimum length is invalid; `>= 65536` encrypts fine.
#[test]
fn official_invalid_encrypt_msg_lengths() {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    let lengths = &vector.v2.invalid.encrypt_msg_lengths;
    assert_eq!(lengths.first(), Some(&0), "first length is the sub-minimum");
    let key = conversation_key("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
    let nonce = [0u8; 32];
    let err = nip44::encrypt_with_nonce("", &key, &nonce).expect_err("empty plaintext must fail");
    assert_eq!(err.kind(), ErrorKind::Crypto);
    for &len in lengths.iter().skip(1) {
        let plaintext = "a".repeat(usize::try_from(len).expect("fits usize"));
        let payload = nip44::encrypt_with_nonce(&plaintext, &key, &nonce)
            .unwrap_or_else(|e| panic!("len {len}: encrypt failed: {e}"));
        let decrypted = nip44::decrypt_with_max_len(&payload, &key, payload.len())
            .unwrap_or_else(|e| panic!("len {len}: decrypt failed: {e}"));
        assert_eq!(decrypted, plaintext, "len {len}: round trip");
    }
}

#[test]
fn shared_secret() {
    let vector: SharedSecretVectors = serde_json::from_str(SHARED_SECRET).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let from_shared =
            ConversationKey::from_shared_secret(&bytes32(&case.shared_secret, "shared_secret"));
        assert_eq!(
            hex(&from_shared.to_bytes()),
            case.conversation_key,
            "case {i}: from_shared_secret"
        );
        let secret = SecretKey::from_hex(&case.sec1).expect("case sec1");
        let peer = PublicKey::from_hex(&case.pub2).expect("case pub2");
        let derived = ConversationKey::derive(&secret, &peer).expect("case derive");
        assert_eq!(
            hex(&derived.to_bytes()),
            case.conversation_key,
            "case {i}: derive == from_shared_secret"
        );
    }
}
