//! Executes `vectors/nip44` against rust-nostr's public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use base64::Engine;
use base64::engine::general_purpose;
use common::{DivergenceCheck, hex, unhex_arr};
use nostr::nips::nip44::v2::{self, ConversationKey};
use nostr::prelude::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

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

fn bytes32(s: &str) -> Option<[u8; 32]> {
    unhex_arr(s)
}

fn conversation_key(s: &str) -> Option<ConversationKey> {
    ConversationKey::from_slice(&bytes32(s)?).ok()
}

fn b64encode(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

fn b64decode(s: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD.decode(s).ok()
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

#[allow(dead_code, reason = "rows are counted, not replayed")]
#[derive(Debug, Deserialize)]
struct MessageKeyRow {
    nonce: String,
    chacha_key: String,
    chacha_nonce: String,
    hmac_key: String,
}

#[allow(dead_code, reason = "rows are counted, not replayed")]
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
    #[allow(dead_code, reason = "from_shared_secret has no rust-nostr counterpart")]
    shared_secret: String,
    conversation_key: String,
}

fn official_get_conversation_key(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.valid.get_conversation_key.iter().enumerate() {
        let outcome = SecretKey::from_hex(&case.sec1)
            .ok()
            .zip(PublicKey::from_hex(&case.pub2).ok())
            .and_then(|(secret, peer)| ConversationKey::derive(&secret, &peer).ok())
            .map(|key| hex(key.as_bytes()));
        let got = outcome.clone().unwrap_or_else(|| "rejected".to_owned());
        check.check(
            &format!("get_conversation_key/{i}"),
            outcome.as_deref() == Some(case.conversation_key.as_str()),
            &got,
        );
    }
}

fn official_get_message_keys(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    // rust-nostr derives message keys internally inside
    // `v2::encrypt_to_bytes_with_nonce`; `MessageKeys` is a private type, so
    // the per-key rows cannot be replayed through the public API.
    for (i, _) in vector.v2.valid.get_message_keys.keys.iter().enumerate() {
        check.skip(&format!("get_message_keys/{i}"));
    }
}

fn official_calc_padded_len(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    // `calc_padding` is private in rust-nostr's `nips::nip44::v2`.
    for (i, _) in vector.v2.valid.calc_padded_len.iter().enumerate() {
        check.skip(&format!("calc_padded_len/{i}"));
    }
}

fn encrypt_payload(plaintext: &str, key: &ConversationKey, nonce: [u8; 32]) -> Option<String> {
    v2::encrypt_to_bytes_with_nonce(key, plaintext.as_bytes(), nonce)
        .ok()
        .map(|bytes| b64encode(&bytes))
}

fn decrypt_payload(payload: &str, key: &ConversationKey) -> Option<String> {
    let bytes = b64decode(payload)?;
    let plaintext = v2::decrypt_to_bytes(key, &bytes).ok()?;
    String::from_utf8(plaintext).ok()
}

fn official_encrypt_decrypt(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.valid.encrypt_decrypt.iter().enumerate() {
        let outcome = (|| -> Option<(String, String)> {
            let key = conversation_key(&case.conversation_key)?;
            let nonce = bytes32(&case.nonce)?;
            let payload = encrypt_payload(&case.plaintext, &key, nonce)?;
            let plaintext = decrypt_payload(&payload, &key)?;
            Some((payload, plaintext))
        })();
        let agrees = outcome.as_ref().is_some_and(|(payload, plaintext)| {
            payload == &case.payload && plaintext == &case.plaintext
        });
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |(payload, _)| format!("encrypts to {payload}"),
        );
        check.check(&format!("encrypt_decrypt/{i}"), agrees, &got);
    }
}

/// Shared runner for `official.json`'s `encrypt_decrypt_long_msg` and
/// `extended.json`: plaintexts/payloads are too large to inline, so the
/// vectors record `pattern.repeat(repeat)` plus SHA-256 checksums.
fn run_long_message(label: &str, cases: &[LongMessageCase], check: &mut DivergenceCheck) {
    for (i, case) in cases.iter().enumerate() {
        let outcome = (|| -> Option<String> {
            let key = conversation_key(&case.conversation_key)?;
            let nonce = bytes32(&case.nonce)?;
            let plaintext = case.pattern.repeat(case.repeat);
            assert!(
                sha256_hex(plaintext.as_bytes()) == case.plaintext_sha256,
                "{label} case {i}: plaintext checksum mismatch"
            );
            let payload = encrypt_payload(&plaintext, &key, nonce)?;
            let decrypted = decrypt_payload(&payload, &key)?;
            if decrypted != plaintext {
                return None;
            }
            Some(sha256_hex(payload.as_bytes()))
        })();
        let agrees = outcome.as_deref() == Some(case.payload_sha256.as_str());
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&format!("{label}/{i}"), agrees, &got);
    }
}

fn official_encrypt_decrypt_long_msg(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    run_long_message(
        "encrypt_decrypt_long_msg",
        &vector.v2.valid.encrypt_decrypt_long_msg,
        check,
    );
}

fn extended_prefix_boundary(check: &mut DivergenceCheck) {
    let vector: ExtendedVectors = serde_json::from_str(EXTENDED).expect("valid JSON");
    run_long_message("extended", &vector.cases, check);
}

fn official_invalid_get_conversation_key(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.invalid.get_conversation_key.iter().enumerate() {
        let rejected = SecretKey::from_hex(&case.sec1).map_or(true, |secret| {
            PublicKey::from_hex(&case.pub2).map_or(true, |peer| {
                ConversationKey::derive(&secret, &peer).is_err()
            })
        });
        check.check(
            &format!("invalid_get_conversation_key/{i}"),
            rejected,
            if rejected { "rejected" } else { "accepted" },
        );
    }
}

fn official_invalid_decrypt(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.v2.invalid.decrypt.iter().enumerate() {
        let rejected = conversation_key(&case.conversation_key)
            .is_none_or(|key| decrypt_payload(&case.payload, &key).is_none());
        check.check(
            &format!("invalid_decrypt/{i}"),
            rejected,
            if rejected { "rejected" } else { "accepted" },
        );
    }
}

/// The vector list predates the extended u32 length prefix: under the current
/// spec only the sub-minimum length is invalid; `>= 65536` encrypts fine.
fn official_invalid_encrypt_msg_lengths(check: &mut DivergenceCheck) {
    let vector: OfficialVectors = serde_json::from_str(OFFICIAL).expect("valid JSON");
    let lengths = &vector.v2.invalid.encrypt_msg_lengths;
    let key = conversation_key("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
        .expect("conversation key");
    let nonce = [0u8; 32];
    for (i, len) in lengths.iter().enumerate() {
        let len = usize::try_from(*len).expect("fits usize");
        let plaintext = "a".repeat(len);
        let outcome = encrypt_payload(&plaintext, &key, nonce).and_then(|payload| {
            let decrypted = decrypt_payload(&payload, &key)?;
            (decrypted == plaintext).then_some(payload)
        });
        // Case 0 is the sub-minimum length (must reject); the rest must
        // round-trip under the extended length prefix.
        let agrees = if i == 0 {
            outcome.is_none()
        } else {
            outcome.is_some()
        };
        let got = outcome.map_or_else(
            || "rejected".to_owned(),
            |p| format!("accepted, len {}", p.len()),
        );
        check.check(&format!("encrypt_msg_lengths/{i}"), agrees, &got);
    }
}

fn shared_secret(check: &mut DivergenceCheck) {
    let vector: SharedSecretVectors = serde_json::from_str(SHARED_SECRET).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let outcome = SecretKey::from_hex(&case.sec1)
            .ok()
            .zip(PublicKey::from_hex(&case.pub2).ok())
            .and_then(|(secret, peer)| ConversationKey::derive(&secret, &peer).ok())
            .map(|key| hex(key.as_bytes()));
        let got = outcome.clone().unwrap_or_else(|| "rejected".to_owned());
        check.check(
            &format!("shared_secret/{i}"),
            outcome.as_deref() == Some(case.conversation_key.as_str()),
            &got,
        );
        // The vector also asserts `from_shared_secret(shared_secret)` yields
        // the same conversation key; rust-nostr has no such derivation entry
        // point — `ConversationKey::from_slice` takes the key verbatim.
        check.skip(&format!("shared_secret/{i}/from_shared_secret"));
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip44.v2");
    official_get_conversation_key(&mut check);
    official_get_message_keys(&mut check);
    official_calc_padded_len(&mut check);
    official_encrypt_decrypt(&mut check);
    official_encrypt_decrypt_long_msg(&mut check);
    extended_prefix_boundary(&mut check);
    official_invalid_get_conversation_key(&mut check);
    official_invalid_decrypt(&mut check);
    official_invalid_encrypt_msg_lengths(&mut check);
    shared_secret(&mut check);
    check.finish();
}
