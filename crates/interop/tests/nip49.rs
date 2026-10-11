//! Executes `vectors/nip49` against rust-nostr's public API.

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

use common::{DivergenceCheck, unhex_arr};
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr::prelude::SecretKey;
use serde::Deserialize;

const OFFICIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/official.json"
));
const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/codec.json"
));
const MAX_LOGN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip49/max-logn.json"
));

/// Valid `encrypt`/`decrypt` case from `codec.json`.
#[derive(Debug, Deserialize)]
struct Case {
    secret: String,
    password: String,
    log_n: u8,
    key_security: u8,
    salt: String,
    nonce: String,
    ncryptsec: String,
}

/// Failure case from `codec.json`.
#[derive(Debug, Deserialize)]
struct InvalidCase {
    ncryptsec: String,
    password: String,
    max_log_n: u8,
    #[serde(rename = "error")]
    #[allow(dead_code, reason = "only rejection is compared")]
    error_category: String,
}

#[derive(Debug, Deserialize)]
struct CodecVector {
    cases: Vec<Case>,
    invalid: Vec<InvalidCase>,
}

/// Spec-example decrypt case from `official.json`.
#[derive(Debug, Deserialize)]
struct OfficialCase {
    ncryptsec: String,
    password: String,
    max_log_n: u8,
    secret: String,
    key_security: u8,
}

#[derive(Debug, Deserialize)]
struct OfficialVector {
    cases: Vec<OfficialCase>,
}

/// Ceiling case from `max-logn.json`. `maxLogN` may be a non-integer
/// fixture (the TS API validates its range separately).
#[derive(Debug, Deserialize)]
struct MaxLognCase {
    input: String,
    password: String,
    #[serde(rename = "maxLogN")]
    max_log_n: serde_json::Value,
    secret: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MaxLognVector {
    cases: Vec<MaxLognCase>,
}

fn decrypt_outcome(input: &str, password: &str, max_log_n: u8) -> Option<(String, u8)> {
    let key = EncryptedSecretKey::from_bech32(input).ok()?;
    let secret = key.decrypt_with_max_log_n(password, max_log_n).ok()?;
    Some((secret.to_secret_hex(), key.key_security() as u8))
}

fn nip49_official(check: &mut DivergenceCheck) {
    let vector: OfficialVector = serde_json::from_str(OFFICIAL).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let outcome = decrypt_outcome(&case.ncryptsec, &case.password, case.max_log_n);
        let agrees = outcome
            .as_ref()
            .is_some_and(|(secret, ksb)| *secret == case.secret && *ksb == case.key_security);
        let got = outcome.map_or_else(|| "rejected".to_owned(), |(s, _)| s);
        check.check(&format!("official/{i}"), agrees, &got);
    }
}

fn nip49_codec(check: &mut DivergenceCheck) {
    let vector: CodecVector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        let outcome = (|| -> Option<String> {
            let secret = SecretKey::from_hex(&case.secret).ok()?;
            let salt = unhex_arr::<16>(&case.salt)?;
            let nonce = unhex_arr::<24>(&case.nonce)?;
            let key = EncryptedSecretKey::new_with_salt_and_nonce(
                &secret,
                &case.password,
                case.log_n,
                KeySecurity::try_from(case.key_security).ok()?,
                salt,
                nonce,
            )
            .ok()?;
            key.to_bech32().ok()
        })();
        let agrees = outcome.as_deref() == Some(case.ncryptsec.as_str());
        let got = outcome.unwrap_or_else(|| "rejected".to_owned());
        check.check(&format!("codec/{i}"), agrees, &got);
    }
    for (i, case) in vector.invalid.iter().enumerate() {
        let rejected = EncryptedSecretKey::from_bech32(&case.ncryptsec)
            .ok()
            .and_then(|key| {
                key.decrypt_with_max_log_n(&case.password, case.max_log_n)
                    .ok()
            })
            .is_none();
        check.check(
            &format!("invalid/{i}"),
            rejected,
            if rejected { "rejected" } else { "accepted" },
        );
    }
}

fn nip49_max_logn(check: &mut DivergenceCheck) {
    let vector: MaxLognVector = serde_json::from_str(MAX_LOGN).expect("valid JSON");
    for (i, case) in vector.cases.iter().enumerate() {
        // `maxLogN` may be a non-integer fixture; rust-nostr's API takes a
        // concrete `u8`, so a non-integer input is not expressible.
        let outcome = case
            .max_log_n
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .and_then(|max| decrypt_outcome(&case.input, &case.password, max));
        let agrees = match (&case.error, &case.secret, &outcome) {
            (Some(_), _, None) => true,
            (None, Some(secret), Some((got, _))) => got == secret,
            _ => false,
        };
        let got = outcome.map_or_else(|| "rejected".to_owned(), |(s, _)| s);
        check.check(&format!("max_logn/{i}"), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip49.ncryptsec");
    nip49_official(&mut check);
    nip49_codec(&mut check);
    nip49_max_logn(&mut check);
    check.finish();
}
