//! `vectors/nip57/codec.json` — NIP-57 `zap_request`, `parse_bolt11`, and
//! `validate_zap_receipt` cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip57.test.ts`; regenerate with
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

use nk_core::{Event, PublicKey, RelayUrl, Timestamp};
use nk_nips::nip57::{
    ZapTarget, parse_bolt11, validate_zap_receipt, zap_request, zap_request_from_receipt,
};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip57/codec.json"
));

const fn default_true() -> bool {
    true
}

const SIGNER: &str = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";

#[derive(Deserialize)]
struct Codec {
    zap_request: Vec<ZapRequestCase>,
    bolt11: Vec<Bolt11Case>,
    receipt: Vec<ReceiptCase>,
}

#[derive(Deserialize)]
struct ZapRequestCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    input: ZapInput,
    amount: serde_json::Value,
    relays: Vec<String>,
    comment: Option<String>,
    lnurl: Option<String>,
    out: Option<ZapOut>,
    err: Option<String>,
}

#[derive(Deserialize)]
struct ZapInput {
    pubkey: Option<String>,
    event: Option<Event>,
}

#[derive(Deserialize)]
struct ZapOut {
    kind: u64,
    created_at: u64,
    content: String,
    tags: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct Bolt11Case {
    name: String,
    invoice: String,
    out: Option<Bolt11Out>,
}

#[derive(Deserialize)]
struct Bolt11Out {
    #[serde(rename = "amountMsats")]
    amount_msats: Option<u64>,
    description: Option<String>,
    #[serde(rename = "descriptionHash")]
    description_hash: Option<String>,
    #[serde(rename = "paymentHash")]
    payment_hash: Option<String>,
    timestamp: u64,
    expiry: u64,
}

#[derive(Deserialize)]
struct ReceiptCase {
    name: String,
    receipt: Event,
    #[serde(rename = "nostrPubkey")]
    nostr_pubkey: String,
    lnurl: Option<String>,
    result: ReceiptResult,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReceiptResult {
    Valid {
        request: Event,
        #[serde(rename = "amountMsats")]
        amount_msats: Option<u64>,
    },
    Invalid {
        reason: String,
    },
}

fn hex32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("vector hex");
    }
    out
}

fn to_hex(bytes: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to String is infallible");
    }
    out
}

#[test]
fn zap_request_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.zap_request {
        if !case.rust {
            // TS writes p/relays values verbatim; the typed Rust API cannot
            // carry non-hex pubkeys, non-u64 amounts, or raw relay strings.
            continue;
        }
        let relays: Vec<RelayUrl> = case
            .relays
            .iter()
            .map(|url| RelayUrl::parse(url).expect("vector relay url must normalize"))
            .collect();
        let comment = case.comment.as_deref().unwrap_or("");
        let amount = case
            .amount
            .as_u64()
            .expect("rust-replayable vector amounts are u64");
        let built = match (&case.input.pubkey, &case.input.event) {
            (Some(pubkey), None) => zap_request(
                ZapTarget::Profile(PublicKey::from_hex(pubkey).expect("vector pubkey")),
                amount,
                &relays,
                comment,
                case.lnurl.as_deref(),
            ),
            (None, Some(event)) => zap_request(
                ZapTarget::Event(event),
                amount,
                &relays,
                comment,
                case.lnurl.as_deref(),
            ),
            _ => panic!("zap {}: input must carry pubkey xor event", case.name),
        };
        match (built, &case.out, &case.err) {
            (Ok(builder), Some(out), _) => {
                let unsigned = builder.build_at(
                    PublicKey::from_hex(SIGNER).expect("signer pubkey"),
                    Timestamp::from_secs(out.created_at),
                );
                assert_eq!(
                    u64::from(unsigned.kind().as_u16()),
                    out.kind,
                    "{}",
                    case.name
                );
                assert_eq!(
                    unsigned.created_at().as_secs(),
                    out.created_at,
                    "{}",
                    case.name
                );
                assert_eq!(unsigned.content(), out.content, "{}", case.name);
                let tags: Vec<Vec<String>> = unsigned
                    .tags()
                    .iter()
                    .map(|tag| tag.as_slice().to_vec())
                    .collect();
                assert_eq!(tags, out.tags, "{}", case.name);
            }
            (Err(error), _, Some(err)) => {
                assert_eq!(err.as_str(), "EventValidationError", "{}", case.name);
                assert_eq!(
                    error.kind(),
                    nk_nips::ErrorKind::EventValidation,
                    "{}",
                    case.name
                );
            }
            (Ok(_), None, _) => panic!("zap {}: expected error, got builder", case.name),
            (Err(error), Some(_), _) => panic!("zap {}: expected tags, got {error}", case.name),
            (Err(error), None, None) => {
                panic!("zap {}: {error} with no expectation", case.name)
            }
        }
    }
}

#[test]
fn bolt11_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.bolt11 {
        match (parse_bolt11(&case.invoice), &case.out) {
            (Some(fields), Some(out)) => {
                assert_eq!(fields.timestamp, out.timestamp, "{}", case.name);
                assert_eq!(fields.expiry, out.expiry, "{}", case.name);
                assert_eq!(fields.amount_msats, out.amount_msats, "{}", case.name);
                assert_eq!(
                    fields.description.as_deref(),
                    out.description.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    fields.description_hash.map(|h| to_hex(&h)),
                    out.description_hash.clone(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    out.payment_hash.as_deref().map(hex32),
                    Some(fields.payment_hash),
                    "{}",
                    case.name
                );
            }
            (None, None) => {}
            (Some(_), None) => panic!("bolt11 {}: expected null, parsed", case.name),
            (None, Some(_)) => panic!("bolt11 {}: expected fields, got none", case.name),
        }
    }
}

#[test]
fn receipt_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.receipt {
        let nostr_pubkey = PublicKey::from_hex(&case.nostr_pubkey).expect("vector nostr pubkey");
        match (
            validate_zap_receipt(&case.receipt, &nostr_pubkey, case.lnurl.as_deref()),
            &case.result,
        ) {
            (
                Ok(valid),
                ReceiptResult::Valid {
                    request,
                    amount_msats,
                    ..
                },
            ) => {
                assert_eq!(valid.request, *request, "{}", case.name);
                assert_eq!(valid.amount_msats, *amount_msats, "{}", case.name);
                // The embedded request round-trips on its own too.
                let again = zap_request_from_receipt(&case.receipt).expect("embedded request");
                assert_eq!(again, valid.request, "{}", case.name);
            }
            (Err(rejection), ReceiptResult::Invalid { reason, .. }) => {
                assert_eq!(rejection.to_string(), *reason, "{}", case.name);
            }
            (Ok(_), ReceiptResult::Invalid { reason, .. }) => {
                panic!("receipt {}: expected {reason:?}, valid", case.name)
            }
            (Err(rejection), ReceiptResult::Valid { .. }) => {
                panic!("receipt {}: expected valid, got {rejection}", case.name)
            }
        }
    }
}
