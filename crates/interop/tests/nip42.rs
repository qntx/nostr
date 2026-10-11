//! Executes `vectors/nip42/codec.json` against rust-nostr's public API.

#![allow(
    unused_crate_dependencies,
    reason = "integration tests do not import the lib crate's dependencies"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "a malformed fixture file must fail the test loudly"
)]
#![allow(
    clippy::tests_outside_test_module,
    reason = "integration test crate is itself the test module"
)]

mod common;

use common::DivergenceCheck;
use nostr::prelude::{
    ClientAuthentication, FinalizeUnsignedEvent, IntoEventBuilder, MachineReadablePrefix,
    PublicKey, RelayUrl,
};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip42/codec.json"
));

const PUBKEY: &str = "79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6";

#[derive(Debug, Deserialize)]
struct AuthCase {
    relay: String,
    challenge: String,
    tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AuthRequiredCase {
    reason: String,
    result: bool,
}

#[derive(Debug, Deserialize)]
struct Vector {
    auth: Vec<AuthCase>,
    auth_required: Vec<AuthRequiredCase>,
}

fn auth_event_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    let pubkey = PublicKey::from_hex(PUBKEY).expect("vector pubkey");
    for (i, case) in vector.auth.iter().enumerate() {
        let outcome = RelayUrl::parse(&case.relay).ok().map(|relay| {
            let unsigned = ClientAuthentication::new(case.challenge.clone(), relay)
                .into_event_builder()
                .custom_created_at(nostr::prelude::Timestamp::from_secs(1_700_000_000))
                .finalize_unsigned(pubkey);
            let tags: Vec<Vec<String>> = unsigned
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_owned())
                .collect();
            (unsigned.kind.as_u16(), tags, unsigned.content)
        });
        let agrees = outcome.as_ref().is_some_and(|(kind, tags, content)| {
            *kind == 22_242 && *tags == case.tags && *content == case.content
        });
        let got = outcome.map_or_else(
            || "input not expressible".to_owned(),
            |(kind, tags, _)| format!("kind={kind} tags={tags:?}"),
        );
        check.check(&i.to_string(), agrees, &got);
    }
}

fn auth_required_vectors(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("valid JSON");
    for (i, case) in vector.auth_required.iter().enumerate() {
        let prefix = MachineReadablePrefix::parse(&case.reason);
        let is_auth_required = matches!(prefix, Some(MachineReadablePrefix::AuthRequired));
        check.check(
            &format!("auth_required/{i}"),
            is_auth_required == case.result,
            &format!("prefix={prefix:?}"),
        );
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip42.auth-event");
    auth_event_vectors(&mut check);
    auth_required_vectors(&mut check);
    check.finish();
}
