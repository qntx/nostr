//! Executes `vectors/nip17/codec.json` against rust-nostr's public API.

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

use common::DivergenceCheck;
use nostr::nips::nip17::{self, InboxRelayList};
use nostr::prelude::{Event, IntoEventBuilder, RelayUrl};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip17/codec.json"
));

#[derive(Deserialize)]
struct Vector {
    wrap: Vec<serde_json::Value>,
    chat: Vec<ChatCase>,
    normalize: Vec<NormalizeCase>,
    relay_list: RelayListSection,
}

#[derive(Deserialize)]
struct ChatCase {
    name: String,
}

#[derive(Deserialize)]
struct NormalizeCase {
    name: String,
}

#[derive(Deserialize)]
struct RelayListSection {
    build: Vec<RelayBuildCase>,
    parse: Vec<RelayParseCase>,
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
    event: serde_json::Value,
    relays: Option<Vec<String>>,
    error: Option<String>,
}

const WRAP_UNEXPRESSIBLE: &str =
    "deterministic multi-recipient gift wrapping is not exposed by rust-nostr";

fn wrap_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for (i, entry) in vector.wrap.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_owned();
        let _ = i;
        check.check(&name, false, WRAP_UNEXPRESSIBLE);
    }
}

fn chat_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.chat {
        check.check(
            &case.name,
            false,
            "kind-14 rumor construction is not exposed by rust-nostr",
        );
    }
}

fn normalize_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.normalize {
        check.check(
            &case.name,
            false,
            "recipient normalization has no rust-nostr counterpart",
        );
    }
}

fn relay_list_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.relay_list.build {
        let outcome: Option<Vec<Vec<String>>> = (|| {
            let relays: Vec<RelayUrl> = case
                .relays
                .iter()
                .map(|r| RelayUrl::parse(r).ok())
                .collect::<Option<_>>()?;
            let builder = InboxRelayList::new(relays).into_event_builder();
            Some(
                builder
                    .tags
                    .iter()
                    .map(|tag| tag.as_slice().to_vec())
                    .collect(),
            )
        })();
        let agrees = match (&case.tags, &case.error, &outcome) {
            (Some(expected), _, Some(tags)) => tags == expected,
            // The vector expects an error (e.g. empty list);
            // rust-nostr's builder has no error path.
            _ => false,
        };
        let got = outcome.map_or_else(
            || "input not expressible".to_owned(),
            |tags| format!("tags={tags:?}"),
        );
        check.check(&format!("build: {}", case.name), agrees, &got);
    }
    for case in &vector.relay_list.parse {
        let outcome: Option<Vec<String>> = serde_json::from_value::<Event>(case.event.clone())
            .ok()
            .map(|event| {
                nip17::extract_relay_list(&event)
                    .map(|url| url.to_string())
                    .collect()
            });
        let agrees = match (&case.relays, &case.error, &outcome) {
            (Some(expected), _, Some(urls)) => urls == expected,
            _ => false,
        };
        let got = outcome.map_or_else(
            || "event not decodable".to_owned(),
            |urls| format!("urls={urls:?}"),
        );
        check.check(&format!("parse: {}", case.name), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip17.dm");
    wrap_cases(&mut check);
    chat_cases(&mut check);
    normalize_cases(&mut check);
    relay_list_cases(&mut check);
    check.finish();
}
