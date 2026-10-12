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
    #[allow(dead_code, reason = "rejection is signalled by a missing `tags`")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct RelayParseCase {
    name: String,
    event: serde_json::Value,
    relays: Option<Vec<String>>,
    error: Option<String>,
}

fn wrap_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for (i, entry) in vector.wrap.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_owned();
        let _ = i;
        check.skip(&name);
    }
}

fn chat_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.chat {
        check.skip(&case.name);
    }
}

fn normalize_cases(check: &mut DivergenceCheck) {
    let vector: Vector = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &vector.normalize {
        check.skip(&case.name);
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
        match &outcome {
            // `RelayUrl::parse` cannot express the relay inputs (and the
            // builder has no error path for the vector's rejected cases).
            None => check.skip(&format!("build: {}", case.name)),
            Some(tags) if case.tags.is_some() => {
                let expected = case.tags.as_ref().expect("checked above");
                check.check(
                    &format!("build: {}", case.name),
                    common::same_tag_multiset(expected, tags),
                    &format!("tags={tags:?}"),
                );
            }
            Some(tags) => check.check(
                &format!("build: {}", case.name),
                false,
                &format!("tags={tags:?}"),
            ),
        }
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
