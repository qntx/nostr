//! Executes `vectors/nip65/codec.json` against rust-nostr's public API.

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
use nostr::nips::nip65::{self, RelayList, RelayMetadata};
use nostr::prelude::{Event, IntoEventBuilder, RelayUrl};
use serde::Deserialize;

const CODEC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip65/codec.json"
));

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct Codec {
    parse: Vec<ParseCase>,
    build: Vec<BuildCase>,
}

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    event: serde_json::Value,
    out: Option<Vec<ItemJson>>,
    err: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ItemJson {
    url: String,
    marker: String,
}

#[derive(Deserialize)]
struct RelayListExpect {
    kind: u64,
    content: String,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    #[serde(default = "default_true")]
    rust: bool,
    items: Vec<ItemJson>,
    relay_list: Option<RelayListExpect>,
    out_tags: Vec<Vec<String>>,
    read: Vec<String>,
    write: Vec<String>,
}

fn metadata(marker: &str) -> Option<RelayMetadata> {
    match marker {
        "read" => Some(RelayMetadata::Read),
        "write" => Some(RelayMetadata::Write),
        _ => None,
    }
}

fn parse_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        let outcome: Option<Vec<ItemJson>> = serde_json::from_value::<Event>(case.event.clone())
            .ok()
            .map(|event| {
                nip65::extract_relay_list(&event)
                    .map(|(url, marker)| ItemJson {
                        url: url.to_string(),
                        marker: marker.map_or_else(|| "both".to_owned(), |m| m.as_str().to_owned()),
                    })
                    .collect()
            });
        let agrees = match (&case.out, &case.err, &outcome) {
            (Some(expected), _, Some(items)) => items
                .iter()
                .map(|i| (&i.url, &i.marker))
                .eq(expected.iter().map(|i| (&i.url, &i.marker))),
            _ => false,
        };
        let got = outcome.map_or_else(
            || "event not decodable".to_owned(),
            |items| format!("items={items:?}"),
        );
        check.check(&format!("parse: {}", case.name), agrees, &got);
    }
}

type BuildOutcome = Option<(Vec<Vec<String>>, u64, String, Vec<String>, Vec<String>)>;

fn build_cases(check: &mut DivergenceCheck) {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.build {
        if !case.rust {
            continue;
        }
        let outcome: BuildOutcome = (|| {
            let items: Vec<(RelayUrl, Option<RelayMetadata>)> = case
                .items
                .iter()
                .map(|item| Some((RelayUrl::parse(&item.url).ok()?, metadata(&item.marker))))
                .collect::<Option<_>>()?;
            let builder = RelayList::new(items.clone()).into_event_builder();
            let tags: Vec<Vec<String>> = builder
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_vec())
                .collect();
            let read: Vec<String> = items
                .iter()
                .filter(|(_, m)| m.is_none_or(|m| m.is_read()))
                .map(|(u, _)| u.to_string())
                .collect();
            let write: Vec<String> = items
                .iter()
                .filter(|(_, m)| m.is_none_or(|m| m.is_write()))
                .map(|(u, _)| u.to_string())
                .collect();
            Some((
                tags,
                u64::from(builder.kind.as_u16()),
                builder.content,
                read,
                write,
            ))
        })();
        let expects = case.relay_list.as_ref().expect("build case has relay_list");
        let agrees = outcome
            .as_ref()
            .is_some_and(|(tags, kind, content, read, write)| {
                tags == &case.out_tags
                    && *kind == expects.kind
                    && content == &expects.content
                    && read == &case.read
                    && write == &case.write
            });
        let got = outcome.map_or_else(
            || "input not expressible".to_owned(),
            |(tags, _, _, _, _)| format!("tags={tags:?}"),
        );
        check.check(&format!("build: {}", case.name), agrees, &got);
    }
}

#[test]
fn vectors() {
    let mut check = DivergenceCheck::new("nip65.relay-list");
    parse_cases(&mut check);
    build_cases(&mut check);
    check.finish();
}
