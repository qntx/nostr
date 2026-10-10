//! `vectors/nip65/codec.json` — NIP-65 `parse_relay_list`,
//! `relay_list_tags`/`relay_list`, and `read_relays`/`write_relays` cases.
//!
//! The same file is replayed by
//! `packages/nostr/tests/vectors/nip65.test.ts`; regenerate with
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

use nk::nips::nip65::{
    RelayListItem, RelayMarker, parse_relay_list, read_relays, relay_list, relay_list_tags,
    write_relays,
};
use nk::{Event, PublicKey, RelayUrl, Timestamp};
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
    event: Event,
    out: Option<Vec<ItemJson>>,
    err: Option<String>,
}

#[derive(Deserialize)]
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

impl ItemJson {
    /// Vector items carry normalized URL strings — the Rust `RelayUrl`
    /// accepts them unchanged (unnormalizable and non-enum-marker cases are
    /// `rust: false`).
    fn item(&self) -> RelayListItem {
        RelayListItem {
            url: RelayUrl::parse(&self.url).expect("vector relay url must normalize"),
            marker: match self.marker.as_str() {
                "read" => RelayMarker::Read,
                "write" => RelayMarker::Write,
                _ => RelayMarker::Both,
            },
        }
    }

    const fn marker_name(marker: RelayMarker) -> &'static str {
        match marker {
            RelayMarker::Read => "read",
            RelayMarker::Write => "write",
            RelayMarker::Both => "both",
        }
    }
}

#[test]
fn parse_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.parse {
        match (parse_relay_list(&case.event), &case.out, &case.err) {
            (Ok(items), Some(expected), _) => {
                let got: Vec<ItemJson> = items
                    .iter()
                    .map(|item| ItemJson {
                        url: item.url.to_string(),
                        marker: ItemJson::marker_name(item.marker).to_owned(),
                    })
                    .collect();
                assert_eq!(
                    got.iter().map(|i| (&i.url, &i.marker)).collect::<Vec<_>>(),
                    expected
                        .iter()
                        .map(|i| (&i.url, &i.marker))
                        .collect::<Vec<_>>(),
                    "parse {}",
                    case.name
                );
            }
            (Err(error), _, Some(err)) => {
                let kind = match err.as_str() {
                    "EventValidationError" => nk::nips::ErrorKind::EventValidation,
                    other => panic!("parse {}: unknown error class {other}", case.name),
                };
                assert_eq!(error.kind(), kind, "parse {}", case.name);
            }
            (Ok(_), None, _) => panic!("parse {}: expected error, got items", case.name),
            (Err(error), Some(_), _) => panic!("parse {}: expected items, got {error}", case.name),
            (Err(error), None, None) => {
                panic!("parse {}: {error} with no expectation", case.name)
            }
        }
    }
}

#[test]
fn build_cases_match() {
    let codec: Codec = serde_json::from_str(CODEC).expect("parse codec.json");
    for case in &codec.build {
        if !case.rust {
            // TS writes item fields verbatim; the Rust types cannot carry
            // unnormalizable urls or non-enum markers.
            continue;
        }
        let items: Vec<RelayListItem> = case.items.iter().map(ItemJson::item).collect();

        let got: Vec<Vec<String>> = relay_list_tags(&items)
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        assert_eq!(got, case.out_tags, "build {}", case.name);

        let expect = case.relay_list.as_ref().expect("build case has relay_list");
        let unsigned = relay_list(&items).build_at(
            PublicKey::from_hex("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
                .expect("pubkey"),
            Timestamp::from_secs(0),
        );
        assert_eq!(
            u64::from(unsigned.kind().as_u16()),
            expect.kind,
            "build {}",
            case.name
        );
        assert_eq!(unsigned.content(), expect.content, "build {}", case.name);

        let read: Vec<String> = read_relays(&items).map(RelayUrl::to_string).collect();
        let write: Vec<String> = write_relays(&items).map(RelayUrl::to_string).collect();
        assert_eq!(read, case.read, "read {}", case.name);
        assert_eq!(write, case.write, "write {}", case.name);
    }
}
