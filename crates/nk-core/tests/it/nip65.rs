//! vectors/nip65/codec.json — `nip65.relay-list`.

use nk_core::Event;
use nk_core::nips::nip65::{RelayList, RelayListItem, RelayMarker};

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct ParseCase {
    name: String,
    event: Value,
    out: Option<Vec<OutItem>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct OutItem {
    url: String,
    marker: Option<String>,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    items: Vec<BuildItem>,
    out_tags: Vec<Vec<String>>,
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct BuildItem {
    url: String,
    marker: String,
}

fn marker(s: Option<&str>) -> RelayMarker {
    match s {
        Some("read") => RelayMarker::Read,
        Some("write") => RelayMarker::Write,
        _ => RelayMarker::Both,
    }
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip65/codec.json"
));

#[test]
fn nip65_parse() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<ParseCase> = serde_json::from_value(doc["parse"].clone()).unwrap();
    for case in &cases {
        let event: Event = serde_json::from_value(case.event.clone()).unwrap();
        match (&case.out, &case.error) {
            // A missing `out` (with or without an error label) means the
            // kind check must reject the event.
            (Some(out), None) => {
                let list =
                    RelayList::try_from(&event).unwrap_or_else(|e| panic!("{}: {e}", case.name));
                let got: Vec<OutItem> = list
                    .items()
                    .iter()
                    .map(|i| OutItem {
                        url: i.url.to_string(),
                        marker: match i.marker {
                            RelayMarker::Read => Some("read".into()),
                            RelayMarker::Write => Some("write".into()),
                            RelayMarker::Both => Some("both".into()),
                        },
                    })
                    .collect();
                let got: Vec<(String, String)> = got
                    .iter()
                    .map(|g| (g.url.clone(), g.marker.clone().unwrap_or_default()))
                    .collect();
                let want: Vec<(String, String)> = out
                    .iter()
                    .map(|o| (o.url.clone(), o.marker.clone().unwrap_or_default()))
                    .collect();
                assert_eq!(got, want, "{}", case.name);
            }
            (None, _) => {
                assert!(RelayList::try_from(&event).is_err(), "{}", case.name);
            }
            _ => panic!("{}: out xor error", case.name),
        }
    }
}

#[test]
fn nip65_build() {
    let doc: Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<BuildCase> = serde_json::from_value(doc["build"].clone()).unwrap();
    for case in &cases {
        // `"rust": false` — TS builds tags from raw strings verbatim;
        // `RelayListItem` requires a normalized `RelayUrl`, so these shapes
        // cannot be expressed. Asserted as marked.
        if case.rust == Some(false) {
            continue;
        }
        let items: Vec<RelayListItem> = case
            .items
            .iter()
            .map(|i| RelayListItem {
                url: nk_core::RelayUrl::parse(&i.url).unwrap(),
                marker: marker(Some(i.marker.as_str())),
            })
            .collect();
        let builder = nk_core::EventBuilder::from(RelayList::new(items.clone()));
        let unsigned = builder.build_at(
            nk_core::PublicKey::from_hex(&"11".repeat(32)).unwrap(),
            nk_core::Timestamp::from_secs(1),
        );
        let tags: Vec<Vec<String>> = unsigned
            .tags()
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        assert_eq!(tags, case.out_tags, "{}", case.name);
        let list = RelayList::new(items.clone());
        if let (Some(read), Some(write)) = (&case.read, &case.write) {
            assert_eq!(
                list.read().map(|u| u.to_string()).collect::<Vec<_>>(),
                *read,
                "{} read",
                case.name
            );
            assert_eq!(
                list.write().map(|u| u.to_string()).collect::<Vec<_>>(),
                *write,
                "{} write",
                case.name
            );
        }
    }
}
