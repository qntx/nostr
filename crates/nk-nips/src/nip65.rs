//! NIP-65 relay lists: parse a kind-10002 event into typed relay items and
//! build relay-list events back.
//!
//! [`parse_relay_list`] is the counterpart of the TS `parseRelayList`: `r`
//! tag values are normalized with [`RelayUrl::parse`] (the same
//! `normalizeURL`), unnormalizable values are skipped, entries are
//! deduplicated by normalized URL keeping the first occurrence, and a marker
//! other than `read`/`write` (or absent) means [`RelayMarker::Both`].
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/65.md>

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nk_core::{Event, EventBuilder, Kind, RelayUrl, Tag, Tags};

use crate::error::{Error, ErrorKind, Result};

/// A NIP-65 `r` tag marker: read-only, write-only, or unmarked (both).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelayMarker {
    /// The relay carries the author's read traffic.
    Read,
    /// The relay carries the author's write traffic.
    Write,
    /// Unmarked — the relay serves both directions.
    Both,
}

/// One NIP-65 relay-list entry: a normalized URL plus its marker.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayListItem {
    /// The normalized relay URL.
    pub url: RelayUrl,
    /// The `r` tag marker (`Both` when absent or unrecognized).
    pub marker: RelayMarker,
}

/// Parses a kind-10002 NIP-65 event into relay list entries — the TS
/// `parseRelayList`.
///
/// `r` tags with a missing or empty value are skipped; values that fail
/// [`RelayUrl::parse`] normalization are skipped; entries are deduplicated by
/// normalized URL keeping the first occurrence.
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10002, got <kind>` when the
/// event is not a relay list.
pub fn parse_relay_list(event: &Event) -> Result<Vec<RelayListItem>> {
    if event.kind() != Kind::RELAY_LIST {
        return Err(Error::new(
            ErrorKind::EventValidation,
            format!(
                "expected kind {}, got {}",
                Kind::RELAY_LIST.as_u16(),
                event.kind().as_u16()
            ),
        ));
    }
    let mut out: Vec<RelayListItem> = Vec::new();
    for tag in event.tags() {
        if tag.name() != "r" {
            continue;
        }
        let Some(value) = tag.value() else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let Ok(url) = RelayUrl::parse(value) else {
            continue;
        };
        if out.iter().any(|item| item.url == url) {
            continue;
        }
        let marker = match tag.as_slice().get(2).map(String::as_str) {
            Some("read") => RelayMarker::Read,
            Some("write") => RelayMarker::Write,
            _ => RelayMarker::Both,
        };
        out.push(RelayListItem { url, marker });
    }
    Ok(out)
}

/// Encodes relay list items as NIP-65 `r` tags — `Both` is unmarked, the TS
/// `relayListToTags`.
#[must_use]
pub fn relay_list_tags(items: &[RelayListItem]) -> Tags {
    items
        .iter()
        .map(|item| {
            let marker = match item.marker {
                RelayMarker::Read => Some("read"),
                RelayMarker::Write => Some("write"),
                RelayMarker::Both => None,
            };
            Tag::reference(item.url.to_string(), marker)
        })
        .collect()
}

/// An unsigned kind-10002 [`EventBuilder`] from relay list items — the TS
/// `relayListEventBuilder`.
pub fn relay_list(items: &[RelayListItem]) -> EventBuilder {
    EventBuilder::new(Kind::RELAY_LIST, "").tags(relay_list_tags(items))
}

/// URLs of the read-enabled items (`read` and `both`) — the TS `readRelays`.
pub fn read_relays(items: &[RelayListItem]) -> impl Iterator<Item = &RelayUrl> {
    items
        .iter()
        .filter(|item| item.marker != RelayMarker::Write)
        .map(|item| &item.url)
}

/// URLs of the write-enabled items (`write` and `both`) — the TS
/// `writeRelays`.
pub fn write_relays(items: &[RelayListItem]) -> impl Iterator<Item = &RelayUrl> {
    items
        .iter()
        .filter(|item| item.marker != RelayMarker::Read)
        .map(|item| &item.url)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::string::ToString;
    use alloc::vec;

    use nk_core::{SecretKey, Timestamp};

    use super::*;

    const SK: &str = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";

    fn event(raw: &[&[&str]], kind: u16) -> Event {
        let keys = nk_core::Keys::new(SecretKey::from_hex(SK).unwrap());
        let unsigned = nk_core::UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::new(kind),
            raw.iter()
                .map(|items| Tag::new(items.iter().map(|s| String::from(*s))).unwrap())
                .collect(),
            "",
        );
        keys.sign_event_with_aux(unsigned, &[7u8; 32]).unwrap()
    }

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).unwrap()
    }

    #[test]
    fn parse_normalizes_dedups_and_marks() {
        let event = event(
            &[
                &["r", "wss://a.example"],
                &["r", "wss://a.example/", "read"], // same normalized URL: dropped
                &["r", "wss://b.example", "write"],
                &["r", "wss://c.example", "bogus"],
                &["r", "not a url"],
                &["r", ""],
                &["r"],
                &["x", "wss://d.example"],
            ],
            10002,
        );
        let items = parse_relay_list(&event).unwrap();
        assert_eq!(
            items,
            vec![
                RelayListItem {
                    url: url("wss://a.example"),
                    marker: RelayMarker::Both
                },
                RelayListItem {
                    url: url("wss://b.example"),
                    marker: RelayMarker::Write
                },
                RelayListItem {
                    url: url("wss://c.example"),
                    marker: RelayMarker::Both
                },
            ]
        );
    }

    #[test]
    fn parse_rejects_other_kinds() {
        let event = event(&[], 3);
        let error = parse_relay_list(&event).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EventValidation);
        assert_eq!(
            error.to_string(),
            "event validation: expected kind 10002, got 3"
        );
    }

    #[test]
    fn tags_omit_marker_for_both() {
        let items = vec![
            RelayListItem {
                url: url("wss://a.example"),
                marker: RelayMarker::Both,
            },
            RelayListItem {
                url: url("wss://b.example"),
                marker: RelayMarker::Read,
            },
            RelayListItem {
                url: url("wss://c.example"),
                marker: RelayMarker::Write,
            },
        ];
        let slices: Vec<Vec<String>> = relay_list_tags(&items)
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect();
        assert_eq!(
            slices,
            vec![
                vec!["r".to_owned(), "wss://a.example/".to_owned()],
                vec![
                    "r".to_owned(),
                    "wss://b.example/".to_owned(),
                    "read".to_owned()
                ],
                vec![
                    "r".to_owned(),
                    "wss://c.example/".to_owned(),
                    "write".to_owned()
                ],
            ]
        );
        assert_eq!(read_relays(&items).count(), 2);
        assert_eq!(write_relays(&items).count(), 2);
    }

    #[test]
    fn relay_list_builds_kind_10002() {
        let items = vec![RelayListItem {
            url: url("wss://a.example"),
            marker: RelayMarker::Read,
        }];
        let unsigned = relay_list(&items).build_at(
            nk_core::PublicKey::from_hex(
                "166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99",
            )
            .unwrap(),
            Timestamp::from_secs(0),
        );
        assert_eq!(unsigned.kind(), Kind::RELAY_LIST);
        assert_eq!(unsigned.content(), "");
        assert_eq!(unsigned.tags().len(), 1);
    }
}
