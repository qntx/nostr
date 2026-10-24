//! NIP-65 relay lists: a kind-10002 event as a typed [`RelayList`] of relay
//! items.
//!
//! `r` tag values are normalized with [`RelayUrl::parse`] (the same
//! `normalizeURL`), unnormalizable values are skipped, entries are
//! deduplicated by normalized URL keeping the first occurrence, and a marker
//! other than `read`/`write` (or absent) means [`RelayMarker::Both`].
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/65.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{Event, EventBuilder, Kind, RelayUrl, Tag, Tags};

/// The error type returned by NIP-65 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The event kind differs from the required one.
    #[error("expected kind {expected}, got {found}")]
    WrongKind {
        /// The required kind value.
        expected: u16,
        /// The event's actual kind.
        found: u16,
    },
}

/// Result type for NIP-65 operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

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

/// A parsed kind-10002 relay list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RelayList {
    items: Vec<RelayListItem>,
}

impl RelayList {
    /// Wraps relay list items — input order is kept.
    #[must_use]
    pub const fn new(items: Vec<RelayListItem>) -> Self {
        Self { items }
    }

    /// All parsed items, in wire order.
    #[must_use]
    pub fn items(&self) -> &[RelayListItem] {
        &self.items
    }

    /// URLs of the read-enabled items (`read` and `both`).
    pub fn read(&self) -> impl Iterator<Item = &RelayUrl> {
        self.items
            .iter()
            .filter(|item| item.marker != RelayMarker::Write)
            .map(|item| &item.url)
    }

    /// URLs of the write-enabled items (`write` and `both`) — TS
    /// `writeRelays`.
    pub fn write(&self) -> impl Iterator<Item = &RelayUrl> {
        self.items
            .iter()
            .filter(|item| item.marker != RelayMarker::Read)
            .map(|item| &item.url)
    }
}

impl TryFrom<&Event> for RelayList {
    type Error = Error;

    /// Parses a kind-10002 event into a relay list.
    ///
    /// `r` tags with a missing or empty value are skipped; values that fail
    /// [`RelayUrl::parse`] normalization are skipped; entries are
    /// deduplicated by normalized URL keeping the first occurrence.
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] — the event is not a relay list.
    fn try_from(event: &Event) -> Result<Self> {
        if event.kind() != Kind::RELAY_LIST {
            return Err(Error::WrongKind {
                expected: Kind::RELAY_LIST.as_u16(),
                found: event.kind().as_u16(),
            });
        }
        let mut items: Vec<RelayListItem> = Vec::new();
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
            if items.iter().any(|item| item.url == url) {
                continue;
            }
            let marker = match tag.as_slice().get(2).map(String::as_str) {
                Some("read") => RelayMarker::Read,
                Some("write") => RelayMarker::Write,
                _ => RelayMarker::Both,
            };
            items.push(RelayListItem { url, marker });
        }
        Ok(Self { items })
    }
}

impl From<RelayList> for EventBuilder {
    /// An unsigned kind-10002 builder carrying the list's `r` tags — the
    /// `Both` is unmarked.
    fn from(list: RelayList) -> Self {
        let tags: Tags = list
            .items
            .iter()
            .map(|item| {
                let marker = match item.marker {
                    RelayMarker::Read => Some("read"),
                    RelayMarker::Write => Some("write"),
                    RelayMarker::Both => None,
                };
                Tag::reference(item.url.to_string(), marker)
            })
            .collect();
        Self::new(Kind::RELAY_LIST, "").tags(tags)
    }
}
