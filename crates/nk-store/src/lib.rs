//! Synchronous event stores for the nostr protocol.
//!
//! [`EventStore`] is the shared trait: [`MemoryStore`] holds `Arc`-shared
//! events in ordered in-memory buckets, and [`SqliteStore`] (the `sqlite`
//! feature) persists to SQLite with the same insertion policy. Both backends
//! share one private `policy` module so put/delete semantics cannot drift.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod memory;
mod policy;

#[cfg(feature = "sqlite")]
mod sqlite;

pub use error::{BackendError, Error, Result};

pub use memory::MemoryStore;

// Dev-dependencies used only by benches and integration tests; without the
// `sqlite` feature the lib test target does not use `serde_json` either.
#[cfg(test)]
use criterion as _;
#[cfg(all(test, not(feature = "sqlite")))]
use serde_json as _;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

use nk_core::{Event, EventId, Filter, Timestamp};

/// The outcome of one [`EventStore::put`]. Mirrors the reference `PutResult`
/// minus `invalid` (a Rust `Event` is shape-valid by construction); the
/// store does not verify signatures — the caller does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PutOutcome {
    /// The event was inserted.
    Accepted,
    /// An identical event is already stored.
    Duplicate,
    /// A replaceable/addressable event replaced an older version.
    Replaced,
    /// The event was refused (stale replaceable or addressable version, or a
    /// fresh tombstone covers it).
    Rejected,
    /// An ephemeral event (kind 20000-29999) is never stored.
    Ephemeral,
    /// A NIP-09 deletion event; it was processed (tombstones recorded) but is
    /// not itself stored.
    Deleted,
}

/// One `(created_at, id)` pair returned by [`EventStore::negentropy_items`].
/// Ordered by `created_at` then id, ascending — the negentropy sort order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NegentropyItem {
    /// The event's `created_at`.
    pub created_at: Timestamp,
    /// The event id.
    pub id: EventId,
}

/// A synchronous event store. Implementations must be `Send + Sync`; the
/// trait is object safe so `Arc<dyn EventStore>` works.
///
/// Lock poisoning is recovered, never fatal: a `MemoryStore` whose lock was
/// poisoned by a panicking writer is read through `PoisonError::into_inner`
/// (the maps stay consistent — updates are applied atomically).
pub trait EventStore: Send + Sync {
    /// Inserts one event under the shared put policy; see [`PutOutcome`].
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn put(&self, event: &Event) -> Result<PutOutcome>;

    /// Inserts every event of `events` in order. In `MemoryStore` this runs
    /// under one write lock; in `SqliteStore` it is one transaction — a
    /// failure rolls back the whole batch.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn put_many(&self, events: &[Event]) -> Result<Vec<PutOutcome>>;

    /// Returns the stored event with `id`, if present and not deleted.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn get(&self, id: &EventId) -> Result<Option<Event>>;

    /// Returns the union of `filters`, deduplicated, newest first
    /// ([`Event::cmp_newest_first`]). Each filter's `limit` applies to that
    /// filter's own result set before the merge.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn query(&self, filters: &[Filter]) -> Result<Vec<Event>>;

    /// Same cardinality as [`EventStore::query`], without materializing.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn count(&self, filters: &[Filter]) -> Result<usize>;

    /// `(created_at, id)` pairs for one filter — its `limit` keeps the
    /// newest — sorted `created_at` then id ascending.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn negentropy_items(&self, filter: &Filter) -> Result<Vec<NegentropyItem>>;

    /// Deletes and tombstones `ids` (local NIP-09). Returns how many of them
    /// were actually stored and deleted.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn remove(&self, ids: &[EventId]) -> Result<usize>;

    /// Wipes every event and tombstone.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] on a backend failure.
    fn clear(&self) -> Result<()>;
}

// The trait must stay object safe.
const _: () = {
    #[expect(dead_code, reason = "the object-safety assertion is compile-time only")]
    fn assert(_: &(dyn EventStore + Send + Sync)) {}
};
