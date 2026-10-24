//! `MemoryStore` — an `RwLock`-guarded in-memory [`EventStore`].
//!
//! Events live as `Arc<Event>` in newest-first ordered buckets: one "all"
//! bucket plus `pubkey`, `kind`, `kind:pubkey`, and `name:first-value`
//! single-letter tag buckets — the same index layout as the reference
//! memory index. A query plans the smallest bucket set for the filter
//! (`authors`×`kinds`, `authors`, `kinds`, or each `#x` condition, whichever
//! covers the fewest events), clips each bucket to `since`/`until`, then
//! merges, deduplicates, and truncates to `limit`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;
use std::sync::{Arc, RwLock};

use nk_core::{Coordinate, Event, EventId, Filter, Kind, PublicKey, Timestamp};

use crate::policy::{self, DeletionState};
use crate::{EventStore, NegentropyItem, PutOutcome, Result};

/// A newest-first event bucket keyed by `(created_at, id)` — the canonical
/// `cmp_newest_first` order as a `BTreeMap` key.
type Bucket = BTreeMap<(Reverse<Timestamp>, EventId), Arc<Event>>;

/// `Lock`-poisoning is recovered via `into_inner` — every mutation applies
/// its whole update before releasing the lock, so a poisoned map still holds
/// a consistent store body.
fn read<T>(result: std::sync::LockResult<T>) -> T {
    result.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The shared store body: events by id, the buckets, and tombstone state.
#[derive(Debug, Default)]
struct Body {
    events: HashMap<EventId, Arc<Event>>,
    all: Bucket,
    by_pubkey: HashMap<PublicKey, Bucket>,
    by_kind: HashMap<Kind, Bucket>,
    by_kind_pubkey: HashMap<(Kind, PublicKey), Bucket>,
    by_tag: HashMap<(u8, Box<str>), Bucket>,
    /// `coordinate → id` of the current addressable winner.
    replaceable: HashMap<Coordinate, EventId>,
    deletion: DeletionState,
}

/// The `name:value` tag-bucket key for the event side — the tag name byte
/// plus its first value verbatim.
fn tag_key(name: &str, value: &str) -> Option<(u8, Box<str>)> {
    let mut bytes = name.bytes();
    let byte = bytes.next()?;
    (name.len() == 1 && byte.is_ascii_alphabetic())
        .then(|| (byte.to_ascii_lowercase(), value.into()))
}

/// Every tag-bucket key for the event's single-letter tags.
fn tag_keys(event: &Event) -> Vec<(u8, Box<str>)> {
    event
        .tags()
        .iter()
        .filter_map(|tag| tag_key(tag.name(), tag.value()?))
        .collect()
}

impl Body {
    /// Inserts `event` into `events` and every bucket.
    fn index_insert(&mut self, event: Event) {
        let id = event.id();
        let key = (Reverse(event.created_at()), id);
        let shared = Arc::new(event);
        self.events.insert(id, Arc::clone(&shared));
        self.all.insert(key, Arc::clone(&shared));
        self.by_pubkey
            .entry(shared.pubkey())
            .or_default()
            .insert(key, Arc::clone(&shared));
        self.by_kind
            .entry(shared.kind())
            .or_default()
            .insert(key, Arc::clone(&shared));
        self.by_kind_pubkey
            .entry((shared.kind(), shared.pubkey()))
            .or_default()
            .insert(key, Arc::clone(&shared));
        if let Some(coordinate) = policy::coordinate_of(&shared) {
            self.replaceable.insert(coordinate, id);
        }
        for tag_key in tag_keys(&shared) {
            self.by_tag
                .entry(tag_key)
                .or_default()
                .insert(key, Arc::clone(&shared));
        }
    }

    /// Removes `id` from `events` and every bucket. Returns whether it was
    /// stored.
    fn index_remove(&mut self, id: &EventId) -> bool {
        let Some(shared) = self.events.remove(id) else {
            return false;
        };
        let key = (Reverse(shared.created_at()), *id);
        self.all.remove(&key);
        if let Some(bucket) = self.by_pubkey.get_mut(&shared.pubkey()) {
            bucket.remove(&key);
        }
        if let Some(bucket) = self.by_kind.get_mut(&shared.kind()) {
            bucket.remove(&key);
        }
        if let Some(bucket) = self
            .by_kind_pubkey
            .get_mut(&(shared.kind(), shared.pubkey()))
        {
            bucket.remove(&key);
        }
        if let Some(coordinate) = policy::coordinate_of(&shared) {
            self.replaceable.remove(&coordinate);
        }
        for tag_key in tag_keys(&shared) {
            if let Some(bucket) = self.by_tag.get_mut(&tag_key) {
                bucket.remove(&key);
            }
        }
        true
    }
}

/// What a backend looks up to decide one put.
struct MemLookup<'a> {
    body: &'a Body,
}

impl policy::Lookup for MemLookup<'_> {
    fn deletion(&self) -> &DeletionState {
        &self.body.deletion
    }
    fn stored(&self, id: &EventId) -> Option<policy::Stored> {
        self.body.events.get(id).map(|e| policy::Stored::of(e))
    }
    fn replaceable(&self, coordinate: &Coordinate) -> Option<(Timestamp, EventId)> {
        self.body
            .replaceable
            .get(coordinate)
            .and_then(|id| self.body.events.get(id))
            .map(|e| (e.created_at(), e.id()))
    }
}

/// An in-memory [`EventStore`].
#[derive(Debug, Default)]
pub struct MemoryStore {
    body: RwLock<Body>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The planned bucket set for `filter` — the smallest total of the
    /// usable indexes, or `all` when nothing is narrower.
    fn plan<'a>(body: &'a Body, filter: &Filter) -> Vec<&'a Bucket> {
        let mut best: Vec<&'a Bucket> = Vec::new();
        let mut best_total = usize::MAX;
        let mut consider = |candidates: Vec<Option<&'a Bucket>>| {
            let mut total = 0usize;
            let mut present: Vec<&'a Bucket> = Vec::new();
            for bucket in candidates.into_iter().flatten() {
                total += bucket.len();
                present.push(bucket);
            }
            if total < best_total {
                best_total = total;
                best = present;
            }
        };
        let authors = filter.get_authors();
        let kinds = filter.get_kinds();
        if let (Some(authors), Some(kinds)) = (authors, kinds) {
            consider(
                authors
                    .iter()
                    .flat_map(|pk| {
                        kinds
                            .iter()
                            .map(move |kind| body.by_kind_pubkey.get(&(*kind, *pk)))
                    })
                    .collect(),
            );
        }
        if let Some(authors) = authors {
            consider(authors.iter().map(|pk| body.by_pubkey.get(pk)).collect());
        }
        if let Some(kinds) = kinds {
            consider(kinds.iter().map(|kind| body.by_kind.get(kind)).collect());
        }
        for letter in filter.tag_letters() {
            if let Some(values) = filter.tag_values(letter) {
                let byte = letter.as_char() as u8;
                consider(
                    values
                        .iter()
                        .map(|v| body.by_tag.get(&(byte, Box::from(v.as_ref()))))
                        .collect(),
                );
            }
        }
        if best.is_empty() || best_total > body.all.len() {
            return vec![&body.all];
        }
        best
    }

    /// Candidate events for one filter: planned buckets walked in canonical
    /// order, clipped to `since`/`until`, matched, and deduplicated across
    /// buckets.
    fn candidates(body: &Body, filter: &Filter) -> Vec<Arc<Event>> {
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut out: Vec<Arc<Event>> = Vec::new();
        for bucket in Self::plan(body, filter) {
            // `Reverse` order: `until` (newest bound) sorts as the lower
            // key; ids bound the same-timestamp edge.
            let lo = filter
                .get_until()
                .map(|t| (Reverse(t), EventId::from_bytes([0; 32])));
            let hi = filter
                .get_since()
                .map(|t| (Reverse(t), EventId::from_bytes([0xff; 32])));
            let range = bucket.range((
                lo.map_or(Bound::Unbounded, Bound::Included),
                hi.map_or(Bound::Unbounded, Bound::Included),
            ));
            let limit = filter
                .get_limit()
                .map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX));
            out.extend(
                range
                    .map(|(_, e)| e)
                    .filter(|event| filter.matches(event.as_ref()) && seen.insert(event.id()))
                    .take(limit)
                    .map(Arc::clone),
            );
        }
        out
    }

    /// One filter's result: planned, deduplicated, newest first, `limit`ed.
    fn matches_filter(&self, filter: &Filter) -> Vec<Arc<Event>> {
        let mut out = {
            let body = read(self.body.read());
            // The `ids` list consults the id index directly.
            filter.get_ids().map_or_else(
                || Self::candidates(&body, filter),
                |ids| {
                    let mut found: Vec<Arc<Event>> = ids
                        .iter()
                        .filter_map(|id| body.events.get(id).map(Arc::clone))
                        .filter(|e| filter.matches(e))
                        .collect();
                    found.sort_by(|a, b| Event::cmp_newest_first(a, b));
                    found
                },
            )
        };
        out.sort_by(|a, b| Event::cmp_newest_first(a, b));
        if let Some(limit) = filter.get_limit() {
            out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        out
    }

    /// Applies the shared put decision — the same effects as the reference
    /// `applyPutMemory`: deletions are stored alongside the tombstones they
    /// produce.
    fn put_locked(body: &mut Body, event: Event) -> PutOutcome {
        match policy::decide_put(&event, &MemLookup { body }) {
            policy::PutDecision::Skip(outcome) => outcome,
            policy::PutDecision::Tombstone(outcome) => {
                body.deletion.ids.insert(event.id());
                body.deletion.pending.remove(&event.id());
                outcome
            }
            policy::PutDecision::Delete { plan } => {
                body.deletion.pending.remove(&event.id());
                let removed_ids = plan.remove_ids.clone();
                body.deletion.absorb(&plan);
                for id in removed_ids {
                    body.index_remove(&id);
                }
                // Tombstone-covered stored events die with the deletion; their
                // ids join the direct tombstones so a re-put is duplicate.
                let doomed = policy::coordinate_removals(&plan.coordinates, &|key| {
                    body.events
                        .values()
                        .find(|e| policy::coordinate_of(e).is_some_and(|c| c == *key))
                        .map(|e| (e.created_at(), e.id()))
                });
                for id in doomed {
                    body.deletion.ids.insert(id);
                    body.index_remove(&id);
                }
                body.index_insert(event);
                PutOutcome::Deleted
            }
            policy::PutDecision::Insert {
                outcome,
                replace_id,
            } => {
                if let Some(id) = replace_id {
                    body.index_remove(&id);
                }
                body.index_insert(event);
                outcome
            }
        }
    }
}

impl EventStore for MemoryStore {
    fn put(&self, event: &Event) -> Result<PutOutcome> {
        let mut body = read(self.body.write());
        Ok(Self::put_locked(&mut body, event.clone()))
    }

    /// One write lock for the whole batch — the in-memory counterpart of
    /// `SqliteStore`'s one transaction.
    fn put_many(&self, events: &[Event]) -> Result<Vec<PutOutcome>> {
        let mut body = read(self.body.write());
        Ok(events
            .iter()
            .map(|event| Self::put_locked(&mut body, event.clone()))
            .collect())
    }

    fn get(&self, id: &EventId) -> Result<Option<Event>> {
        let body = read(self.body.read());
        if body.deletion.ids.contains(id) {
            return Ok(None);
        }
        Ok(body.events.get(id).map(|e| (**e).clone()))
    }

    fn query(&self, filters: &[Filter]) -> Result<Vec<Event>> {
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut out: Vec<Arc<Event>> = Vec::new();
        for filter in filters {
            out.extend(
                self.matches_filter(filter)
                    .into_iter()
                    .filter(|event| seen.insert(event.id())),
            );
        }
        out.sort_by(|a, b| Event::cmp_newest_first(a, b));
        Ok(out.into_iter().map(|e| (*e).clone()).collect())
    }

    fn count(&self, filters: &[Filter]) -> Result<usize> {
        let mut seen: HashSet<EventId> = HashSet::new();
        for filter in filters {
            seen.extend(self.matches_filter(filter).into_iter().map(|e| e.id()));
        }
        Ok(seen.len())
    }

    fn negentropy_items(&self, filter: &Filter) -> Result<Vec<NegentropyItem>> {
        let mut items: Vec<NegentropyItem> = self
            .matches_filter(filter)
            .into_iter()
            .map(|e| NegentropyItem {
                created_at: e.created_at(),
                id: e.id(),
            })
            .collect();
        items.sort();
        Ok(items)
    }

    fn remove(&self, ids: &[EventId]) -> Result<usize> {
        let mut body = read(self.body.write());
        let mut removed = 0;
        for id in ids {
            body.deletion.ids.insert(*id);
            if body.index_remove(id) {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn clear(&self) -> Result<()> {
        *read(self.body.write()) = Body::default();
        Ok(())
    }
}
