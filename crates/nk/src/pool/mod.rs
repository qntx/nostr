//! A multi-relay fan-out handle — one [`Relay`] per URL, concurrent
//! operations, per-relay results. Mechanism only; policy lives in the
//! higher-level client.

mod subscription;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::future::join_all;
use nk_core::{CountResult, Event, EventId, Filter, RelayUrl, Timestamp};

use crate::relay::{
    Error, FetchEnd, FetchOutcome, PublishOutcome, Reconciliation, Relay, RelayOptions,
    RelayStatus, Result,
};

pub use subscription::{PoolEvent, PoolSubscription};

/// A fan-out over one [`Relay`] per URL. `Clone` is cheap — every handle
/// shares the same relay map.
#[derive(Clone)]
pub struct RelayPool {
    inner: Arc<Inner>,
}

struct Inner {
    /// Live relays keyed by normalized URL.
    relays: Mutex<HashMap<RelayUrl, Relay>>,
    /// Options for every relay the pool creates.
    options: RelayOptions,
}

/// A `fetch` result across relays.
#[derive(Debug)]
#[non_exhaustive]
pub struct PoolFetch {
    /// Merged events, deduplicated by id, newest first.
    pub events: Vec<Event>,
    /// Each relay's end state or error.
    pub relays: BTreeMap<RelayUrl, Result<FetchEnd>>,
}

impl RelayPool {
    /// An empty pool; relays are created lazily per URL.
    #[must_use]
    pub fn new(options: RelayOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                relays: Mutex::new(HashMap::new()),
                options,
            }),
        }
    }

    /// The shared relay for `url` — returns the cached handle or spawns
    /// one. An entry whose status is `Closed` (through any handle) is
    /// replaced with a fresh relay. Needs a tokio runtime, like
    /// [`Relay::new`].
    #[must_use]
    pub fn relay(&self, url: &RelayUrl) -> Relay {
        let mut relays = self
            .inner
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match relays.get(url) {
            Some(relay) if relay.status() != RelayStatus::Closed => relay.clone(),
            _ => {
                let relay = Relay::new(url, self.inner.options.clone());
                relays.insert(url.clone(), relay.clone());
                relay
            }
        }
    }

    /// The status of every tracked relay.
    #[must_use]
    pub fn statuses(&self) -> BTreeMap<RelayUrl, RelayStatus> {
        self.inner
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(url, relay)| (url.clone(), relay.status()))
            .collect()
    }

    /// Closes and forgets the relay for `url`; `false` when absent.
    pub async fn remove(&self, url: &RelayUrl) -> bool {
        let relay = self
            .inner
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(url);
        match relay {
            Some(relay) => {
                relay.close().await;
                true
            }
            None => false,
        }
    }

    /// Closes every tracked relay concurrently and forgets them. The pool
    /// stays usable — later calls create fresh relays.
    pub async fn close(&self) {
        let relays: Vec<Relay> = self
            .inner
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, r)| r)
            .collect();
        join_all(relays.iter().map(Relay::close)).await;
    }

    /// Normalizes and deduplicates the URL set.
    fn urls<'a>(urls: impl IntoIterator<Item = &'a RelayUrl>) -> Vec<RelayUrl> {
        urls.into_iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The shared relay for each deduplicated URL.
    fn relays_for(&self, urls: &[RelayUrl]) -> Vec<(RelayUrl, Relay)> {
        urls.iter().map(|u| (u.clone(), self.relay(u))).collect()
    }

    /// Opens a `REQ` on every listed relay; the returned stream merges
    /// events and aggregates EOSE.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list.
    pub async fn subscribe<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filters: Vec<Filter>,
    ) -> Result<PoolSubscription> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let relays = self.relays_for(&Self::urls(urls));
        Ok(PoolSubscription::open(relays, filters).await)
    }

    /// A bounded read across relays: events merged by id, newest first;
    /// each relay's `FetchEnd` or error is in `relays`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list.
    pub async fn fetch<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filters: Vec<Filter>,
        timeout: Duration,
    ) -> Result<PoolFetch> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let relays = self.relays_for(&Self::urls(urls));
        let results = join_all(relays.iter().map(|(u, r)| {
            let filters = filters.clone();
            async move { (u.clone(), r.fetch(filters, timeout).await) }
        }))
        .await;
        let mut by_id = HashMap::new();
        let mut ends = BTreeMap::new();
        for (url, outcome) in results {
            Self::merge_fetch(url, outcome, &mut by_id, &mut ends);
        }
        let mut events: Vec<Event> = by_id.into_values().collect();
        events.sort_by(Event::cmp_newest_first);
        Ok(PoolFetch {
            events,
            relays: ends,
        })
    }

    /// One relay's fetch result merged into the by-id map and ends.
    fn merge_fetch(
        url: RelayUrl,
        outcome: Result<FetchOutcome>,
        by_id: &mut HashMap<EventId, Event>,
        ends: &mut BTreeMap<RelayUrl, Result<FetchEnd>>,
    ) {
        match outcome {
            Ok(outcome) => {
                ends.insert(url, Ok(outcome.end));
                for event in outcome.events {
                    by_id.entry(event.id()).or_insert(event);
                }
            }
            Err(error) => {
                ends.insert(url, Err(error));
            }
        }
    }

    /// Publishes `event` on every listed relay concurrently.
    pub async fn publish<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        event: &Event,
    ) -> BTreeMap<RelayUrl, Result<PublishOutcome>> {
        let relays = self.relays_for(&Self::urls(urls));
        let results = join_all(
            relays
                .iter()
                .map(|(u, r)| async move { (u.clone(), r.publish(event).await) }),
        )
        .await;
        results.into_iter().collect()
    }

    /// `COUNT` on every listed relay concurrently.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list.
    pub async fn count<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filters: Vec<Filter>,
    ) -> Result<BTreeMap<RelayUrl, Result<CountResult>>> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let relays = self.relays_for(&Self::urls(urls));
        let results = join_all(relays.iter().map(|(u, r)| {
            let filters = filters.clone();
            async move { (u.clone(), r.count(filters).await) }
        }))
        .await;
        Ok(results.into_iter().collect())
    }

    /// NIP-77 reconcile on every listed relay concurrently.
    pub async fn reconcile<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filter: Filter,
        items: Vec<(Timestamp, EventId)>,
    ) -> BTreeMap<RelayUrl, Result<Reconciliation>> {
        let relays = self.relays_for(&Self::urls(urls));
        let results = join_all(relays.iter().map(|(u, r)| {
            let filter = filter.clone();
            let items = items.clone();
            async move { (u.clone(), r.reconcile(filter, items).await) }
        }))
        .await;
        results.into_iter().collect()
    }
}

impl std::fmt::Debug for RelayPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.inner.relays.lock().map_or(0, |g| g.len());
        f.debug_struct("RelayPool")
            .field("relays", &count)
            .finish_non_exhaustive()
    }
}

const _: () = {
    const fn assert_send_sync_unpin<T: Send + Sync + Unpin>() {}
    assert_send_sync_unpin::<RelayPool>();
    assert_send_sync_unpin::<PoolFetch>();
    assert_send_sync_unpin::<PoolSubscription>();
    assert_send_sync_unpin::<PoolEvent>();
};
