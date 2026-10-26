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
    Error, FetchEnd, PublishOutcome, Reconciliation, Relay, RelayOptions, RelayStatus, Result,
};

pub(crate) use subscription::RecentIds;
pub use subscription::{PoolEvent, PoolSubscription};

/// A fan-out over one [`Relay`] per URL. `Clone` is cheap — every handle
/// shares the same relay map.
///
/// The fan-out methods create relays on demand and must therefore run
/// inside a tokio runtime.
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
    /// replaced with a fresh relay.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime — a new relay calls `tokio::spawn`.
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

    /// Runs `op` on every plan entry's relay concurrently and collects
    /// the per-relay outputs.
    async fn fan_out<A, T, Fut>(
        &self,
        plan: impl IntoIterator<Item = (RelayUrl, A)>,
        op: impl Fn(Relay, A) -> Fut,
    ) -> BTreeMap<RelayUrl, T>
    where
        Fut: Future<Output = T>,
    {
        join_all(plan.into_iter().map(|(url, arg)| {
            let fut = op(self.relay(&url), arg);
            async move { (url, fut.await) }
        }))
        .await
        .into_iter()
        .collect()
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
        let plan = Self::urls(urls)
            .into_iter()
            .map(|u| (u, filters.clone()))
            .collect();
        Ok(self.subscribe_routed(plan).await)
    }

    /// Opens a per-relay `REQ` plan — one filter list per relay.
    ///
    /// Use this when routes differ per relay (e.g. from
    /// `Gossip::route(..).with_fallback(..)`); a relay whose list is
    /// empty surfaces [`PoolEvent::Failed`] with
    /// [`Error::InvalidFilters`].
    pub async fn subscribe_routed(
        &self,
        plan: BTreeMap<RelayUrl, Vec<Filter>>,
    ) -> PoolSubscription {
        let relays = plan
            .into_iter()
            .map(|(u, filters)| {
                let relay = self.relay(&u);
                (u, relay, filters)
            })
            .collect();
        PoolSubscription::open(relays).await
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
        let plan = Self::urls(urls)
            .into_iter()
            .map(|u| (u, filters.clone()))
            .collect();
        Ok(self.fetch_routed(plan, timeout).await)
    }

    /// A bounded read with a per-relay filter plan — one list per
    /// relay. Use this when routes differ per relay (e.g. from
    /// `Gossip::route(..).with_fallback(..)`); a relay whose list is
    /// empty surfaces [`Error::InvalidFilters`] in `relays`.
    pub async fn fetch_routed(
        &self,
        plan: BTreeMap<RelayUrl, Vec<Filter>>,
        timeout: Duration,
    ) -> PoolFetch {
        let results = self
            .fan_out(plan, |relay, filters| async move {
                relay.fetch(filters, timeout).await
            })
            .await;
        let mut by_id = HashMap::new();
        let mut ends = BTreeMap::new();
        for (url, outcome) in results {
            match outcome {
                Ok(outcome) => {
                    ends.insert(url, Ok(outcome.end));
                    by_id.extend(outcome.events.into_iter().map(|e| (e.id(), e)));
                }
                Err(error) => {
                    ends.insert(url, Err(error));
                }
            }
        }
        let mut events: Vec<Event> = by_id.into_values().collect();
        events.sort_by(Event::cmp_newest_first);
        PoolFetch {
            events,
            relays: ends,
        }
    }

    /// Publishes `event` on every listed relay concurrently.
    pub async fn publish<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        event: &Event,
    ) -> BTreeMap<RelayUrl, Result<PublishOutcome>> {
        let plan = Self::urls(urls).into_iter().map(|u| (u, ()));
        self.fan_out(plan, |relay, ()| async move { relay.publish(event).await })
            .await
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
        let plan = Self::urls(urls).into_iter().map(|u| (u, filters.clone()));
        Ok(self
            .fan_out(plan, |relay, f| async move { relay.count(f).await })
            .await)
    }

    /// NIP-77 reconcile on every listed relay concurrently.
    pub async fn reconcile<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filter: Filter,
        items: Vec<(Timestamp, EventId)>,
    ) -> BTreeMap<RelayUrl, Result<Reconciliation>> {
        let plan = Self::urls(urls)
            .into_iter()
            .map(|u| (u, (filter.clone(), items.clone())));
        self.fan_out(plan, |relay, (f, its)| async move {
            relay.reconcile(f, its).await
        })
        .await
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
