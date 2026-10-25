//! The composing client: a `RelayPool`, a gossip routing table, an
//! event store and a background persister behind one handle.
//!
//! Sync/DM and NIP-46 layers build on this facade; it adds composition
//! and ingest only — no new protocol logic.

mod persist;
mod subscription;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use nk_core::{Event, EventBuilder, Filter, Kind, NostrSigner, PublicKey, RelayUrl, SignerError};
use nk_store::EventStore;
use persist::Persister;
pub use subscription::ClientSubscription;

use crate::gossip::{Gossip, GossipOptions, Routes};
use crate::pool::{PoolFetch, RelayPool};
use crate::relay::{self, PublishOutcome, RelayOptions};

/// The client's error type.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An empty filter list was passed.
    #[error("empty filter list")]
    InvalidFilters,
    /// No relay is usable for the operation — no targets and no
    /// defaults to fall back on.
    #[error("no relays available")]
    NoRelays,
    /// A signer is required but `ClientOptions::signer` was `None`.
    #[error("no signer configured")]
    NoSigner,
    /// The signer failed.
    #[error("{0}")]
    Signer(#[source] SignerError),
    /// `observe` got an event that fails `Event::verify`.
    #[error("invalid event")]
    InvalidEvent,
    /// The event store failed.
    #[error("{0}")]
    Store(#[source] nk_store::Error),
    /// The client is closed, or the runtime is shutting down mid-call.
    #[error("client closed")]
    Closed,
}

/// Result type for `Client` operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// `Client` configuration — a public-field bag like [`RelayOptions`].
/// `#[non_exhaustive]` — construct via `Default::default()` and mutate
/// the fields:
///
/// ```
/// let mut opts = nk::client::ClientOptions::default();
/// opts.persist = false;
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientOptions {
    /// Default relays — publish/fetch/hydrate fall back to these.
    /// Deduplicated at construction, order kept.
    pub relays: Vec<RelayUrl>,
    /// The client's signer — injected into every pool relay (it
    /// overwrites `relay.signer`).
    pub signer: Option<Arc<dyn NostrSigner>>,
    /// The event store. Default: an in-memory `MemoryStore`.
    pub store: Arc<dyn EventStore>,
    /// Whether ingested events are written to `store` (default true).
    pub persist: bool,
    /// Per-relay options for the pool — `signer` is overwritten by
    /// `ClientOptions::signer`.
    pub relay: RelayOptions,
    /// Gossip routing table options.
    pub gossip: GossipOptions,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            signer: None,
            store: Arc::new(nk_store::MemoryStore::new()),
            persist: true,
            relay: RelayOptions::default(),
            gossip: GossipOptions::default(),
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("relays", &self.relays)
            .field("signer", &self.signer.as_ref().map(|_| ".."))
            .field("store", &"..")
            .field("persist", &self.persist)
            .field("relay", &self.relay)
            .field("gossip", &self.gossip)
            .finish()
    }
}

/// The inner state — shared by every `Client` clone.
struct Inner {
    pool: RelayPool,
    gossip: Mutex<Gossip>,
    store: Arc<dyn EventStore>,
    persister: Option<Persister>,
    relays: Vec<RelayUrl>,
    signer: Option<Arc<dyn NostrSigner>>,
    closed: AtomicBool,
}

/// A cheap `Clone` handle over one pool, one routing table, one store.
///
/// Needs a tokio runtime — every method drives the pool's relays, and
/// the persister task runs on it.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Builds a `Client`: deduplicates `relays`, spawns the persister
    /// when `persist` is on, and starts the pool with `relay` options
    /// whose signer is `options.signer`.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime — `new` spawns the persister task.
    #[must_use]
    pub fn new(options: ClientOptions) -> Self {
        let relays = dedup(options.relays);
        let mut relay = options.relay;
        relay.signer.clone_from(&options.signer);
        let persister = options
            .persist
            .then(|| Persister::spawn(Arc::clone(&options.store)));
        Self {
            inner: Arc::new(Inner {
                pool: RelayPool::new(relay),
                gossip: Mutex::new(Gossip::new(options.gossip)),
                store: options.store,
                persister,
                relays,
                signer: options.signer,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// The default relays.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        &self.inner.relays
    }

    /// The configured signer.
    #[must_use]
    pub fn signer(&self) -> Option<&Arc<dyn NostrSigner>> {
        self.inner.signer.as_ref()
    }

    /// The relay pool.
    #[must_use]
    pub fn pool(&self) -> &RelayPool {
        &self.inner.pool
    }

    /// The event store.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn EventStore> {
        &self.inner.store
    }

    /// The stored routes for `pubkey` — outbox, inbox, DM list.
    #[must_use]
    pub fn routes(&self, pubkey: &PublicKey) -> Option<Routes> {
        self.gossip().routes(pubkey).cloned()
    }

    /// Signs `builder` with the configured signer.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigner`] — no signer configured.
    /// [`Error::Signer`] — the signer failed.
    /// [`Error::Closed`] — the client is closed.
    pub async fn sign(&self, builder: EventBuilder) -> Result<Event> {
        self.check_open()?;
        let signer = self.inner.signer.as_ref().ok_or(Error::NoSigner)?;
        let pubkey = signer.public_key().await.map_err(Error::Signer)?;
        signer
            .sign_event(builder.build(pubkey))
            .await
            .map_err(Error::Signer)
    }

    /// Publishes `event` to its gossip targets plus the default relays
    /// (deduplicated). The event is ingested once any relay accepts it.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelays`] — nothing to publish to.
    /// [`Error::Closed`] — the client is closed.
    pub async fn publish(
        &self,
        event: &Event,
    ) -> Result<BTreeMap<RelayUrl, relay::Result<PublishOutcome>>> {
        self.check_open()?;
        let mut targets = self.gossip().publish_relays(event);
        for url in &self.inner.relays {
            if !targets.contains(url) {
                targets.push(url.clone());
            }
        }
        self.publish_targets(targets, event).await
    }

    /// Publishes `event` to the given relays.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelays`] — `urls` is empty.
    /// [`Error::Closed`] — the client is closed.
    pub async fn publish_to<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        event: &Event,
    ) -> Result<BTreeMap<RelayUrl, relay::Result<PublishOutcome>>> {
        self.check_open()?;
        let targets: Vec<RelayUrl> = urls.into_iter().cloned().collect();
        self.publish_targets(targets, event).await
    }

    /// The publish tail both entry points share: empty targets fail,
    /// otherwise publish and ingest on the first accepted `OK`.
    async fn publish_targets(
        &self,
        targets: Vec<RelayUrl>,
        event: &Event,
    ) -> Result<BTreeMap<RelayUrl, relay::Result<PublishOutcome>>> {
        if targets.is_empty() {
            return Err(Error::NoRelays);
        }
        let results = self.inner.pool.publish(&targets, event).await;
        let accepted = results
            .values()
            .any(|r| matches!(r, Ok(out) if out.accepted));
        if accepted {
            self.ingest(std::slice::from_ref(event)).await;
        }
        Ok(results)
    }

    /// A gossip-routed live subscription — authors go to their outbox
    /// relays, `#p` to their inbox relays, the rest to the defaults.
    /// Each first-receipt event is ingested as it streams.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] — `filters` is empty.
    /// [`Error::NoRelays`] — no routes and no defaults to fall back on.
    /// [`Error::Closed`] — the client is closed.
    pub async fn subscribe(&self, filters: Vec<Filter>) -> Result<ClientSubscription> {
        self.check_open()?;
        let plan = self.routed_plan(&filters)?;
        Ok(ClientSubscription {
            inner: self.inner.pool.subscribe_routed(plan).await,
            client: self.clone(),
        })
    }

    /// A live subscription on explicit relays (skips gossip routing).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] — `filters` is empty.
    /// [`Error::NoRelays`] — `urls` is empty.
    /// [`Error::Closed`] — the client is closed.
    pub async fn subscribe_to<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filters: Vec<Filter>,
    ) -> Result<ClientSubscription> {
        self.check_open()?;
        let plan = explicit_plan(urls, &filters)?;
        Ok(ClientSubscription {
            inner: self.inner.pool.subscribe_routed(plan).await,
            client: self.clone(),
        })
    }

    /// A gossip-routed bounded read — authors go to their outbox
    /// relays, `#p` to their inbox relays, and whatever can't be routed
    /// goes to the default relays. Returned events are ingested.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] — `filters` is empty.
    /// [`Error::NoRelays`] — no routes and no defaults to fall back on.
    /// [`Error::Closed`] — the client is closed.
    pub async fn fetch(&self, filters: Vec<Filter>, timeout: Duration) -> Result<PoolFetch> {
        self.check_open()?;
        let plan = self.routed_plan(&filters)?;
        let out = self.inner.pool.fetch_routed(plan, timeout).await;
        self.ingest(&out.events).await;
        Ok(out)
    }

    /// A bounded read from explicit relays (skips gossip routing).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] — `filters` is empty.
    /// [`Error::NoRelays`] — `urls` is empty.
    /// [`Error::Closed`] — the client is closed.
    pub async fn fetch_from<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a RelayUrl>,
        filters: Vec<Filter>,
        timeout: Duration,
    ) -> Result<PoolFetch> {
        self.check_open()?;
        let plan = explicit_plan(urls, &filters)?;
        let out = self.inner.pool.fetch_routed(plan, timeout).await;
        self.ingest(&out.events).await;
        Ok(out)
    }

    /// Loads kind `10002`/`10050` relay lists for `pubkeys` from the
    /// default relays into the gossip table.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelays`] — no default relays configured.
    /// [`Error::Closed`] — the client is closed.
    pub async fn hydrate(&self, pubkeys: &[PublicKey], timeout: Duration) -> Result<()> {
        self.check_open()?;
        if pubkeys.is_empty() {
            return Ok(());
        }
        let lists = Filter::new()
            .kinds([Kind::RELAY_LIST, Kind::DIRECT_MESSAGE_RELAYS_LIST])
            .authors(pubkeys.iter().copied());
        let plan = explicit_plan(&self.inner.relays, &[lists])?;
        let out = self.inner.pool.fetch_routed(plan, timeout).await;
        self.ingest(&out.events).await;
        Ok(())
    }

    /// Verifies `event` and ingests it — the entry point for events the
    /// caller received elsewhere.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEvent`] — `verify` fails.
    /// [`Error::Closed`] — the client is closed.
    pub async fn observe(&self, event: &Event) -> Result<()> {
        self.check_open()?;
        event.verify().map_err(|_| Error::InvalidEvent)?;
        self.ingest(std::slice::from_ref(event)).await;
        Ok(())
    }

    /// Reads the local store — a `spawn_blocking` call so the sync
    /// backend never stalls the runtime.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] — the store failed.
    /// [`Error::Closed`] — the client is closed, or the runtime shut
    /// down mid-call (a `JoinError` from `spawn_blocking`).
    pub async fn query(&self, filters: Vec<Filter>) -> Result<Vec<Event>> {
        self.check_open()?;
        let store = Arc::clone(&self.inner.store);
        tokio::task::spawn_blocking(move || store.query(&filters))
            .await
            .map_err(|_| Error::Closed)?
            .map_err(Error::Store)
    }

    /// Waits for every event ingested so far to be written; the result
    /// is the first store error since the previous flush, if any.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] — the store failed since the previous flush.
    /// [`Error::Closed`] — the client is closed.
    pub async fn flush(&self) -> Result<()> {
        self.check_open()?;
        match &self.inner.persister {
            Some(p) => p.flush().await.map_or(Ok(()), |e| Err(Error::Store(e))),
            None => Ok(()),
        }
    }

    /// Closes the pool and flushes the store — the flush result is
    /// ignored. Later async calls return [`Error::Closed`]; accessors
    /// stay usable.
    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner.pool.close().await;
        if let Some(p) = &self.inner.persister {
            drop(p.flush().await);
        }
    }

    /// The gossip plan for `filters`: routed relays, with the remainder
    /// on the default relays.
    fn routed_plan(&self, filters: &[Filter]) -> Result<Plan> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let plan = self
            .gossip()
            .route(filters)
            .with_fallback(&self.inner.relays)
            .map_err(|_| Error::NoRelays)?;
        if plan.is_empty() {
            return Err(Error::NoRelays);
        }
        Ok(plan)
    }

    /// `Err(Closed)` once `close` ran.
    fn check_open(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// The gossip lock — poisoning is recovered via `into_inner`.
    fn gossip(&self) -> std::sync::MutexGuard<'_, Gossip> {
        self.inner
            .gossip
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The one ingest path: gossip updates synchronously, then the
    /// persister queues the events (the store mutex never crosses an
    /// `.await`).
    async fn ingest(&self, events: &[Event]) {
        {
            let mut gossip = self.gossip();
            for event in events {
                gossip.ingest(event);
            }
        }
        if let Some(p) = &self.inner.persister {
            p.push(events.to_vec()).await;
        }
    }

    /// The live-path ingest — synchronous: gossip first, then a
    /// non-blocking `try_push` (a full channel warns and skips caching;
    /// `poll_next` must never block).
    fn ingest_live(&self, event: &Event) {
        {
            let mut gossip = self.gossip();
            gossip.ingest(event);
        }
        if let Some(p) = &self.inner.persister {
            p.try_push(vec![event.clone()]);
        }
    }
}

/// A per-relay filter plan.
type Plan = BTreeMap<RelayUrl, Vec<Filter>>;

/// The same `filters` on every relay in `urls`.
fn explicit_plan<'a>(
    urls: impl IntoIterator<Item = &'a RelayUrl>,
    filters: &[Filter],
) -> Result<Plan> {
    if filters.is_empty() {
        return Err(Error::InvalidFilters);
    }
    let plan: Plan = urls
        .into_iter()
        .map(|u| (u.clone(), filters.to_vec()))
        .collect();
    if plan.is_empty() {
        return Err(Error::NoRelays);
    }
    Ok(plan)
}

/// Deduplicates keeping first-seen order.
fn dedup(urls: Vec<RelayUrl>) -> Vec<RelayUrl> {
    let mut seen = std::collections::HashSet::with_capacity(urls.len());
    let mut out = Vec::with_capacity(urls.len());
    for url in urls {
        if seen.insert(url.clone()) {
            out.push(url);
        }
    }
    out
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("relays", &self.inner.relays)
            .field("closed", &self.inner.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
