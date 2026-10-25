//! The background store writer: events flow through a bounded channel
//! and are batched into one `put_many` per drain on `spawn_blocking` —
//! the synchronous store never blocks the runtime. `flush` travels the
//! same channel, so it can't pass earlier events.

use std::sync::Arc;

use nk_core::Event;
use nk_store::{BackendError, EventStore};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

/// Channel cap in *messages* — each can carry a batch.
const CAPACITY: usize = 1024;

/// Most events folded into one `put_many` drain.
const BATCH_MAX: usize = 512;

/// One persister message: a batch to write, or a flush probe.
enum Msg {
    /// Events to write.
    Events(Vec<Event>),
    /// Reply once everything queued ahead is written; carries the first
    /// store error since the previous flush.
    Flush(oneshot::Sender<Option<nk_store::Error>>),
}

/// A handle to the store-writing task — it ends when every channel sender
/// drops (the `Client` closes the pool first, then flushes).
pub(crate) struct Persister {
    tx: mpsc::Sender<Msg>,
}

impl Persister {
    /// Spawns the writer task for `store` (needs a tokio runtime).
    pub(crate) fn spawn(store: Arc<dyn EventStore>) -> Self {
        let (tx, rx) = mpsc::channel(CAPACITY);
        tokio::spawn(run(store, rx));
        Self { tx }
    }

    /// Queues `events` with backpressure; a closed channel is ignored.
    pub(crate) async fn push(&self, events: Vec<Event>) {
        drop(self.tx.send(Msg::Events(events)).await);
    }

    /// Queues `events` without blocking — a full channel warns and
    /// returns `false` (the store is a cache; memory stays bounded).
    pub(crate) fn try_push(&self, events: Vec<Event>) -> bool {
        if self.tx.try_send(Msg::Events(events)).is_ok() {
            true
        } else {
            warn!("persister channel full — events not cached");
            false
        }
    }

    /// Resolves once every event queued ahead is written; the payload is
    /// the first store error since the previous flush.
    pub(crate) async fn flush(&self) -> Option<nk_store::Error> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Msg::Flush(tx)).await.ok()?;
        rx.await.ok().flatten()
    }
}

/// The writer loop: drain `rx` in batches (a `Flush` waits at the front
/// of the channel — `try_recv` order keeps it behind the events queued
/// before it), write through `spawn_blocking`, keep the first error.
async fn run(store: Arc<dyn EventStore>, mut rx: mpsc::Receiver<Msg>) {
    let mut pending: Option<nk_store::Error> = None;
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::new();
        let mut flush: Option<oneshot::Sender<Option<nk_store::Error>>> = None;
        let mut msg = first;
        // Drain consecutive Events into `batch`, bounded by BATCH_MAX;
        // stop at the first Flush so it still answers in order.
        loop {
            match msg {
                Msg::Events(events) => batch.extend(events),
                Msg::Flush(tx) => {
                    flush = Some(tx);
                    break;
                }
            }
            if batch.len() >= BATCH_MAX {
                break;
            }
            match rx.try_recv() {
                Ok(next) => msg = next,
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            let store = Arc::clone(&store);
            match tokio::task::spawn_blocking(move || store.put_many(&batch)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!("store write failed: {e}");
                    pending.get_or_insert(e);
                }
                Err(e) => {
                    warn!("store write task failed: {e}");
                    pending.get_or_insert(nk_store::Error::Backend(BackendError::new(e)));
                }
            }
        }
        if let Some(tx) = flush {
            drop(tx.send(pending.take()));
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use nk_core::rand_core::UnwrapErr;
    use nk_core::{EventBuilder, EventId, Filter, Keys, SecretKey};
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    use super::*;

    fn event(n: u8) -> Event {
        let k = Keys::new(SecretKey::from_bytes([n; 32]).unwrap());
        k.sign_event(
            EventBuilder::new(nk_core::Kind::new(1), "x").build(k.public_key()),
            &mut UnwrapErr(nk_core::SysRng),
        )
        .unwrap()
    }

    /// A store that fails `put_many` once `fail` is armed.
    struct FailingStore {
        inner: nk_store::MemoryStore,
        fail: AtomicBool,
    }

    impl EventStore for FailingStore {
        fn put(&self, event: &Event) -> nk_store::Result<nk_store::PutOutcome> {
            self.inner.put(event)
        }

        fn put_many(&self, events: &[Event]) -> nk_store::Result<Vec<nk_store::PutOutcome>> {
            if self.fail.load(AtomicOrdering::Relaxed) {
                return Err(nk_store::Error::Backend(BackendError::new(
                    std::io::Error::other("boom"),
                )));
            }
            self.inner.put_many(events)
        }

        fn get(&self, id: &EventId) -> nk_store::Result<Option<Event>> {
            self.inner.get(id)
        }

        fn query(&self, filters: &[Filter]) -> nk_store::Result<Vec<Event>> {
            self.inner.query(filters)
        }

        fn count(&self, filters: &[Filter]) -> nk_store::Result<usize> {
            self.inner.count(filters)
        }

        fn negentropy_items(
            &self,
            filter: &Filter,
        ) -> nk_store::Result<Vec<nk_store::NegentropyItem>> {
            self.inner.negentropy_items(filter)
        }

        fn remove(&self, ids: &[EventId]) -> nk_store::Result<usize> {
            self.inner.remove(ids)
        }

        fn clear(&self) -> nk_store::Result<()> {
            self.inner.clear()
        }
    }

    #[tokio::test]
    async fn flush_after_writes_persists_events() {
        let store: Arc<dyn EventStore> = Arc::new(nk_store::MemoryStore::new());
        let p = Persister::spawn(Arc::clone(&store));
        p.push(vec![event(1)]).await;
        assert!(p.flush().await.is_none());
        assert_eq!(store.count(&[Filter::new()]).unwrap(), 1);
    }

    #[tokio::test]
    async fn store_error_surfaces_once() {
        let fail = Arc::new(FailingStore {
            inner: nk_store::MemoryStore::new(),
            fail: AtomicBool::new(true),
        });
        let store: Arc<dyn EventStore> = Arc::<FailingStore>::clone(&fail);
        let p = Persister::spawn(store);
        p.push(vec![event(2)]).await;
        assert!(p.flush().await.is_some(), "first error surfaces");
        fail.fail.store(false, AtomicOrdering::Relaxed);
        assert!(p.flush().await.is_none(), "cleared after surfacing");
    }

    #[tokio::test]
    async fn flush_orders_writes() {
        let store: Arc<dyn EventStore> = Arc::new(nk_store::MemoryStore::new());
        let p = Persister::spawn(Arc::clone(&store));
        p.push(vec![event(3)]).await;
        assert!(p.flush().await.is_none());
        assert_eq!(store.count(&[Filter::new()]).unwrap(), 1, "A written");
        p.push(vec![event(4)]).await;
        assert!(p.flush().await.is_none());
        assert_eq!(store.count(&[Filter::new()]).unwrap(), 2, "B follows A");
    }
}
