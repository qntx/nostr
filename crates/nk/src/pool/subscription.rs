//! [`PoolSubscription`]: a merged `Stream` over per-relay
//! [`Subscription`]s — first-receipt dedupe, one aggregate `EOSE`, and
//! per-relay `Closed`/`Failed` reporting. No extra task; `SelectAll`
//! drives the children.

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::join_all;
use futures_util::stream::{SelectAll, Stream, StreamExt};
use nk_core::{Event, EventId, Filter, RelayUrl};

use crate::relay::{CloseReason, Error, Relay, Subscription, SubscriptionEvent};

/// An item on a [`PoolSubscription`] stream.
#[derive(Debug)]
#[non_exhaustive]
pub enum PoolEvent {
    /// A verified, matching event — first receipt of an id only.
    Event {
        /// The relay that delivered it first.
        relay: RelayUrl,
        /// The event.
        event: Event,
    },
    /// Every attached relay sent `EOSE` or ended, and at least one sent
    /// `EOSE`. Emitted exactly once.
    Eose,
    /// A relay's subscription ended.
    Closed {
        /// The ended relay.
        relay: RelayUrl,
        /// Why it ended.
        reason: CloseReason,
    },
    /// That relay's subscribe call failed before a stream existed.
    Failed {
        /// The failed relay.
        relay: RelayUrl,
        /// The error it returned.
        error: Error,
    },
}

/// One relay's stream, tagged so `SelectAll` knows who spoke.
struct Tagged {
    relay: RelayUrl,
    sub: Subscription,
}

impl Stream for Tagged {
    type Item = (RelayUrl, SubscriptionEvent);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.sub
            .poll_next_unpin(cx)
            .map(|item| item.map(|i| (self.relay.clone(), i)))
    }
}

/// A fixed-capacity cross-relay dedupe set — the oldest id is evicted at
/// capacity.
struct RecentIds {
    seen: HashSet<EventId>,
    order: VecDeque<EventId>,
    capacity: usize,
}

impl RecentIds {
    const CAPACITY: usize = 65_536;

    fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity.min(1024)),
            order: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// `true` when `id` is new; evicts the oldest at capacity.
    fn insert(&mut self, id: EventId) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        true
    }
}

/// A merged subscription across relays.
pub struct PoolSubscription {
    inner: SelectAll<Tagged>,
    /// Relays still owed an `EOSE` — `Closed` clears them too.
    awaiting_eose: HashSet<RelayUrl>,
    /// At least one relay has sent `EOSE`.
    saw_eose: bool,
    /// The aggregate `Eose` was already emitted.
    eose_sent: bool,
    /// Cross-relay dedupe — first receipt of an id only.
    recent: RecentIds,
    /// Pending items: `Failed` items queued at open, then the aggregate.
    pending: VecDeque<PoolEvent>,
}

impl PoolSubscription {
    /// Opens a `REQ` on each relay, queues `Failed` items for the ones
    /// that couldn't, and tracks every attached relay for EOSE.
    pub(crate) async fn open(relays: Vec<(RelayUrl, Relay)>, filters: Vec<Filter>) -> Self {
        // Concurrent opens — a slow relay must not serialize the
        // others' connect timeouts.
        let results = join_all(relays.iter().map(|(url, relay)| {
            let filters = filters.clone();
            async move { (url.clone(), relay.subscribe(filters).await) }
        }))
        .await;
        let mut subs = Vec::with_capacity(results.len());
        let mut pending = VecDeque::new();
        let mut awaiting = HashSet::with_capacity(results.len());
        for (url, outcome) in results {
            match outcome {
                Ok(sub) => {
                    awaiting.insert(url.clone());
                    subs.push(Tagged { relay: url, sub });
                }
                Err(error) => {
                    pending.push_back(PoolEvent::Failed { relay: url, error });
                }
            }
        }
        Self {
            inner: SelectAll::from_iter(subs),
            awaiting_eose: awaiting,
            saw_eose: false,
            eose_sent: false,
            recent: RecentIds::with_capacity(RecentIds::CAPACITY),
            pending,
        }
    }

    /// The relays still attached to the stream.
    pub fn relays(&self) -> impl Iterator<Item = &RelayUrl> {
        self.inner.iter().map(|t| &t.relay)
    }

    /// Queues the aggregate `Eose` once every relay has answered.
    fn queue_eose(&mut self) {
        if !self.eose_sent && self.awaiting_eose.is_empty() {
            self.eose_sent = true;
            self.pending.push_back(PoolEvent::Eose);
        }
    }

    /// One child item → `Some` to surface, `None` when consumed.
    fn on_item(&mut self, relay: RelayUrl, item: SubscriptionEvent) -> Option<PoolEvent> {
        match item {
            SubscriptionEvent::Event(event) => self
                .recent
                .insert(event.id())
                .then_some(PoolEvent::Event { relay, event }),
            SubscriptionEvent::Eose => {
                self.saw_eose = true;
                self.awaiting_eose.remove(&relay);
                self.queue_eose();
                None
            }
            SubscriptionEvent::Closed(reason) => {
                self.awaiting_eose.remove(&relay);
                if self.saw_eose {
                    self.queue_eose();
                }
                Some(PoolEvent::Closed { relay, reason })
            }
        }
    }
}

impl Stream for PoolSubscription {
    type Item = PoolEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(item) = self.pending.pop_front() {
                return Poll::Ready(Some(item));
            }
            let Some((relay, item)) = futures_util::ready!(self.inner.poll_next_unpin(cx)) else {
                return Poll::Ready(None);
            };
            let Some(out) = self.on_item(relay, item) else {
                continue;
            };
            return Poll::Ready(Some(out));
        }
    }
}

impl std::fmt::Debug for PoolSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolSubscription")
            .field("awaiting_eose", &self.awaiting_eose.len())
            .field("eose_sent", &self.eose_sent)
            .finish_non_exhaustive()
    }
}
