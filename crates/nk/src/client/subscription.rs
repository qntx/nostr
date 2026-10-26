//! `ClientSubscription` — a [`PoolSubscription`] that ingests every
//! event it yields into the client's gossip table and store.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use nk_core::RelayUrl;

use super::Client;
use crate::pool::{PoolEvent, PoolSubscription};

/// A live subscription from the client's `subscribe` methods.
///
/// Every yielded event is ingested into the gossip table and queued
/// for the store *before* it reaches the consumer — `routes` and
/// `query` are current as the stream yields.
pub struct ClientSubscription {
    pub(crate) inner: PoolSubscription,
    pub(crate) client: Client,
}

impl ClientSubscription {
    /// The relays this subscription is attached to.
    pub fn relays(&self) -> impl Iterator<Item = &RelayUrl> {
        self.inner.relays()
    }
}

impl std::fmt::Debug for ClientSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSubscription")
            .field("relays", &self.inner.relays().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Stream for ClientSubscription {
    type Item = PoolEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(PoolEvent::Event { relay, event })) => {
                this.client.ingest_live(&event);
                Poll::Ready(Some(PoolEvent::Event { relay, event }))
            }
            other => other,
        }
    }
}

const _: fn() = || {
    const fn assert<T: Send + Sync + Unpin>() {}
    assert::<ClientSubscription>();
};
