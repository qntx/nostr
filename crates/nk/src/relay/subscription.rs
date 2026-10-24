//! The per-subscription event stream returned by [`Relay::subscribe`].

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::Stream;
use nk_core::{Event, SubscriptionId};
use tokio::sync::mpsc;

use super::Cmd;

/// Why a subscription ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The relay sent `CLOSED` with this machine-readable message.
    Relay(String),
    /// The consumer fell behind; the subscription closed locally.
    Lagged,
    /// `Relay::close` ended every subscription.
    RelayClosed,
}

/// An item on a [`Subscription`] stream.
#[derive(Debug)]
#[non_exhaustive]
pub enum SubscriptionEvent {
    /// A verified, filter-matching event.
    Event(Event),
    /// The relay's `EOSE` — stored results are complete.
    Eose,
    /// The subscription ended; the stream terminates after this item.
    Closed(CloseReason),
}

/// A live `REQ` on a relay. Dropping it sends `CLOSE`.
pub struct Subscription {
    id: SubscriptionId,
    rx: mpsc::Receiver<SubscriptionEvent>,
    cmd: mpsc::Sender<Cmd>,
    /// Set by the driver when the sub is ended while the channel is full
    /// (lagged) or the relay is closing.
    terminal: Arc<std::sync::Mutex<Option<CloseReason>>>,
    done: bool,
}

impl Subscription {
    /// The subscription's wire id.
    #[must_use]
    pub const fn id(&self) -> &SubscriptionId {
        &self.id
    }
}

impl Stream for Subscription {
    type Item = SubscriptionEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some(item)),
            Poll::Ready(None) => {
                this.done = true;
                let reason = this
                    .terminal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                reason.map_or(Poll::Ready(None), |r| {
                    Poll::Ready(Some(SubscriptionEvent::Closed(r)))
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        drop(self.cmd.try_send(Cmd::CloseSub {
            id: self.id.clone(),
        }));
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub(crate) fn channel_pair(
    id: SubscriptionId,
    cmd: mpsc::Sender<Cmd>,
    capacity: usize,
) -> (
    Subscription,
    mpsc::Sender<SubscriptionEvent>,
    Arc<std::sync::Mutex<Option<CloseReason>>>,
) {
    let (tx, rx) = mpsc::channel(capacity);
    let terminal = Arc::new(std::sync::Mutex::new(None));
    (
        Subscription {
            id,
            rx,
            cmd,
            terminal: Arc::clone(&terminal),
            done: false,
        },
        tx,
        terminal,
    )
}
