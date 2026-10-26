//! The per-subscription event stream returned by [`Relay::subscribe`].

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use nk_core::{Event, SubscriptionId};
use tokio::sync::{mpsc, oneshot};

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
    /// Drop-side `CLOSE` requests — unbounded, never lost under load.
    drops: mpsc::UnboundedSender<SubscriptionId>,
    /// The driver's close reason — sent before `tx` drops, so it is
    /// always waiting when the channel ends.
    terminal: oneshot::Receiver<CloseReason>,
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
                Poll::Ready(this.terminal.try_recv().ok().map(SubscriptionEvent::Closed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // `unbounded_send` fails only when the driver is gone — the socket
        // and its `CLOSE` obligation died with it.
        drop(self.drops.send(self.id.clone()));
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The driver's half of a subscription channel: the event sender plus
/// the one-shot terminal reason.
pub(crate) struct SubHandles {
    /// Event channel — dropped after `terminal` on `end`.
    pub(crate) tx: mpsc::Sender<SubscriptionEvent>,
    /// The reason the stream ended, read once `rx` closes.
    terminal: oneshot::Sender<CloseReason>,
}

impl SubHandles {
    /// Ends the stream: the reason is sent first, then the channel
    /// closes — the `Closed` item is never lost behind a full `rx`.
    pub(crate) fn end(self, reason: CloseReason) {
        drop(self.terminal.send(reason));
        drop(self.tx);
    }
}

pub(crate) fn channel_pair(
    id: SubscriptionId,
    drops: mpsc::UnboundedSender<SubscriptionId>,
    capacity: usize,
) -> (Subscription, SubHandles) {
    let (tx, rx) = mpsc::channel(capacity);
    let (terminal_tx, terminal_rx) = oneshot::channel();
    (
        Subscription {
            id,
            rx,
            drops,
            terminal: terminal_rx,
            done: false,
        },
        SubHandles {
            tx,
            terminal: terminal_tx,
        },
    )
}
