//! The single-relay client.

mod driver;
mod error;
mod options;
mod session;
mod subscription;
mod transport;

pub use error::{Error, Result, TransportError};
pub use options::RelayOptions;
pub use subscription::{CloseReason, Subscription, SubscriptionEvent};

use std::time::Duration;

use nk_core::{Event, Filter, RelayUrl, SubscriptionId};
use tokio::sync::{mpsc, oneshot, watch};

/// What the driver is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayStatus {
    /// No socket; the first operation connects.
    Disconnected,
    /// Handshake or reconnect backoff in flight.
    Connecting,
    /// The socket is live.
    Connected,
    /// `close` ran; the driver is terminal.
    Closed,
}

/// A `fetch`'s result.
#[derive(Debug)]
#[non_exhaustive]
pub struct FetchOutcome {
    /// Stored events matching the filters, newest first.
    pub events: Vec<Event>,
    /// How the fetch ended.
    pub end: FetchEnd,
}

/// How a `fetch` ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchEnd {
    /// `EOSE` received normally.
    Eose,
    /// The relay `CLOSED` the subscription early; the message is the reason.
    Closed(String),
    /// The fetch deadline elapsed.
    Timeout,
}

/// A publish's `OK`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublishOutcome {
    /// The relay's `saved` flag.
    pub accepted: bool,
    /// The relay's machine-readable message.
    pub message: String,
}

pub(crate) enum Cmd {
    Connect(oneshot::Sender<Result<()>>),
    Subscribe {
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<Subscription>>,
    },
    Fetch {
        filters: Vec<Filter>,
        timeout: Duration,
        reply: oneshot::Sender<Result<FetchOutcome>>,
    },
    Publish {
        event: Event,
        reply: oneshot::Sender<Result<PublishOutcome>>,
    },
    CloseSub {
        id: SubscriptionId,
    },
    /// The off-loop signer finished (or failed to produce) an `AUTH`
    /// event for `challenge`.
    AuthDone {
        event: Result<Event>,
        challenge: String,
    },
    /// `Relay::count` — send `["COUNT", id, filters...]`.
    Count {
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<nk_core::CountResult>>,
    },
    Close(oneshot::Sender<()>),
}

/// A single-relay client. `Clone` is cheap; dropping the last handle stops
/// the driver.
#[derive(Clone)]
pub struct Relay {
    cmd: mpsc::Sender<Cmd>,
    status: watch::Receiver<RelayStatus>,
}

impl Relay {
    /// Creates the driver (spawns on the current tokio runtime); the socket
    /// connects lazily on first use.
    #[must_use]
    pub fn new(url: &RelayUrl, options: RelayOptions) -> Self {
        let (cmd, rx) = mpsc::channel(256);
        let (status_tx, status_rx) = watch::channel(RelayStatus::Disconnected);
        let (drop_tx, drop_rx) = mpsc::unbounded_channel();
        tokio::spawn(driver::driver_loop(
            rx,
            drop_rx,
            drop_tx,
            cmd.clone(),
            url.as_str().to_owned(),
            options,
            status_tx,
        ));
        Self {
            cmd,
            status: status_rx,
        }
    }

    /// Connects now instead of lazily.
    ///
    /// # Errors
    ///
    /// [`Error::Disconnected`] when the handshake fails inside the
    /// connect timeout; [`Error::Closed`] once `close` has run.
    pub async fn connect(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Connect(tx))
            .await
            .map_err(|_| Error::Closed)?;
        rx.await.map_err(|_| Error::Closed)?
    }

    /// Opens a `REQ`. `filters` must not be empty (NIP-01).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list;
    /// [`Error::Closed`] once `close` has run.
    pub async fn subscribe(&self, filters: Vec<Filter>) -> Result<Subscription> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Subscribe { filters, reply })
            .await
            .map_err(|_| Error::Closed)?;
        rx.await.map_err(|_| Error::Closed)?
    }

    /// A bounded read: collects until `EOSE`, `CLOSED`, or `timeout`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list;
    /// [`Error::Closed`] once `close` has run.
    pub async fn fetch(&self, filters: Vec<Filter>, timeout: Duration) -> Result<FetchOutcome> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Fetch {
                filters,
                timeout,
                reply: tx,
            })
            .await
            .map_err(|_| Error::Closed)?;
        rx.await.map_err(|_| Error::Closed)?
    }

    /// Sends `EVENT` and waits for `OK`. Concurrent publishes of the same
    /// event id join the in-flight request.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] once `close` has run; [`Error::Disconnected`]
    /// when the socket drops before `OK` arrives.
    pub async fn publish(&self, event: &Event) -> Result<PublishOutcome> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Publish {
                event: event.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| Error::Closed)?;
        rx.await.map_err(|_| Error::Closed)?
    }

    /// The driver's current state.
    #[must_use]
    pub fn status(&self) -> RelayStatus {
        *self.status.borrow()
    }

    /// Terminates the driver — every subscription ends `Closed(RelayClosed)`.
    /// NIP-45 `COUNT`: returns the number of stored events matching
    /// `filters`. Times out at `publish_timeout`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilters`] on an empty filter list;
    /// [`Error::Timeout`] when the relay does not answer in time.
    pub async fn count(&self, filters: Vec<Filter>) -> Result<nk_core::CountResult> {
        if filters.is_empty() {
            return Err(Error::InvalidFilters);
        }
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Count { filters, reply: tx })
            .await
            .map_err(|_| Error::Disconnected)?;
        rx.await.map_err(|_| Error::Disconnected)?
    }

    /// Terminal close: subscriptions end `Closed(RelayClosed)` and the
    /// socket shuts; idempotent.
    pub async fn close(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Close(tx)).await.is_ok() {
            drop(rx.await);
        }
    }
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
