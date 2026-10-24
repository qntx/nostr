//! The single-relay client.

mod error;
mod options;
mod session;
mod subscription;

pub use error::{Error, Result, TransportError};
pub use options::RelayOptions;
pub use subscription::{CloseReason, Subscription, SubscriptionEvent};

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use nk_core::{ClientMessage, Event, EventId, Filter, RelayMessage, RelayUrl, SubscriptionId};
use session::{Out, Session};
use subscription::channel_pair;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::debug;
use yawc::{Frame, WebSocket};

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
    Close(oneshot::Sender<()>),
}

struct SubHandles {
    tx: mpsc::Sender<SubscriptionEvent>,
    terminal: Arc<std::sync::Mutex<Option<CloseReason>>>,
}

/// A single-relay client. `Clone` is cheap; dropping the last handle stops
/// the driver.
#[derive(Clone)]
pub struct Relay {
    cmd: mpsc::Sender<Cmd>,
    status: watch::Receiver<RelayStatus>,
}

type Sock = yawc::TcpWebSocket;
type PublishWaiters = Vec<oneshot::Sender<Result<PublishOutcome>>>;

/// Sends one client message; transport failures surface as
/// [`Error::Transport`].
async fn send_msg(ws: &mut Sock, msg: ClientMessage<'_>) -> Result<()> {
    ws.send(Frame::text(msg.to_json()))
        .await
        .map_err(|e| Error::Transport(TransportError::new(e)))
}

/// Fails every pending publish with `Disconnected` after a socket drop.
fn fail_pending(session: &mut Session, publishes: &mut HashMap<EventId, PublishWaiters>) {
    for id in session.take_pending() {
        if let Some(waiters) = publishes.remove(&id) {
            for w in waiters {
                drop(w.send(Err(Error::Disconnected)));
            }
        }
    }
}

/// Handshakes once inside the connect timeout.
async fn connect_once(url: &url::Url, options: &RelayOptions) -> Result<Sock> {
    tokio::time::timeout(options.connect_timeout, WebSocket::connect(url.clone()))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Transport(TransportError::new(e)))
}

/// Replays every open `REQ` after (re)connect.
async fn replay(session: &Session, ws: &mut Sock) {
    for (id, filters) in session.replay_reqs() {
        drop(
            send_msg(
                ws,
                ClientMessage::Req {
                    subscription_id: Cow::Owned(id),
                    filters: Cow::Owned(filters),
                },
            )
            .await,
        );
    }
}

/// The detached fetch collector: drains the sub's stream until `EOSE`,
/// `CLOSED`, or the deadline.
async fn collect_fetch(
    rx: &mut mpsc::Receiver<SubscriptionEvent>,
    timeout: Duration,
) -> FetchOutcome {
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(SubscriptionEvent::Event(e))) => events.push(e),
            Ok(Some(SubscriptionEvent::Eose)) => {
                return FetchOutcome {
                    events,
                    end: FetchEnd::Eose,
                };
            }
            Ok(Some(SubscriptionEvent::Closed(CloseReason::Relay(r)))) => {
                return FetchOutcome {
                    events,
                    end: FetchEnd::Closed(r),
                };
            }
            Ok(Some(SubscriptionEvent::Closed(_)) | None) | Err(_) => {
                return FetchOutcome {
                    events,
                    end: FetchEnd::Timeout,
                };
            }
        }
    }
}

/// Randomized ±25% of `base` so a fleet doesn't reconnect in lockstep.
fn jittered(base: Duration) -> Duration {
    use nk_core::rand_core::TryRng;
    let mut rng = nk_core::SysRng;
    let mut buf = [0u8; 8];
    let frac = rng
        .try_fill_bytes(&mut buf)
        .map_or(25, |()| (u64::from_le_bytes(buf) % 51) as u32);
    base.mul_f64(0.75 + f64::from(frac) / 100.0)
}

/// Shared driver state threaded through the per-command handlers.
struct Driver {
    session: Session,
    subs: HashMap<SubscriptionId, SubHandles>,
    publishes: HashMap<EventId, PublishWaiters>,
    ws: Option<Sock>,
    cmd: mpsc::Sender<Cmd>,
    url: Option<url::Url>,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
    backoff: Duration,
    reconnect_at: Option<tokio::time::Instant>,
    next_sub: u64,
}

impl Driver {
    /// The single disconnect path: drop the socket, fail pending publishes,
    /// and (when enabled) arm the jittered backoff reconnect.
    fn disconnect(&mut self) {
        self.ws = None;
        self.status.send_replace(RelayStatus::Disconnected);
        fail_pending(&mut self.session, &mut self.publishes);
        if self.options.reconnect {
            self.reconnect_at = Some(tokio::time::Instant::now() + jittered(self.backoff));
            self.backoff = (self.backoff * 2).min(self.options.reconnect_max);
        }
    }

    /// Allocates the next subscription id from the per-relay counter.
    fn alloc_sub_id(&mut self) -> Option<SubscriptionId> {
        self.next_sub = self.next_sub.checked_add(1)?;
        SubscriptionId::new(self.next_sub.to_string()).ok()
    }

    /// Connects if the socket is down; replays open `REQ`s on success.
    async fn ensure_connected(&mut self) -> Result<()> {
        if self.ws.is_some() {
            return Ok(());
        }
        let Some(url) = self.url.clone() else {
            self.disconnect();
            return Err(Error::InvalidUrl);
        };
        self.status.send_replace(RelayStatus::Connecting);
        match connect_once(&url, &self.options).await {
            Ok(mut sock) => {
                self.status.send_replace(RelayStatus::Connected);
                self.backoff = self.options.reconnect_min;
                self.reconnect_at = None;
                replay(&self.session, &mut sock).await;
                self.ws = Some(sock);
                Ok(())
            }
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// Writes a client message; a send failure drops the socket through
    /// [`Driver::disconnect`].
    async fn write(&mut self, msg: ClientMessage<'_>) -> Result<()> {
        let Some(sock) = self.ws.as_mut() else {
            return Err(Error::Disconnected);
        };
        match send_msg(sock, msg).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// Sends a `REQ` (no-op while disconnected — replay covers it).
    async fn req(&mut self, id: &SubscriptionId, filters: &[Filter]) -> Result<()> {
        if self.ws.is_none() {
            return Ok(());
        }
        self.write(ClientMessage::Req {
            subscription_id: Cow::Borrowed(id),
            filters: Cow::Borrowed(filters),
        })
        .await
    }

    /// Sends a `CLOSE` (no-op while disconnected).
    async fn close(&mut self, id: &SubscriptionId) -> Result<()> {
        if self.ws.is_none() {
            return Ok(());
        }
        self.write(ClientMessage::Close(Cow::Borrowed(id))).await
    }

    /// Connects now and reports the handshake's real error.
    async fn on_connect(&mut self, reply: oneshot::Sender<Result<()>>) {
        drop(reply.send(self.ensure_connected().await));
    }

    /// Registers the subscription. With reconnect enabled a dead socket
    /// just means the `REQ` replays later; without it a failed connect
    /// attempt propagates the error.
    async fn on_subscribe(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<Subscription>>,
    ) {
        let Some(id) = self.alloc_sub_id() else {
            drop(reply.send(Err(Error::SubscriptionId)));
            return;
        };
        let was_connected = self.ws.is_some();
        self.session.add_sub(id.clone(), filters.clone());
        if let Err(e) = self.ensure_connected().await
            && !self.options.reconnect
        {
            let _ = self.session.close_sub(&id);
            drop(reply.send(Err(e)));
            return;
        }
        let (sub, tx, terminal) = channel_pair(
            id.clone(),
            self.cmd.clone(),
            self.options.subscription_capacity,
        );
        self.subs.insert(id.clone(), SubHandles { tx, terminal });
        // A socket that was already open needs the REQ written now; a fresh
        // connect got it through replay.
        if was_connected {
            drop(self.req(&id, &filters).await);
        }
        drop(reply.send(Ok(sub)));
    }

    /// Sends `EVENT`; fails fast with `Disconnected` on a dead socket.
    async fn on_publish(&mut self, event: Event, reply: oneshot::Sender<Result<PublishOutcome>>) {
        drop(self.ensure_connected().await);
        if self.ws.is_none() {
            drop(reply.send(Err(Error::Disconnected)));
            return;
        }
        if !self.session.add_pending(event.id()) {
            self.publishes.entry(event.id()).or_default().push(reply);
            return;
        }
        self.publishes.insert(event.id(), vec![reply]);
        let r = self
            .write(ClientMessage::Event(Cow::Borrowed(&event)))
            .await;
        if r.is_err() {
            // The publish is now a failed pending entry; disconnect already
            // failed every waiter.
        }
    }

    /// Bounded collect until `EOSE`, `CLOSED`, or the timeout.
    async fn on_fetch(
        &mut self,
        filters: Vec<Filter>,
        timeout: Duration,
        reply: oneshot::Sender<Result<FetchOutcome>>,
    ) {
        let Some(id) = self.alloc_sub_id() else {
            drop(reply.send(Err(Error::SubscriptionId)));
            return;
        };
        let was_connected = self.ws.is_some();
        self.session.add_sub(id.clone(), filters.clone());
        if let Err(e) = self.ensure_connected().await
            && !self.options.reconnect
        {
            let _ = self.session.close_sub(&id);
            drop(reply.send(Err(e)));
            return;
        }
        let (tx, mut rx) = mpsc::channel(256);
        self.subs.insert(
            id.clone(),
            SubHandles {
                tx,
                terminal: Arc::new(std::sync::Mutex::new(None)),
            },
        );
        if was_connected {
            drop(self.req(&id, &filters).await);
        }
        let cmd = self.cmd.clone();
        tokio::spawn(async move {
            let outcome = collect_fetch(&mut rx, timeout).await;
            drop(cmd.send(Cmd::CloseSub { id }).await);
            drop(reply.send(Ok(outcome)));
        });
    }

    /// Ends the subscription locally and sends `CLOSE`.
    async fn on_close_sub(&mut self, id: SubscriptionId) {
        self.subs.remove(&id);
        let _ = self.session.close_sub(&id);
        drop(self.close(&id).await);
    }

    /// Terminal: every subscription ends `Closed(RelayClosed)`.
    async fn on_close(&mut self, reply: oneshot::Sender<()>) {
        self.status.send_replace(RelayStatus::Closed);
        self.reconnect_at = None;
        for (_, h) in self.subs.drain() {
            if let Ok(mut t) = h.terminal.lock() {
                *t = Some(CloseReason::RelayClosed);
            }
            drop(h.tx);
        }
        if let Some(mut sock) = self.ws.take() {
            drop(
                sock.send(Frame::close(yawc::close::CloseCode::Normal, &[][..]))
                    .await,
            );
        }
        if reply.send(()).is_err() {
            debug!("close reply receiver dropped");
        }
    }

    /// Forwards `EOSE` to the subscription's stream.
    fn send_eose(&self, id: &SubscriptionId) {
        if let Some(h) = self.subs.get(id) {
            drop(h.tx.try_send(SubscriptionEvent::Eose));
        }
    }

    /// Ends `id` with `reason`: terminal mark, sender dropped.
    fn end_sub(&mut self, id: &SubscriptionId, reason: CloseReason) {
        let Some(h) = self.subs.remove(id) else {
            return;
        };
        if let Ok(mut t) = h.terminal.lock() {
            *t = Some(reason);
        }
        drop(h.tx);
    }

    /// Fans one `OK` out to every waiter that joined the publish.
    fn resolve_publish(&mut self, id: EventId, accepted: bool, message: &str) {
        let Some(waiters) = self.publishes.remove(&id) else {
            return;
        };
        for w in waiters {
            drop(w.send(Ok(PublishOutcome {
                accepted,
                message: message.to_owned(),
            })));
        }
    }

    /// Delivers an event; a lagged consumer ends `Closed(Lagged)` + `CLOSE`.
    fn deliver(&mut self, id: &SubscriptionId, event: Event, to_close: &mut Vec<SubscriptionId>) {
        let lagged = self
            .subs
            .get(id)
            .is_some_and(|h| h.tx.try_send(SubscriptionEvent::Event(event)).is_err());
        if !lagged {
            return;
        }
        self.end_sub(id, CloseReason::Lagged);
        let _ = self.session.close_sub(id);
        to_close.push(id.clone());
    }

    /// Routes one inbound frame through the session.
    async fn on_frame(&mut self, frame: Frame) {
        if frame.opcode() != yawc::OpCode::Text {
            return;
        }
        let outs: Vec<Out> = std::str::from_utf8(frame.payload())
            .ok()
            .and_then(|t| RelayMessage::from_json(t).ok())
            .map(|m| self.session.handle(m))
            .unwrap_or_default();
        let mut to_close = Vec::new();
        for out in outs {
            match out {
                Out::Deliver { id, event } => self.deliver(&id, event, &mut to_close),
                Out::Eose(id) => self.send_eose(&id),
                Out::Closed { id, reason } => self.end_sub(&id, CloseReason::Relay(reason)),
                Out::PublishDone {
                    id,
                    accepted,
                    message,
                } => self.resolve_publish(id, accepted, &message),
                Out::Notice(m) => debug!("relay notice: {m}"),
                Out::SendClose(id) => to_close.push(id),
            }
        }
        for id in to_close {
            drop(self.close(&id).await);
        }
    }

    /// One command off the channel; `false` means the driver exits.
    async fn dispatch(&mut self, cmd: Option<Cmd>) -> bool {
        match cmd {
            None => {
                if let Some(mut sock) = self.ws.take() {
                    drop(
                        sock.send(Frame::close(yawc::close::CloseCode::Normal, &[][..]))
                            .await,
                    );
                }
                false
            }
            Some(Cmd::Connect(reply)) => {
                self.on_connect(reply).await;
                true
            }
            Some(Cmd::Subscribe { filters, reply }) => {
                self.on_subscribe(filters, reply).await;
                true
            }
            Some(Cmd::Publish { event, reply }) => {
                self.on_publish(event, reply).await;
                true
            }
            Some(Cmd::Fetch {
                filters,
                timeout,
                reply,
            }) => {
                self.on_fetch(filters, timeout, reply).await;
                true
            }
            Some(Cmd::CloseSub { id }) => {
                self.on_close_sub(id).await;
                true
            }
            Some(Cmd::Close(reply)) => {
                self.on_close(reply).await;
                false
            }
        }
    }

    /// A reconnect attempt after the armed deadline.
    async fn try_reconnect(&mut self) {
        self.reconnect_at = None;
        let Some(url) = self.url.clone() else {
            return;
        };
        self.status.send_replace(RelayStatus::Connecting);
        match connect_once(&url, &self.options).await {
            Ok(mut sock) => {
                self.status.send_replace(RelayStatus::Connected);
                self.backoff = self.options.reconnect_min;
                replay(&self.session, &mut sock).await;
                self.ws = Some(sock);
            }
            Err(e) => {
                debug!("reconnect failed: {e}");
                self.disconnect();
            }
        }
    }
}

async fn driver_loop(
    mut rx: mpsc::Receiver<Cmd>,
    cmd_tx: mpsc::Sender<Cmd>,
    url: String,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
) {
    let mut d = Driver {
        session: Session::default(),
        subs: HashMap::new(),
        publishes: HashMap::new(),
        ws: None,
        cmd: cmd_tx,
        url: url.parse::<url::Url>().ok(),
        options,
        status,
        backoff: options.reconnect_min,
        reconnect_at: None,
        next_sub: 0,
    };
    let mut ping = tokio::time::interval(options.ping_interval);
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                if !d.dispatch(cmd).await {
                    return;
                }
            }
            frame = async {
                match d.ws.as_mut() {
                    Some(sock) => Some(sock.next_frame().await),
                    None => None,
                }
            }, if d.ws.is_some() => {
                match frame {
                    Some(Ok(f)) => d.on_frame(f).await,
                    Some(Err(e)) => {
                        debug!("ws error: {e}");
                        d.disconnect();
                    }
                    None => d.disconnect(),
                }
            }
            () = async {
                match d.reconnect_at {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            }, if d.options.reconnect && d.ws.is_none() && d.reconnect_at.is_some() => {
                d.try_reconnect().await;
            }
            _ = ping.tick(), if d.ws.is_some() => {
                if let Some(sock) = d.ws.as_mut() {
                    drop(sock.send(Frame::ping(&[][..])).await);
                }
            }
        }
    }
}

impl Relay {
    /// Creates the driver (spawns on the current tokio runtime); the socket
    /// connects lazily on first use.
    #[must_use]
    pub fn new(url: &RelayUrl, options: RelayOptions) -> Self {
        let (cmd, rx) = mpsc::channel(256);
        let (status_tx, status_rx) = watch::channel(RelayStatus::Disconnected);
        tokio::spawn(driver_loop(
            rx,
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
