//! The driver task: owns the socket, the session, and the select loop.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nk_core::{ClientMessage, Event, EventBuilder, EventId, Filter, RelayMessage, SubscriptionId};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::debug;

use super::neg::{NegSession, Reconciliation};
use super::session::{Out, Retry, Session};
use super::subscription::{CloseReason, Subscription, SubscriptionEvent, channel_pair};
use super::transport::{Endpoint, Inbound, Transport};
use super::{
    Cmd, Error, FetchEnd, FetchOutcome, PublishOutcome, RelayOptions, RelayStatus, Result,
    TransportError,
};

type PublishWaiters = Vec<oneshot::Sender<Result<PublishOutcome>>>;

/// A live `NEG-OPEN`: the session, its waiter, and the retry context.
struct NegEntry {
    session: NegSession,
    reply: oneshot::Sender<Result<Reconciliation>>,
    filter: Filter,
    items: Vec<(nk_core::Timestamp, EventId)>,
    out: Reconciliation,
}

/// Per-subscription channel handles.
struct SubHandles {
    tx: mpsc::Sender<SubscriptionEvent>,
    /// Shared terminal slot; `Subscription`'s stream reads it after the
    /// channel ends.
    terminal: Arc<std::sync::Mutex<Option<CloseReason>>>,
}

/// Fails every pending publish with `Disconnected` after a socket drop.
fn fail_pending(
    session: &mut Session,
    publishes: &mut HashMap<EventId, PublishWaiters>,
    pending_events: &mut HashMap<EventId, Event>,
) {
    for id in session.take_pending() {
        pending_events.remove(&id);
        if let Some(waiters) = publishes.remove(&id) {
            for w in waiters {
                drop(w.send(Err(Error::Disconnected)));
            }
        }
    }
}

/// Handshakes once inside the connect timeout.
async fn connect_once(url: &Endpoint, options: &RelayOptions) -> Result<Transport> {
    Transport::connect(url, options.connect_timeout).await
}

/// Replays every open `REQ` after (re)connect.
async fn replay(session: &Session, ws: &mut Transport) {
    for (id, filters) in session.replay_reqs() {
        drop(
            ws.send(&ClientMessage::Req {
                subscription_id: Cow::Owned(id),
                filters: Cow::Owned(filters),
            })
            .await,
        );
    }
}

/// The detached fetch collector: drains the sub's stream until `EOSE`,
/// `CLOSED`, or the deadline.
async fn collect_fetch(
    rx: &mut mpsc::Receiver<SubscriptionEvent>,
    terminal: &std::sync::Mutex<Option<CloseReason>>,
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
            Ok(Some(SubscriptionEvent::Closed(_))) | Err(_) => {
                return FetchOutcome {
                    events,
                    end: FetchEnd::Timeout,
                };
            }
            // Channel end without a terminal item: the driver's mark.
            Ok(None) => {
                let reason = terminal
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let end = match reason {
                    Some(CloseReason::Relay(r)) => FetchEnd::Closed(r),
                    Some(_) | None => FetchEnd::Timeout,
                };
                return FetchOutcome { events, end };
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
    /// Drop-side `CLOSE` requests — unbounded, always delivered.
    drops: mpsc::UnboundedReceiver<SubscriptionId>,
    /// Sender side — handed to each new .
    drop_tx: mpsc::UnboundedSender<SubscriptionId>,
    subs: HashMap<SubscriptionId, SubHandles>,
    publishes: HashMap<EventId, PublishWaiters>,
    /// The `EVENT` payload per pending publish — needed to resend after
    /// an `auth-required:` + `AUTH` retry.
    pending_events: HashMap<EventId, Event>,
    ws: Option<Transport>,
    cmd: mpsc::Sender<Cmd>,
    url: Option<Endpoint>,
    /// The relay url text for `EventBuilder::auth`.
    url_string: String,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
    /// Latest AUTH challenge and whether it has been answered.
    challenge: Option<(String, bool)>,
    /// The AUTH event id awaiting its `OK`.
    auth_ok_id: Option<EventId>,
    /// COUNT id → waiter for `Out::Counted` (or its `CLOSED` reason).
    counts: HashMap<SubscriptionId, oneshot::Sender<Result<nk_core::CountResult>>>,
    /// `(retry, fallback)` requests queued behind the in-flight AUTH.
    auth_pending: Option<Vec<(Retry, Out)>>,
    /// Live NEG sessions by id.
    negs: HashMap<SubscriptionId, NegEntry>,
    backoff: Duration,
    reconnect_at: Option<tokio::time::Instant>,
    /// Deadline after the last ping with no inbound frame.
    pong_deadline: Option<tokio::time::Instant>,
    next_sub: u64,
}

impl Driver {
    /// The single disconnect path: drop the socket, fail pending publishes,
    /// and (when enabled) arm the jittered backoff reconnect.
    fn disconnect(&mut self) {
        self.ws = None;
        self.pong_deadline = None;
        self.status.send_replace(RelayStatus::Disconnected);
        fail_pending(
            &mut self.session,
            &mut self.publishes,
            &mut self.pending_events,
        );
        if self.options.reconnect {
            self.reconnect_at = Some(tokio::time::Instant::now() + jittered(self.backoff));
            self.backoff = (self.backoff * 2).min(self.options.reconnect_max);
        }
    }

    /// Allocates the next subscription id from the per-relay counter.
    fn alloc_sub_id(&mut self) -> SubscriptionId {
        self.next_sub = self.next_sub.wrapping_add(1);
        SubscriptionId::from(self.next_sub)
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
        match sock.send(&msg).await {
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

    /// Sends a `COUNT` (no-op while disconnected).
    async fn count(&mut self, id: &SubscriptionId, filters: &[Filter]) -> Result<()> {
        if self.ws.is_none() {
            return Ok(());
        }
        self.write(ClientMessage::Count {
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
        let id = self.alloc_sub_id();
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
            self.drop_tx.clone(),
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

    /// NIP-45 count: one `COUNT`, one waiter, `publish_timeout` deadline.
    async fn on_count(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<nk_core::CountResult>>,
    ) {
        let id = self.alloc_sub_id();
        self.session.add_count(id.clone(), filters.clone());
        drop(self.ensure_connected().await);
        let (tx, rx) = oneshot::channel();
        self.counts.insert(id.clone(), tx);
        drop(self.count(&id, &filters).await);
        let timeout = self.options.publish_timeout;
        tokio::spawn(async move {
            let out = match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(Error::Disconnected),
                Err(_) => Err(Error::Timeout),
            };
            drop(reply.send(out));
        });
    }

    /// NIP-77: build the session, send `NEG-OPEN`, arm the timeout.
    async fn on_reconcile(
        &mut self,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
        reply: oneshot::Sender<Result<Reconciliation>>,
    ) {
        let id = self.alloc_sub_id();
        let mut session = match NegSession::new(&items) {
            Ok(s) => s,
            Err(e) => {
                drop(reply.send(Err(e)));
                return;
            }
        };
        let msg = match session.initiate() {
            Ok(m) => m,
            Err(e) => {
                drop(reply.send(Err(e)));
                return;
            }
        };
        let _ = self.session.add_neg(id.clone());
        self.negs.insert(
            id.clone(),
            NegEntry {
                session,
                reply,
                filter: filter.clone(),
                items,
                out: Reconciliation::default(),
            },
        );
        drop(self.ensure_connected().await);
        drop(
            self.write(ClientMessage::NegOpen {
                subscription_id: Cow::Borrowed(&id),
                filter: Cow::Borrowed(&filter),
                message: Cow::Borrowed(&*msg),
            })
            .await,
        );
        let tx = self.cmd.clone();
        let timeout = self.options.publish_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            drop(tx.send(Cmd::NegTimeout { id }).await);
        });
    }

    /// One `NEG-MSG` round on `id`.
    async fn on_neg_msg(&mut self, id: &SubscriptionId, message: &str) {
        let Some(entry) = self.negs.get_mut(id) else {
            return;
        };
        match entry.session.on_msg(message, &mut entry.out) {
            Ok(Some(next)) => {
                drop(
                    self.write(ClientMessage::NegMsg {
                        subscription_id: Cow::Borrowed(id),
                        message: Cow::Borrowed(&*next),
                    })
                    .await,
                );
            }
            Ok(None) => {
                let Some(done) = self.negs.remove(id) else {
                    return;
                };
                self.session_close_neg(id);
                drop(self.write(ClientMessage::NegClose(Cow::Borrowed(id))).await);
                drop(done.reply.send(Ok(done.out)));
            }
            Err(e) => {
                let Some(failed) = self.negs.remove(id) else {
                    return;
                };
                drop(failed.reply.send(Err(e)));
            }
        }
    }

    /// Removes a neg id from the session table.
    fn session_close_neg(&mut self, id: &SubscriptionId) {
        self.session.close_neg(id);
    }

    /// `NEG-ERR` — auth-required retries, else the reason surfaces.
    fn on_neg_err(&mut self, id: &SubscriptionId, message: &str) {
        let Some(entry) = self.negs.remove(id) else {
            return;
        };
        if message.starts_with("auth-required:") && self.challenge.is_some() {
            let retry = Retry::Neg {
                id: id.clone(),
                filter: entry.filter.clone(),
                items: entry.items.clone(),
            };
            let fallback = Out::NegErr {
                id: id.clone(),
                reason: message.to_owned(),
            };
            self.negs.insert(id.clone(), entry);
            self.on_auth_required(retry, fallback);
            return;
        }
        drop(entry.reply.send(Err(Error::Refused(message.to_owned()))));
    }

    /// A `CLOSED` on a neg id — same auth/Refused routing as `NEG-ERR`.
    fn on_neg_closed(&mut self, id: &SubscriptionId, reason: &str) {
        let Some(entry) = self.negs.remove(id) else {
            return;
        };
        if reason.starts_with("auth-required:") && self.challenge.is_some() {
            let retry = Retry::Neg {
                id: id.clone(),
                filter: entry.filter.clone(),
                items: entry.items.clone(),
            };
            let fallback = Out::NegErr {
                id: id.clone(),
                reason: reason.to_owned(),
            };
            self.negs.insert(id.clone(), entry);
            self.on_auth_required(retry, fallback);
            return;
        }
        drop(entry.reply.send(Err(Error::Refused(reason.to_owned()))));
    }

    /// Rebuilds a neg session after a good `AUTH`.
    async fn retry_neg(
        &mut self,
        id: SubscriptionId,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
    ) {
        let Some(entry) = self.negs.get_mut(&id) else {
            return;
        };
        let Ok(mut session) = NegSession::new(&items) else {
            return;
        };
        let Ok(msg) = session.initiate() else {
            return;
        };
        entry.session = session;
        let _ = self.session.add_neg(id.clone());
        drop(
            self.write(ClientMessage::NegOpen {
                subscription_id: Cow::Borrowed(&id),
                filter: Cow::Borrowed(&filter),
                message: Cow::Borrowed(&*msg),
            })
            .await,
        );
    }

    /// The reconcile deadline hit — end the session with `Timeout`.
    async fn on_neg_timeout(&mut self, id: SubscriptionId) {
        let Some(entry) = self.negs.remove(&id) else {
            return;
        };
        drop(
            self.write(ClientMessage::NegClose(Cow::Borrowed(&id)))
                .await,
        );
        drop(entry.reply.send(Err(Error::Timeout)));
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
        self.pending_events.insert(event.id(), event.clone());
        let r = self
            .write(ClientMessage::Event(Cow::Borrowed(&event)))
            .await;
        if r.is_err() {
            // The publish is now a failed pending entry; disconnect already
            // failed every waiter.
        }
    }

    /// Unbounded, lossless drop path.
    async fn on_fetch(
        &mut self,
        filters: Vec<Filter>,
        timeout: Duration,
        reply: oneshot::Sender<Result<FetchOutcome>>,
    ) {
        let id = self.alloc_sub_id();
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
        let terminal = Arc::new(std::sync::Mutex::new(None));
        self.subs.insert(
            id.clone(),
            SubHandles {
                tx,
                terminal: Arc::clone(&terminal),
            },
        );
        if was_connected {
            drop(self.req(&id, &filters).await);
        }
        let cmd = self.cmd.clone();
        tokio::spawn(async move {
            let outcome = collect_fetch(&mut rx, &terminal, timeout).await;
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
            sock.close().await;
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

    /// Ends `id` with `reason`: set the terminal mark, drop the sender —
    /// the stream yields `Closed(reason)` when the channel drains.
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
        self.pending_events.remove(&id);
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

    /// Routes one inbound text frame through the session.
    async fn on_frame(&mut self, text: &str) {
        let Ok(msg) = RelayMessage::from_json(text) else {
            return;
        };
        // NEG frames bypass the sub/count session entirely.
        match msg {
            RelayMessage::NegMsg {
                subscription_id,
                message,
            } => self.on_neg_msg(&subscription_id, &message).await,
            RelayMessage::NegErr {
                subscription_id,
                message,
            } => self.on_neg_err(&subscription_id, &message),
            other => {
                // A CLOSED on a neg id needs the waiter's reason.
                if let RelayMessage::Closed {
                    subscription_id,
                    message,
                } = &other
                {
                    self.on_neg_closed(subscription_id, message);
                }
                let outs = self.session.handle(other);
                self.route_outs(outs).await;
            }
        }
    }

    /// Applies one batch of session outputs.
    async fn route_outs(&mut self, outs: Vec<Out>) {
        let mut to_close = Vec::new();
        for out in outs {
            match out {
                Out::Deliver { id, event } => self.deliver(&id, event, &mut to_close),
                Out::Eose(id) => self.send_eose(&id),
                Out::Closed { id, reason } => {
                    self.on_count_closed(&id, &reason);
                    self.end_sub(&id, CloseReason::Relay(reason));
                }
                Out::PublishDone {
                    id,
                    accepted,
                    message,
                } => self.on_publish_done(id, accepted, &message).await,
                Out::Rejected { id, reason } => {
                    debug!("rejected event for {id}: {reason:?}");
                }
                Out::AuthChallenge(c) => self.challenge = Some((c, false)),
                Out::AuthRequired { retry, fallback } => {
                    self.on_auth_required(retry, *fallback);
                }
                Out::Counted { id, result } => self.on_counted(&id, result),
                Out::NegErr { id, reason } => self.on_neg_closed(&id, &reason),
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
                    sock.close().await;
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
            Some(Cmd::Count { filters, reply }) => {
                self.on_count(filters, reply).await;
                true
            }
            Some(Cmd::AuthDone { event, challenge }) => {
                self.on_auth_done(event, challenge).await;
                true
            }
            Some(Cmd::Reconcile {
                filter,
                items,
                reply,
            }) => {
                self.on_reconcile(filter, items, reply).await;
                true
            }
            Some(Cmd::NegTimeout { id }) => {
                self.on_neg_timeout(id).await;
                true
            }
            Some(Cmd::Close(reply)) => {
                self.on_close(reply).await;
                false
            }
        }
    }

    /// One resolved read: liveness evidence first, then route or drop.
    async fn on_wire(&mut self, frame: Option<Result<Option<Inbound>>>) {
        if frame.is_some() {
            self.pong_deadline = None;
        }
        match frame {
            Some(Ok(Some(Inbound::Text(t)))) => self.on_frame(&t).await,
            Some(Ok(Some(_))) => {}
            Some(Ok(None)) | None => self.disconnect(),
            Some(Err(e)) => {
                debug!("ws error: {e}");
                self.disconnect();
            }
        }
    }

    /// An `auth-required:` refusal: queue `retry` behind the in-flight
    /// AUTH or kick one off through `Cmd::AuthNeeded` (signing happens
    /// off the select loop).
    fn on_auth_required(&mut self, retry: Retry, fallback: Out) {
        let Some(signer) = self.options.signer.clone() else {
            self.route_fallback(fallback);
            return;
        };
        let Some((challenge, answered)) = self.challenge.clone() else {
            self.route_fallback(fallback);
            return;
        };
        let _ = answered;
        if let Some(waiting) = self.auth_pending.as_mut() {
            waiting.push((retry, fallback));
            return;
        }
        self.auth_pending = Some(vec![(retry, fallback)]);
        // Sign the AUTH event off the select loop; it reports via Cmd::AuthDone.
        let tx = self.cmd.clone();
        let url = self.url_string.clone();
        tokio::spawn(async move {
            let event = async {
                let pk = signer
                    .public_key()
                    .await
                    .map_err(|e| Error::Transport(TransportError::new(e)))?;
                let unsigned = EventBuilder::auth(
                    &nk_core::RelayUrl::parse(&url).map_err(|_| Error::InvalidUrl)?,
                    &challenge,
                )
                .build(pk);
                signer
                    .sign_event(unsigned)
                    .await
                    .map_err(|e| Error::Transport(TransportError::new(e)))
            }
            .await;
            drop(tx.send(Cmd::AuthDone { event, challenge }).await);
        });
    }

    /// Resends the pending `EVENT` after a good `AUTH`.
    async fn retry_publish(&mut self, id: EventId) {
        let Some(event) = self.pending_events.get(&id).cloned() else {
            return;
        };
        self.session.readd_pending(id);
        drop(
            self.write(ClientMessage::Event(Cow::Borrowed(&event)))
                .await,
        );
    }

    /// `Cmd::AuthDone` — send the signed `AUTH` and wait for its `OK`, or
    /// route the original reasons when signing failed.
    async fn on_auth_done(&mut self, event: Result<Event>, challenge: String) {
        // Mark this challenge answered only when we have an event to send.
        if let Some((c, answered)) = self.challenge.as_mut()
            && *c == challenge
        {
            *answered = true;
        }
        let Ok(event) = event else {
            self.fail_auth_queue();
            return;
        };
        self.auth_ok_id = Some(event.id());
        let _ = self.session.add_pending(event.id());
        drop(self.write(ClientMessage::Auth(Cow::Borrowed(&event))).await);
    }

    /// Routes every queued `(retry, fallback)` to the fallback path.
    fn fail_auth_queue(&mut self) {
        self.auth_ok_id = None;
        let Some(waiting) = self.auth_pending.take() else {
            return;
        };
        for (_, fallback) in waiting {
            self.route_fallback(fallback);
        }
    }

    /// An `OK` for the in-flight `AUTH` event: retry or surface.
    async fn on_auth_ok(&mut self, accepted: bool) {
        self.auth_ok_id = None;
        let Some(waiting) = self.auth_pending.take() else {
            return;
        };
        if !accepted {
            for (_, fallback) in waiting {
                self.route_fallback(fallback);
            }
            return;
        }
        for (retry, _) in waiting {
            match retry {
                Retry::Req { id, filters } => {
                    self.session.add_sub(id.clone(), filters.clone());
                    drop(self.req(&id, &filters).await);
                }
                Retry::Publish(id) => self.retry_publish(id).await,
                Retry::Count { id, filters } => {
                    let _ = self.session.add_count(id.clone(), filters.clone());
                    drop(self.count(&id, &filters).await);
                }
                Retry::Neg { id, filter, items } => self.retry_neg(id, filter, items).await,
            }
        }
    }

    /// Surfaces the original refusal output when AUTH can't run.
    fn route_fallback(&mut self, fallback: Out) {
        match fallback {
            Out::Closed { id, reason } => self.end_sub(&id, CloseReason::Relay(reason)),
            Out::PublishDone {
                id,
                accepted,
                message,
            } => self.resolve_publish(id, accepted, &message),
            Out::NegErr { id, reason } => {
                if let Some(entry) = self.negs.remove(&id) {
                    drop(entry.reply.send(Err(Error::Refused(reason))));
                }
            }
            other => debug!("unhandled auth fallback: {other:?}"),
        }
    }

    /// One `OK`: the in-flight `AUTH` verdict, else a publish reply.
    async fn on_publish_done(&mut self, id: EventId, accepted: bool, message: &str) {
        if self.auth_ok_id == Some(id) {
            self.on_auth_ok(accepted).await;
        } else {
            self.resolve_publish(id, accepted, message);
        }
    }

    /// A NIP-45 reply → its waiter.
    fn on_counted(&mut self, id: &SubscriptionId, result: nk_core::CountResult) {
        if let Some(tx) = self.counts.remove(id) {
            drop(tx.send(Ok(result)));
        }
    }

    /// A `CLOSED` on a count id → its waiter with the relay's reason.
    fn on_count_closed(&mut self, id: &SubscriptionId, reason: &str) {
        if let Some(tx) = self.counts.remove(id) {
            drop(tx.send(Err(Error::Refused(reason.to_owned()))));
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

pub(crate) async fn driver_loop(
    mut rx: mpsc::Receiver<Cmd>,
    drops: mpsc::UnboundedReceiver<SubscriptionId>,
    drop_tx: mpsc::UnboundedSender<SubscriptionId>,
    cmd_tx: mpsc::Sender<Cmd>,
    url: String,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
) {
    let mut d = Driver {
        session: Session::default(),
        drops,
        drop_tx,
        subs: HashMap::new(),
        publishes: HashMap::new(),
        pending_events: HashMap::new(),
        ws: None,
        cmd: cmd_tx,
        url: Endpoint::parse(&url).ok(),
        url_string: url,
        options: options.clone(),
        status,
        backoff: options.reconnect_min,
        challenge: None,
        auth_ok_id: None,
        counts: HashMap::new(),
        negs: HashMap::new(),
        auth_pending: None,
        reconnect_at: None,
        pong_deadline: None,
        next_sub: 0,
    };
    let mut ping = tokio::time::interval(d.options.ping_interval);
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                if !d.dispatch(cmd).await {
                    return;
                }
            }
            frame = async {
                match d.ws.as_mut() {
                    Some(sock) => Some(sock.next().await),
                    None => None,
                }
            }, if d.ws.is_some() => {
                d.on_wire(frame).await;
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
                let Some(sock) = d.ws.as_mut() else {
                    continue;
                };
                match sock.ping().await {
                    Ok(()) => {
                        // Arm once per unanswered ping — re-arming on every
                        // tick would keep the deadline just out of reach.
                        if d.pong_deadline.is_none() {
                            d.pong_deadline = Some(
                                tokio::time::Instant::now() + d.options.pong_deadline,
                            );
                        }
                    }
                    Err(e) => {
                        debug!("ping failed: {e}");
                        d.disconnect();
                    }
                }
            }
            () = async {
                match d.pong_deadline {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            }, if d.pong_deadline.is_some() && d.ws.is_some() => {
                debug!("pong deadline expired");
                d.disconnect();
            }
            drop_id = d.drops.recv() => {
                if let Some(id) = drop_id {
                    d.on_close_sub(id).await;
                }
            }
        }
    }
}
