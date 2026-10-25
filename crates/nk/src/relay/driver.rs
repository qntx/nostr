//! The driver task: owns the socket (through [`Connection`]), the waiter
//! tables, the deadline queue, and the select loop. Protocol decisions
//! live in [`Session`]; this module routes its [`Out`]s.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nk_core::{ClientMessage, CountResult, Event, EventId, Filter, RelayUrl, SubscriptionId};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::time::{DelayQueue, delay_queue};
use tracing::debug;

use super::connection::Connection;
use super::neg::Reconciliation;
use super::session::{Out, Session};
use super::subscription::{CloseReason, Subscription, SubscriptionEvent, channel_pair};
use super::transport::{Endpoint, Inbound};
use super::{
    Cmd, Error, FetchEnd, FetchOutcome, PublishOutcome, RelayOptions, RelayStatus, Result,
};

/// A request's one-shot deadline in the [`DelayQueue`].
#[derive(Debug)]
enum Deadline {
    /// A subscription-id-keyed request (fetch/count/reconcile).
    Request(SubscriptionId),
    /// A pending publish's `OK` deadline.
    Publish(EventId),
}

/// One live request's driver-side reply channel.
enum Waiter {
    /// A subscription's event channel.
    Stream(SubHandles),
    /// A fetch accumulating events in place.
    Fetch {
        /// Events collected so far.
        events: Vec<Event>,
        /// The caller's reply.
        reply: oneshot::Sender<Result<FetchOutcome>>,
        /// The deadline-queue entry.
        deadline: delay_queue::Key,
    },
    /// A `COUNT` awaiting `Counted`.
    Count {
        /// The caller's reply.
        reply: oneshot::Sender<Result<CountResult>>,
        /// The deadline-queue entry.
        deadline: delay_queue::Key,
    },
    /// A reconcile awaiting `Reconciled`.
    Reconcile {
        /// The caller's reply.
        reply: oneshot::Sender<Result<Reconciliation>>,
        /// The deadline-queue entry.
        deadline: delay_queue::Key,
    },
}

impl Waiter {
    /// Terminates this waiter with `error`; a stream ends with its
    /// terminal mark instead.
    fn fail(self, error: Error) {
        match self {
            Self::Stream(h) => Driver::mark_terminal(h, CloseReason::RelayClosed),
            Self::Fetch { reply, .. } => drop(reply.send(Err(error))),
            Self::Count { reply, .. } => drop(reply.send(Err(error))),
            Self::Reconcile { reply, .. } => drop(reply.send(Err(error))),
        }
    }
}

/// A pending publish's reply fan-out.
struct PublishWaiter {
    /// Everyone who joined this publish.
    replies: Vec<oneshot::Sender<Result<PublishOutcome>>>,
    /// The deadline-queue entry.
    deadline: delay_queue::Key,
}

/// What a finished signing task yields.
type SignResult = (String, Result<Event, nk_core::SignerError>);

/// Per-subscription channel handles.
struct SubHandles {
    tx: mpsc::Sender<SubscriptionEvent>,
    /// Shared terminal slot; `Subscription`'s stream reads it after the
    /// channel ends.
    terminal: Arc<std::sync::Mutex<Option<CloseReason>>>,
}

/// Shared driver state threaded through the per-command handlers.
struct Driver {
    session: Session,
    conn: Connection,
    waiters: HashMap<SubscriptionId, Waiter>,
    publishes: HashMap<EventId, PublishWaiter>,
    /// One queue for every request/publish deadline.
    deadlines: DelayQueue<Deadline>,
    /// Off-loop AUTH signing; results arrive through the select loop.
    signing: JoinSet<SignResult>,
    /// Drop-side `CLOSE` requests — unbounded, always delivered.
    drops: mpsc::UnboundedReceiver<SubscriptionId>,
    /// Sender side — handed to each new [`Subscription`].
    drop_tx: mpsc::UnboundedSender<SubscriptionId>,
    /// The relay url — `EventBuilder::auth` takes it unchanged.
    relay_url: RelayUrl,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
    next_sub: u64,
}

impl Driver {
    /// The single disconnect path: drop the socket, fail every one-shot
    /// waiter, and let [`Connection`] arm the backoff.
    fn disconnect(&mut self) {
        self.conn.disconnect();
        self.status.send_replace(RelayStatus::Disconnected);
        let lost = self.session.disconnected();
        for id in lost.requests {
            self.fail_waiter(&id, Error::Disconnected);
        }
        for id in lost.publishes {
            self.fail_publish(&id);
        }
    }

    /// Connects when the socket is down; replays open `REQ`s on success.
    /// A replay write failure is a disconnect, surfaced to the caller.
    async fn ensure_connected(&mut self) -> Result<()> {
        if self.conn.is_open() {
            return Ok(());
        }
        self.status.send_replace(RelayStatus::Connecting);
        match self.conn.connect().await {
            Ok(()) => {
                self.status.send_replace(RelayStatus::Connected);
                self.replay().await
            }
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// Writes one message; a failure is a disconnect.
    async fn write(&mut self, msg: &ClientMessage<'_>) {
        if let Err(e) = self.conn.send(msg).await {
            debug!("send failed: {e}");
            self.disconnect();
        }
    }

    /// Allocates the next subscription id from the per-relay counter.
    fn alloc_sub_id(&mut self) -> SubscriptionId {
        self.next_sub = self.next_sub.wrapping_add(1);
        SubscriptionId::from(self.next_sub)
    }

    /// Arms a request deadline; returns its queue key.
    fn arm(&mut self, id: SubscriptionId, dur: Duration) -> delay_queue::Key {
        self.deadlines
            .insert_at(Deadline::Request(id), tokio::time::Instant::now() + dur)
    }

    /// Arms a publish deadline; returns its queue key.
    fn arm_publish(&mut self, id: EventId, dur: Duration) -> delay_queue::Key {
        self.deadlines
            .insert_at(Deadline::Publish(id), tokio::time::Instant::now() + dur)
    }

    /// Removes the waiter for `id`, dropping its queue entry.
    fn take_waiter(&mut self, id: &SubscriptionId) -> Option<Waiter> {
        let w = self.waiters.remove(id)?;
        match &w {
            Waiter::Fetch { deadline, .. }
            | Waiter::Count { deadline, .. }
            | Waiter::Reconcile { deadline, .. } => {
                drop(self.deadlines.try_remove(deadline));
            }
            Waiter::Stream(_) => {}
        }
        Some(w)
    }

    /// Removes the publish waiter for `id`, dropping its queue entry.
    fn take_publish(&mut self, id: &EventId) -> Option<PublishWaiter> {
        let w = self.publishes.remove(id)?;
        drop(self.deadlines.try_remove(&w.deadline));
        Some(w)
    }

    /// Fails a request waiter with `error` and drops its deadline.
    fn fail_waiter(&mut self, id: &SubscriptionId, error: Error) {
        if let Some(w) = self.take_waiter(id) {
            w.fail(error);
        }
    }

    /// Fails a publish's waiters with `Disconnected` (the only caller
    /// path) and drops its deadline.
    fn fail_publish(&mut self, id: &EventId) {
        if let Some(w) = self.take_publish(id) {
            for reply in w.replies {
                drop(reply.send(Err(Error::Disconnected)));
            }
        }
    }

    /// Ends a stream waiter with the terminal mark, dropping its sender.
    fn mark_terminal(h: SubHandles, reason: CloseReason) {
        if let Ok(mut t) = h.terminal.lock() {
            *t = Some(reason);
        }
        drop(h.tx);
    }

    /// `Cmd::Connect` — handshake now, report the real error.
    async fn on_connect(&mut self, reply: oneshot::Sender<Result<()>>) {
        drop(reply.send(self.ensure_connected().await));
    }

    /// `Cmd::Subscribe` — registers the sub; with reconnect enabled a dead
    /// socket just means the `REQ` replays later.
    async fn on_subscribe(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<Subscription>>,
    ) {
        let id = self.alloc_sub_id();
        let msg = self.session.open_sub(&id, filters);
        let was_connected = self.conn.is_open();
        if let Err(e) = self.ensure_connected().await
            && !self.options.reconnect
        {
            drop(self.session.close(&id));
            drop(reply.send(Err(e)));
            return;
        }
        let (sub, tx, terminal) = channel_pair(
            id.clone(),
            self.drop_tx.clone(),
            self.options.subscription_capacity,
        );
        self.waiters
            .insert(id, Waiter::Stream(SubHandles { tx, terminal }));
        if was_connected {
            self.write(&msg).await;
        }
        drop(reply.send(Ok(sub)));
    }

    /// `Cmd::Fetch` — a one-shot bounded read; fails fast when the socket
    /// can't connect.
    async fn on_fetch(
        &mut self,
        filters: Vec<Filter>,
        timeout: Duration,
        reply: oneshot::Sender<Result<FetchOutcome>>,
    ) {
        if let Err(e) = self.ensure_connected().await {
            drop(reply.send(Err(e)));
            return;
        }
        let id = self.alloc_sub_id();
        let msg = self.session.open_fetch(&id, filters);
        let deadline = self.arm(id.clone(), timeout);
        self.waiters.insert(
            id,
            Waiter::Fetch {
                events: Vec::new(),
                reply,
                deadline,
            },
        );
        self.write(&msg).await;
    }

    /// `Cmd::Publish` — fails fast when the socket can't connect; a join
    /// on an in-flight id shares the same deadline.
    async fn on_publish(&mut self, event: Event, reply: oneshot::Sender<Result<PublishOutcome>>) {
        if let Err(e) = self.ensure_connected().await {
            drop(reply.send(Err(e)));
            return;
        }
        let Some(msg) = self.session.publish(event.clone()) else {
            // Join the in-flight publish — same waiters, same deadline.
            if let Some(w) = self.publishes.get_mut(&event.id()) {
                w.replies.push(reply);
            }
            return;
        };
        let deadline = self.arm_publish(event.id(), self.options.request_timeout);
        self.publishes.insert(
            event.id(),
            PublishWaiter {
                replies: vec![reply],
                deadline,
            },
        );
        self.write(&msg).await;
    }

    /// `Cmd::Count` — one `COUNT`, one waiter, `request_timeout` deadline.
    async fn on_count(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<CountResult>>,
    ) {
        if let Err(e) = self.ensure_connected().await {
            drop(reply.send(Err(e)));
            return;
        }
        let id = self.alloc_sub_id();
        let msg = self.session.open_count(&id, filters);
        let deadline = self.arm(id.clone(), self.options.request_timeout);
        self.waiters.insert(id, Waiter::Count { reply, deadline });
        self.write(&msg).await;
    }

    /// `Cmd::Reconcile` — a NIP-77 sync; `request_timeout` deadline.
    async fn on_reconcile(
        &mut self,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
        reply: oneshot::Sender<Result<Reconciliation>>,
    ) {
        if let Err(e) = self.ensure_connected().await {
            drop(reply.send(Err(e)));
            return;
        }
        let id = self.alloc_sub_id();
        let msg = match self.session.open_neg(id.clone(), filter, items) {
            Ok(m) => m,
            Err(e) => {
                drop(reply.send(Err(e)));
                return;
            }
        };
        let deadline = self.arm(id.clone(), self.options.request_timeout);
        self.waiters
            .insert(id, Waiter::Reconcile { reply, deadline });
        self.write(&msg).await;
    }

    /// `Cmd::Close` — terminal: streams end `Closed(RelayClosed)` and the
    /// socket closes. Returns `false` so the loop exits.
    async fn on_close(&mut self, reply: oneshot::Sender<()>) {
        self.shutdown().await;
        if reply.send(()).is_err() {
            debug!("close reply receiver dropped");
        }
    }

    /// The shared teardown: terminal marks, socket close, status.
    async fn shutdown(&mut self) {
        self.status.send_replace(RelayStatus::Closed);
        self.deadlines.clear();
        for (_, w) in self.waiters.drain() {
            w.fail(Error::Closed);
        }
        for (_, w) in self.publishes.drain() {
            for reply in w.replies {
                drop(reply.send(Err(Error::Closed)));
            }
        }
        self.conn.close().await;
    }

    /// A dropped `Subscription` — remove the waiter and send `CLOSE`.
    async fn on_drop(&mut self, id: SubscriptionId) {
        self.waiters.remove(&id);
        if let Some(msg) = self.session.close(&id) {
            self.write(&msg).await;
        }
    }

    /// One resolved read: liveness evidence first, then route.
    async fn on_wire(&mut self, frame: Result<Option<Inbound>>) {
        match frame {
            Ok(Some(Inbound::Text(text))) => {
                self.conn.saw_inbound();
                let Ok(msg) = nk_core::RelayMessage::from_json(&text) else {
                    return;
                };
                let outs = self.session.handle(msg);
                self.route_outs(outs).await;
            }
            Ok(Some(_)) => self.conn.saw_inbound(),
            Ok(None) => self.disconnect(),
            Err(e) => {
                debug!("read failed: {e}");
                self.disconnect();
            }
        }
    }

    /// A fired deadline: close the session entry, surface `Timeout`.
    async fn on_deadline(&mut self, expired: delay_queue::Expired<Deadline>) {
        match expired.into_inner() {
            Deadline::Publish(id) => {
                self.session.forget_publish(&id);
                self.publish_deadline(&id);
            }
            Deadline::Request(id) => {
                // The deadline already fired — the queue entry is gone;
                // remove the waiter map entry only.
                if let Some(msg) = self.session.close(&id) {
                    self.write(&msg).await;
                }
                match self.waiters.remove(&id) {
                    Some(Waiter::Fetch { events, reply, .. }) => {
                        drop(reply.send(Ok(FetchOutcome {
                            events,
                            end: FetchEnd::Timeout,
                        })));
                    }
                    Some(w) => w.fail(Error::Timeout),
                    None => {}
                }
            }
        }
    }

    /// A finished signing task — `signed` routes the AUTH or re-signs.
    async fn on_signed(&mut self, result: SignResult) {
        let (challenge, event) = result;
        match event {
            Ok(event) => {
                let outs = self.session.signed(&challenge, event);
                self.route_outs(outs).await;
            }
            Err(e) => {
                debug!("signer failed: {e}");
                let outs = self.session.sign_failed();
                self.route_outs(outs).await;
            }
        }
    }

    /// Applies one batch of session outputs.
    async fn route_outs(&mut self, outs: Vec<Out>) {
        let mut to_write = Vec::new();
        for out in outs {
            match out {
                Out::Send(msg) => to_write.push(msg),
                Out::Sign(challenge) => self.spawn_sign(challenge),
                Out::Event { id, event } => self.deliver(&id, event, &mut to_write),
                Out::Eose(id) => self.on_eose(&id, &mut to_write),
                Out::Closed { id, reason } => self.on_closed_waiter(&id, reason),
                Out::Counted { id, result } => self.resolve_count(&id, result),
                Out::Reconciled { id, result } => self.resolve_reconcile(&id, result),
                Out::Failed { id, error } => self.fail_waiter(&id, error),
                Out::Published {
                    id,
                    accepted,
                    message,
                } => self.resolve_publish(id, accepted, &message),
                Out::Rejected { id, reason } => {
                    debug!("rejected event for {id}: {reason:?}");
                }
                Out::Notice(m) => debug!("relay notice: {m}"),
            }
        }
        for msg in to_write {
            self.write(&msg).await;
        }
    }

    /// Spawns the off-loop signer for one challenge; the `JoinSet` result
    /// lands back on the select loop.
    fn spawn_sign(&mut self, challenge: String) {
        let Some(signer) = self.options.signer.clone() else {
            return;
        };
        let url = self.relay_url.clone();
        let ch = challenge.clone();
        self.signing.spawn(async move {
            let event = async {
                let pk = signer.public_key().await?;
                let unsigned = nk_core::EventBuilder::auth(&url, &ch).build(pk);
                signer.sign_event(unsigned).await
            }
            .await;
            (challenge, event)
        });
    }

    /// Delivers an event to its waiter; a lagged stream ends `Lagged`.
    fn deliver(
        &mut self,
        id: &SubscriptionId,
        event: Event,
        to_write: &mut Vec<ClientMessage<'static>>,
    ) {
        match self.waiters.get_mut(id) {
            Some(Waiter::Fetch { events, .. }) => {
                events.push(event);
            }
            Some(Waiter::Stream(h)) if h.tx.try_send(SubscriptionEvent::Event(event)).is_err() => {
                self.end_stream(id, CloseReason::Lagged, to_write);
            }
            _ => {}
        }
    }

    /// Replays every open `REQ` after a connect; a write failure is a
    /// disconnect surfaced to the caller.
    async fn replay(&mut self) -> Result<()> {
        for msg in self.session.replay() {
            if let Err(e) = self.conn.send(&msg).await {
                self.disconnect();
                return Err(e);
            }
        }
        Ok(())
    }

    /// A fired publish deadline — `Timeout` to every waiter that joined.
    fn publish_deadline(&mut self, id: &EventId) {
        if let Some(w) = self.publishes.remove(id) {
            for reply in w.replies {
                drop(reply.send(Err(Error::Timeout)));
            }
        }
    }

    /// A `Counted` reply → its waiter, dropping the deadline.
    fn resolve_count(&mut self, id: &SubscriptionId, result: CountResult) {
        if let Some(Waiter::Count { reply, .. }) = self.take_waiter(id) {
            drop(reply.send(Ok(result)));
        }
    }

    /// A `Reconciled` reply → its waiter, dropping the deadline.
    fn resolve_reconcile(&mut self, id: &SubscriptionId, result: Reconciliation) {
        if let Some(Waiter::Reconcile { reply, .. }) = self.take_waiter(id) {
            drop(reply.send(Ok(result)));
        }
    }

    /// Ends a stream waiter and queues its `CLOSE`.
    fn end_stream(
        &mut self,
        id: &SubscriptionId,
        reason: CloseReason,
        to_write: &mut Vec<ClientMessage<'static>>,
    ) {
        if let Some(Waiter::Stream(h)) = self.waiters.remove(id) {
            Self::mark_terminal(h, reason);
        }
        if let Some(msg) = self.session.close(id) {
            to_write.push(msg);
        }
    }

    /// `EOSE`: a fetch resolves `Eose`; a stream gets the item — a full
    /// channel ends it `Lagged` like a dropped event.
    fn on_eose(&mut self, id: &SubscriptionId, to_write: &mut Vec<ClientMessage<'static>>) {
        if let Some(Waiter::Stream(h)) = self.waiters.get_mut(id)
            && h.tx.try_send(SubscriptionEvent::Eose).is_err()
        {
            self.end_stream(id, CloseReason::Lagged, to_write);
            return;
        }
        // Only a fetch resolves here — a stream stays open.
        if matches!(self.waiters.get(id), Some(Waiter::Fetch { .. }))
            && let Some(Waiter::Fetch { events, reply, .. }) = self.take_waiter(id)
        {
            drop(reply.send(Ok(FetchOutcome {
                events,
                end: FetchEnd::Eose,
            })));
        }
    }

    /// A terminal `Closed` for `id`: maps to the right waiter output.
    fn on_closed_waiter(&mut self, id: &SubscriptionId, reason: String) {
        match self.take_waiter(id) {
            Some(Waiter::Stream(h)) => Self::mark_terminal(h, CloseReason::Relay(reason)),
            Some(Waiter::Fetch { events, reply, .. }) => {
                drop(reply.send(Ok(FetchOutcome {
                    events,
                    end: FetchEnd::Closed(reason),
                })));
            }
            Some(w) => w.fail(Error::Refused(reason)),
            None => {}
        }
    }

    /// Fans one `OK` out to every waiter that joined the publish.
    fn resolve_publish(&mut self, id: EventId, accepted: bool, message: &str) {
        let Some(w) = self.take_publish(&id) else {
            return;
        };
        for reply in w.replies {
            drop(reply.send(Ok(PublishOutcome {
                accepted,
                message: message.to_owned(),
            })));
        }
    }

    /// One command off the channel; `false` means the driver exits.
    async fn dispatch(&mut self, cmd: Option<Cmd>) -> bool {
        match cmd {
            // The last `Relay` dropped — the channel closed on its own.
            None => {
                self.shutdown().await;
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
            Some(Cmd::Fetch {
                filters,
                timeout,
                reply,
            }) => {
                self.on_fetch(filters, timeout, reply).await;
                true
            }
            Some(Cmd::Publish { event, reply }) => {
                self.on_publish(event, reply).await;
                true
            }
            Some(Cmd::Count { filters, reply }) => {
                self.on_count(filters, reply).await;
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
            Some(Cmd::Close(reply)) => {
                self.on_close(reply).await;
                false
            }
        }
    }

    /// The reconnect deadline fired — connect and replay, or stay down.
    async fn on_reconnect_due(&mut self) {
        if let Err(e) = self.ensure_connected().await {
            debug!("reconnect failed: {e}");
        }
    }

    /// The ping interval fired — a write failure is a dead socket.
    async fn on_ping_tick(&mut self) {
        if let Err(e) = self.conn.ping().await {
            debug!("ping failed: {e}");
            self.disconnect();
        }
    }

    /// One select iteration; `false` means the driver exits.
    #[allow(
        clippy::cognitive_complexity,
        reason = "select! arms are independent handlers"
    )]
    async fn step(
        &mut self,
        rx: &mut mpsc::Receiver<Cmd>,
        ping: &mut tokio::time::Interval,
    ) -> bool {
        let open = self.conn.is_open();
        let reconnect_at = self.conn.reconnect_at();
        let pong_due = self.conn.pong_deadline();
        tokio::select! {
            cmd = rx.recv() => {
                return self.dispatch(cmd).await;
            }
            frame = async {
                if open { self.conn.next().await } else { Ok(None) }
            }, if open => {
                self.on_wire(frame).await;
            }
            Some(expired) = futures_util::StreamExt::next(&mut self.deadlines), if !self.deadlines.is_empty() => {
                self.on_deadline(expired).await;
            }
            signed = self.signing.join_next(), if !self.signing.is_empty() => {
                match signed {
                    Some(Ok(result)) => self.on_signed(result).await,
                    // A panicking signer or an aborted task: fail the queue.
                    Some(Err(e)) => {
                        debug!("sign task failed: {e}");
                        let outs = self.session.sign_failed();
                        self.route_outs(outs).await;
                    }
                    None => {}
                }
            }
            () = async {
                match reconnect_at {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            }, if self.options.reconnect && !open && reconnect_at.is_some() => {
                self.on_reconnect_due().await;
            }
            _ = ping.tick(), if open => {
                self.on_ping_tick().await;
            }
            () = async {
                match pong_due {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            }, if pong_due.is_some() && open => {
                debug!("pong deadline expired");
                self.disconnect();
            }
            Some(id) = self.drops.recv() => {
                self.on_drop(id).await;
            }
        }
        true
    }
}

/// The driver task.
pub(crate) async fn driver_loop(
    mut rx: mpsc::Receiver<Cmd>,
    drops: mpsc::UnboundedReceiver<SubscriptionId>,
    drop_tx: mpsc::UnboundedSender<SubscriptionId>,
    relay_url: RelayUrl,
    options: RelayOptions,
    status: watch::Sender<RelayStatus>,
) {
    // An unparseable URL yields `Error::InvalidUrl` from `connect` —
    // permanent, never retried. (`RelayUrl` can't produce one from tests.)
    let endpoint = Endpoint::parse(relay_url.as_str()).ok();
    let mut d = Driver {
        session: Session::new(options.signer.is_some()),
        conn: Connection::new(endpoint, &options),
        waiters: HashMap::new(),
        publishes: HashMap::new(),
        deadlines: DelayQueue::new(),
        signing: JoinSet::new(),
        drops,
        drop_tx,
        relay_url,
        options,
        status,
        next_sub: 0,
    };
    let mut ping = tokio::time::interval(d.options.ping_interval);
    while d.step(&mut rx, &mut ping).await {}
}
