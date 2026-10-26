//! The driver task: owns the socket (through [`Connection`]), the waiter
//! tables, the deadline queue, and the select loop. Protocol decisions
//! live in [`Session`]; this module drains its [`Out`] queue.

use std::collections::HashMap;
use std::time::Duration;

use nk_core::{ClientMessage, CountResult, Event, EventId, Filter, RelayUrl, SubscriptionId};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue};
use tracing::debug;

use super::connection::{Connection, Timer};
use super::neg::Reconciliation;
use super::session::{Out, Session};
use super::subscription::{CloseReason, SubHandles, Subscription, SubscriptionEvent, channel_pair};
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
    },
    /// A `COUNT` awaiting `Counted`.
    Count(oneshot::Sender<Result<CountResult>>),
    /// A reconcile awaiting `Reconciled`.
    Reconcile(oneshot::Sender<Result<Reconciliation>>),
}

impl Waiter {
    /// Terminates this waiter with `error`; a stream ends with its
    /// terminal reason instead.
    fn fail(self, error: Error) {
        match self {
            Self::Stream(h) => h.end(CloseReason::RelayClosed),
            Self::Fetch { reply, .. } => drop(reply.send(Err(error))),
            Self::Count(reply) => drop(reply.send(Err(error))),
            Self::Reconcile(reply) => drop(reply.send(Err(error))),
        }
    }
}

/// One waiter-table row: the reply channel plus its deadline-queue key.
struct Entry {
    waiter: Waiter,
    /// The armed request deadline, if this one-shot has one.
    deadline: Option<delay_queue::Key>,
}

/// A pending publish's reply fan-out.
struct PublishWaiter {
    /// Everyone who joined this publish.
    replies: Vec<oneshot::Sender<Result<PublishOutcome>>>,
    /// The deadline-queue entry.
    deadline: delay_queue::Key,
}

impl PublishWaiter {
    /// Resolves every joiner with `result()` — `Error` is not `Clone`,
    /// so each reply builds its own.
    fn finish(self, result: impl Fn() -> Result<PublishOutcome>) {
        for reply in self.replies {
            drop(reply.send(result()));
        }
    }
}

/// What a finished signing task yields.
type SignResult = (String, Result<Event, nk_core::SignerError>);

/// Shared driver state threaded through the per-command handlers.
struct Driver {
    session: Session,
    conn: Connection,
    entries: HashMap<SubscriptionId, Entry>,
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
            if let Some(w) = self.take_publish(&id) {
                w.finish(|| Err(Error::Disconnected));
            }
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

    /// Connects for a one-shot caller; on failure the error is sent and
    /// `None` returned — `None` means the command is answered.
    async fn connected<T>(
        &mut self,
        reply: oneshot::Sender<Result<T>>,
    ) -> Option<oneshot::Sender<Result<T>>> {
        match self.ensure_connected().await {
            Ok(()) => Some(reply),
            Err(e) => {
                drop(reply.send(Err(e)));
                None
            }
        }
    }

    /// Writes one message; a no-op while the socket is down (live subs
    /// replay on reconnect, one-shots never exist while it is down), and
    /// a live-socket write failure is a disconnect.
    async fn write(&mut self, msg: &ClientMessage<'_>) {
        if !self.conn.is_open() {
            return;
        }
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
            .insert_at(Deadline::Request(id), Instant::now() + dur)
    }

    /// Arms a publish deadline; returns its queue key.
    fn arm_publish(&mut self, id: EventId, dur: Duration) -> delay_queue::Key {
        self.deadlines
            .insert_at(Deadline::Publish(id), Instant::now() + dur)
    }

    /// Removes `id`'s entry and cancels its live deadline, if any.
    fn take(&mut self, id: &SubscriptionId) -> Option<Entry> {
        let entry = self.entries.remove(id)?;
        if let Some(key) = &entry.deadline {
            drop(self.deadlines.try_remove(key));
        }
        Some(entry)
    }

    /// Removes the publish waiter for `id`, dropping its queue entry.
    fn take_publish(&mut self, id: &EventId) -> Option<PublishWaiter> {
        let w = self.publishes.remove(id)?;
        drop(self.deadlines.try_remove(&w.deadline));
        Some(w)
    }

    /// Fails a request waiter with `error` and drops its deadline.
    fn fail_waiter(&mut self, id: &SubscriptionId, error: Error) {
        if let Some(entry) = self.take(id) {
            entry.waiter.fail(error);
        }
    }

    /// `Cmd::Connect` — handshake now, report the real error.
    async fn on_connect(&mut self, reply: oneshot::Sender<Result<()>>) {
        drop(reply.send(self.ensure_connected().await));
    }

    /// `Cmd::Subscribe` — connects first, then opens, so a fresh
    /// connect's replay never duplicates the new `REQ`. With reconnect
    /// enabled a dead socket just means the `REQ` replays later.
    async fn on_subscribe(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<Subscription>>,
    ) {
        if let Err(e) = self.ensure_connected().await
            && !self.options.reconnect
        {
            drop(reply.send(Err(e)));
            return;
        }
        let id = self.alloc_sub_id();
        self.session.open_sub(&id, filters);
        let (sub, handles) = channel_pair(
            id.clone(),
            self.drop_tx.clone(),
            self.options.subscription_capacity,
        );
        self.entries.insert(
            id,
            Entry {
                waiter: Waiter::Stream(handles),
                deadline: None,
            },
        );
        self.flush().await;
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
        let Some(reply) = self.connected(reply).await else {
            return;
        };
        let id = self.alloc_sub_id();
        self.session.open_fetch(&id, filters);
        let deadline = self.arm(id.clone(), timeout);
        self.entries.insert(
            id,
            Entry {
                waiter: Waiter::Fetch {
                    events: Vec::new(),
                    reply,
                },
                deadline: Some(deadline),
            },
        );
        self.flush().await;
    }

    /// `Cmd::Publish` — fails fast when the socket can't connect; a join
    /// on an in-flight id shares the same deadline.
    async fn on_publish(&mut self, event: Event, reply: oneshot::Sender<Result<PublishOutcome>>) {
        let Some(reply) = self.connected(reply).await else {
            return;
        };
        if !self.session.publish(event.clone()) {
            // Join the in-flight publish — same waiters, same deadline.
            if let Some(w) = self.publishes.get_mut(&event.id()) {
                w.replies.push(reply);
            }
            return;
        }
        let deadline = self.arm_publish(event.id(), self.options.request_timeout);
        self.publishes.insert(
            event.id(),
            PublishWaiter {
                replies: vec![reply],
                deadline,
            },
        );
        self.flush().await;
    }

    /// `Cmd::Count` — one `COUNT`, one waiter, `request_timeout` deadline.
    async fn on_count(
        &mut self,
        filters: Vec<Filter>,
        reply: oneshot::Sender<Result<CountResult>>,
    ) {
        let Some(reply) = self.connected(reply).await else {
            return;
        };
        let id = self.alloc_sub_id();
        self.session.open_count(&id, filters);
        let deadline = self.arm(id.clone(), self.options.request_timeout);
        self.entries.insert(
            id,
            Entry {
                waiter: Waiter::Count(reply),
                deadline: Some(deadline),
            },
        );
        self.flush().await;
    }

    /// `Cmd::Reconcile` — a NIP-77 sync; `request_timeout` deadline.
    async fn on_reconcile(
        &mut self,
        filter: Filter,
        items: Vec<(nk_core::Timestamp, EventId)>,
        reply: oneshot::Sender<Result<Reconciliation>>,
    ) {
        let Some(reply) = self.connected(reply).await else {
            return;
        };
        let id = self.alloc_sub_id();
        if let Err(e) = self.session.open_neg(id.clone(), filter, items) {
            drop(reply.send(Err(e)));
            return;
        }
        let deadline = self.arm(id.clone(), self.options.request_timeout);
        self.entries.insert(
            id,
            Entry {
                waiter: Waiter::Reconcile(reply),
                deadline: Some(deadline),
            },
        );
        self.flush().await;
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
        for (_, entry) in self.entries.drain() {
            entry.waiter.fail(Error::Closed);
        }
        for (_, w) in self.publishes.drain() {
            w.finish(|| Err(Error::Closed));
        }
        self.conn.close().await;
    }

    /// A dropped `Subscription` — remove the waiter and send `CLOSE`.
    async fn on_drop(&mut self, id: SubscriptionId) {
        drop(self.take(&id));
        self.session.close(&id);
        self.flush().await;
    }

    /// One resolved read: liveness evidence first, then route.
    async fn on_wire(&mut self, frame: Result<Option<Inbound>>) {
        match frame {
            Ok(Some(Inbound::Text(text))) => {
                self.conn.saw_inbound();
                let Ok(msg) = nk_core::RelayMessage::from_json(&text) else {
                    return;
                };
                self.session.handle(msg);
                self.flush().await;
            }
            Ok(Some(Inbound::Control)) => self.conn.saw_inbound(),
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
                // The deadline already fired — an expired DelayQueue
                // key's slab slot can be reused by another entry, so
                // `try_remove` is forbidden on this path; remove the
                // waiter by map only.
                if let Some(w) = self.publishes.remove(&id) {
                    w.finish(|| Err(Error::Timeout));
                }
            }
            Deadline::Request(id) => {
                self.session.close(&id);
                self.flush().await;
                // Same expired-key rule as the publish path: map remove
                // only, never `try_remove`.
                match self.entries.remove(&id).map(|e| e.waiter) {
                    Some(Waiter::Fetch { events, reply }) => {
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

    /// A finished signing task — `signed` queues the AUTH or re-signs.
    async fn on_signed(&mut self, result: SignResult) {
        let (challenge, event) = result;
        match event {
            Ok(event) => self.session.signed(&challenge, event),
            Err(e) => {
                debug!("signer failed: {e}");
                self.session.sign_failed();
            }
        }
        self.flush().await;
    }

    /// Drains the session's output queue in order.
    async fn flush(&mut self) {
        while let Some(out) = self.session.poll_out() {
            match out {
                Out::Send(msg) => self.write(&msg).await,
                Out::Sign(challenge) => self.spawn_sign(challenge),
                Out::Event { id, event } => self.deliver(&id, event),
                Out::Eose(id) => self.on_eose(&id),
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
    fn deliver(&mut self, id: &SubscriptionId, event: Event) {
        let lagged = match self.entries.get_mut(id).map(|e| &mut e.waiter) {
            Some(Waiter::Fetch { events, .. }) => {
                events.push(event);
                false
            }
            Some(Waiter::Stream(h)) => h.tx.try_send(SubscriptionEvent::Event(event)).is_err(),
            _ => false,
        };
        if lagged {
            self.end_stream(id, CloseReason::Lagged);
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

    /// A `Counted` reply → its waiter, dropping the deadline.
    fn resolve_count(&mut self, id: &SubscriptionId, result: CountResult) {
        if let Some(entry) = self.take(id)
            && let Waiter::Count(reply) = entry.waiter
        {
            drop(reply.send(Ok(result)));
        }
    }

    /// A `Reconciled` reply → its waiter, dropping the deadline.
    fn resolve_reconcile(&mut self, id: &SubscriptionId, result: Reconciliation) {
        if let Some(entry) = self.take(id)
            && let Waiter::Reconcile(reply) = entry.waiter
        {
            drop(reply.send(Ok(result)));
        }
    }

    /// Ends a stream waiter; its `CLOSE` lands in the session's queue.
    fn end_stream(&mut self, id: &SubscriptionId, reason: CloseReason) {
        if let Some(entry) = self.take(id)
            && let Waiter::Stream(h) = entry.waiter
        {
            h.end(reason);
        }
        self.session.close(id);
    }

    /// `EOSE`: a fetch resolves `Eose`; a stream gets the item — a full
    /// channel ends it `Lagged` like a dropped event.
    fn on_eose(&mut self, id: &SubscriptionId) {
        if let Some(entry) = self.entries.get_mut(id)
            && let Waiter::Stream(h) = &mut entry.waiter
            && h.tx.try_send(SubscriptionEvent::Eose).is_err()
        {
            self.end_stream(id, CloseReason::Lagged);
            return;
        }
        // Only a fetch resolves here — a stream stays open.
        if matches!(
            self.entries.get(id).map(|e| &e.waiter),
            Some(Waiter::Fetch { .. })
        ) && let Some(entry) = self.take(id)
            && let Waiter::Fetch { events, reply } = entry.waiter
        {
            drop(reply.send(Ok(FetchOutcome {
                events,
                end: FetchEnd::Eose,
            })));
        }
    }

    /// A terminal `Closed` for `id`: maps to the right waiter output.
    fn on_closed_waiter(&mut self, id: &SubscriptionId, reason: String) {
        match self.take(id).map(|e| e.waiter) {
            Some(Waiter::Stream(h)) => h.end(CloseReason::Relay(reason)),
            Some(Waiter::Fetch { events, reply }) => {
                drop(reply.send(Ok(FetchOutcome {
                    events,
                    end: FetchEnd::Closed(reason),
                })));
            }
            Some(w) => w.fail(Error::Refused(reason)),
            None => {}
        }
    }

    /// A publish's `OK` resolved — fans out to every waiter that joined.
    fn resolve_publish(&mut self, id: EventId, accepted: bool, message: &str) {
        let Some(w) = self.take_publish(&id) else {
            return;
        };
        w.finish(|| {
            Ok(PublishOutcome {
                accepted,
                message: message.to_owned(),
            })
        });
    }

    /// The connection's armed timer fired.
    async fn on_timer(&mut self, timer: Timer) {
        match timer {
            Timer::Reconnect => {
                if let Err(e) = self.ensure_connected().await {
                    debug!("reconnect failed: {e}");
                }
            }
            Timer::Ping => {
                if let Err(e) = self.conn.ping().await {
                    debug!("ping failed: {e}");
                    self.disconnect();
                }
            }
            Timer::Pong => {
                debug!("pong deadline expired");
                self.disconnect();
            }
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

    /// One select iteration; `false` means the driver exits.
    #[allow(
        clippy::cognitive_complexity,
        reason = "select! arms are independent handlers"
    )]
    async fn step(&mut self, rx: &mut mpsc::Receiver<Cmd>) -> bool {
        let open = self.conn.is_open();
        let deadline = self.conn.deadline();
        tokio::select! {
            cmd = rx.recv() => {
                return self.dispatch(cmd).await;
            }
            frame = self.conn.next(), if open => {
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
                        self.session.sign_failed();
                        self.flush().await;
                    }
                    None => {}
                }
            }
            () = sleep_until(deadline.map(|(at, _)| at)) => {
                if let Some((_, timer)) = deadline {
                    self.on_timer(timer).await;
                }
            }
            Some(id) = self.drops.recv() => {
                self.on_drop(id).await;
            }
        }
        true
    }
}

/// Sleeps until `at`; pends forever when no timer is armed.
async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
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
        entries: HashMap::new(),
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
    while d.step(&mut rx).await {}
}
