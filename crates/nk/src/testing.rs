//! `test-util`: an in-process mock relay for integration tests.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, service::service_fn};
use hyper_util::rt::TokioIo;
use nk_core::{ClientMessage, Event, RelayUrl, SubscriptionId};
use nk_store::{EventStore, MemoryStore, PutOutcome};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;
use yawc::{Frame, OpCode, WebSocket};

/// One control message to the mock's writer task.
#[derive(Clone)]
enum Hook {
    /// Send a raw text frame verbatim.
    Raw(String),
    /// Close the socket (client sees a drop; it should reconnect).
    Drop,
    /// Stop reading the socket: the codec never sees the client's pings,
    /// so no pong is sent — the client's liveness deadline fires.
    Freeze,
}

/// The live connection: frames go out through `hook_rx`.
/// `EVENT` → store + `OK`, then live delivery to this conn's `REQ`s.
async fn on_event(
    ws: &mut yawc::HttpWebSocket,
    store: &MemoryStore,
    open: &[(SubscriptionId, Vec<nk_core::Filter>)],
    event: &Event,
) {
    let (saved, note) = match store.put(event) {
        Ok(PutOutcome::Duplicate) => (false, "duplicate:"),
        Ok(PutOutcome::Rejected) => (false, "rejected:"),
        Ok(_) => (true, ""),
        Err(_) => (false, "error:"),
    };
    let ok = format!(r#"["OK","{}",{},"{}"]"#, event.id().to_hex(), saved, note);
    drop(ws.send(Frame::text(ok)).await);
    if !saved {
        return;
    }
    for (id, filters) in open {
        if filters.iter().any(|f| f.matches(event)) {
            let frame = format!(r#"["EVENT","{}",{}]"#, id.as_str(), event.to_json());
            drop(ws.send(Frame::text(frame)).await);
        }
    }
}

/// `REQ` → stored matches + `EOSE`; the sub stays open for live events.
async fn on_req(
    ws: &mut yawc::HttpWebSocket,
    store: &MemoryStore,
    open: &mut Vec<(SubscriptionId, Vec<nk_core::Filter>)>,
    hold: &AtomicBool,
    id: &SubscriptionId,
    filters: &[nk_core::Filter],
) {
    // Held REQs are recorded but get no stored events and no EOSE — tests
    // drive the reply themselves through `send_raw`.
    if hold.load(Ordering::Relaxed) {
        return;
    }
    for ev in store.query(filters).unwrap_or_default() {
        let frame = format!(r#"["EVENT","{}",{}]"#, id.as_str(), ev.to_json());
        drop(ws.send(Frame::text(frame)).await);
    }
    let eose = format!(r#"["EOSE","{}"]"#, id.as_str());
    drop(ws.send(Frame::text(eose)).await);
    open.push((id.clone(), filters.to_vec()));
}

/// Routes one client text frame; `false` closes the connection.
async fn on_client_frame(
    ws: &mut yawc::HttpWebSocket,
    store: &MemoryStore,
    open: &mut Vec<(SubscriptionId, Vec<nk_core::Filter>)>,
    hold: &AtomicBool,
    text: &str,
) -> bool {
    let Ok(msg) = ClientMessage::from_json(text) else {
        return true;
    };
    match msg {
        ClientMessage::Event(event) => on_event(ws, store, open, &event).await,
        ClientMessage::Req {
            subscription_id,
            filters,
        } => on_req(ws, store, open, hold, &subscription_id, &filters).await,
        ClientMessage::Close(id) => {
            open.retain(|(s, _)| s != id.as_ref());
            let closed = format!(
                r#"["CLOSED","{}","closed: subscription closed"]"#,
                id.as_str()
            );
            drop(ws.send(Frame::text(closed)).await);
        }
        _ => {}
    }
    true
}

async fn serve_ws(
    mut ws: yawc::HttpWebSocket,
    store: Arc<MemoryStore>,
    hold: Arc<AtomicBool>,
    mut hook_rx: broadcast::Receiver<Hook>,
    log: mpsc::Sender<String>,
) {
    // Open subscriptions on this connection for live EVENT delivery.
    let mut open: Vec<(SubscriptionId, Vec<nk_core::Filter>)> = Vec::new();
    loop {
        tokio::select! {
            frame = ws.next() => {
                let Some(f) = frame else { return; };
                match f.opcode() {
                    OpCode::Close => return,
                    OpCode::Text => {}
                    _ => continue,
                }
                let Ok(text) = std::str::from_utf8(f.payload()) else {
                    continue;
                };
                drop(log.send(text.to_owned()).await);
                if !on_client_frame(&mut ws, &store, &mut open, &hold, text).await {
                    return;
                }
            }
            hook = hook_rx.recv() => {
                match hook {
                    Ok(Hook::Raw(text)) => drop(ws.send(Frame::text(text)).await),
                    Ok(Hook::Drop) | Err(broadcast::error::RecvError::Closed) => return,
                    // Frozen: stop reading the socket so the codec never
                    // answers a ping; the client sees a dead connection.
                    Ok(Hook::Freeze) => {
                        while let Ok(h) = hook_rx.recv().await {
                            if matches!(h, Hook::Drop) {
                                return;
                            }
                        }
                        return;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
        }
    }
}

/// One accepted TCP connection: HTTP/1 + upgrades.
async fn serve_conn(
    stream: tokio::net::TcpStream,
    store: Arc<MemoryStore>,
    hold: Arc<AtomicBool>,
    rx: broadcast::Receiver<Hook>,
    log: mpsc::Sender<String>,
    conns: Arc<AtomicUsize>,
) {
    conns.fetch_add(1, Ordering::Relaxed);
    let io = TokioIo::new(stream);
    let svc = service_fn(|req: Request<Incoming>| {
        std::future::ready(Ok::<_, Infallible>(serve_request(
            req,
            Arc::clone(&store),
            Arc::clone(&hold),
            rx.resubscribe(),
            log.clone(),
        )))
    });
    drop(
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await,
    );
    conns.fetch_sub(1, Ordering::Relaxed);
}

/// One HTTP request: upgrade it, then spawn the WebSocket loop.
fn serve_request(
    mut req: Request<Incoming>,
    store: Arc<MemoryStore>,
    hold: Arc<AtomicBool>,
    rx: broadcast::Receiver<Hook>,
    log: mpsc::Sender<String>,
) -> Response<Empty<Bytes>> {
    match WebSocket::upgrade(&mut req) {
        Ok((resp, fut)) => {
            tokio::spawn(async move {
                match fut.await {
                    Ok(ws) => serve_ws(ws, store, hold, rx, log).await,
                    Err(e) => debug!("mock ws upgrade: {e}"),
                }
            });
            resp
        }
        Err(_) => Response::new(Empty::new()),
    }
}

/// An in-process nostr relay bound to `127.0.0.1:0`, backed by
/// [`MemoryStore`].
///
/// `EVENT` gets `OK` (store outcome), `REQ` gets stored events then `EOSE`
/// plus live delivery, `CLOSE` removes the sub. Debug is manual: the accept
/// handle and channels are opaque.
pub struct MockRelay {
    url: RelayUrl,
    hooks: broadcast::Sender<Hook>,
    /// Every raw client frame the mock received (for assertions).
    log_rx: mpsc::Receiver<String>,
    conns: Arc<AtomicUsize>,
    hold: Arc<AtomicBool>,
    _accept: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for MockRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockRelay")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl MockRelay {
    /// Binds a listener and starts serving.
    ///
    /// # Errors
    ///
    /// `std::io::Error` when the port bind fails or the URL cannot parse.
    pub async fn start() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let url = RelayUrl::parse(&format!("ws://{addr}"))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let store = Arc::new(MemoryStore::new());
        let conns = Arc::new(AtomicUsize::new(0));
        let conns_accept = Arc::clone(&conns);
        let hold = Arc::new(AtomicBool::new(false));
        let hold_accept = Arc::clone(&hold);
        let (hook_tx, _) = broadcast::channel::<Hook>(16);
        let (log_tx, log_rx) = mpsc::channel::<String>(256);
        let hook_for_accept = hook_tx.clone();
        let accept = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let store = Arc::clone(&store);
                let log = log_tx.clone();
                let rx = hook_for_accept.subscribe();
                tokio::spawn(serve_conn(
                    stream,
                    store,
                    Arc::clone(&hold_accept),
                    rx,
                    log,
                    Arc::clone(&conns_accept),
                ));
            }
        });
        Ok(Self {
            url,
            hooks: hook_tx,
            log_rx,
            conns,
            hold,
            _accept: accept,
        })
    }

    /// The `ws://` URL to pass to [`Relay::new`](crate::relay::Relay::new).
    #[must_use]
    pub fn url(&self) -> RelayUrl {
        self.url.clone()
    }

    /// Sends a raw text frame verbatim (malformed/NOTICE/CLOSED probes).
    pub fn send_raw(&self, text: &str) {
        drop(self.hooks.send(Hook::Raw(text.to_owned())));
    }

    /// Freezes the connection: the server stops reading the socket, so
    /// the codec never answers the client's pings — liveness times out.
    pub fn freeze_connection(&self) {
        drop(self.hooks.send(Hook::Freeze));
    }

    /// Severs the connection — the client should observe a drop and
    /// reconnect.
    pub fn drop_connection(&self) {
        drop(self.hooks.send(Hook::Drop));
    }

    /// The next raw client frame the mock received.
    pub async fn next_client_frame(&mut self) -> Option<String> {
        self.log_rx.recv().await
    }

    /// Holds or releases REQs: while held the mock records a REQ but sends
    /// neither stored events nor `EOSE` — tests answer it via `send_raw`.
    pub fn set_hold_reqs(&self, hold: bool) {
        self.hold.store(hold, Ordering::Relaxed);
    }

    /// Live connections — `0` after every client socket closes.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.conns.load(Ordering::Relaxed)
    }

    /// Waits for a client frame whose text contains `needle`.
    pub async fn wait_for_frame(
        &mut self,
        needle: &str,
        timeout: std::time::Duration,
    ) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        while let Ok(Some(text)) = tokio::time::timeout_at(deadline, self.log_rx.recv()).await {
            if text.contains(needle) {
                return Some(text);
            }
        }
        None
    }
}
