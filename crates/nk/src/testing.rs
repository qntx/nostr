//! `test-util`: an in-process mock relay for integration tests.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode, service::service_fn};
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

/// Per-mock state shared by every accepted connection.
#[derive(Clone)]
struct Shared {
    /// The mock's event store — `REQ` replies, `COUNT`, live checks.
    store: Arc<MemoryStore>,
    /// Held-mode flag — swallow frames, answer nothing.
    hold: Arc<AtomicBool>,
    /// NIP-42: refuse unauthenticated `EVENT`/`REQ`/`COUNT`/`NEG-OPEN`.
    require_auth: Arc<AtomicBool>,
    /// The mock's `ws://` URL (checked in AUTH `relay` tags).
    relay_url: Arc<str>,
    /// Live WebSocket session count.
    conns: Arc<AtomicUsize>,
    /// Every raw client frame, for test assertions.
    log: mpsc::Sender<String>,
    /// Stored events, broadcast to every connection so each forwards to
    /// its own matching subscriptions.
    events: broadcast::Sender<Event>,
    /// The NIP-11 document, when `set_information` has run.
    information: Arc<Mutex<Option<String>>>,
}

/// The live connection: frames go out through `hook_rx`.
/// `EVENT` → store + `OK`, then live delivery to this conn's `REQ`s.
async fn on_event(ws: &mut yawc::HttpWebSocket, shared: &Shared, event: &Event) {
    let (saved, note) = match shared.store.put(event) {
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
    // Live delivery goes through the broadcast: every connection
    // (including this one) forwards to its own matching subscriptions.
    drop(shared.events.send(event.clone()));
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

/// Decrements `conns` when the WebSocket loop exits.
struct ConnGuard(Arc<AtomicUsize>);

impl ConnGuard {
    /// Returns a guard that decrements `conns` on drop.
    fn new(conns: &Arc<AtomicUsize>) -> Self {
        Self(Arc::clone(conns))
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A per-connection challenge id.
fn ulid_like() -> String {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{n:016x}")
}

/// Lowercase hex, for negentropy wire messages.
fn to_hex(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

/// Builds the server-side negentropy for one `NEG-OPEN` filter.
fn server_neg(
    store: &MemoryStore,
    filter: &nk_core::Filter,
) -> Option<negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>> {
    let mut storage = negentropy::NegentropyStorageVector::new();
    for item in store.negentropy_items(filter).unwrap_or_default() {
        drop(storage.insert(
            item.created_at.as_secs(),
            negentropy::Id::from_byte_array(*item.id.as_bytes()),
        ));
    }
    drop(storage.seal());
    negentropy::Negentropy::owned(storage, 60_000).ok()
}

/// One `NEG-MSG` server round: reply hex for `message`.
fn server_neg_round(
    neg: &mut negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>,
    id: &SubscriptionId,
    message: &str,
) -> String {
    let query = faster_hex::hex_decode_vec(message.as_bytes()).unwrap_or_default();
    let out = neg.reconcile(&query).unwrap_or_default();
    format!(r#"["NEG-MSG","{}", "{}"]"#, id.as_str(), to_hex(&out))
}

/// The AUTH event's verdict: kind, tags, signature, and freshness.
fn verify_auth_event(event: &Event, relay_url: &str, challenge: &str) -> Result<(), &'static str> {
    if event.kind().as_u16() != 22242 {
        return Err("kind");
    }
    let relay_ok = event
        .tags()
        .iter()
        .any(|t| t.name() == "relay" && t.value() == Some(relay_url));
    if !relay_ok {
        return Err("relay tag");
    }
    let chal_ok = event
        .tags()
        .iter()
        .any(|t| t.name() == "challenge" && t.value() == Some(challenge));
    if !chal_ok {
        return Err("challenge tag");
    }
    if event.verify().is_err() {
        return Err("signature");
    }
    let now = nk_core::Timestamp::now().as_secs();
    if event.created_at().as_secs().abs_diff(now) > 600 {
        return Err("timestamp");
    }
    Ok(())
}

/// Per-connection NIP-42 state.
struct AuthState<'a> {
    /// The mock-wide `require_auth` flag.
    required: &'a AtomicBool,
    /// This connection's authed flag.
    authed: &'a AtomicBool,
    /// The mock's relay url (checked in the `relay` tag).
    url: &'a str,
    /// The challenge this connection issued.
    challenge: &'a str,
}

/// The reply when `require_auth` and this conn hasn't authed.
async fn auth_reject(ws: &mut yawc::HttpWebSocket, id: &str) {
    let frame = format!(
        r#"["CLOSED","{id}","auth-required: we only allow publishing to authenticated clients"]"#
    );
    drop(ws.send(Frame::text(frame)).await);
}

/// One connection's live delivery: every open subscription whose
/// filters match gets an `EVENT` frame for `event`.
async fn forward_event(
    ws: &mut yawc::HttpWebSocket,
    open: &[(SubscriptionId, Vec<nk_core::Filter>)],
    event: &Event,
) {
    for (id, filters) in open {
        if filters.iter().any(|f| f.matches(event)) {
            let frame = format!(r#"["EVENT","{}",{}]"#, id.as_str(), event.to_json());
            drop(ws.send(Frame::text(frame)).await);
        }
    }
}

/// Routes one client text frame; `false` closes the connection.
async fn on_client_frame(
    ws: &mut yawc::HttpWebSocket,
    shared: &Shared,
    open: &mut Vec<(SubscriptionId, Vec<nk_core::Filter>)>,
    negs: &mut HashMap<
        SubscriptionId,
        negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>,
    >,
    auth: &AuthState<'_>,
    text: &str,
) -> bool {
    let Ok(msg) = ClientMessage::from_json(text) else {
        return true;
    };
    match msg {
        ClientMessage::Event(event) => {
            if shared.hold.load(Ordering::Relaxed) {
                return true;
            }
            if auth.required.load(Ordering::Relaxed) && !auth.authed.load(Ordering::Relaxed) {
                let frame = format!(
                    r#"["OK","{}",false,"auth-required: we only allow publishing to authenticated clients"]"#,
                    event.id().to_hex()
                );
                drop(ws.send(Frame::text(frame)).await);
                return true;
            }
            on_event(ws, shared, &event).await;
        }
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            if auth.required.load(Ordering::Relaxed) && !auth.authed.load(Ordering::Relaxed) {
                auth_reject(ws, subscription_id.as_str()).await;
                return true;
            }
            on_req(
                ws,
                &shared.store,
                open,
                &shared.hold,
                &subscription_id,
                &filters,
            )
            .await;
        }
        ClientMessage::Count {
            subscription_id,
            filters,
        } => {
            if auth.required.load(Ordering::Relaxed) && !auth.authed.load(Ordering::Relaxed) {
                auth_reject(ws, subscription_id.as_str()).await;
                return true;
            }
            if shared.hold.load(Ordering::Relaxed) {
                return true;
            }
            let n = shared.store.count(&filters).unwrap_or(0);
            let frame = format!(
                r#"["COUNT","{}",{{"count":{n}}}]"#,
                subscription_id.as_str()
            );
            drop(ws.send(Frame::text(frame)).await);
        }
        ClientMessage::NegOpen {
            subscription_id,
            filter,
            message,
        } => {
            if auth.required.load(Ordering::Relaxed) && !auth.authed.load(Ordering::Relaxed) {
                auth_reject(ws, subscription_id.as_str()).await;
                return true;
            }
            if shared.hold.load(Ordering::Relaxed) {
                return true;
            }
            if let Some(mut neg) = server_neg(&shared.store, &filter) {
                let reply = server_neg_round(&mut neg, &subscription_id, &message);
                negs.insert(subscription_id.clone().into_owned(), neg);
                drop(ws.send(Frame::text(reply)).await);
            }
        }
        ClientMessage::NegMsg {
            subscription_id,
            message,
        } => {
            if let Some(neg) = negs.get_mut(&subscription_id) {
                let reply = server_neg_round(neg, &subscription_id, &message);
                drop(ws.send(Frame::text(reply)).await);
            }
        }
        ClientMessage::NegClose(id) => {
            negs.remove(&id);
        }
        ClientMessage::Auth(event) => match verify_auth_event(&event, auth.url, auth.challenge) {
            Ok(()) => {
                auth.authed.store(true, Ordering::Relaxed);
                let frame = format!(r#"["OK","{}",true,""]"#, event.id().to_hex());
                drop(ws.send(Frame::text(frame)).await);
            }
            Err(why) => {
                let frame = format!(
                    r#"["OK","{}",false,"invalid: auth {why}"]"#,
                    event.id().to_hex()
                );
                drop(ws.send(Frame::text(frame)).await);
            }
        },
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
    shared: Shared,
    mut hook_rx: broadcast::Receiver<Hook>,
) {
    // `connections()` counts live WebSocket sessions: one per upgraded
    // socket, from the first frame until this loop exits.
    shared.conns.fetch_add(1, Ordering::Relaxed);
    let _guard = ConnGuard::new(&shared.conns);
    // Open subscriptions on this connection for live EVENT delivery.
    let mut open: Vec<(SubscriptionId, Vec<nk_core::Filter>)> = Vec::new();
    // Live server-side negentropy sessions keyed by NEG-OPEN id.
    let mut negs: HashMap<
        SubscriptionId,
        negentropy::Negentropy<'static, negentropy::NegentropyStorageVector>,
    > = HashMap::new();
    let mut events_rx = shared.events.subscribe();
    let authed = AtomicBool::new(!shared.require_auth.load(Ordering::Relaxed));
    let challenge = format!("auth-challenge-{}", ulid_like());
    if shared.require_auth.load(Ordering::Relaxed) {
        let frame = format!(r#"["AUTH","{challenge}"]"#);
        drop(ws.send(Frame::text(frame)).await);
    }
    let auth = AuthState {
        required: &shared.require_auth,
        authed: &authed,
        url: &shared.relay_url,
        challenge: &challenge,
    };
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
                drop(shared.log.try_send(text.to_owned()));
                if !on_client_frame(&mut ws, &shared, &mut open, &mut negs, &auth, text).await {
                    return;
                }
            }
            event = events_rx.recv() => {
                if let Ok(ev) = event {
                    forward_event(&mut ws, &open, &ev).await;
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
async fn serve_conn(stream: tokio::net::TcpStream, shared: Shared, rx: broadcast::Receiver<Hook>) {
    let io = TokioIo::new(stream);
    let svc = service_fn(|req: Request<Incoming>| {
        std::future::ready(Ok::<_, Infallible>(serve_request(
            req,
            shared.clone(),
            rx.resubscribe(),
        )))
    });
    drop(
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await,
    );
}

/// One HTTP request: upgrade it, then spawn the WebSocket loop.
fn serve_request(
    mut req: Request<Incoming>,
    shared: Shared,
    rx: broadcast::Receiver<Hook>,
) -> Response<Full<Bytes>> {
    match WebSocket::upgrade(&mut req) {
        Ok((resp, fut)) => {
            tokio::spawn(async move {
                match fut.await {
                    Ok(ws) => {
                        serve_ws(ws, shared, rx).await;
                    }
                    Err(e) => debug!("mock ws upgrade: {e}"),
                }
            });
            resp.map(|_| Full::new(Bytes::new()))
        }
        Err(_) => serve_http_fallback(&req, &shared),
    }
}

/// A non-upgrade request: the NIP-11 document when it carries
/// `Accept: application/nostr+json` and `set_information` ran,
/// otherwise 404.
fn serve_http_fallback(req: &Request<Incoming>, shared: &Shared) -> Response<Full<Bytes>> {
    let accepts = req
        .headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/nostr+json"));
    let information = shared
        .information
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let (true, Some(json)) = (accepts, information) {
        let mut response = Response::new(Full::new(Bytes::from(json)));
        response.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/nostr+json"),
        );
        return response;
    }
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
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
    require_auth: Arc<AtomicBool>,
    /// The shared event store — seeds `REQ` replies and `COUNT`.
    store: Arc<MemoryStore>,
    /// The NIP-11 document — `set_information`.
    information: Arc<Mutex<Option<String>>>,
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
        let (hook_tx, _) = broadcast::channel::<Hook>(16);
        let (log_tx, log_rx) = mpsc::channel::<String>(4096);
        let hook_for_accept = hook_tx.clone();
        let store = Arc::new(MemoryStore::new());
        let shared = Shared {
            store: Arc::clone(&store),
            hold: Arc::new(AtomicBool::new(false)),
            require_auth: Arc::new(AtomicBool::new(false)),
            relay_url: Arc::from(url.as_str().to_owned()),
            conns: Arc::new(AtomicUsize::new(0)),
            log: log_tx,
            events: broadcast::channel(1024).0,
            information: Arc::new(Mutex::new(None)),
        };
        let accept_shared = shared.clone();
        let accept = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let rx = hook_for_accept.subscribe();
                tokio::spawn(serve_conn(stream, accept_shared.clone(), rx));
            }
        });
        Ok(Self {
            url,
            hooks: hook_tx,
            log_rx,
            conns: shared.conns,
            hold: shared.hold,
            require_auth: shared.require_auth,
            store,
            information: shared.information,
            _accept: accept,
        })
    }

    /// The shared event store — seed stored events for `REQ`/`COUNT`.
    #[must_use]
    pub fn store(&self) -> &MemoryStore {
        &self.store
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

    /// Toggles NIP-42: new connections get an `AUTH` challenge and all
    /// commands are refused with `auth-required:` until a good AUTH event.
    pub fn require_auth(&self, require: bool) {
        self.require_auth.store(require, Ordering::Relaxed);
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

    /// Serves a NIP-11 document on the relay's own port: a non-upgrade
    /// GET carrying `Accept: application/nostr+json` gets
    /// 200 `application/nostr+json` with `json`; other non-upgrade
    /// requests get 404.
    pub fn set_information(&self, json: &str) {
        *self
            .information
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(String::from(json));
    }

    /// Holds or releases REQs: while held the mock records a REQ but sends
    /// neither stored events nor `EOSE` — tests answer it via `send_raw`.
    pub fn set_hold(&self, hold: bool) {
        self.hold.store(hold, Ordering::Relaxed);
    }

    /// Live connections — `0` after every client socket closes.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.conns.load(Ordering::Relaxed)
    }

    /// Waits for a client frame whose text contains `needle`.
    pub async fn wait_for_frame(&mut self, needle: &str, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        while let Ok(Some(text)) = tokio::time::timeout_at(deadline, self.log_rx.recv()).await {
            if text.contains(needle) {
                return Some(text);
            }
        }
        None
    }
}

/// A programmable plain-HTTP response for [`MockHttp`] routes.
#[derive(Clone, Debug)]
pub struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Option<Duration>,
}

impl MockResponse {
    /// A response carrying just a status.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay: None,
        }
    }

    /// Adds a response header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((String::from(name), String::from(value)));
        self
    }

    /// Sets the response body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Delays the response — timeout testing.
    #[must_use]
    pub const fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// A request [`MockHttp`] received, logged for assertions.
#[derive(Clone, Debug)]
pub struct MockRequest {
    /// The method.
    pub method: String,
    /// The path plus query.
    pub path: String,
    /// The request headers.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
}

/// An in-process HTTP/1 server for `http`-feature tests. Programmable
/// routes on `(method, path_and_query)`; unrouted requests get 404.
pub struct MockHttp {
    url: String,
    routes: Arc<Mutex<HashMap<(String, String), MockResponse>>>,
    requests: mpsc::Receiver<MockRequest>,
    _accept: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for MockHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttp")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl MockHttp {
    /// Binds a listener and starts serving.
    ///
    /// # Errors
    ///
    /// `std::io::Error` when the port bind fails.
    pub async fn start() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let routes: Arc<Mutex<HashMap<(String, String), MockResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, requests) = mpsc::channel(256);
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&routes), tx));
        Ok(Self {
            url: format!("http://{addr}"),
            routes,
            requests,
            _accept: accept,
        })
    }

    /// `http://127.0.0.1:PORT`.
    #[must_use]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Programs `method` + `path_and_query` to answer `response`.
    pub fn route(&self, method: &str, path_and_query: &str, response: MockResponse) {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                (String::from(method), String::from(path_and_query)),
                response,
            );
    }

    /// The next request the mock logged.
    pub async fn next_request(&mut self) -> Option<MockRequest> {
        self.requests.recv().await
    }
}

/// The accept loop: every connection gets its own `serve_http` task.
async fn accept_loop(
    listener: TcpListener,
    routes: Arc<Mutex<HashMap<(String, String), MockResponse>>>,
    tx: mpsc::Sender<MockRequest>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(serve_http(stream, Arc::clone(&routes), tx.clone()));
    }
}

/// One HTTP request on the mock: log it, then answer the route.
async fn serve_http(
    stream: tokio::net::TcpStream,
    routes: Arc<Mutex<HashMap<(String, String), MockResponse>>>,
    tx: mpsc::Sender<MockRequest>,
) {
    let io = TokioIo::new(stream);
    let svc = service_fn(|req: Request<Incoming>| {
        let routes = Arc::clone(&routes);
        let tx = tx.clone();
        async move {
            let method = req.method().to_string();
            let path = req
                .uri()
                .path_and_query()
                .map_or_else(|| String::from("/"), ToString::to_string);
            let headers = req
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        v.to_str().map_or_else(|_| String::new(), String::from),
                    )
                })
                .collect();
            let body = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            drop(tx.try_send(MockRequest {
                method: method.clone(),
                path: path.clone(),
                headers,
                body,
            }));
            let hit = routes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&(method, path))
                .cloned();
            Ok::<_, Infallible>(answer_hit(hit).await)
        }
    });
    drop(
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .await,
    );
}

/// Answers a routed (or unrouted) request; `delay` applies first.
async fn answer_hit(hit: Option<MockResponse>) -> Response<Full<Bytes>> {
    let Some(mock) = hit else {
        let mut response = Response::new(Full::new(Bytes::new()));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    };
    if let Some(delay) = mock.delay {
        tokio::time::sleep(delay).await;
    }
    let mut response = Response::new(Full::new(Bytes::from(mock.body)));
    *response.status_mut() = StatusCode::from_u16(mock.status).unwrap_or(StatusCode::OK);
    for (name, value) in &mock.headers {
        if let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
