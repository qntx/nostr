//! NIP-46 remote signing: a [`nk_core::NostrSigner`] that delegates to a bunker
//! over relays. The client key is a local, disposable [`Keys`] — the
//! remote user key never enters this process.
//!
//! The signer owns a private [`RelayPool`]; its NIP-42 signer is the
//! client `Keys` — sharing a pool whose AUTH signer were the remote
//! signer itself would recurse (AUTH → RPC → AUTH).
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/46.md>

mod rpc;

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::StreamExt;
use nk_core::nips::nip44::ConversationKey;
use nk_core::nips::nip46::{
    BunkerUri, ClientMetadata, Method, NostrConnectUri, Request, parse_switch_relays,
};
use nk_core::rand_core::TryRng;
use nk_core::{
    Event, EventBuilder, Filter, Keys, Kind, PublicKey, RelayUrl, SignerBackendError, SignerError,
    SysRng, Tag, UnsignedEvent,
};
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::debug;

use crate::gossip::P_TAG;
use crate::pool::{PoolEvent, RelayPool};
use crate::relay::{self, PublishOutcome, RelayOptions};

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// A remote-signer call failed. Results and secrets are never echoed —
/// a `connect` result may carry the handshake secret.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URI lists no relays.
    #[error("the URI lists no relays")]
    NoRelays,
    /// A relay URL in the URI (or a `switch_relays` reply) is invalid.
    #[error("invalid relay URL")]
    InvalidRelayUrl(#[source] nk_core::url::Error),
    /// The client keys do not match the `nostrconnect://` URI.
    #[error("client keys do not match the nostrconnect URI")]
    ClientMismatch,
    /// The unsigned event's pubkey is not the remote user's.
    #[error("unsigned event pubkey mismatch")]
    PublicKeyMismatch,
    /// The OS RNG failed while drawing a request id.
    #[error("rng failure")]
    Rng,
    /// NIP-44 encryption of the RPC payload failed.
    #[error("encryption failure")]
    Encrypt(#[source] nk_core::nips::nip44::Error),
    /// Signing the request event with the client keys failed.
    #[error("request signing failed")]
    Sign(#[source] nk_core::key::Error),
    /// No relay accepted the request event.
    #[error("no relay accepted the request event")]
    NotPublished(BTreeMap<RelayUrl, relay::Result<PublishOutcome>>),
    /// The remote signer reported an error.
    #[error("remote signer error: {0}")]
    Remote(String),
    /// The response carried neither a result nor an error.
    #[error("empty response")]
    EmptyResponse,
    /// The response `result` did not satisfy the method's contract; the
    /// payload is never echoed.
    #[error("unexpected {} result", .0.as_str())]
    UnexpectedResult(Method),
    /// The response event JSON was unparseable or badly signed.
    #[error("invalid event from the remote signer")]
    InvalidEvent,
    /// The signed event does not match the unsigned template.
    #[error("signed event does not match the unsigned template")]
    EventMismatch,
    /// A NIP-46 codec failure.
    #[error("codec failure")]
    Codec(#[source] nk_core::nips::nip46::Error),
    /// A response-filter construction invariant failed — unreachable: the
    /// built filters use a literal kind list and hex-encoded public keys.
    #[error("invalid filter")]
    Filter(#[source] nk_core::filter::Error),
    /// No reply inside the deadline.
    #[error("the remote signer did not answer in time")]
    Timeout,
    /// [`RemoteSigner::close`] has run — the signer is terminal.
    #[error("the remote signer is closed")]
    Closed,
}

/// The `auth_url` callback on [`RemoteSignerOptions`].
pub type AuthUrlCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// [`RemoteSigner`] tuning. `#[non_exhaustive]` — construct via
/// `Default::default()` and mutate the fields:
///
/// ```
/// let mut opts = nk::nip46::RemoteSignerOptions::default();
/// opts.perms = vec![String::from("sign_event")];
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct RemoteSignerOptions {
    /// Deadline for one RPC reply.
    pub request_timeout: Duration,
    /// Deadline after an `auth_url` challenge, and for the
    /// `nostrconnect://` handshake.
    pub auth_timeout: Duration,
    /// Requested permissions sent with `connect` (`method[:kind]` list).
    pub perms: Vec<String>,
    /// Client metadata sent with `connect`.
    pub metadata: Option<ClientMetadata>,
    /// Called with the URL when the bunker answers `auth_url` for a
    /// pending request.
    pub on_auth_url: Option<AuthUrlCallback>,
    /// `RelayOptions` for the private pool — `signer` is overwritten
    /// with the client keys.
    pub relay: RelayOptions,
}

impl Default for RemoteSignerOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            auth_timeout: Duration::from_secs(300),
            perms: Vec::new(),
            metadata: None,
            on_auth_url: None,
            relay: RelayOptions::default(),
        }
    }
}

impl fmt::Debug for RemoteSignerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSignerOptions")
            .field("request_timeout", &self.request_timeout)
            .field("auth_timeout", &self.auth_timeout)
            .field("perms", &self.perms)
            .field("metadata", &self.metadata)
            .field("on_auth_url", &self.on_auth_url.as_ref().map(|_| ".."))
            .field("relay", &self.relay)
            .finish()
    }
}

/// The shared state behind every [`RemoteSigner`] clone.
struct Inner {
    /// The local, disposable client key — signs every request event and
    /// the private pool's NIP-42 AUTHs.
    client: Keys,
    /// The remote signer's public key.
    remote: PublicKey,
    /// The handshake secret, echoed back to persistence via
    /// `bunker_uri` — never logged.
    secret: Option<String>,
    /// Client↔remote NIP-44 channel, derived once.
    conversation: ConversationKey,
    /// The private relay pool.
    pool: RelayPool,
    /// The current relays — `switch_relays` swaps the list.
    relays: RwLock<Vec<RelayUrl>>,
    /// The in-flight request ids.
    pending: Arc<rpc::Pending>,
    /// The listener task; swapped by `switch_relays`.
    listener: Mutex<Option<JoinHandle<()>>>,
    /// The remote user's public key, fetched lazily.
    user: OnceCell<PublicKey>,
    options: RemoteSignerOptions,
    closed: AtomicBool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let listener = self
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = listener {
            handle.abort();
        }
    }
}

/// A NIP-46 remote signer. `Clone` is cheap; every clone shares the pool,
/// the listener, and the pending table.
#[derive(Clone)]
pub struct RemoteSigner {
    inner: Arc<Inner>,
}

/// Parses and deduplicates the URI's relay list, keeping order.
fn parse_relays(raw: &[String]) -> Result<Vec<RelayUrl>> {
    let mut seen = HashSet::with_capacity(raw.len());
    let mut out = Vec::with_capacity(raw.len());
    for url in raw {
        let url = RelayUrl::parse(url).map_err(Error::InvalidRelayUrl)?;
        if seen.insert(url.clone()) {
            out.push(url);
        }
    }
    if out.is_empty() {
        return Err(Error::NoRelays);
    }
    Ok(out)
}

/// The private pool for this signer — `relay.signer` is always the
/// client keys so a NIP-42 challenge never loops through the bunker.
fn pool_with(options: &RemoteSignerOptions, client: &Keys) -> RelayPool {
    let mut relay = options.relay.clone();
    relay.signer = Some(Arc::new(client.clone()));
    RelayPool::new(relay)
}

/// Subscribes `pool` for responses on `relays` — kinds 24133 authored
/// by `remote`, `#p`-tagged to `client` — and spawns the listener task.
///
/// `limit(0)` marks the sub live-only; `Filter::matches` ignores it, so
/// nothing is filtered out locally either.
async fn spawn_listener(
    pool: &RelayPool,
    relays: &[RelayUrl],
    remote: PublicKey,
    client: PublicKey,
    conversation: &ConversationKey,
    pending: &Arc<rpc::Pending>,
) -> Result<JoinHandle<()>> {
    let filter = Filter::new()
        .kinds([Kind::NOSTR_CONNECT])
        .and_then(|f| f.authors([remote]))
        .and_then(|f| f.tag(P_TAG, [client.to_hex()]))
        .map_err(Error::Filter)?
        .limit(0);
    let plan = relays
        .iter()
        .map(|u| (u.clone(), vec![filter.clone()]))
        .collect();
    let sub = pool.subscribe_routed(plan).await;
    Ok(tokio::spawn(rpc::listen(
        sub,
        conversation.clone(),
        Arc::clone(pending),
    )))
}

/// A 16-byte random request id, lowercase hex.
fn request_id() -> Result<String> {
    let mut rng = SysRng;
    let mut buf = [0u8; 16];
    rng.try_fill_bytes(&mut buf).map_err(|_| Error::Rng)?;
    Ok(faster_hex::hex_string(&buf))
}

/// A request builder for methods with no dedicated constructor.
fn call(method: Method, params: Vec<String>) -> impl FnOnce(String) -> Request {
    move |id| Request { id, method, params }
}

impl RemoteSigner {
    /// Builds the shared state on `pool` and spawns the response
    /// listener for `remote`.
    async fn assemble(
        client: Keys,
        remote: PublicKey,
        secret: Option<String>,
        relays: Vec<RelayUrl>,
        pool: RelayPool,
        options: RemoteSignerOptions,
    ) -> Result<Self> {
        let conversation =
            ConversationKey::derive(client.secret_key(), &remote).map_err(Error::Encrypt)?;
        let pending = Arc::new(rpc::Pending::default());
        let listener = spawn_listener(
            &pool,
            &relays,
            remote,
            client.public_key(),
            &conversation,
            &pending,
        )
        .await?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                remote,
                secret,
                conversation,
                pool,
                relays: RwLock::new(relays),
                pending,
                listener: Mutex::new(Some(listener)),
                user: OnceCell::new(),
                options,
                closed: AtomicBool::new(false),
            }),
        })
    }

    /// Subscribes to an already-known `bunker://` pointer without a
    /// `connect` RPC — reconnect must reuse the original client key.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelays`] on an empty relay list;
    /// [`Error::InvalidRelayUrl`] on a bad URL; [`Error::Encrypt`] when
    /// the conversation key cannot be derived.
    pub async fn attach(
        bunker: &BunkerUri,
        client: Keys,
        options: RemoteSignerOptions,
    ) -> Result<Self> {
        let relays = parse_relays(&bunker.relays)?;
        let pool = pool_with(&options, &client);
        Self::assemble(
            client,
            bunker.remote_signer,
            bunker.secret.clone(),
            relays,
            pool,
            options,
        )
        .await
    }

    /// Connects to a `bunker://` pointer: `attach`, the `connect` RPC
    /// (`ack`, or the secret echoed back), a best-effort `switch_relays`,
    /// then `get_public_key` to prove the session.
    ///
    /// # Errors
    ///
    /// The [`attach`](Self::attach) errors; [`Error::UnexpectedResult`]
    /// when `connect` answers neither `ack` nor the secret; any RPC
    /// failure from [`Self::public_key`]. A failure after attach closes
    /// the signer.
    pub async fn connect(
        bunker: &BunkerUri,
        client: Keys,
        options: RemoteSignerOptions,
    ) -> Result<Self> {
        let signer = Self::attach(bunker, client, options).await?;
        let ready = async {
            let remote = signer.inner.remote;
            let secret = bunker.secret.clone();
            let perms = signer.inner.options.perms.clone();
            let metadata = signer.inner.options.metadata.clone();
            let result = signer
                .rpc(move |id| {
                    Request::connect(id, &remote, secret.as_deref(), &perms, metadata.as_ref())
                })
                .await?;
            let secret_ok = signer
                .inner
                .secret
                .as_deref()
                .is_some_and(|s| !s.is_empty() && result == s);
            if result != "ack" && !secret_ok {
                return Err(Error::UnexpectedResult(Method::Connect));
            }
            if let Err(e) = signer.switch_relays().await {
                debug!("switch_relays failed: {e}");
            }
            signer.public_key().await?;
            Ok(())
        }
        .await;
        match ready {
            Ok(()) => Ok(signer),
            Err(e) => {
                signer.close().await;
                Err(e)
            }
        }
    }

    /// Waits for a bunker to complete the client-initiated
    /// `nostrconnect://` handshake: a kind-24133 response encrypted to
    /// the client whose `result` equals the URI's secret; its author
    /// becomes the remote signer.
    ///
    /// # Errors
    ///
    /// [`Error::ClientMismatch`] when `client` does not match the URI
    /// (checked before any I/O); [`Error::NoRelays`],
    /// [`Error::InvalidRelayUrl`], [`Error::Encrypt`] as in
    /// [`Self::attach`]; [`Error::Timeout`] at `auth_timeout`;
    /// [`Error::Closed`] when the handshake stream ends first. A
    /// failure after the handshake closes the signer.
    pub async fn nostr_connect(
        uri: &NostrConnectUri,
        client: Keys,
        options: RemoteSignerOptions,
    ) -> Result<Self> {
        if uri.client() != client.public_key() {
            return Err(Error::ClientMismatch);
        }
        let relays = parse_relays(uri.relays())?;
        let pool = pool_with(&options, &client);
        // No author filter — the remote signer is unknown until it
        // answers with the secret.
        let filter = Filter::new()
            .kinds([Kind::NOSTR_CONNECT])
            .and_then(|f| f.tag(P_TAG, [client.public_key().to_hex()]))
            .map_err(Error::Filter)?
            .limit(0);
        let plan = relays
            .iter()
            .map(|u| (u.clone(), vec![filter.clone()]))
            .collect();
        let mut sub = pool.subscribe_routed(plan).await;
        let deadline = Instant::now() + options.auth_timeout;
        let remote: Result<PublicKey> = loop {
            tokio::select! {
                item = sub.next() => match item {
                    Some(PoolEvent::Event { event, .. }) => {
                        if let Ok(conversation) =
                            ConversationKey::derive(client.secret_key(), &event.pubkey())
                            && let Ok(payload) = conversation.decrypt(event.content())
                            && let Ok(response) =
                                nk_core::nips::nip46::Response::from_json(&payload)
                            && response.result.as_deref() == Some(uri.secret())
                        {
                            break Ok(event.pubkey());
                        }
                    }
                    Some(_) => {}
                    None => break Err(Error::Closed),
                },
                () = tokio::time::sleep_until(deadline) => break Err(Error::Timeout),
            }
        };
        drop(sub);
        let remote = match remote {
            Ok(remote) => remote,
            Err(e) => {
                pool.close().await;
                return Err(e);
            }
        };
        let signer = Self::assemble(
            client,
            remote,
            Some(uri.secret().to_owned()),
            relays,
            pool,
            options,
        )
        .await?;
        let ready = async {
            if let Err(e) = signer.switch_relays().await {
                debug!("switch_relays failed: {e}");
            }
            signer.public_key().await?;
            Ok(())
        }
        .await;
        match ready {
            Ok(()) => Ok(signer),
            Err(e) => {
                signer.close().await;
                Err(e)
            }
        }
    }

    /// One RPC round trip: register the reply channel first, then
    /// encrypt, sign, and publish the kind-24133 request on the current
    /// relays. A reply racing the publish wins; `auth_url` replies move
    /// the deadline to `auth_timeout`.
    async fn rpc(&self, request: impl FnOnce(String) -> Request) -> Result<String> {
        let inner = &*self.inner;
        if inner.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }
        let id = request_id()?;
        // Registered before publishing: an early reply can never race
        // the pending insert.
        let (guard, mut rx) = inner.pending.register(id.clone());
        let content = {
            let mut rng = SysRng;
            inner
                .conversation
                .encrypt(&request(id).to_json(), &mut rng)
                .map_err(Error::Encrypt)?
        };
        let unsigned = EventBuilder::new(Kind::NOSTR_CONNECT, content)
            .tags([Tag::public_key(inner.remote, None, None)])
            .build(inner.client.public_key());
        let event = {
            let mut rng = SysRng;
            inner
                .client
                .sign_event(unsigned, &mut rng)
                .map_err(Error::Sign)?
        };
        let relays = inner
            .relays
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut publish = std::pin::pin!(inner.pool.publish(&relays, &event).fuse());
        let mut deadline = Instant::now() + inner.options.request_timeout;
        let result = loop {
            tokio::select! {
                out = &mut publish => {
                    // Fused: once delivered this branch stays pending.
                    if out.values().all(|r| !matches!(r, Ok(o) if o.accepted)) {
                        break Err(Error::NotPublished(out));
                    }
                }
                reply = rx.recv() => match reply {
                    Some(rpc::Reply::AuthUrl(url)) => {
                        if !url.is_empty()
                            && let Some(callback) = &inner.options.on_auth_url
                        {
                            callback(&url);
                        }
                        deadline = Instant::now() + inner.options.auth_timeout;
                    }
                    Some(rpc::Reply::Response { result, error }) => {
                        break match (result, error) {
                            (_, Some(error)) if !error.is_empty() => Err(Error::Remote(error)),
                            (Some(result), _) => Ok(result),
                            _ => Err(Error::EmptyResponse),
                        };
                    }
                    None => break Err(Error::Closed),
                },
                () = tokio::time::sleep_until(deadline) => break Err(Error::Timeout),
            }
        };
        drop(guard);
        result
    }

    /// The remote user's public key — the `get_public_key` result,
    /// fetched once and cached.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedResult`] on a non-public-key result; the RPC
    /// errors of the RPC layer.
    pub async fn public_key(&self) -> Result<PublicKey> {
        self.inner
            .user
            .get_or_try_init(|| async {
                let result = self.rpc(call(Method::GetPublicKey, Vec::new())).await?;
                PublicKey::from_wire_hex(&result)
                    .map_err(|_| Error::UnexpectedResult(Method::GetPublicKey))
            })
            .await
            .copied()
    }

    /// Remote-signs `unsigned`: the remote user must be its pubkey, the
    /// reply must verify and match the template.
    ///
    /// # Errors
    ///
    /// [`Error::PublicKeyMismatch`] before any RPC when the template's
    /// pubkey is not the remote user's; [`Error::InvalidEvent`] on
    /// unparseable or badly-signed JSON; [`Error::EventMismatch`] when
    /// the signed event differs from the template; the RPC errors.
    pub async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event> {
        let user = self.public_key().await?;
        if unsigned.pubkey() != user {
            return Err(Error::PublicKeyMismatch);
        }
        let result = self.rpc(|id| Request::sign_event(id, &unsigned)).await?;
        let event = Event::from_json(&result).map_err(|_| Error::InvalidEvent)?;
        event.verify().map_err(|_| Error::InvalidEvent)?;
        if !event.matches_unsigned(&unsigned) {
            return Err(Error::EventMismatch);
        }
        Ok(event)
    }

    /// `ping` — the result must be `"pong"`.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedResult`] otherwise; the RPC errors.
    pub async fn ping(&self) -> Result<()> {
        let result = self.rpc(call(Method::Ping, Vec::new())).await?;
        if result != "pong" {
            return Err(Error::UnexpectedResult(Method::Ping));
        }
        Ok(())
    }

    /// NIP-44 encrypts `text` for `peer` through the remote signer.
    ///
    /// # Errors
    ///
    /// The RPC errors; [`Error::Remote`] on a bunker-side failure.
    pub async fn nip44_encrypt(&self, peer: &PublicKey, text: &str) -> Result<String> {
        self.rpc(call(
            Method::Nip44Encrypt,
            vec![peer.to_hex(), text.to_owned()],
        ))
        .await
    }

    /// NIP-44 decrypts `text` from `peer` through the remote signer.
    ///
    /// # Errors
    ///
    /// The RPC errors; [`Error::Remote`] on a bunker-side failure.
    pub async fn nip44_decrypt(&self, peer: &PublicKey, text: &str) -> Result<String> {
        self.rpc(call(
            Method::Nip44Decrypt,
            vec![peer.to_hex(), text.to_owned()],
        ))
        .await
    }

    /// NIP-04 encrypts `text` for `peer` through the remote signer.
    ///
    /// # Errors
    ///
    /// The RPC errors; [`Error::Remote`] on a bunker-side failure.
    pub async fn nip04_encrypt(&self, peer: &PublicKey, text: &str) -> Result<String> {
        self.rpc(call(
            Method::Nip04Encrypt,
            vec![peer.to_hex(), text.to_owned()],
        ))
        .await
    }

    /// NIP-04 decrypts `text` from `peer` through the remote signer.
    ///
    /// # Errors
    ///
    /// The RPC errors; [`Error::Remote`] on a bunker-side failure.
    pub async fn nip04_decrypt(&self, peer: &PublicKey, text: &str) -> Result<String> {
        self.rpc(call(
            Method::Nip04Decrypt,
            vec![peer.to_hex(), text.to_owned()],
        ))
        .await
    }

    /// Asks the bunker for its preferred relay list (`null` = nothing
    /// changes). On a list, the response listener is respawned on the
    /// new relays first, then the relay set is swapped and the old
    /// listener aborted.
    ///
    /// # Errors
    ///
    /// [`Error::Codec`] on a malformed result; [`Error::NoRelays`] on an
    /// empty list; [`Error::InvalidRelayUrl`] on a bad URL; the RPC
    /// errors.
    pub async fn switch_relays(&self) -> Result<Option<Vec<RelayUrl>>> {
        let result = self.rpc(call(Method::SwitchRelays, Vec::new())).await?;
        let Some(raw) = parse_switch_relays(&result).map_err(Error::Codec)? else {
            return Ok(None);
        };
        let new_relays = parse_relays(&raw)?;
        // The new listener goes up before the old one drops — no reply
        // window is left uncovered.
        let handle = spawn_listener(
            &self.inner.pool,
            &new_relays,
            self.inner.remote,
            self.inner.client.public_key(),
            &self.inner.conversation,
            &self.inner.pending,
        )
        .await?;
        let old = {
            let mut listener = self
                .inner
                .listener
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Checked under the listener lock: `close` flags first and
            // takes the handle under this lock, so a close racing the new
            // subscription either is seen here or aborts the new handle.
            if self.inner.closed.load(Ordering::Relaxed) {
                handle.abort();
                return Err(Error::Closed);
            }
            self.inner
                .relays
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(&new_relays);
            listener.replace(handle)
        };
        if let Some(old) = old {
            old.abort();
        }
        Ok(Some(new_relays))
    }

    /// `logout`, then closes unconditionally — a courtesy teardown.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedResult`] when the result is not `"ack"`; the
    /// RPC errors. The signer is closed either way.
    pub async fn logout(&self) -> Result<()> {
        let result = self.rpc(call(Method::Logout, Vec::new())).await;
        self.close().await;
        match result {
            Ok(result) if result == "ack" => Ok(()),
            Ok(_) => Err(Error::UnexpectedResult(Method::Logout)),
            Err(e) => Err(e),
        }
    }

    /// Terminates the signer: pending calls end `Closed`, the listener
    /// is aborted, and the private pool closes. Idempotent.
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let listener = self
            .inner
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = listener {
            handle.abort();
        }
        self.inner.pending.clear();
        self.inner.pool.close().await;
    }

    /// The `bunker://` pointer for persistence: the remote signer, the
    /// current relays (updated by `switch_relays`), and the secret.
    #[must_use]
    pub fn bunker_uri(&self) -> BunkerUri {
        BunkerUri {
            remote_signer: self.inner.remote,
            relays: self
                .inner
                .relays
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|u| u.as_str().to_owned())
                .collect(),
            secret: self.inner.secret.clone(),
        }
    }

    /// The local client key's public key.
    #[must_use]
    pub fn client_public_key(&self) -> PublicKey {
        self.inner.client.public_key()
    }
}

/// Maps the module error onto the signer contract: only a template
/// pubkey mismatch is a real `PublicKeyMismatch`.
fn signer_error(e: Error) -> SignerError {
    match e {
        Error::PublicKeyMismatch => SignerError::PublicKeyMismatch,
        other => SignerError::Backend(SignerBackendError::new(other)),
    }
}

impl nk_core::NostrSigner for RemoteSigner {
    fn public_key(&self) -> nk_core::BoxFuture<'_, Result<PublicKey, SignerError>> {
        Box::pin(async move { Self::public_key(self).await.map_err(signer_error) })
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> nk_core::BoxFuture<'_, Result<Event, SignerError>> {
        Box::pin(async move { Self::sign_event(self, unsigned).await.map_err(signer_error) })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> nk_core::BoxFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Self::nip44_encrypt(self, peer, text)
                .await
                .map_err(signer_error)
        })
    }

    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> nk_core::BoxFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Self::nip44_decrypt(self, peer, text)
                .await
                .map_err(signer_error)
        })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> nk_core::BoxFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Self::nip04_encrypt(self, peer, text)
                .await
                .map_err(signer_error)
        })
    }

    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> nk_core::BoxFuture<'a, Result<String, SignerError>> {
        Box::pin(async move {
            Self::nip04_decrypt(self, peer, text)
                .await
                .map_err(signer_error)
        })
    }
}

impl fmt::Debug for RemoteSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("remote", &self.inner.remote)
            .field("client", &self.inner.client.public_key())
            .field("relays", &self.bunker_uri().relays)
            .finish_non_exhaustive()
    }
}

const _: () = {
    const fn assert_send_sync_unpin<T: Send + Sync + Unpin>() {}
    assert_send_sync_unpin::<RemoteSigner>();
};

const _: fn(&BunkerUri, &NostrConnectUri, &RemoteSigner, Keys, RemoteSignerOptions) =
    |bunker, uri, signer, client, options| {
        const fn assert_send<F: Future + Send>(_: &F) {}
        assert_send(&RemoteSigner::connect(
            bunker,
            client.clone(),
            options.clone(),
        ));
        let unsigned = EventBuilder::new(Kind::new(1), "").build(client.public_key());
        assert_send(&signer.sign_event(unsigned));
        assert_send(&RemoteSigner::nostr_connect(uri, client, options));
    };
