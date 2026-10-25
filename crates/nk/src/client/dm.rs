//! NIP-17 private messages — signer-driven NIP-59 gift wraps routed by
//! each party's kind `10050` DM relay list.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use nk_core::nips::nip17::{
    ChatMessage, DmRelayList, Recipient, ReplyTo, wrap_direct_message_with_signer,
};
use nk_core::nips::nip59::{RandomScope, Rumor, Timestamps, WrapOptions};
use nk_core::{
    Event, EventBuilder, Filter, Kind, NostrSigner, PublicKey, RelayUrl, SingleLetterTag, SysRng,
    Timestamp,
};

use super::{Client, Error, Result};
use crate::pool::{PoolEvent, PoolSubscription, RecentIds};
use crate::relay::{self, PublishOutcome};

/// Options for [`Client::send_private_message`]. `#[non_exhaustive]` —
/// construct via `Default::default()` and mutate the fields:
///
/// ```
/// let mut opts = nk::client::DmOptions::default();
/// opts.ephemeral = true;
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DmOptions {
    /// `["subject", ..]` tag on the rumor.
    pub subject: Option<String>,
    /// `replyTo` — the unmarked `["e", <id>, <relay-or-"">]` reply tag.
    pub reply_to: Option<ReplyTo>,
    /// NIP-40 `expiration` on the seal.
    pub expiration: Option<Timestamp>,
    /// Send an ephemeral kind `21059` wrap instead of `1059`.
    pub ephemeral: bool,
}

/// What [`Client::send_private_message`] produced and published — the
/// rumor plus one delivery record per wrap (the sender's own copy
/// included).
#[derive(Debug)]
#[non_exhaustive]
pub struct SentMessage {
    /// The unsigned kind-14 rumor that was wrapped.
    pub rumor: Rumor,
    /// One entry per wrap, in the order `wrap_direct_message` returned.
    pub wraps: Vec<WrapDelivery>,
}

/// One published gift wrap and each relay's `OK`.
#[derive(Debug)]
#[non_exhaustive]
pub struct WrapDelivery {
    /// The wrap's recipient.
    pub recipient: PublicKey,
    /// The kind-1059/21059 gift wrap event.
    pub wrap: Event,
    /// Per-relay publish results for this wrap.
    pub results: BTreeMap<RelayUrl, relay::Result<PublishOutcome>>,
}

/// A decrypted private message.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ReceivedMessage {
    /// The gift wrap it arrived in.
    pub wrap: Event,
    /// The unsigned rumor inside.
    pub rumor: Rumor,
}

/// An item of the [`PrivateMessages`] stream.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PrivateMessageEvent {
    /// A gift wrap that decrypted to a valid rumor.
    Message(Box<ReceivedMessage>),
    /// The subscription caught up to `EOSE`.
    Eose,
}

/// The live DM stream: verified-and-decrypted wraps in order,
/// deduplicated by rumor id. `Unpin`; the boxed stream is `Send`.
pub struct PrivateMessages {
    inner: Pin<Box<dyn futures_util::Stream<Item = PrivateMessageEvent> + Send>>,
}

impl futures_util::Stream for PrivateMessages {
    type Item = PrivateMessageEvent;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl std::fmt::Debug for PrivateMessages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateMessages").finish_non_exhaustive()
    }
}

const P_TAG: SingleLetterTag = match SingleLetterTag::new('p') {
    Some(t) => t,
    None => unreachable!(),
};

impl Client {
    /// Publishes a kind `10050` DM relay list — signs `relays` and
    /// publishes them, updating this client's own DM routes on
    /// acceptance.
    ///
    /// # Errors
    ///
    /// [`Error::Dm`] — the list failed `DmRelayList` validation (empty).
    /// [`Error::NoSigner`], [`Error::Signer`] — from [`Client::sign`].
    /// [`Error::NoRelays`], [`Error::Closed`] — from [`Client::publish`].
    pub async fn set_dm_relays(
        &self,
        relays: impl IntoIterator<Item = RelayUrl>,
    ) -> Result<BTreeMap<RelayUrl, relay::Result<PublishOutcome>>> {
        self.check_open()?;
        let list = DmRelayList::from_urls(relays).map_err(Error::Dm)?;
        let event = self.sign(EventBuilder::from(list)).await?;
        self.publish(&event).await
    }

    /// Wraps `content` for `recipients` (plus the sender's own copy) and
    /// publishes each wrap to its recipient's DM relays.
    ///
    /// Missing DM routes are hydrated from the default relays first — a
    /// target still without a `10050` list is [`Error::NoDmRelays`]
    /// before any wrap is built.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigner`], [`Error::Signer`] — from the signer.
    /// [`Error::Dm`] — empty recipients or a rumor/wrap build failure.
    /// [`Error::NoDmRelays`] — a target has no DM relays.
    /// [`Error::Closed`] — the client is closed.
    pub async fn send_private_message(
        &self,
        recipients: &[Recipient],
        content: impl Into<String>,
        options: DmOptions,
    ) -> Result<SentMessage> {
        self.check_open()?;
        let signer = Arc::clone(self.signer().ok_or(Error::NoSigner)?);
        let sender = signer.public_key().await.map_err(Error::Signer)?;
        let mut message = ChatMessage::new(recipients.iter().cloned(), content);
        if let Some(reply_to) = options.reply_to {
            message = message.reply_to(reply_to);
        }
        if let Some(subject) = options.subject {
            message = message.subject(subject);
        }
        let rumor = message
            .into_rumor(sender, Timestamp::now())
            .map_err(Error::Dm)?;

        // Targets: the sender's own copy plus every recipient.
        let mut targets = vec![sender];
        for recipient in recipients {
            if !targets.contains(&recipient.pubkey) {
                targets.push(recipient.pubkey);
            }
        }
        let dm_relays = self.dm_relays(&targets).await?;

        let mut wrap_options = WrapOptions::new(Timestamps::Random {
            now: Timestamp::now(),
            scope: RandomScope::SealAndWrap,
        });
        if let Some(at) = options.expiration {
            wrap_options = wrap_options.expiration(at);
        }
        wrap_options = wrap_options.ephemeral(options.ephemeral);
        let wraps = wrap_direct_message_with_signer(
            signer.as_ref(),
            recipients,
            &rumor,
            &wrap_options,
            &mut SysRng,
        )
        .await
        .map_err(Error::Dm)?;

        let deliveries = futures_util::future::join_all(wraps.into_iter().map(|(target, wrap)| {
            let dm_relays = dm_relays.get(&target).cloned().unwrap_or_default();
            self.deliver_wrap(target, wrap, dm_relays)
        }))
        .await;
        Ok(SentMessage {
            rumor,
            wraps: deliveries,
        })
    }

    /// Fetches and decrypts kind `1059` gift wraps addressed to the
    /// signer's key from its DM relays.
    ///
    /// Wraps that fail verification or decryption are skipped (and never
    /// ingested or stored); the result is deduplicated by rumor id and
    /// sorted by `(created_at, id)`.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigner`], [`Error::Signer`] — from the signer.
    /// [`Error::NoDmRelays`] — the signer has no DM routes.
    /// [`Error::Closed`] — the client is closed.
    pub async fn fetch_private_messages(
        &self,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>> {
        self.check_open()?;
        let signer = Arc::clone(self.signer().ok_or(Error::NoSigner)?);
        let self_pk = signer.public_key().await.map_err(Error::Signer)?;
        let relays = self.dm_relays(&[self_pk]).await?;
        let mut filter = Filter::new()
            .kinds([Kind::GIFT_WRAP])
            .tag(P_TAG, [self_pk.to_hex()]);
        if let Some(s) = since {
            filter = filter.since(s);
        }
        if let Some(u) = until {
            filter = filter.until(u);
        }
        let plan = super::explicit_plan(
            relays.get(&self_pk).map_or(&[][..], Vec::as_slice),
            &[filter],
        )?;
        let out = self.pool().fetch_routed(plan, timeout).await;
        let mut pairs: Vec<(Event, Rumor)> = Vec::new();
        for wrap in out.events {
            match Rumor::from_gift_wrap_with_signer(&wrap, signer.as_ref()).await {
                Ok(rumor) => pairs.push((wrap, rumor)),
                Err(e) => {
                    tracing::debug!(
                        "skipping undecryptable gift wrap {}: {e}",
                        wrap.id().to_hex()
                    );
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        pairs.retain(|(_, rumor)| seen.insert(rumor.id()));
        pairs.sort_by_key(|(_, rumor)| (rumor.unsigned().created_at(), rumor.id()));
        self.ingest(
            &pairs
                .iter()
                .map(|(wrap, _)| wrap.clone())
                .collect::<Vec<_>>(),
        )
        .await;
        Ok(pairs
            .into_iter()
            .map(|(wrap, rumor)| ReceivedMessage { wrap, rumor })
            .collect())
    }

    /// A live stream of decrypted private messages on the signer's DM
    /// relays (kinds `1059`/`21059`). Undecryptable wraps are skipped
    /// and never ingested — verified wraps are ingested as they arrive.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigner`], [`Error::Signer`] — from the signer.
    /// [`Error::NoDmRelays`] — the signer has no DM routes.
    /// [`Error::Closed`] — the client is closed.
    pub async fn subscribe_private_messages(
        &self,
        since: Option<Timestamp>,
    ) -> Result<PrivateMessages> {
        self.check_open()?;
        let signer = Arc::clone(self.signer().ok_or(Error::NoSigner)?);
        let self_pk = signer.public_key().await.map_err(Error::Signer)?;
        let relays = self.dm_relays(&[self_pk]).await?;
        let mut filter = Filter::new()
            .kinds([Kind::GIFT_WRAP, Kind::GIFT_WRAP_EPHEMERAL])
            .tag(P_TAG, [self_pk.to_hex()]);
        if let Some(s) = since {
            filter = filter.since(s);
        }
        let plan = super::explicit_plan(
            relays.get(&self_pk).map_or(&[][..], Vec::as_slice),
            &[filter],
        )?;
        let sub = self.pool().subscribe_routed(plan).await;
        Ok(PrivateMessages {
            inner: Box::pin(dm_stream(sub, self.clone(), signer)),
        })
    }

    /// Publishes `wrap` to `dm_relays`, ingesting it when any relay
    /// accepts — one [`WrapDelivery`] per wrap.
    async fn deliver_wrap(
        &self,
        target: PublicKey,
        wrap: Event,
        dm_relays: Vec<RelayUrl>,
    ) -> WrapDelivery {
        let results = self.pool().publish(&dm_relays, &wrap).await;
        if results.values().any(|r| matches!(r, Ok(o) if o.accepted)) {
            self.ingest(std::slice::from_ref(&wrap)).await;
        }
        WrapDelivery {
            recipient: target,
            wrap,
            results,
        }
    }

    /// DM relays per pubkey: hydrates every unlisted pubkey in one call
    /// (only when there are default relays; the hydrate result is
    /// ignored) — the first pubkey still without a list is
    /// [`Error::NoDmRelays`].
    async fn dm_relays(&self, pubkeys: &[PublicKey]) -> Result<BTreeMap<PublicKey, Vec<RelayUrl>>> {
        if !self.relays().is_empty() {
            let missing: Vec<PublicKey> = pubkeys
                .iter()
                .copied()
                .filter(|pk| self.routes(pk).is_none_or(|r| r.dm().is_empty()))
                .collect();
            if !missing.is_empty() {
                drop(self.hydrate(&missing, self.request_timeout()).await);
            }
        }
        let mut out = BTreeMap::new();
        for pk in pubkeys {
            let relays = self.routes(pk).map(|r| r.dm().to_vec()).unwrap_or_default();
            if relays.is_empty() {
                return Err(Error::NoDmRelays(*pk));
            }
            out.insert(*pk, relays);
        }
        Ok(out)
    }
}

/// The DM stream — `filter_map` sequential and order-preserving; the
/// dedupe set lives in a short-lived `Mutex` (never held across the
/// signer's `.await`).
fn dm_stream(
    sub: PoolSubscription,
    client: Client,
    signer: Arc<dyn NostrSigner>,
) -> impl futures_util::Stream<Item = PrivateMessageEvent> + Send {
    let recent = Arc::new(std::sync::Mutex::new(RecentIds::with_capacity(1024)));
    sub.filter_map(move |item| {
        map_dm_item(
            item,
            client.clone(),
            Arc::clone(&signer),
            Arc::clone(&recent),
        )
    })
}

/// One `PoolEvent` → `Option<PrivateMessageEvent>`: unwrap, dedupe,
/// ingest the good wraps, skip the rest.
async fn map_dm_item(
    item: PoolEvent,
    client: Client,
    signer: Arc<dyn NostrSigner>,
    recent: Arc<std::sync::Mutex<RecentIds>>,
) -> Option<PrivateMessageEvent> {
    let PoolEvent::Event { event, .. } = item else {
        return match item {
            PoolEvent::Eose => Some(PrivateMessageEvent::Eose),
            _ => None,
        };
    };
    let rumor = match Rumor::from_gift_wrap_with_signer(&event, signer.as_ref()).await {
        Ok(rumor) => rumor,
        Err(e) => {
            tracing::debug!(
                "skipping undecryptable gift wrap {}: {e}",
                event.id().to_hex()
            );
            return None;
        }
    };
    let new = recent
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(rumor.id());
    if !new {
        return None;
    }
    client.ingest_live(&event);
    Some(PrivateMessageEvent::Message(Box::new(ReceivedMessage {
        wrap: event,
        rumor,
    })))
}

const _: fn(&Client) = |client: &Client| {
    const fn assert_send<F: Future + Send>(_: &F) {}
    let set = client.set_dm_relays(std::iter::empty::<RelayUrl>());
    assert_send(&set);
    let send = client.send_private_message(&[], "", DmOptions::default());
    assert_send(&send);
    let fetch = client.fetch_private_messages(None, None, Duration::from_secs(1));
    assert_send(&fetch);
    let sub = client.subscribe_private_messages(None);
    assert_send(&sub);
};
