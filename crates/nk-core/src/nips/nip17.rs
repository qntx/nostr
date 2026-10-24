//! NIP-17 private direct messages.
//!
//! Counterpart of `@qntx/nostr/nips/nip17`: kind `10050` DM relay lists,
//! kind `14` chat-message rumor construction, and per-recipient gift
//! wrapping built on [`crate::nips::nip59`].
//!
//! TS drives wrapping through the injected asynchronous `Nip59Crypto`; this
//! layer mirrors the local-key flow — [`wrap_direct_message`]. A signer
//! layer composes the same flow from [`crate::nips::nip59`]'s pure steps for
//! remote signers.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/17.md>

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    Event, EventBuilder, EventId, Keys, Kind, PublicKey, RelayUrl, Tag, Tags, Timestamp,
    UnsignedEvent,
};

use crate::nips::nip59::{self, Rumor, WrapOptions};

/// The error type returned by NIP-17 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The event kind differs from the required one.
    #[error("expected kind {expected}, got {found}")]
    WrongKind {
        /// The required kind value.
        expected: u16,
        /// The event's actual kind.
        found: u16,
    },
    /// A recipients or relay list argument was empty.
    #[error("{0}")]
    Empty(&'static str),
    /// A NIP-59 wrap/unwrap step failed.
    #[error("{0}")]
    Wrap(#[from] nip59::Error),
    /// `rng` failed inside a NIP-59 step (already surfaced there).
    #[error("rng failed")]
    Rng,
}

/// Result type for NIP-17 operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// A parsed kind `10050` DM relay list — the normalized relay URLs, in
/// first-seen order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DmRelayList {
    relays: Vec<RelayUrl>,
}

impl DmRelayList {
    /// The normalized relay URLs, first-seen order.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        &self.relays
    }
}

impl TryFrom<&Event> for DmRelayList {
    type Error = Error;

    /// Parses a kind `10050` event. Each `["relay",
    /// <url>]` tag's value is normalized like `normalizeRelayUrls` (invalid
    /// entries skipped, first-seen dedup).
    ///
    /// # Errors
    ///
    /// [`Error::WrongKind`] — the event is not a DM relay list.
    fn try_from(event: &Event) -> Result<Self> {
        if event.kind() != Kind::DIRECT_MESSAGE_RELAYS_LIST {
            return Err(Error::WrongKind {
                expected: Kind::DIRECT_MESSAGE_RELAYS_LIST.as_u16(),
                found: event.kind().as_u16(),
            });
        }
        Ok(Self {
            relays: RelayUrl::normalize_all(event.tags().iter().filter_map(|tag| {
                if tag.name() == "relay" {
                    tag.value()
                } else {
                    None
                }
            })),
        })
    }
}

impl From<DmRelayList> for EventBuilder {
    /// Builds an unsigned kind `10050` template — TS
    /// `dmRelayListEventBuilder`. A NIP-17 relay list requires at least one
    /// `relay` tag; an empty list still produces a builder (the
    /// `From` conversion is infallible).
    fn from(list: DmRelayList) -> Self {
        let tags: Tags = list
            .relays
            .iter()
            .map(|url| Tag::custom("relay", [url.as_str()]))
            .collect();
        Self::new(Kind::DIRECT_MESSAGE_RELAYS_LIST, "").tags(tags)
    }
}

impl DmRelayList {
    /// Encodes relay URLs as a relay list: each
    /// entry is normalized, invalid/empty entries skipped, results
    /// deduplicated first-seen.
    ///
    /// # Errors
    ///
    /// [`Error::Empty`] `DM relay list requires at least one relay` — no
    /// usable relay URL was given.
    pub fn from_urls<I, S>(relays: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let relays = RelayUrl::normalize_all(relays);
        if relays.is_empty() {
            return Err(Error::Empty("DM relay list requires at least one relay"));
        }
        Ok(Self { relays })
    }
}

/// A direct-message recipient. The relay hint goes on the
/// wrap's `p` tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Recipient {
    /// The recipient's public key.
    pub pubkey: PublicKey,
    /// Optional relay hint for the wrap's `p` tag.
    pub relay_hint: Option<RelayUrl>,
}

/// The event a chat message replies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplyTo {
    /// The replied-to event id.
    pub id: EventId,
    /// Optional relay hint for the unmarked `e` tag; absent serializes as
    /// `""`, matching TS.
    pub relay_hint: Option<RelayUrl>,
}

/// A kind `14` chat-message rumor builder:
/// `ChatMessageOptions`. Tag order: one `p` per recipient (with relay
/// hint), then the unmarked reply `e` tag, then `subject`.
#[derive(Clone, Debug)]
pub struct ChatMessage {
    recipients: Vec<Recipient>,
    content: String,
    reply_to: Option<ReplyTo>,
    subject: Option<String>,
}

impl ChatMessage {
    /// A chat message to `recipients` with `content` (TS
    /// `buildChatMessageRumor`'s positional arguments).
    #[must_use]
    pub fn new<I: IntoIterator<Item = Recipient>>(
        recipients: I,
        content: impl Into<String>,
    ) -> Self {
        Self {
            recipients: normalize_recipients(recipients),
            content: content.into(),
            reply_to: None,
            subject: None,
        }
    }

    /// `replyTo`: the unmarked `["e", <id>, <relay-or-"">]` reply tag,
    /// appended after the `p` tags.
    #[must_use]
    pub fn reply_to(mut self, reply: ReplyTo) -> Self {
        self.reply_to = Some(reply);
        self
    }

    /// `subject`: the `["subject", <subject>]` tag, appended last.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Builds the kind `14` rumor authored by `sender` at `created_at` (TS
    /// `buildChatMessageRumor`).
    ///
    /// # Errors
    ///
    /// [`Error::Empty`] `recipients must not be empty` — NIP-17 requires at
    /// least one `p` tag.
    pub fn into_rumor(self, sender: PublicKey, created_at: Timestamp) -> Result<Rumor> {
        if self.recipients.is_empty() {
            return Err(Error::Empty("recipients must not be empty"));
        }
        let mut tags = Vec::with_capacity(self.recipients.len() + 2);
        for recipient in &self.recipients {
            tags.push(Tag::public_key(
                recipient.pubkey,
                recipient.relay_hint.as_ref(),
                None,
            ));
        }
        if let Some(reply) = &self.reply_to {
            // Kind-14 reply e-tag is unmarked and always carries the relay
            // slot: `["e", <id>, <relay-or-"">]` — `Tag::event` would omit
            // it entirely.
            tags.push(Tag::custom(
                "e",
                [
                    reply.id.to_hex(),
                    reply
                        .relay_hint
                        .as_ref()
                        .map_or_else(String::new, |url| url.as_str().to_owned()),
                ],
            ));
        }
        if let Some(subject) = &self.subject {
            tags.push(Tag::custom("subject", [subject.as_str()]));
        }
        Ok(Rumor::new(UnsignedEvent::new(
            sender,
            created_at,
            Kind::PRIVATE_DIRECT_MESSAGE,
            tags.into_iter().collect(),
            self.content,
        )))
    }
}

/// Dedupes by public key, keeping the first
/// occurrence (and its relay hint).
pub(crate) fn normalize_recipients<I: IntoIterator<Item = Recipient>>(
    recipients: I,
) -> Vec<Recipient> {
    let mut out: Vec<Recipient> = Vec::new();
    for recipient in recipients {
        if out.iter().any(|seen| seen.pubkey == recipient.pubkey) {
            continue;
        }
        out.push(recipient);
    }
    out
}

/// Wraps `rumor` once per wrap target; a
/// local `Keys`.
///
/// Targets mirror `wrapTargets(rumor.pubkey, recipients)` exactly: the
/// sender copy comes first — inheriting the relay hint when the sender
/// appears in `recipients` — followed by the recipients deduplicated by
/// public key (first occurrence kept; the sender never gets a second copy).
/// Each copy is a `seal` then `gift_wrap` of the same rumor, consuming
/// `rng` in that order per target; the wrap carries the target's relay
/// hint and `options`' ephemeral flag while TS drops `extra_tags` for
/// direct messages.
///
/// # Errors
///
/// [`Error::Empty`] `recipients must not be empty`, and any [`nip59`]
/// errors propagated per copy.
pub fn wrap_direct_message<R>(
    sender: &Keys,
    recipients: &[Recipient],
    rumor: &Rumor,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Vec<(PublicKey, Event)>>
where
    R: rand_core::TryCryptoRng + ?Sized,
{
    if recipients.is_empty() {
        return Err(Error::Empty("recipients must not be empty"));
    }
    let own = rumor.unsigned().pubkey();
    let mut targets: Vec<Recipient> = Vec::with_capacity(recipients.len() + 1);
    targets.push(Recipient {
        pubkey: own,
        relay_hint: recipients
            .iter()
            .find(|r| r.pubkey == own)
            .and_then(|r| r.relay_hint.clone()),
    });
    for recipient in recipients {
        if targets.iter().any(|t| t.pubkey == recipient.pubkey) {
            continue;
        }
        targets.push(recipient.clone());
    }
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        let seal = nip59::seal(rumor, sender, &target.pubkey, options, rng)?;
        let wrap = nip59::gift_wrap(
            &seal,
            &target.pubkey,
            &options.dm_wrap(target.relay_hint),
            rng,
        )?;
        out.push((target.pubkey, wrap));
    }
    Ok(out)
}
