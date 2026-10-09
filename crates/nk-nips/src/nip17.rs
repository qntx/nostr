//! NIP-17 private direct messages.
//!
//! Counterpart of `@qntx/nostr/nips/nip17` behind the `nip17` feature: kind
//! `10050` DM relay lists, kind `14` chat-message rumor construction, and
//! per-recipient gift wrapping built on [`crate::nip59`].
//!
//! TS drives wrapping through the injected asynchronous `Nip59Crypto`; this
//! layer mirrors the local-key flow — [`wrap_direct_message_with_rng`] and the
//! `os-rng` [`wrap_direct_message`]. A signer layer composes the same flow
//! from [`crate::nip59`]'s pure steps for remote signers.
//!
//! Errors are [`ErrorKind::Nip17`], mirroring TS `Nip17Error`; errors from the
//! NIP-59 layer keep their `Nip59`/`Crypto` kinds.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use nk_core::{
    Event, EventBuilder, EventId, Keys, Kind, PublicKey, RelayUrl, Tag, Tags, Timestamp,
    UnsignedEvent,
};

use crate::Result;
use crate::error::{Error, ErrorKind};
use crate::nip59::{self, Rumor, WrapOptions};

/// A direct-message recipient — TS `Recipient`. The relay hint goes on the
/// wrap's `p` tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Recipient {
    /// The recipient's public key.
    pub pubkey: PublicKey,
    /// Optional relay hint for the wrap's `p` tag.
    pub relay_hint: Option<RelayUrl>,
}

/// The event a chat message replies to — TS `ReplyTo`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplyTo {
    /// The replied-to event id.
    pub id: EventId,
    /// Optional relay hint for the unmarked `e` tag; absent serializes as
    /// `""`, matching TS.
    pub relay_hint: Option<RelayUrl>,
}

/// Options for [`chat_message_rumor`] — TS `ChatMessageOptions` without
/// `created_at`, which is an explicit parameter here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatMessageOptions {
    /// Optional `["subject", <subject>]` tag — appended last.
    pub subject: Option<String>,
    /// Optional unmarked `["e", <id>, <relay-or-"">]` reply tag — appended
    /// after the `p` tags.
    pub reply_to: Option<ReplyTo>,
}

/// Parses a kind `10050` DM relay list — TS `parseDmRelayList`. Each
/// `["relay", <url>]` tag's value is normalized like `normalizeRelayUrls`
/// (invalid entries skipped, first-seen dedup).
///
/// # Errors
///
/// [`ErrorKind::EventValidation`] `expected kind 10050, got <kind>` — the
/// event is not a DM relay list.
pub fn parse_dm_relay_list(event: &Event) -> Result<Vec<RelayUrl>> {
    if event.kind() != Kind::DIRECT_MESSAGE_RELAYS_LIST {
        return Err(Error::new(
            ErrorKind::EventValidation,
            alloc::format!(
                "expected kind {}, got {}",
                Kind::DIRECT_MESSAGE_RELAYS_LIST.as_u16(),
                event.kind().as_u16(),
            ),
        ));
    }
    Ok(RelayUrl::normalize_all(event.tags().iter().filter_map(
        |tag| {
            if tag.name() == "relay" {
                tag.value()
            } else {
                None
            }
        },
    )))
}

/// Encodes relay URLs as NIP-17 `["relay", <url>]` tags — TS
/// `dmRelayListToTags`. Entries are normalized; empty and invalid entries are
/// skipped, results deduplicated in first-seen order.
#[must_use]
pub fn dm_relay_list_tags<I, S>(relays: I) -> Tags
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    RelayUrl::normalize_all(relays)
        .iter()
        .map(|url| Tag::custom("relay", [url.as_str()]))
        .collect()
}

/// Builds an unsigned kind `10050` template — TS `dmRelayListEventBuilder`.
/// NIP-17 requires at least one relay tag.
///
/// # Errors
///
/// [`ErrorKind::Nip17`] `DM relay list requires at least one relay` — no
/// usable relay URL was given.
pub fn dm_relay_list<I, S>(relays: I) -> Result<EventBuilder>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let tags = dm_relay_list_tags(relays);
    if tags.is_empty() {
        return Err(Error::new(
            ErrorKind::Nip17,
            "DM relay list requires at least one relay",
        ));
    }
    Ok(EventBuilder::new(Kind::DIRECT_MESSAGE_RELAYS_LIST, "").tags(tags))
}

/// TS `normalizeRecipients`: dedupes by public key, keeping the first
/// occurrence (and its relay hint).
#[must_use]
pub fn normalize_recipients<I: IntoIterator<Item = Recipient>>(recipients: I) -> Vec<Recipient> {
    let mut out: Vec<Recipient> = Vec::new();
    for recipient in recipients {
        if out.iter().any(|seen| seen.pubkey == recipient.pubkey) {
            continue;
        }
        out.push(recipient);
    }
    out
}

/// Builds a kind `14` chat-message rumor — TS `buildChatMessageRumor`. Tag
/// order: one `p` per recipient (with relay hint), then the unmarked reply
/// `e` tag, then `subject`.
///
/// # Errors
///
/// [`ErrorKind::Nip17`] `recipients must not be empty` — NIP-17 requires at
/// least one `p` tag.
pub fn chat_message_rumor(
    sender: PublicKey,
    recipients: &[Recipient],
    content: &str,
    created_at: Timestamp,
    options: &ChatMessageOptions,
) -> Result<Rumor> {
    if recipients.is_empty() {
        return Err(Error::new(ErrorKind::Nip17, "recipients must not be empty"));
    }
    let mut tags = Vec::with_capacity(recipients.len() + 2);
    for recipient in recipients {
        tags.push(Tag::public_key(
            recipient.pubkey,
            recipient.relay_hint.as_ref(),
            None,
        ));
    }
    if let Some(reply) = &options.reply_to {
        // Kind-14 reply e-tag is unmarked and always carries the relay slot:
        // `["e", <id>, <relay-or-"">]` — `Tag::event` would omit it entirely.
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
    if let Some(subject) = &options.subject {
        tags.push(Tag::custom("subject", [subject.as_str()]));
    }
    Ok(Rumor::new(UnsignedEvent::new(
        sender,
        created_at,
        Kind::PRIVATE_DIRECT_MESSAGE,
        tags.into_iter().collect(),
        content,
    )))
}

/// Wraps `rumor` once per wrap target — TS `wrapDirectMessage` driven by a
/// local `Keys`.
///
/// Targets mirror `wrapTargets(rumor.pubkey, recipients)` exactly: the sender
/// copy comes first — inheriting the relay hint when the sender appears in
/// `recipients` — followed by the recipients deduplicated by public key
/// (first occurrence kept; the sender never gets a second copy). Each copy
/// is a [`nip59::seal_with_rng`] then [`nip59::gift_wrap_with_rng`] of the
/// same rumor, consuming `rng` in that order per target; the wrap carries the
/// target's relay hint and `options`' ephemeral flag while TS drops
/// `extra_tags` for direct messages.
///
/// # Errors
///
/// [`ErrorKind::Nip17`] `recipients must not be empty`, and any
/// [`seal`/`gift_wrap` errors](nip59) propagated per copy.
pub fn wrap_direct_message_with_rng<R>(
    sender: &Keys,
    recipients: &[Recipient],
    rumor: &Rumor,
    options: &WrapOptions,
    rng: &mut R,
) -> Result<Vec<(PublicKey, Event)>>
where
    R: rand_core::CryptoRng + ?Sized,
{
    if recipients.is_empty() {
        return Err(Error::new(ErrorKind::Nip17, "recipients must not be empty"));
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
        let seal = nip59::seal_with_rng(rumor, sender, &target.pubkey, options, rng)?;
        let wrap = nip59::gift_wrap_with_rng(
            &seal,
            &target.pubkey,
            &options.dm_wrap(target.relay_hint),
            rng,
        )?;
        out.push((target.pubkey, wrap));
    }
    Ok(out)
}

/// [`wrap_direct_message_with_rng`] with OS-entropy randomness.
///
/// # Errors
///
/// See [`wrap_direct_message_with_rng`].
///
/// # Panics
///
/// When the OS entropy source fails — the same contract as
/// [`nk_core::Keys::generate`].
#[cfg(feature = "os-rng")]
pub fn wrap_direct_message(
    sender: &Keys,
    recipients: &[Recipient],
    rumor: &Rumor,
    options: &WrapOptions,
) -> Result<Vec<(PublicKey, Event)>> {
    wrap_direct_message_with_rng(
        sender,
        recipients,
        rumor,
        options,
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use nk_core::SecretKey;

    use super::*;
    use crate::nip59::Timestamps;

    struct FixedRng {
        next: u8,
    }

    impl rand_core::TryRng for FixedRng {
        type Error = rand_core::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst.iter_mut() {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for FixedRng {}

    fn keys(byte: u8) -> Keys {
        Keys::new(SecretKey::from_bytes([byte; 32]).unwrap())
    }

    fn recipient(keys: &Keys, relay: Option<&str>) -> Recipient {
        Recipient {
            pubkey: keys.public_key(),
            relay_hint: relay.map(|r| RelayUrl::parse(r).unwrap()),
        }
    }

    fn options() -> WrapOptions {
        WrapOptions::new(Timestamps::Fixed {
            seal: Timestamp::from_secs(1_700_000_100),
            wrap: Timestamp::from_secs(1_700_000_200),
        })
    }

    fn rumor(sender: &Keys) -> Rumor {
        Rumor::new(UnsignedEvent::new(
            sender.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::PRIVATE_DIRECT_MESSAGE,
            Tags::new(),
            "hi",
        ))
    }

    #[test]
    fn dm_relay_list_round_trips() {
        let builder = dm_relay_list([
            "wss://relay.example.com/",
            "relay.example.com",
            "wss://other.example.com/path",
        ])
        .unwrap();
        let unsigned = builder.build_at(keys(0x11).public_key(), Timestamp::from_secs(1));
        let tags: Vec<&[String]> = unsigned.tags().iter().map(Tag::as_slice).collect();
        assert_eq!(
            tags,
            [
                ["relay", "wss://relay.example.com/"].as_slice(),
                ["relay", "wss://other.example.com/path"].as_slice(),
            ]
        );
    }

    #[test]
    fn dm_relay_list_rejects_empty() {
        let error = dm_relay_list(["not a url", ""]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Nip17);
        assert_eq!(
            error.to_string(),
            "nip17: DM relay list requires at least one relay"
        );
    }

    #[test]
    fn parse_dm_relay_list_filters_and_normalizes() {
        let author = keys(0x11);
        let unsigned = EventBuilder::new(Kind::DIRECT_MESSAGE_RELAYS_LIST, "")
            .tags([
                Tag::custom("relay", ["wss://a.example.com"]),
                Tag::custom("relay", ["not a url"]),
                Tag::custom("relay", ["wss://a.example.com/"]),
                Tag::custom("x", ["ignored"]),
            ])
            .build_at(author.public_key(), Timestamp::from_secs(1));
        let event = author.sign_event_with_aux(unsigned, &[0x42; 32]).unwrap();
        let urls = parse_dm_relay_list(&event).unwrap();
        assert_eq!(urls, [RelayUrl::parse("wss://a.example.com/").unwrap()]);
    }

    #[test]
    fn parse_dm_relay_list_rejects_wrong_kind() {
        let author = keys(0x11);
        let unsigned = EventBuilder::new(Kind::TEXT_NOTE, "")
            .build_at(author.public_key(), Timestamp::from_secs(1));
        let event = author.sign_event_with_aux(unsigned, &[0x42; 32]).unwrap();
        let error = parse_dm_relay_list(&event).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::EventValidation);
        assert_eq!(
            error.to_string(),
            "event validation: expected kind 10050, got 1"
        );
    }

    #[test]
    fn normalize_recipients_dedupes_first_seen() {
        let a = keys(0x21);
        let b = keys(0x22);
        let relay = "wss://relay.example.com/";
        let out = normalize_recipients([
            recipient(&a, None),
            recipient(&b, Some(relay)),
            recipient(&a, Some(relay)),
            recipient(&b, None),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out.first().map(|r| r.pubkey), Some(a.public_key()));
        assert_eq!(
            out.first().and_then(|r| r.relay_hint.as_ref()),
            None,
            "first occurrence wins"
        );
        assert_eq!(
            out.get(1)
                .and_then(|r| r.relay_hint.as_ref().map(RelayUrl::as_str)),
            Some("wss://relay.example.com/")
        );
    }

    #[test]
    fn chat_message_rumor_tag_order() {
        let sender = keys(0x31);
        let a = keys(0x32);
        let b = keys(0x33);
        let reply = EventId::from_slice(&[0x44; 32]).unwrap();
        let rumor = chat_message_rumor(
            sender.public_key(),
            &[
                recipient(&a, Some("wss://relay.example.com/")),
                recipient(&b, None),
            ],
            "hello",
            Timestamp::from_secs(1_700_000_000),
            &ChatMessageOptions {
                subject: Some(String::from("catch up")),
                reply_to: Some(ReplyTo {
                    id: reply,
                    relay_hint: None,
                }),
            },
        )
        .unwrap();
        let tags: Vec<&[String]> = rumor.unsigned().tags().iter().map(Tag::as_slice).collect();
        assert_eq!(
            tags,
            [
                [
                    "p",
                    a.public_key().to_hex().as_str(),
                    "wss://relay.example.com/"
                ]
                .as_slice(),
                ["p", b.public_key().to_hex().as_str()].as_slice(),
                ["e", reply.to_hex().as_str(), ""].as_slice(),
                ["subject", "catch up"].as_slice(),
            ]
        );
        assert_eq!(rumor.unsigned().kind(), Kind::PRIVATE_DIRECT_MESSAGE);
        assert_eq!(rumor.unsigned().pubkey(), sender.public_key());
    }

    #[test]
    fn chat_message_rumor_rejects_empty() {
        let error = chat_message_rumor(
            keys(0x31).public_key(),
            &[],
            "hi",
            Timestamp::from_secs(1),
            &ChatMessageOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Nip17);
        assert_eq!(error.to_string(), "nip17: recipients must not be empty");
    }

    #[test]
    fn wrap_direct_message_self_copy_first_and_dedupes() {
        let sender = keys(0x41);
        let a = keys(0x42);
        let b = keys(0x43);
        let rumor = rumor(&sender);
        let mut rng = FixedRng { next: 0x07 };
        let out = wrap_direct_message_with_rng(
            &sender,
            &[
                recipient(&a, None),
                recipient(&sender, Some("wss://self.example.com/")),
                recipient(&b, None),
                recipient(&a, Some("wss://dup.example.com/")),
            ],
            &rumor,
            &options(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out.first().map(|(pk, _)| *pk), Some(sender.public_key()));
        // The self copy inherits the sender's own relay hint, and the wrap
        // `p` tag carries it; duplicates and the sender produce no copies.
        let self_tags: Vec<&[String]> = out
            .first()
            .unwrap()
            .1
            .tags()
            .iter()
            .map(Tag::as_slice)
            .collect();
        assert_eq!(
            self_tags,
            [[
                "p",
                sender.public_key().to_hex().as_str(),
                "wss://self.example.com/"
            ]
            .as_slice()]
        );
        let rest: Vec<PublicKey> = out.iter().skip(1).map(|(pk, _)| *pk).collect();
        assert_eq!(rest, [a.public_key(), b.public_key()]);
        // Every wrap unwraps to the same rumor for its recipient.
        for (pk, wrap) in &out {
            let recipient_keys = if *pk == sender.public_key() {
                sender.clone()
            } else if *pk == a.public_key() {
                a.clone()
            } else {
                b.clone()
            };
            assert_eq!(nip59::unwrap(wrap, &recipient_keys).unwrap(), rumor);
        }
    }

    #[test]
    fn wrap_direct_message_rejects_empty() {
        let sender = keys(0x41);
        let mut rng = FixedRng { next: 0x07 };
        let error =
            wrap_direct_message_with_rng(&sender, &[], &rumor(&sender), &options(), &mut rng)
                .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Nip17);
        assert_eq!(error.to_string(), "nip17: recipients must not be empty");
    }
}
