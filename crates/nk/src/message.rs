//! Client and relay wire messages (NIP-01, NIP-42, NIP-45, NIP-77) — the
//! counterpart of `core/message.ts`.
//!
//! `encode` is byte-identical to `encodeClientMessage`/`encodeRelayMessage`
//! (filters and events go through the canonical writer); `parse` applies the
//! NIP-01 parse table from `docs/nk/api/nk-core.mdx` and rulings 5–6 of
//! NK-ADR-012: subscription ids are validated in both directions (1..=64
//! Unicode scalar values) and the `OK` event id must be 64 lowercase hex.
//! Every parse failure is [`ErrorKind::Message`].

use alloc::borrow::Cow;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical;
use crate::error::{Error, ErrorKind, Result};
use crate::event::{Event, EventId};
use crate::filter::Filter;
use crate::hex;
use crate::limits::SUBSCRIPTION_ID_MAX_CHARS;

/// A NIP-01 subscription id: 1..=64 Unicode scalar values.
#[cfg_attr(not(feature = "os-rng"), doc = "```compile_fail")]
#[cfg_attr(
    not(feature = "os-rng"),
    doc = "let _ = nk::SubscriptionId::generate();"
)]
#[cfg_attr(not(feature = "os-rng"), doc = "```")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Validates `id`; fails when empty or longer than 64 scalar values.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Message`] when the length is outside `1..=64`.
    pub fn new<S>(id: S) -> Result<Self>
    where
        S: Into<String>,
    {
        let id = id.into();
        let len = id.chars().count();
        if len == 0 || len > SUBSCRIPTION_ID_MAX_CHARS {
            return Err(Error::new(
                ErrorKind::Message,
                alloc::format!("subscription id length must be 1..{SUBSCRIPTION_ID_MAX_CHARS}"),
            ));
        }
        Ok(Self(id))
    }

    /// A random 16-hex-char subscription id (TS `createSubscriptionId`).
    pub fn generate_with_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + ?Sized,
    {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        Self(hex::encode(&bytes))
    }

    /// A random subscription id from the OS RNG.
    ///
    /// # Panics
    ///
    /// Panics when the OS random source fails. Callers that must handle
    /// entropy failure use [`Self::generate_with_rng`] with their own source.
    #[cfg(feature = "os-rng")]
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::UnwrapErr(getrandom::SysRng))
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for SubscriptionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for SubscriptionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubscriptionId {
    /// Deserializes a string and validates the 1..=64 scalar-value bound.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// A NIP-45 `HyperLogLog` sketch: 256 registers as a 512-char lowercase hex
/// string on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CountHll([u8; 256]);

impl CountHll {
    /// The all-zero sketch (merge identity).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0; 256])
    }

    /// Register-wise maximum of `self` and `other` (NIP-45 sketch merge).
    pub fn merge(&mut self, other: &Self) {
        for (slot, byte) in self.0.iter_mut().zip(other.0) {
            *slot = (*slot).max(byte);
        }
    }
}

impl FromStr for CountHll {
    type Err = Error;

    /// Parses a 512-char hex string of any case (lowercase on display).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Message`] when `s` is not 512 hex characters (matching
    /// the `MessageError` thrown by TS `mergeCountHll`).
    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 512 {
            return Err(Error::new(
                ErrorKind::Message,
                "invalid NIP-45 HLL sketch: expected 512-char hex",
            ));
        }
        hex::decode_caller::<256>(s).map(Self).map_err(|_| {
            Error::new(
                ErrorKind::Message,
                "invalid NIP-45 HLL sketch: expected 512-char hex",
            )
        })
    }
}

impl fmt::Display for CountHll {
    /// The lowercase 512-char hex form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl Serialize for CountHll {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&alloc::format!("{self}"))
    }
}

impl<'de> Deserialize<'de> for CountHll {
    /// Deserializes a 512-char hex string of any case.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// A relay `COUNT` reply payload (NIP-45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountResult {
    /// The reported count.
    pub count: u64,
    /// `true` when the count is an estimate (ignored on parse when not a bool).
    pub approximate: Option<bool>,
    /// The optional HLL sketch (ignored on parse when not 512-hex).
    pub hll: Option<CountHll>,
}

/// Client → relay messages (NIP-01 + NIP-42 AUTH + NIP-45 COUNT + NIP-77).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage<'a> {
    /// `["EVENT", <event>]` — publish a signed event.
    Event(Cow<'a, Event>),
    /// `["REQ", <id>, <filter>, ...]` — open a subscription.
    Req {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// At least one filter on the wire; `encode` of an empty slice emits
        /// `["REQ","<id>"]` unchanged.
        filters: Cow<'a, [Filter]>,
    },
    /// `["COUNT", <id>, <filter>, ...]` — a NIP-45 count request.
    Count {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// Same rules as [`ClientMessage::Req::filters`].
        filters: Cow<'a, [Filter]>,
    },
    /// `["CLOSE", <id>]` — close a subscription.
    Close(Cow<'a, SubscriptionId>),
    /// `["AUTH", <event>]` — a NIP-42 kind-22242 auth event.
    Auth(Cow<'a, Event>),
    /// `["NEG-OPEN", <id>, <filter>, <hex>]` — open a NIP-77 sync.
    NegOpen {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The sync filter.
        filter: Cow<'a, Filter>,
        /// The initial negentropy message (non-empty, even-length hex).
        message: Cow<'a, str>,
    },
    /// `["NEG-MSG", <id>, <hex>]` — continue a NIP-77 sync.
    NegMsg {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The negentropy message (non-empty, even-length hex).
        message: Cow<'a, str>,
    },
    /// `["NEG-CLOSE", <id>]` — end a NIP-77 sync.
    NegClose(Cow<'a, SubscriptionId>),
}

/// Relay → client messages.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayMessage<'a> {
    /// `["EVENT", <id>, <event>]` — an event matching a subscription.
    Event {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The signed event.
        event: Cow<'a, Event>,
    },
    /// `["OK", <event id>, <accepted>, <message>]`.
    Ok {
        /// The acknowledged event id (64 lowercase hex on the wire).
        event_id: EventId,
        /// Whether the relay stored the event.
        accepted: bool,
        /// The machine-readable prefix + human-readable detail.
        message: Cow<'a, str>,
    },
    /// `["EOSE", <id>]` — end of stored events.
    Eose(Cow<'a, SubscriptionId>),
    /// `["CLOSED", <id>, <message>]` — subscription closed by the relay.
    Closed {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The machine-readable prefix + human-readable detail.
        message: Cow<'a, str>,
    },
    /// `["NOTICE", <message>]` — a free-form notice.
    Notice(Cow<'a, str>),
    /// `["AUTH", <challenge>]` — a NIP-42 auth challenge.
    Auth {
        /// The challenge string.
        challenge: Cow<'a, str>,
    },
    /// `["COUNT", <id>, <result>]` — a NIP-45 count reply.
    Count {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The count payload.
        result: CountResult,
    },
    /// `["NEG-MSG", <id>, <hex>]` — a NIP-77 sync answer.
    NegMsg {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The negentropy message (non-empty, even-length hex).
        message: Cow<'a, str>,
    },
    /// `["NEG-ERR", <id>, <message>]` — a NIP-77 sync failure.
    NegErr {
        /// Subscription id.
        subscription_id: Cow<'a, SubscriptionId>,
        /// The error detail.
        message: Cow<'a, str>,
    },
}

const fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn msg_error(message: impl Into<Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Message, message)
}

/// `fail` becomes an owned copy inside the error.
fn fail_msg(fail: &str) -> Error {
    msg_error(fail.to_owned())
}

/// The subscription id at `index`, validated to 1..=64 scalar values.
fn parse_sub_id(items: &[serde_json::Value], index: usize, fail: &str) -> Result<SubscriptionId> {
    items
        .get(index)
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| Err(fail_msg(fail)), SubscriptionId::new)
}

/// A non-empty, even-length hex string, lowercased.
fn parse_neg_hex(item: Option<&serde_json::Value>, fail: &str) -> Result<String> {
    let Some(raw) = item.and_then(serde_json::Value::as_str) else {
        return Err(fail_msg(fail));
    };
    if raw.is_empty() || raw.len() % 2 != 0 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(fail_msg(fail));
    }
    Ok(raw.to_lowercase())
}

fn parse_event(item: Option<&serde_json::Value>, fail: &str) -> Result<Event> {
    let Some(item) = item else {
        return Err(fail_msg(fail));
    };
    Event::deserialize(item)
        .map_err(|source| Error::with_source(ErrorKind::Message, fail.to_owned(), source))
}

fn parse_filter(item: Option<&serde_json::Value>, fail: &str) -> Result<Filter> {
    let Some(item) = item else {
        return Err(fail_msg(fail));
    };
    Filter::deserialize(item)
        .map_err(|source| Error::with_source(ErrorKind::Message, fail.to_owned(), source))
}

/// Splits `raw` into the message type and the remaining items.
fn parse_wire(raw: &str, side: &'static str) -> Result<(String, Vec<serde_json::Value>)> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|source| {
        Error::with_source(
            ErrorKind::Message,
            alloc::format!("{side} message is not valid JSON"),
            source,
        )
    })?;
    let serde_json::Value::Array(items) = value else {
        return Err(msg_error(alloc::format!(
            "{side} message must be a non-empty JSON array"
        )));
    };
    let mut items = items.into_iter();
    let Some(kind) = items.next().and_then(|v| v.as_str().map(str::to_owned)) else {
        return Err(msg_error(alloc::format!(
            "{side} message must be a non-empty JSON array"
        )));
    };
    Ok((kind, items.collect()))
}

impl ClientMessage<'_> {
    /// The NIP-01 JSON wire form — byte-identical to `encodeClientMessage`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Event(event) => {
                out.push_str("[\"EVENT\",");
                canonical::write_signed(event, &mut out);
                out.push(']');
            }
            Self::Req {
                subscription_id,
                filters,
            }
            | Self::Count {
                subscription_id,
                filters,
            } => {
                let kind = if matches!(self, Self::Req { .. }) {
                    "REQ"
                } else {
                    "COUNT"
                };
                out.push_str("[\"");
                out.push_str(kind);
                out.push_str("\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                for filter in filters.iter() {
                    out.push(',');
                    filter.write_canonical(&mut out);
                }
                out.push(']');
            }
            Self::Close(subscription_id) => {
                out.push_str("[\"CLOSE\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(']');
            }
            Self::Auth(event) => {
                out.push_str("[\"AUTH\",");
                canonical::write_signed(event, &mut out);
                out.push(']');
            }
            Self::NegOpen {
                subscription_id,
                filter,
                message,
            } => {
                out.push_str("[\"NEG-OPEN\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                filter.write_canonical(&mut out);
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::NegMsg {
                subscription_id,
                message,
            } => {
                out.push_str("[\"NEG-MSG\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::NegClose(subscription_id) => {
                out.push_str("[\"NEG-CLOSE\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(']');
            }
        }
        out
    }

    /// Parses a client → relay JSON message.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Message`] on any malformed input (not a JSON array,
    /// unknown type, wrong arity/types, invalid filter, bad subscription id,
    /// or malformed NEG hex).
    pub fn parse(raw: &str) -> Result<ClientMessage<'static>> {
        let (kind, items) = parse_wire(raw, "client")?;
        let fail = alloc::format!("invalid {kind} client message");
        match kind.as_str() {
            "EVENT" if items.len() == 1 => Ok(ClientMessage::Event(Cow::Owned(parse_event(
                items.first(),
                "invalid EVENT client message",
            )?))),
            "REQ" | "COUNT" if !items.is_empty() => {
                let subscription_id = parse_sub_id(&items, 0, &fail)?;
                let filters: Vec<Filter> = items
                    .iter()
                    .skip(1)
                    .map(|item| parse_filter(Some(item), "invalid REQ/COUNT filter"))
                    .collect::<Result<_>>()?;
                if filters.is_empty() {
                    return Err(msg_error(fail));
                }
                let filters = Cow::Owned(filters);
                Ok(if kind == "REQ" {
                    ClientMessage::Req {
                        subscription_id: Cow::Owned(subscription_id),
                        filters,
                    }
                } else {
                    ClientMessage::Count {
                        subscription_id: Cow::Owned(subscription_id),
                        filters,
                    }
                })
            }
            "CLOSE" if items.len() == 1 => Ok(ClientMessage::Close(Cow::Owned(parse_sub_id(
                &items, 0, &fail,
            )?))),
            "AUTH" if items.len() == 1 => Ok(ClientMessage::Auth(Cow::Owned(parse_event(
                items.first(),
                "invalid AUTH client message",
            )?))),
            "NEG-OPEN" if items.len() == 4 => Err(msg_error(
                "obsolete 5-element NEG-OPEN; expected [NEG-OPEN, id, filter, hex]",
            )),
            "NEG-OPEN" if items.len() == 3 => {
                let subscription_id = parse_sub_id(&items, 0, &fail)?;
                let filter = parse_filter(items.get(1), "invalid NEG-OPEN filter")?;
                let message = parse_neg_hex(items.get(2), &fail)?;
                Ok(ClientMessage::NegOpen {
                    subscription_id: Cow::Owned(subscription_id),
                    filter: Cow::Owned(filter),
                    message: Cow::Owned(message),
                })
            }
            "NEG-MSG" if items.len() == 2 => Ok(ClientMessage::NegMsg {
                subscription_id: Cow::Owned(parse_sub_id(&items, 0, &fail)?),
                message: Cow::Owned(parse_neg_hex(items.get(1), &fail)?),
            }),
            "NEG-CLOSE" if items.len() == 1 => Ok(ClientMessage::NegClose(Cow::Owned(
                parse_sub_id(&items, 0, &fail)?,
            ))),
            "EVENT" | "REQ" | "COUNT" | "CLOSE" | "AUTH" | "NEG-OPEN" | "NEG-MSG" | "NEG-CLOSE" => {
                Err(msg_error(fail))
            }
            _ => Err(msg_error(alloc::format!(
                "unknown client message type: {kind}"
            ))),
        }
    }

    /// Converts every borrowed field to owned, giving a `'static` message.
    #[must_use]
    pub fn into_owned(self) -> ClientMessage<'static> {
        match self {
            Self::Event(event) => ClientMessage::Event(Cow::Owned(event.into_owned())),
            Self::Req {
                subscription_id,
                filters,
            } => ClientMessage::Req {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                filters: Cow::Owned(filters.into_owned()),
            },
            Self::Count {
                subscription_id,
                filters,
            } => ClientMessage::Count {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                filters: Cow::Owned(filters.into_owned()),
            },
            Self::Close(id) => ClientMessage::Close(Cow::Owned(id.into_owned())),
            Self::Auth(event) => ClientMessage::Auth(Cow::Owned(event.into_owned())),
            Self::NegOpen {
                subscription_id,
                filter,
                message,
            } => ClientMessage::NegOpen {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                filter: Cow::Owned(filter.into_owned()),
                message: Cow::Owned(message.into_owned()),
            },
            Self::NegMsg {
                subscription_id,
                message,
            } => ClientMessage::NegMsg {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                message: Cow::Owned(message.into_owned()),
            },
            Self::NegClose(id) => ClientMessage::NegClose(Cow::Owned(id.into_owned())),
        }
    }
}

impl RelayMessage<'_> {
    /// The NIP-01 JSON wire form — byte-identical to `encodeRelayMessage`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Event {
                subscription_id,
                event,
            } => {
                out.push_str("[\"EVENT\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                canonical::write_signed(event, &mut out);
                out.push(']');
            }
            Self::Ok {
                event_id,
                accepted,
                message,
            } => {
                out.push_str("[\"OK\",\"");
                canonical::push_hex(event_id.as_bytes(), &mut out);
                out.push_str("\",");
                out.push_str(bool_str(*accepted));
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::Eose(subscription_id) => {
                out.push_str("[\"EOSE\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(']');
            }
            Self::Closed {
                subscription_id,
                message,
            } => {
                out.push_str("[\"CLOSED\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::Notice(message) => {
                out.push_str("[\"NOTICE\",");
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::Auth { challenge } => {
                out.push_str("[\"AUTH\",");
                canonical::push_json_string(challenge, &mut out);
                out.push(']');
            }
            Self::Count {
                subscription_id,
                result,
            } => {
                out.push_str("[\"COUNT\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push_str(",{\"count\":");
                canonical::push_u64(result.count, &mut out);
                if let Some(approximate) = result.approximate {
                    out.push_str(",\"approximate\":");
                    out.push_str(bool_str(approximate));
                }
                if let Some(hll) = &result.hll {
                    out.push_str(",\"hll\":\"");
                    canonical::push_hex(&hll.0, &mut out);
                    out.push('"');
                }
                out.push_str("}]");
            }
            Self::NegMsg {
                subscription_id,
                message,
            } => {
                out.push_str("[\"NEG-MSG\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
            Self::NegErr {
                subscription_id,
                message,
            } => {
                out.push_str("[\"NEG-ERR\",");
                canonical::push_json_string(subscription_id.as_str(), &mut out);
                out.push(',');
                canonical::push_json_string(message, &mut out);
                out.push(']');
            }
        }
        out
    }

    /// Parses a relay → client JSON message.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Message`] on any malformed input. `OK` requires a 64-char
    /// lowercase hex event id (NK-ADR-012 ruling 5); `COUNT` ignores
    /// non-bool `approximate` and non-512-hex `hll` instead of failing.
    pub fn parse(raw: &str) -> Result<RelayMessage<'static>> {
        let (kind, items) = parse_wire(raw, "relay")?;
        let fail = alloc::format!("invalid {kind} relay message");
        match kind.as_str() {
            "EVENT" if items.len() == 2 => Ok(RelayMessage::Event {
                subscription_id: Cow::Owned(parse_sub_id(&items, 0, &fail)?),
                event: Cow::Owned(parse_event(items.get(1), "invalid EVENT relay message")?),
            }),
            "OK" if items.len() == 3 => {
                let event_id = items
                    .first()
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| {
                        EventId::deserialize(serde_json::Value::String(text.to_owned())).ok()
                    })
                    .ok_or_else(|| msg_error("invalid OK relay message"))?;
                let Some(accepted) = items.get(1).and_then(serde_json::Value::as_bool) else {
                    return Err(msg_error("invalid OK relay message"));
                };
                let Some(message) = items.get(2).and_then(serde_json::Value::as_str) else {
                    return Err(msg_error("invalid OK relay message"));
                };
                Ok(RelayMessage::Ok {
                    event_id,
                    accepted,
                    message: Cow::Owned(message.to_owned()),
                })
            }
            "EOSE" if items.len() == 1 => Ok(RelayMessage::Eose(Cow::Owned(parse_sub_id(
                &items, 0, &fail,
            )?))),
            "CLOSED" if items.len() == 2 => {
                let subscription_id = parse_sub_id(&items, 0, &fail)?;
                let Some(message) = items.get(1).and_then(serde_json::Value::as_str) else {
                    return Err(msg_error(fail));
                };
                Ok(RelayMessage::Closed {
                    subscription_id: Cow::Owned(subscription_id),
                    message: Cow::Owned(message.to_owned()),
                })
            }
            "NOTICE" if items.len() == 1 => {
                let Some(message) = items.first().and_then(serde_json::Value::as_str) else {
                    return Err(msg_error(fail));
                };
                Ok(RelayMessage::Notice(Cow::Owned(message.to_owned())))
            }
            "AUTH" if items.len() == 1 => {
                let Some(challenge) = items.first().and_then(serde_json::Value::as_str) else {
                    return Err(msg_error(fail));
                };
                Ok(RelayMessage::Auth {
                    challenge: Cow::Owned(challenge.to_owned()),
                })
            }
            "COUNT" if items.len() == 2 => {
                let subscription_id = parse_sub_id(&items, 0, &fail)?;
                let Some(payload) = items.get(1).and_then(serde_json::Value::as_object) else {
                    return Err(msg_error(fail));
                };
                let Some(count) = payload
                    .get("count")
                    .and_then(|v| crate::json::de_u64(v).ok())
                else {
                    return Err(msg_error(fail));
                };
                let approximate = payload
                    .get("approximate")
                    .and_then(serde_json::Value::as_bool);
                let hll = payload
                    .get("hll")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| CountHll::from_str(text).ok());
                Ok(RelayMessage::Count {
                    subscription_id: Cow::Owned(subscription_id),
                    result: CountResult {
                        count,
                        approximate,
                        hll,
                    },
                })
            }
            "NEG-MSG" if items.len() == 2 => Ok(RelayMessage::NegMsg {
                subscription_id: Cow::Owned(parse_sub_id(&items, 0, &fail)?),
                message: Cow::Owned(parse_neg_hex(items.get(1), &fail)?),
            }),
            "NEG-ERR" if items.len() == 2 || items.len() == 3 => {
                let subscription_id = parse_sub_id(&items, 0, &fail)?;
                let Some(message) = items.get(1).and_then(serde_json::Value::as_str) else {
                    return Err(msg_error(fail));
                };
                Ok(RelayMessage::NegErr {
                    subscription_id: Cow::Owned(subscription_id),
                    message: Cow::Owned(message.to_owned()),
                })
            }
            "EVENT" | "OK" | "EOSE" | "CLOSED" | "NOTICE" | "AUTH" | "COUNT" | "NEG-MSG"
            | "NEG-ERR" => Err(msg_error(fail)),
            _ => Err(msg_error(alloc::format!(
                "unknown relay message type: {kind}"
            ))),
        }
    }

    /// Converts every borrowed field to owned, giving a `'static` message.
    #[must_use]
    pub fn into_owned(self) -> RelayMessage<'static> {
        match self {
            Self::Event {
                subscription_id,
                event,
            } => RelayMessage::Event {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                event: Cow::Owned(event.into_owned()),
            },
            Self::Ok {
                event_id,
                accepted,
                message,
            } => RelayMessage::Ok {
                event_id,
                accepted,
                message: Cow::Owned(message.into_owned()),
            },
            Self::Eose(id) => RelayMessage::Eose(Cow::Owned(id.into_owned())),
            Self::Closed {
                subscription_id,
                message,
            } => RelayMessage::Closed {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                message: Cow::Owned(message.into_owned()),
            },
            Self::Notice(message) => RelayMessage::Notice(Cow::Owned(message.into_owned())),
            Self::Auth { challenge } => RelayMessage::Auth {
                challenge: Cow::Owned(challenge.into_owned()),
            },
            Self::Count {
                subscription_id,
                result,
            } => RelayMessage::Count {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                result,
            },
            Self::NegMsg {
                subscription_id,
                message,
            } => RelayMessage::NegMsg {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                message: Cow::Owned(message.into_owned()),
            },
            Self::NegErr {
                subscription_id,
                message,
            } => RelayMessage::NegErr {
                subscription_id: Cow::Owned(subscription_id.into_owned()),
                message: Cow::Owned(message.into_owned()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]
    use alloc::borrow::Cow;
    use alloc::string::ToString;

    use super::*;
    use crate::kind::Kind;

    fn signed_event() -> Event {
        let keys =
            crate::key::Keys::new(crate::key::SecretKey::from_bytes([3; 32]).expect("scalar"));
        let unsigned = crate::event::UnsignedEvent::new(
            keys.public_key(),
            crate::time::Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            crate::tag::Tags::new(),
            "gm",
        );
        keys.sign_event_with_aux(unsigned, &[1; 32]).expect("sign")
    }

    #[test]
    fn subscription_id_bounds_count_scalar_values() {
        assert!(SubscriptionId::new("").is_err());
        assert!(SubscriptionId::new("a").is_ok());
        assert_eq!(
            SubscriptionId::new("a".repeat(64))
                .expect("64 chars")
                .as_str()
                .chars()
                .count(),
            64
        );
        assert!(SubscriptionId::new("a".repeat(65)).is_err());
        // Astral characters count once each, not per UTF-16 unit.
        assert!(SubscriptionId::new("\u{1F600}".repeat(64)).is_ok());
        assert!(SubscriptionId::new("\u{1F600}".repeat(65)).is_err());
        assert_eq!(
            SubscriptionId::new("x".repeat(65)).unwrap_err().kind(),
            ErrorKind::Message
        );
    }

    #[test]
    fn subscription_id_traits_and_serde() {
        let id = SubscriptionId::new("sub").expect("valid");
        assert_eq!(id.to_string(), "sub");
        assert_eq!(id.as_ref(), "sub");
        assert_eq!(serde_json::to_string(&id).expect("ser"), "\"sub\"");
        let back: SubscriptionId = serde_json::from_str("\"sub\"").expect("de");
        assert_eq!(back, id);
        assert!(serde_json::from_str::<SubscriptionId>("\"\"").is_err());
        assert!(serde_json::from_str::<SubscriptionId>("123").is_err());
    }

    #[test]
    fn subscription_id_generate_with_rng_is_16_lower_hex() {
        struct Zero;
        impl rand_core::TryRng for Zero {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                dest.fill(0);
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Zero {}
        let id = SubscriptionId::generate_with_rng(&mut Zero);
        assert_eq!(id.as_str(), "0000000000000000");
    }

    #[test]
    fn count_hll_zero_merge_and_hex() {
        let mut a = CountHll::zero();
        assert_eq!(a.to_string(), "00".repeat(256));
        let upper = "AB".repeat(256);
        let b = CountHll::from_str(&upper).expect("any case parses");
        a.merge(&b);
        assert_eq!(a.to_string(), upper.to_lowercase());
        assert!(CountHll::from_str("ab").is_err());
        assert!(CountHll::from_str(&"zz".repeat(256)).is_err());
        assert_eq!(
            CountHll::from_str("ab").unwrap_err().kind(),
            ErrorKind::Message
        );
    }

    #[test]
    fn client_encode_matches_ts() {
        let id = SubscriptionId::new("sub").expect("id");
        let filter = Filter::new().kinds([Kind::TEXT_NOTE]);
        assert_eq!(
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            }
            .encode(),
            "[\"REQ\",\"sub\",{\"kinds\":[1]}]"
        );
        // An empty filter slice encodes as `["REQ","sub"]` per the design table.
        assert_eq!(
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(&[][..]),
            }
            .encode(),
            "[\"REQ\",\"sub\"]"
        );
        assert_eq!(
            ClientMessage::Close(Cow::Borrowed(&id)).encode(),
            "[\"CLOSE\",\"sub\"]"
        );
        assert_eq!(
            ClientMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("deadbeef"),
            }
            .encode(),
            "[\"NEG-MSG\",\"sub\",\"deadbeef\"]"
        );
        assert_eq!(
            ClientMessage::NegClose(Cow::Borrowed(&id)).encode(),
            "[\"NEG-CLOSE\",\"sub\"]"
        );
        let event = signed_event();
        let wire = ClientMessage::Event(Cow::Borrowed(&event)).encode();
        assert!(wire.starts_with("[\"EVENT\",{\"id\":\""));
        // Round-trip: parse(encode(x)) reproduces an equivalent message.
        assert_eq!(
            ClientMessage::parse(&wire).expect("parse"),
            ClientMessage::Event(Cow::Owned(event))
        );
    }

    #[test]
    fn client_parse_rules() {
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        assert!(matches!(
            ClientMessage::parse(&alloc::format!("[\"EVENT\",{event_json}]")).expect("event"),
            ClientMessage::Event(_)
        ));
        for bad in [
            "not json",
            "{}",
            "[]",
            "[42]",
            "[\"REQ\"]",
            "[\"REQ\",\"sub\"]",
            "[\"REQ\",1,{\"kinds\":[1]}]",
            "[\"REQ\",\"sub\",42]",
            "[\"REQ\",\"s\",{\"kinds\":[65536]}]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]}]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"aabb\",\"extra\"]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"abc\"]",
            "[\"NEG-OPEN\",\"s\",{\"kinds\":[1]},\"zz\"]",
            "[\"NEG-MSG\",\"s\",\"\"]",
            "[\"NEG-MSG\",\"s\",\"a\"]",
            "[\"UNKNOWN\",\"s\"]",
            "[\"CLOSE\",\"\"]",
            "[\"CLOSE\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
        ] {
            assert_eq!(
                ClientMessage::parse(bad).unwrap_err().kind(),
                ErrorKind::Message,
                "{bad}"
            );
        }
        // Uppercase NEG hex is lowercased on parse.
        let ClientMessage::NegMsg { message, .. } =
            ClientMessage::parse("[\"NEG-MSG\",\"s\",\"FF00\"]").expect("neg-msg")
        else {
            panic!("expected NegMsg");
        };
        assert_eq!(message.as_ref(), "ff00");
    }

    #[test]
    fn relay_parse_rules() {
        let event = signed_event();
        let event_json = serde_json::to_string(&event).expect("ser");
        let ok = RelayMessage::parse(&alloc::format!(
            "[\"OK\",\"{}\",true,\"saved\"]",
            event.id().to_hex()
        ))
        .expect("ok");
        assert!(matches!(ok, RelayMessage::Ok { accepted: true, .. }));
        // Ruling 5: uppercase or short ids are rejected.
        for bad in [
            "not json",
            "[\"OK\",\"id\",true,\"\"]",
            "[\"OK\",\"AAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",true,\"\"]",
            "[\"OK\",\"aaaa\",true,\"\"]",
            "[\"EOSE\",\"\"]",
            "[\"EVENT\",\"s\",{}]",
            "[\"COUNT\",\"s\",{\"count\":-1}]",
            "[\"COUNT\",\"s\",{\"count\":1.5}]",
            "[\"COUNT\",\"s\",\"x\"]",
            "[\"NEG-ERR\",\"s\"]",
        ] {
            assert_eq!(
                RelayMessage::parse(bad).unwrap_err().kind(),
                ErrorKind::Message,
                "{bad}"
            );
        }
        let relay_event =
            RelayMessage::parse(&alloc::format!("[\"EVENT\",\"s\",{event_json}]")).expect("event");
        assert!(matches!(relay_event, RelayMessage::Event { .. }));
    }

    #[test]
    fn relay_count_result_parsing() {
        // approximate/hll wrong types are ignored, not errors.
        let RelayMessage::Count { result, .. } = RelayMessage::parse(
            "[\"COUNT\",\"s\",{\"count\":7,\"approximate\":\"yes\",\"hll\":\"zz\"}]",
        )
        .expect("count") else {
            panic!("expected Count");
        };
        assert_eq!(
            result,
            CountResult {
                count: 7,
                approximate: None,
                hll: None,
            }
        );
        let RelayMessage::Count {
            result: max_result, ..
        } = RelayMessage::parse(&alloc::format!(
            "[\"COUNT\",\"s\",{{\"count\":{},\"approximate\":true,\"hll\":\"{}\"}}]",
            9_007_199_254_740_991u64,
            "ab".repeat(256).to_uppercase()
        ))
        .expect("max safe")
        else {
            panic!("expected Count");
        };
        assert_eq!(max_result.count, 9_007_199_254_740_991);
        assert_eq!(max_result.approximate, Some(true));
        assert_eq!(max_result.hll.expect("hll").to_string(), "ab".repeat(256));
        // 2^53 is rejected.
        assert!(RelayMessage::parse("[\"COUNT\",\"s\",{\"count\":9007199254740992}]").is_err());
    }

    #[test]
    fn relay_encode_matches_ts() {
        let id = SubscriptionId::new("sub").expect("id");
        let event = signed_event();
        assert_eq!(
            RelayMessage::Ok {
                event_id: event.id(),
                accepted: true,
                message: Cow::Borrowed(""),
            }
            .encode(),
            alloc::format!("[\"OK\",\"{}\",true,\"\"]", event.id().to_hex())
        );
        assert_eq!(
            RelayMessage::Eose(Cow::Borrowed(&id)).encode(),
            "[\"EOSE\",\"sub\"]"
        );
        assert_eq!(
            RelayMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                result: CountResult {
                    count: 7,
                    approximate: Some(true),
                    hll: Some(CountHll::from_str(&"ab".repeat(256)).expect("hll")),
                },
            }
            .encode(),
            alloc::format!(
                "[\"COUNT\",\"sub\",{{\"count\":7,\"approximate\":true,\"hll\":\"{}\"}}]",
                "ab".repeat(256)
            )
        );
    }

    #[test]
    fn into_owned_gives_static() {
        let id = SubscriptionId::new("sub").expect("id");
        let msg = ClientMessage::Close(Cow::Borrowed(&id));
        let owned_msg: ClientMessage<'static> = msg.into_owned();
        assert_eq!(owned_msg, ClientMessage::Close(Cow::Owned(id.clone())));
        let relay = RelayMessage::Eose(Cow::Owned(id));
        let owned_relay: RelayMessage<'static> = relay.into_owned();
        assert!(matches!(owned_relay, RelayMessage::Eose(_)));
    }

    #[test]
    #[cfg(feature = "os-rng")]
    fn subscription_id_generate_is_16_lower_hex() {
        let id = SubscriptionId::generate();
        assert_eq!(id.as_str().len(), 16);
        assert!(
            id.as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn count_hll_serde_round_trip() {
        let hll = CountHll::from_str(&"ab".repeat(256)).expect("hll");
        let json = serde_json::to_string(&hll).expect("ser");
        assert_eq!(json, alloc::format!("\"{}\"", "ab".repeat(256)));
        let back: CountHll = serde_json::from_str(&json).expect("de");
        assert_eq!(back, hll);
        // Any case parses; wrong lengths, non-hex, and non-strings fail.
        let upper: CountHll =
            serde_json::from_str(&alloc::format!("\"{}\"", "AB".repeat(256))).expect("uppercase");
        assert_eq!(upper, hll);
        assert!(serde_json::from_str::<CountHll>("\"ab\"").is_err());
        assert!(
            serde_json::from_str::<CountHll>(&alloc::format!("\"{}\"", "zz".repeat(256))).is_err()
        );
        assert!(serde_json::from_str::<CountHll>("5").is_err());
    }

    #[test]
    fn into_owned_covers_every_variant() {
        let id = SubscriptionId::new("sub").expect("id");
        let filter = Filter::new().kinds([Kind::TEXT_NOTE]);
        let event = signed_event();
        let event_id = event.id();
        let clients: [ClientMessage<'_>; 8] = [
            ClientMessage::Event(Cow::Borrowed(&event)),
            ClientMessage::Req {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            },
            ClientMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                filters: Cow::Borrowed(core::slice::from_ref(&filter)),
            },
            ClientMessage::Close(Cow::Borrowed(&id)),
            ClientMessage::Auth(Cow::Borrowed(&event)),
            ClientMessage::NegOpen {
                subscription_id: Cow::Borrowed(&id),
                filter: Cow::Borrowed(&filter),
                message: Cow::Borrowed("aabb"),
            },
            ClientMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
            ClientMessage::NegClose(Cow::Borrowed(&id)),
        ];
        for message in clients {
            let encoded = message.encode();
            let owned: ClientMessage<'static> = message.into_owned();
            assert_eq!(owned.encode(), encoded);
        }
        let relays: [RelayMessage<'_>; 9] = [
            RelayMessage::Event {
                subscription_id: Cow::Borrowed(&id),
                event: Cow::Borrowed(&event),
            },
            RelayMessage::Ok {
                event_id,
                accepted: true,
                message: Cow::Borrowed("m"),
            },
            RelayMessage::Eose(Cow::Borrowed(&id)),
            RelayMessage::Closed {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("m"),
            },
            RelayMessage::Notice(Cow::Borrowed("n")),
            RelayMessage::Auth {
                challenge: Cow::Borrowed("c"),
            },
            RelayMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                result: CountResult {
                    count: 1,
                    approximate: Some(true),
                    hll: Some(CountHll::zero()),
                },
            },
            RelayMessage::NegMsg {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
            RelayMessage::NegErr {
                subscription_id: Cow::Borrowed(&id),
                message: Cow::Borrowed("aabb"),
            },
        ];
        for message in relays {
            let encoded = message.encode();
            let owned: RelayMessage<'static> = message.into_owned();
            assert_eq!(owned.encode(), encoded);
        }
    }

    #[test]
    fn types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SubscriptionId>();
        assert_send_sync::<CountHll>();
        assert_send_sync::<CountResult>();
        assert_send_sync::<ClientMessage<'static>>();
        assert_send_sync::<RelayMessage<'static>>();
    }
}
