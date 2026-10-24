//! Relay → client messages.

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;

use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    CountResult, Error, Result, SubscriptionId, end, event_item, parse_neg_hex, read_type,
    string_item, sub_id,
};
use crate::event::{Event, EventId, canonical};

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

const TYPES: &[&str] = &[
    "EVENT", "OK", "EOSE", "CLOSED", "NOTICE", "AUTH", "COUNT", "NEG-MSG", "NEG-ERR",
];

const fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

impl RelayMessage<'_> {
    /// The canonical NIP-01 JSON wire form.
    #[must_use]
    pub fn to_json(&self) -> String {
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
    /// The same errors as [`crate::message::ClientMessage::from_json`]
    /// except [`Error::ObsoleteNegOpen`]. `OK` requires a 64-char lowercase
    /// hex event id; `COUNT` ignores non-bool `approximate` and non-512-hex
    /// `hll` instead of failing.
    pub fn from_json(raw: &str) -> Result<RelayMessage<'static>> {
        serde_json::from_str(raw).map_err(|e| Error::InvalidJson {
            source: crate::json::JsonError::from(e),
        })
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

impl Serialize for RelayMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Event {
                subscription_id,
                event,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(&**event)?;
                seq.end()
            }
            Self::Ok {
                event_id,
                accepted,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element("OK")?;
                seq.serialize_element(event_id)?;
                seq.serialize_element(accepted)?;
                seq.serialize_element(&**message)?;
                seq.end()
            }
            Self::Eose(subscription_id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EOSE")?;
                seq.serialize_element(&**subscription_id)?;
                seq.end()
            }
            Self::Closed {
                subscription_id,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("CLOSED")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(&**message)?;
                seq.end()
            }
            Self::Notice(message) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("NOTICE")?;
                seq.serialize_element(&**message)?;
                seq.end()
            }
            Self::Auth { challenge } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(&**challenge)?;
                seq.end()
            }
            Self::Count {
                subscription_id,
                result,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("COUNT")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(result)?;
                seq.end()
            }
            Self::NegMsg {
                subscription_id,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("NEG-MSG")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(&**message)?;
                seq.end()
            }
            Self::NegErr {
                subscription_id,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("NEG-ERR")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(&**message)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RelayMessage<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = RelayMessage<'static>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a relay message array")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a message is a labelled seq of variants"
            )]
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let ty = read_type(&mut seq, TYPES)?;
                match ty {
                    "EVENT" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let event = event_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Event {
                            subscription_id: Cow::Owned(subscription_id),
                            event: Cow::Owned(event),
                        })
                    }
                    "OK" => {
                        let event_id = seq
                            .next_element::<EventId>()?
                            .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))?;
                        let accepted = seq
                            .next_element::<bool>()?
                            .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))?;
                        let message = string_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Ok {
                            event_id,
                            accepted,
                            message: Cow::Owned(message),
                        })
                    }
                    "EOSE" => {
                        let id = sub_id(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Eose(Cow::Owned(id)))
                    }
                    "CLOSED" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let message = string_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Closed {
                            subscription_id: Cow::Owned(subscription_id),
                            message: Cow::Owned(message),
                        })
                    }
                    "NOTICE" => {
                        let message = string_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Notice(Cow::Owned(message)))
                    }
                    "AUTH" => {
                        let challenge = string_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Auth {
                            challenge: Cow::Owned(challenge),
                        })
                    }
                    "COUNT" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let result = seq
                            .next_element::<CountResult>()?
                            .ok_or_else(|| DeError::custom(Error::InvalidMessage { ty }))?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::Count {
                            subscription_id: Cow::Owned(subscription_id),
                            result,
                        })
                    }
                    "NEG-MSG" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let message =
                            parse_neg_hex(&string_item(&mut seq, ty)?).map_err(DeError::custom)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::NegMsg {
                            subscription_id: Cow::Owned(subscription_id),
                            message: Cow::Owned(message),
                        })
                    }
                    "NEG-ERR" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let message = string_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(RelayMessage::NegErr {
                            subscription_id: Cow::Owned(subscription_id),
                            message: Cow::Owned(message),
                        })
                    }
                    _ => Err(DeError::custom(Error::InvalidMessage { ty })),
                }
            }
        }

        deserializer.deserialize_seq(MessageVisitor)
    }
}
