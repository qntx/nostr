//! Client → relay messages (NIP-01 + NIP-42 AUTH + NIP-45 COUNT + NIP-77).

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    Error, Result, SubscriptionId, end, event_item, filter_item, parse_neg_hex, read_type,
    string_item, sub_id,
};
use crate::event::{Event, canonical};
use crate::filter::Filter;

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

const TYPES: &[&str] = &[
    "EVENT",
    "REQ",
    "COUNT",
    "CLOSE",
    "AUTH",
    "NEG-OPEN",
    "NEG-MSG",
    "NEG-CLOSE",
];

impl ClientMessage<'_> {
    /// The canonical NIP-01 JSON wire form.
    #[must_use]
    pub fn to_json(&self) -> String {
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
    /// [`Error::InvalidJson`] when the text is not JSON,
    /// [`Error::NotAMessageArray`] when it is not a non-empty array starting
    /// with the type string, [`Error::UnknownType`] for an unrecognized
    /// type, [`Error::InvalidMessage`] for wrong arity or field types,
    /// [`Error::InvalidPayload`] when an embedded event or filter fails
    /// wire validation, [`Error::InvalidSubscriptionId`] for a bad
    /// subscription id, [`Error::ObsoleteNegOpen`] for the 5-element
    /// `NEG-OPEN`, and [`Error::InvalidNegMessage`] for malformed NEG hex.
    pub fn from_json(raw: &str) -> Result<ClientMessage<'static>> {
        serde_json::from_str(raw).map_err(|e| Error::InvalidJson {
            source: crate::json::JsonError::from(e),
        })
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

impl Serialize for ClientMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Event(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(&**event)?;
                seq.end()
            }
            Self::Req {
                subscription_id,
                filters,
            }
            | Self::Count {
                subscription_id,
                filters,
            } => {
                let ty = if matches!(self, Self::Req { .. }) {
                    "REQ"
                } else {
                    "COUNT"
                };
                let mut seq = serializer.serialize_seq(Some(2 + filters.len()))?;
                seq.serialize_element(ty)?;
                seq.serialize_element(&**subscription_id)?;
                for filter in filters.iter() {
                    seq.serialize_element(filter)?;
                }
                seq.end()
            }
            Self::Close(subscription_id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("CLOSE")?;
                seq.serialize_element(&**subscription_id)?;
                seq.end()
            }
            Self::Auth(event) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(&**event)?;
                seq.end()
            }
            Self::NegOpen {
                subscription_id,
                filter,
                message,
            } => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element("NEG-OPEN")?;
                seq.serialize_element(&**subscription_id)?;
                seq.serialize_element(&**filter)?;
                seq.serialize_element(&**message)?;
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
            Self::NegClose(subscription_id) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("NEG-CLOSE")?;
                seq.serialize_element(&**subscription_id)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ClientMessage<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = ClientMessage<'static>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a client message array")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a message is a labelled seq of variants"
            )]
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let ty = read_type(&mut seq, TYPES)?;
                match ty {
                    "EVENT" => {
                        let event = event_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(ClientMessage::Event(Cow::Owned(event)))
                    }
                    "REQ" | "COUNT" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let mut filters = Vec::new();
                        while let Some(filter) = seq.next_element::<Filter>()? {
                            filters.push(filter);
                        }
                        if filters.is_empty() {
                            return Err(DeError::custom(Error::InvalidMessage { ty }));
                        }
                        let filters = Cow::Owned(filters);
                        Ok(if ty == "REQ" {
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
                    "CLOSE" => {
                        let id = sub_id(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(ClientMessage::Close(Cow::Owned(id)))
                    }
                    "AUTH" => {
                        let event = event_item(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(ClientMessage::Auth(Cow::Owned(event)))
                    }
                    "NEG-OPEN" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let filter = filter_item(&mut seq, ty)?;
                        let message =
                            parse_neg_hex(&string_item(&mut seq, ty)?).map_err(DeError::custom)?;
                        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(DeError::custom(Error::ObsoleteNegOpen));
                        }
                        Ok(ClientMessage::NegOpen {
                            subscription_id: Cow::Owned(subscription_id),
                            filter: Cow::Owned(filter),
                            message: Cow::Owned(message),
                        })
                    }
                    "NEG-MSG" => {
                        let subscription_id = sub_id(&mut seq, ty)?;
                        let message =
                            parse_neg_hex(&string_item(&mut seq, ty)?).map_err(DeError::custom)?;
                        end(&mut seq, ty)?;
                        Ok(ClientMessage::NegMsg {
                            subscription_id: Cow::Owned(subscription_id),
                            message: Cow::Owned(message),
                        })
                    }
                    "NEG-CLOSE" => {
                        let id = sub_id(&mut seq, ty)?;
                        end(&mut seq, ty)?;
                        Ok(ClientMessage::NegClose(Cow::Owned(id)))
                    }
                    _ => Err(DeError::custom(Error::InvalidMessage { ty })),
                }
            }
        }

        deserializer.deserialize_seq(MessageVisitor)
    }
}
