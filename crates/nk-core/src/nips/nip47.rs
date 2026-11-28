//! NIP-47 Nostr Wallet Connect codecs.
//!
//! Connection URIs, wallet info events, request JSON, typed response and
//! notification validation, and response-envelope matching. Transport,
//! encryption, signing, and client sessions live outside this sans-IO module.

#![allow(
    clippy::excessive_nesting,
    reason = "URI and JSON codecs validate nested wire shapes directly"
)]

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use serde_json::Value;

use crate::event::{Event, EventId};
use crate::hex;
use crate::key::{PublicKey, SecretKey};
use crate::limits::MAX_SAFE_INTEGER;

/// NIP-47 info event kind.
pub const INFO_KIND: u16 = 13194;
/// NIP-47 request kind.
pub const REQUEST_KIND: u16 = 23194;
/// NIP-47 response kind.
pub const RESPONSE_KIND: u16 = 23195;
/// NWC-02 NIP-04 notification kind.
pub const NOTIFICATION_NIP04_KIND: u16 = 23196;
/// NWC-02 NIP-44 notification kind.
pub const NOTIFICATION_KIND: u16 = 23197;

const MAX_PAYLOAD_CHARS: usize = 1_048_576;
const MAX_STRING_CHARS: usize = 65_535;

/// Why a NIP-47 codec operation failed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The connection URI is malformed: scheme, lowercase hex, relay list, or query.
    #[error("invalid NWC connection URI")]
    Uri,
    /// The event is not a valid NIP-47 artifact (wrong kind or missing fields).
    #[error("invalid NIP-47 event")]
    Event,
    /// The wallet info offers no encryption scheme this implementation supports.
    #[error("unsupported NWC encryption negotiation")]
    Encryption,
    /// The payload fails validation (JSON shape, result type, strings, integers, budget rules).
    #[error("invalid NIP-47 payload")]
    Payload,
}

/// `nip47` result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// A parsed `nostr+walletconnect://` connection URI.
#[derive(Debug, Clone)]
pub struct NwcUri {
    /// Wallet-service public key.
    pub wallet_pubkey: PublicKey,
    /// Relay URLs, all `wss://` or loopback `ws://`.
    pub relays: Vec<String>,
    /// Client secret key.
    pub secret: SecretKey,
    /// Optional lightning address.
    pub lud16: Option<String>,
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'+' {
            out.push(b' ');
            index += 1;
        } else if byte == b'%'
            && index + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                bytes.get(index + 1).copied().and_then(hex_nibble),
                bytes.get(index + 2).copied().and_then(hex_nibble),
            )
        {
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_loopback_ws(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("ws://") else {
        return false;
    };
    for host in ["localhost", "127.0.0.1"] {
        let Some(after_host) = rest.strip_prefix(host) else {
            continue;
        };
        if after_host.is_empty() || after_host.starts_with(['/', '?', '#']) {
            return true;
        }
        let Some(after_colon) = after_host.strip_prefix(':') else {
            continue;
        };
        let port_len = after_colon
            .find(['/', '?', '#'])
            .unwrap_or(after_colon.len());
        let port = &after_colon[..port_len];
        let suffix = &after_colon[port_len..];
        if port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            continue;
        }
        if suffix.is_empty() || suffix.starts_with(['/', '?', '#']) {
            return true;
        }
    }
    false
}

impl FromStr for NwcUri {
    type Err = Error;

    /// Parses `nostr+walletconnect://<pubkey>?relay=wss://…&secret=<64hex>[&lud16=…]`.
    /// Wire hex is strict lowercase; uppercase is invalid rather than repaired.
    fn from_str(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("nostr+walletconnect://")
            .ok_or(Error::Uri)?;
        let (host, query) = rest.split_once('?').ok_or(Error::Uri)?;
        let wallet_pubkey = PublicKey::from_wire_hex(host).map_err(|_| Error::Uri)?;
        let mut relays = Vec::new();
        let mut secret = None;
        let mut lud16 = None;
        for part in query.split('&') {
            if part.is_empty() {
                continue;
            }
            let (raw_key, raw_value) = part.split_once('=').unwrap_or((part, ""));
            let key = form_decode(raw_key);
            let value = form_decode(raw_value);
            match key.as_str() {
                "relay" => {
                    if !value.starts_with("wss://") && !is_loopback_ws(&value) {
                        return Err(Error::Uri);
                    }
                    relays.push(value);
                }
                "secret" if secret.is_none() => {
                    let bytes = hex::decode_wire::<32>(&value).map_err(|_| Error::Uri)?;
                    secret = Some(SecretKey::from_bytes(bytes).map_err(|_| Error::Uri)?);
                }
                "lud16" if lud16.is_none() => lud16 = Some(value),
                _ => {}
            }
        }
        if relays.is_empty() {
            return Err(Error::Uri);
        }
        Ok(Self {
            wallet_pubkey,
            relays,
            secret: secret.ok_or(Error::Uri)?,
            lud16,
        })
    }
}

/// Request/notification encryption schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encryption {
    /// NIP-44 v2.
    Nip44V2,
    /// Legacy NIP-04.
    Nip04,
}

impl Encryption {
    /// Wire identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nip44V2 => "nip44_v2",
            Self::Nip04 => "nip04",
        }
    }
}

/// Parsed kind-13194 wallet metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Method names from the event content.
    pub methods: Vec<String>,
    /// `encryption` tag entries; `None` when the tag is absent (legacy NIP-04-only wallet).
    pub encryptions: Option<Vec<String>>,
    /// `extensions` tag entries.
    pub extensions: Vec<String>,
    /// `notifications` tag entries.
    pub notifications: Vec<String>,
}

impl Info {
    /// Parses a kind-13194 event. Signature verification is the caller's concern.
    ///
    /// # Errors
    /// [`Error::Event`] when the kind is not 13194.
    pub fn from_event(event: &Event) -> Result<Self> {
        if event.kind().as_u16() != INFO_KIND {
            return Err(Error::Event);
        }
        let mut encryptions = None;
        let mut extensions = Vec::new();
        let mut notifications = Vec::new();
        for tag in event.tags() {
            let Some(value) = tag.value() else {
                continue;
            };
            match tag.name() {
                "encryption" => {
                    encryptions = Some(value.split_ascii_whitespace().map(str::to_owned).collect());
                }
                "extensions" => {
                    extensions = value.split_ascii_whitespace().map(str::to_owned).collect();
                }
                "notifications" => {
                    notifications = value.split_ascii_whitespace().map(str::to_owned).collect();
                }
                _ => {}
            }
        }
        Ok(Self {
            methods: event
                .content()
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect(),
            encryptions,
            extensions,
            notifications,
        })
    }

    /// Picks NIP-44 when offered, otherwise NIP-04; an absent tag means NIP-04.
    ///
    /// # Errors
    /// [`Error::Encryption`] when the tag exists but offers neither scheme.
    pub fn negotiate(&self) -> Result<Encryption> {
        let Some(encryptions) = &self.encryptions else {
            return Ok(Encryption::Nip04);
        };
        if encryptions.iter().any(|entry| entry == "nip44_v2") {
            return Ok(Encryption::Nip44V2);
        }
        if encryptions.iter().any(|entry| entry == "nip04") {
            return Ok(Encryption::Nip04);
        }
        Err(Error::Encryption)
    }
}

/// NIP-47 methods implemented by this codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `pay_invoice`.
    PayInvoice,
    /// `make_invoice`.
    MakeInvoice,
    /// `lookup_invoice`.
    LookupInvoice,
    /// `get_balance`.
    GetBalance,
    /// `get_info`.
    GetInfo,
    /// `list_transactions` (NWC-05).
    ListTransactions,
    /// `get_budget` (NWC-13).
    GetBudget,
}

impl Method {
    /// Wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayInvoice => "pay_invoice",
            Self::MakeInvoice => "make_invoice",
            Self::LookupInvoice => "lookup_invoice",
            Self::GetBalance => "get_balance",
            Self::GetInfo => "get_info",
            Self::ListTransactions => "list_transactions",
            Self::GetBudget => "get_budget",
        }
    }

    /// Parses a wire method name.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pay_invoice" => Some(Self::PayInvoice),
            "make_invoice" => Some(Self::MakeInvoice),
            "lookup_invoice" => Some(Self::LookupInvoice),
            "get_balance" => Some(Self::GetBalance),
            "get_info" => Some(Self::GetInfo),
            "list_transactions" => Some(Self::ListTransactions),
            "get_budget" => Some(Self::GetBudget),
            _ => None,
        }
    }
}

/// `pay_invoice` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayInvoiceParams {
    /// BOLT11 invoice.
    pub invoice: String,
    /// Optional amount in msats.
    pub amount: Option<u64>,
    /// Optional metadata as compact JSON text.
    pub metadata: Option<String>,
}

/// `make_invoice` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeInvoiceParams {
    /// Amount in msats.
    pub amount: u64,
    /// Optional description.
    pub description: Option<String>,
    /// Optional description hash hex.
    pub description_hash: Option<String>,
    /// Optional expiry in seconds.
    pub expiry: Option<u64>,
    /// Optional metadata as compact JSON text.
    pub metadata: Option<String>,
}

/// `lookup_invoice` parameters; at least one selector must be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupInvoiceParams {
    /// Payment hash selector.
    pub payment_hash: Option<String>,
    /// Invoice selector.
    pub invoice: Option<String>,
}

/// `list_transactions` parameters (NWC-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListTransactionsParams {
    /// Inclusive lower timestamp.
    pub from: Option<u64>,
    /// Inclusive upper timestamp.
    pub until: Option<u64>,
    /// Page size.
    pub limit: Option<u64>,
    /// Page offset.
    pub offset: Option<u64>,
    /// Restrict to unpaid invoices.
    pub unpaid: Option<bool>,
    /// Transaction direction.
    pub transaction_type: Option<TransactionType>,
}

/// Transaction direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionType {
    /// Incoming invoice/receipt.
    Incoming,
    /// Outgoing payment.
    Outgoing,
}

impl TransactionType {
    /// Wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        }
    }
}

/// Typed NIP-47 request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Pay a BOLT11 invoice.
    PayInvoice(PayInvoiceParams),
    /// Create an invoice.
    MakeInvoice(MakeInvoiceParams),
    /// Look up an invoice.
    LookupInvoice(LookupInvoiceParams),
    /// Read the balance.
    GetBalance,
    /// Read wallet metadata.
    GetInfo,
    /// List transactions.
    ListTransactions(ListTransactionsParams),
    /// Read connection budget.
    GetBudget,
}

impl Request {
    /// The method carried by this request.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::PayInvoice(_) => Method::PayInvoice,
            Self::MakeInvoice(_) => Method::MakeInvoice,
            Self::LookupInvoice(_) => Method::LookupInvoice,
            Self::GetBalance => Method::GetBalance,
            Self::GetInfo => Method::GetInfo,
            Self::ListTransactions(_) => Method::ListTransactions,
            Self::GetBudget => Method::GetBudget,
        }
    }

    /// The exact plaintext JSON key order produced by the TypeScript codec.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"method\":\"");
        out.push_str(self.method().as_str());
        out.push_str("\",\"params\":{");
        match self {
            Self::PayInvoice(params) => {
                push_json_prop(&mut out, true, "invoice", &json_string(&params.invoice));
                let mut first = false;
                if let Some(amount) = params.amount {
                    push_json_prop(&mut out, first, "amount", &amount.to_string());
                    first = false;
                }
                if let Some(metadata) = &params.metadata {
                    push_json_prop(&mut out, first, "metadata", metadata);
                }
            }
            Self::MakeInvoice(params) => {
                push_json_prop(&mut out, true, "amount", &params.amount.to_string());
                let mut first = false;
                if let Some(description) = &params.description {
                    push_json_prop(&mut out, first, "description", &json_string(description));
                    first = false;
                }
                if let Some(hash) = &params.description_hash {
                    push_json_prop(&mut out, first, "description_hash", &json_string(hash));
                    first = false;
                }
                if let Some(expiry) = params.expiry {
                    push_json_prop(&mut out, first, "expiry", &expiry.to_string());
                    first = false;
                }
                if let Some(metadata) = &params.metadata {
                    push_json_prop(&mut out, first, "metadata", metadata);
                }
            }
            Self::LookupInvoice(params) => {
                let mut first = true;
                if let Some(hash) = &params.payment_hash {
                    push_json_prop(&mut out, first, "payment_hash", &json_string(hash));
                    first = false;
                }
                if let Some(invoice) = &params.invoice {
                    push_json_prop(&mut out, first, "invoice", &json_string(invoice));
                }
            }
            Self::ListTransactions(params) => {
                let mut first = true;
                if let Some(from) = params.from {
                    push_json_prop(&mut out, first, "from", &from.to_string());
                    first = false;
                }
                if let Some(until) = params.until {
                    push_json_prop(&mut out, first, "until", &until.to_string());
                    first = false;
                }
                if let Some(limit) = params.limit {
                    push_json_prop(&mut out, first, "limit", &limit.to_string());
                    first = false;
                }
                if let Some(offset) = params.offset {
                    push_json_prop(&mut out, first, "offset", &offset.to_string());
                    first = false;
                }
                if let Some(unpaid) = params.unpaid {
                    push_json_prop(
                        &mut out,
                        first,
                        "unpaid",
                        if unpaid { "true" } else { "false" },
                    );
                    first = false;
                }
                if let Some(kind) = params.transaction_type {
                    push_json_prop(&mut out, first, "type", &json_string(kind.as_str()));
                }
            }
            Self::GetBalance | Self::GetInfo | Self::GetBudget => {}
        }
        out.push_str("}}");
        out
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

fn push_json_prop(out: &mut String, first: bool, key: &str, encoded_value: &str) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(encoded_value);
}

/// Transaction state values recognized by NWC-05.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionState {
    /// Pending.
    Pending,
    /// Settled.
    Settled,
    /// Accepted hold invoice.
    Accepted,
    /// Expired invoice.
    Expired,
    /// Failed payment.
    Failed,
}

impl TransactionState {
    /// Wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

/// Wire-shaped NWC transaction. `metadata` is compact JSON text, never a serde value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::struct_field_names,
    reason = "transaction_type is the wire concept name without a Rust keyword collision"
)]
pub struct Transaction {
    /// Direction.
    pub transaction_type: TransactionType,
    /// Recognized state; unknown wire states are dropped.
    pub state: Option<TransactionState>,
    /// BOLT11 invoice.
    pub invoice: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Description hash.
    pub description_hash: Option<String>,
    /// Payment preimage.
    pub preimage: Option<String>,
    /// Payment hash.
    pub payment_hash: String,
    /// Amount in msats.
    pub amount: u64,
    /// Fees paid in msats.
    pub fees_paid: Option<u64>,
    /// Creation unix time.
    pub created_at: u64,
    /// Expiry unix time.
    pub expires_at: Option<u64>,
    /// Settlement unix time.
    pub settled_at: Option<u64>,
    /// Metadata as compact JSON text.
    pub metadata: Option<String>,
}

/// `pay_invoice` success result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayResult {
    /// Payment preimage.
    pub preimage: String,
    /// Fees paid in msats.
    pub fees_paid: Option<u64>,
}

/// `get_info` success result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletInfo {
    /// Alias.
    pub alias: Option<String>,
    /// Color.
    pub color: Option<String>,
    /// Node pubkey.
    pub pubkey: Option<String>,
    /// Network.
    pub network: Option<String>,
    /// Block height.
    pub block_height: Option<u64>,
    /// Block hash.
    pub block_hash: Option<String>,
    /// Method names.
    pub methods: Vec<String>,
    /// Extension identifiers.
    pub extensions: Option<Vec<String>>,
    /// Notification types.
    pub notifications: Option<Vec<String>>,
}

/// `list_transactions` success result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionList {
    /// Page entries.
    pub transactions: Vec<Transaction>,
    /// Matching count excluding pagination.
    pub total_count: Option<u64>,
}

/// NWC-13 budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Spent msats in the current period.
    pub used_budget: u64,
    /// Total allowance in msats.
    pub total_budget: u64,
    /// Renewal unix time; forbidden for `Never`, required otherwise.
    pub renews_at: Option<u64>,
    /// Renewal period.
    pub renewal_period: RenewalPeriod,
}

/// Budget renewal period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RenewalPeriod {
    /// Daily.
    Daily,
    /// Weekly.
    Weekly,
    /// Monthly.
    Monthly,
    /// Yearly.
    Yearly,
    /// Never renews.
    Never,
}

impl RenewalPeriod {
    /// Wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
            Self::Never => "never",
        }
    }
}

/// Typed successful NWC result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NwcResult {
    /// Payment result.
    PayInvoice(PayResult),
    /// Created invoice.
    MakeInvoice(Transaction),
    /// Looked-up invoice.
    LookupInvoice(Transaction),
    /// Balance in msats.
    GetBalance(u64),
    /// Wallet metadata.
    GetInfo(WalletInfo),
    /// Transaction page.
    ListTransactions(TransactionList),
    /// Configured budget, or `None` for the empty result object.
    GetBudget(Option<Budget>),
}

/// NIP-47 error code. Unknown wire codes map to [`ErrorCode::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// Rate limited.
    RateLimited,
    /// Method not implemented.
    NotImplemented,
    /// Insufficient balance.
    InsufficientBalance,
    /// Spending quota exceeded.
    QuotaExceeded,
    /// Restricted key.
    Restricted,
    /// Unauthorized connection key.
    Unauthorized,
    /// Internal wallet error.
    Internal,
    /// Unsupported encryption.
    UnsupportedEncryption,
    /// Other or unknown wire code.
    Other,
    /// Payment failed.
    PaymentFailed,
    /// Invoice not found.
    NotFound,
}

impl ErrorCode {
    /// Canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "RATE_LIMITED",
            Self::NotImplemented => "NOT_IMPLEMENTED",
            Self::InsufficientBalance => "INSUFFICIENT_BALANCE",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::Restricted => "RESTRICTED",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Internal => "INTERNAL",
            Self::UnsupportedEncryption => "UNSUPPORTED_ENCRYPTION",
            Self::Other => "OTHER",
            Self::PaymentFailed => "PAYMENT_FAILED",
            Self::NotFound => "NOT_FOUND",
        }
    }

    /// Maps a wire code; unknown values become [`ErrorCode::Other`].
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "RATE_LIMITED" => Self::RateLimited,
            "NOT_IMPLEMENTED" => Self::NotImplemented,
            "INSUFFICIENT_BALANCE" => Self::InsufficientBalance,
            "QUOTA_EXCEEDED" => Self::QuotaExceeded,
            "RESTRICTED" => Self::Restricted,
            "UNAUTHORIZED" => Self::Unauthorized,
            "INTERNAL" => Self::Internal,
            "UNSUPPORTED_ENCRYPTION" => Self::UnsupportedEncryption,
            "PAYMENT_FAILED" => Self::PaymentFailed,
            "NOT_FOUND" => Self::NotFound,
            _ => Self::Other,
        }
    }
}

/// Wallet-supplied error payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletError {
    /// Canonicalized error code.
    pub code: ErrorCode,
    /// Wire code verbatim.
    pub wallet_code: String,
    /// Human-readable wallet message.
    pub message: String,
}

/// NWC-02 notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// `payment_received`.
    PaymentReceived(Transaction),
    /// `payment_sent`.
    PaymentSent(Transaction),
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn string_field<'a>(obj: &'a Value, key: &str, required: bool) -> Result<Option<&'a str>> {
    match obj.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(value)) if utf16_len(value) <= MAX_STRING_CHARS => Ok(Some(value)),
        _ => Err(Error::Payload),
    }
}

fn uint_field(obj: &Value, key: &str, required: bool) -> Result<Option<u64>> {
    match obj.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        None | Some(Value::Null) => Err(Error::Payload),
        Some(value) => match value.as_u64() {
            Some(number) if number <= MAX_SAFE_INTEGER => Ok(Some(number)),
            _ => Err(Error::Payload),
        },
    }
}

fn string_list(obj: &Value, key: &str, required: bool) -> Result<Option<Vec<String>>> {
    match obj.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(value) = item.as_str() else {
                    return Err(Error::Payload);
                };
                if utf16_len(value) > MAX_STRING_CHARS {
                    return Err(Error::Payload);
                }
                out.push(value.to_owned());
            }
            Ok(Some(out))
        }
        _ => Err(Error::Payload),
    }
}

fn metadata_field(obj: &Value) -> Result<Option<String>> {
    match obj.get("metadata") {
        None | Some(Value::Null) => Ok(None),
        Some(value) if value.is_object() => serde_json::to_string(value)
            .map(Some)
            .map_err(|_| Error::Payload),
        _ => Err(Error::Payload),
    }
}

fn parse_transaction(value: &Value) -> Result<Transaction> {
    let obj = value.as_object().ok_or(Error::Payload)?;
    let transaction_type = match obj.get("type").and_then(Value::as_str) {
        Some("incoming") => TransactionType::Incoming,
        Some("outgoing") => TransactionType::Outgoing,
        _ => return Err(Error::Payload),
    };
    let state = match obj.get("state").and_then(Value::as_str) {
        Some("pending") => Some(TransactionState::Pending),
        Some("settled") => Some(TransactionState::Settled),
        Some("accepted") => Some(TransactionState::Accepted),
        Some("expired") => Some(TransactionState::Expired),
        Some("failed") => Some(TransactionState::Failed),
        Some(_) | None => None,
    };
    if let Some(raw) = obj.get("state")
        && !raw.is_string()
        && !raw.is_null()
    {
        return Err(Error::Payload);
    }
    Ok(Transaction {
        transaction_type,
        state,
        invoice: string_field(value, "invoice", false)?.map(str::to_owned),
        description: string_field(value, "description", false)?.map(str::to_owned),
        description_hash: string_field(value, "description_hash", false)?.map(str::to_owned),
        preimage: string_field(value, "preimage", false)?.map(str::to_owned),
        payment_hash: string_field(value, "payment_hash", true)?
            .ok_or(Error::Payload)?
            .to_owned(),
        amount: uint_field(value, "amount", true)?.ok_or(Error::Payload)?,
        fees_paid: uint_field(value, "fees_paid", false)?,
        created_at: uint_field(value, "created_at", true)?.ok_or(Error::Payload)?,
        expires_at: uint_field(value, "expires_at", false)?,
        settled_at: uint_field(value, "settled_at", false)?,
        metadata: metadata_field(value)?,
    })
}

fn parse_budget(obj: &Value) -> Result<Option<Budget>> {
    let map = obj.as_object().ok_or(Error::Payload)?;
    if map.is_empty() {
        return Ok(None);
    }
    let renewal = match obj.get("renewal_period").and_then(Value::as_str) {
        Some("daily") => RenewalPeriod::Daily,
        Some("weekly") => RenewalPeriod::Weekly,
        Some("monthly") => RenewalPeriod::Monthly,
        Some("yearly") => RenewalPeriod::Yearly,
        Some("never") => RenewalPeriod::Never,
        _ => return Err(Error::Payload),
    };
    let renews_at = uint_field(obj, "renews_at", false)?;
    if renewal == RenewalPeriod::Never {
        if renews_at.is_some() {
            return Err(Error::Payload);
        }
    } else if renews_at.is_none() {
        return Err(Error::Payload);
    }
    Ok(Some(Budget {
        used_budget: uint_field(obj, "used_budget", true)?.ok_or(Error::Payload)?,
        total_budget: uint_field(obj, "total_budget", true)?.ok_or(Error::Payload)?,
        renews_at,
        renewal_period: renewal,
    }))
}

fn parse_result(method: Method, value: &Value) -> Result<NwcResult> {
    if !value.is_object() {
        return Err(Error::Payload);
    }
    match method {
        Method::PayInvoice => Ok(NwcResult::PayInvoice(PayResult {
            preimage: string_field(value, "preimage", true)?
                .ok_or(Error::Payload)?
                .to_owned(),
            fees_paid: uint_field(value, "fees_paid", false)?,
        })),
        Method::MakeInvoice => Ok(NwcResult::MakeInvoice(parse_transaction(value)?)),
        Method::LookupInvoice => Ok(NwcResult::LookupInvoice(parse_transaction(value)?)),
        Method::GetBalance => Ok(NwcResult::GetBalance(
            uint_field(value, "balance", true)?.ok_or(Error::Payload)?,
        )),
        Method::GetInfo => Ok(NwcResult::GetInfo(WalletInfo {
            alias: string_field(value, "alias", false)?.map(str::to_owned),
            color: string_field(value, "color", false)?.map(str::to_owned),
            pubkey: string_field(value, "pubkey", false)?.map(str::to_owned),
            network: string_field(value, "network", false)?.map(str::to_owned),
            block_height: uint_field(value, "block_height", false)?,
            block_hash: string_field(value, "block_hash", false)?.map(str::to_owned),
            methods: string_list(value, "methods", true)?.ok_or(Error::Payload)?,
            extensions: string_list(value, "extensions", false)?,
            notifications: string_list(value, "notifications", false)?,
        })),
        Method::ListTransactions => {
            let Some(items) = value.get("transactions").and_then(Value::as_array) else {
                return Err(Error::Payload);
            };
            let mut transactions = Vec::with_capacity(items.len());
            for item in items {
                transactions.push(parse_transaction(item)?);
            }
            Ok(NwcResult::ListTransactions(TransactionList {
                transactions,
                total_count: uint_field(value, "total_count", false)?,
            }))
        }
        Method::GetBudget => Ok(NwcResult::GetBudget(parse_budget(value)?)),
    }
}

/// Validates a decrypted response payload. Absent `result`/`error` keys count as null.
///
/// # Errors
/// [`Error::Payload`] on malformed JSON, size/type violations, mismatched `result_type`, or a
/// payload carrying both/neither of `result` and `error`.
pub fn parse_response_payload(
    method: Method,
    json: &str,
) -> Result<core::result::Result<NwcResult, WalletError>> {
    if utf16_len(json) > MAX_PAYLOAD_CHARS {
        return Err(Error::Payload);
    }
    let doc: Value = serde_json::from_str(json).map_err(|_| Error::Payload)?;
    let obj = doc.as_object().ok_or(Error::Payload)?;
    if obj.get("result_type").and_then(Value::as_str) != Some(method.as_str()) {
        return Err(Error::Payload);
    }
    let result = obj.get("result").filter(|value| !value.is_null());
    let error = obj.get("error").filter(|value| !value.is_null());
    match (result, error) {
        (Some(result), None) => parse_result(method, result).map(Ok),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(Value::as_str)
                .filter(|value| utf16_len(value) <= MAX_STRING_CHARS)
                .ok_or(Error::Payload)?;
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|value| utf16_len(value) <= MAX_STRING_CHARS)
                .ok_or(Error::Payload)?;
            Ok(Err(WalletError {
                code: ErrorCode::from_wire(code),
                wallet_code: code.to_owned(),
                message: message.to_owned(),
            }))
        }
        _ => Err(Error::Payload),
    }
}

/// Validates a decrypted NWC-02 notification payload; unknown notification types return `None`.
///
/// # Errors
/// [`Error::Payload`] on malformed JSON or an invalid transaction shape.
pub fn parse_notification_payload(json: &str) -> Result<Option<Notification>> {
    if utf16_len(json) > MAX_PAYLOAD_CHARS {
        return Err(Error::Payload);
    }
    let doc: Value = serde_json::from_str(json).map_err(|_| Error::Payload)?;
    let obj = doc.as_object().ok_or(Error::Payload)?;
    let kind = obj.get("notification_type").and_then(Value::as_str);
    if kind != Some("payment_received") && kind != Some("payment_sent") {
        return Ok(None);
    }
    let transaction = parse_transaction(obj.get("notification").ok_or(Error::Payload)?)?;
    Ok(Some(if kind == Some("payment_received") {
        Notification::PaymentReceived(transaction)
    } else {
        Notification::PaymentSent(transaction)
    }))
}

/// Authentic-envelope match for a response to a request: kind, wallet authorship, request `e`
/// reference, and client `p` reference. Signature verification is explicitly the caller's job.
#[must_use]
pub fn is_response_to(response: &Event, request: &Event) -> bool {
    if response.kind().as_u16() != RESPONSE_KIND {
        return false;
    }
    let Some(wallet) = request
        .tags()
        .iter()
        .filter(|tag| tag.name() == "p")
        .find_map(|tag| tag.value())
        .and_then(|value| PublicKey::from_wire_hex(value).ok())
    else {
        return false;
    };
    if response.pubkey() != wallet {
        return false;
    }
    let request_id = request.id();
    let references_request = response
        .tags()
        .iter()
        .filter(|tag| tag.name() == "e")
        .filter_map(|tag| tag.value())
        .filter_map(|value| EventId::from_wire_hex(value).ok())
        .any(|id| id == request_id);
    let addresses_client = response
        .tags()
        .iter()
        .filter(|tag| tag.name() == "p")
        .filter_map(|tag| tag.value())
        .filter_map(|value| PublicKey::from_wire_hex(value).ok())
        .any(|pubkey| pubkey == request.pubkey());
    references_request && addresses_client
}
