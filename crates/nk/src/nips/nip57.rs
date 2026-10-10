//! NIP-57 Lightning Zaps (TS `nips/nip57.ts`).
//!
//! Kind-9734 zap-request templates, BOLT11 invoice field decoding, and
//! kind-9735 receipt validation. All functions are pure — no LNURL fetching,
//! no relay publishing. Receipt checks never error; a [`ZapRejection`]
//! mirrors the TS `reason` strings one-to-one.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::{Event, EventAddress, EventBuilder, Kind, PublicKey, RelayUrl, Tag, Tags};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Checksum, Fe32, Fe32IterExt, Fe1024};
use sha2::{Digest, Sha256};

use crate::nips::error::{Error, ErrorKind, Result};

/// `Number.MAX_SAFE_INTEGER` — invoice amounts and the `x` field beyond this
/// lose precision in JS, so both sides treat them as absent (N8).
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MSATS_PER_BTC: u64 = 100_000_000_000;
const MSATS_PER_MILLI: u64 = 100_000_000;
const MSATS_PER_MICRO: u64 = 100_000;
const MSATS_PER_NANO: u64 = 100;

const TIMESTAMP_WORDS: usize = 7;
const SIGNATURE_WORDS: usize = 104;
const HASH_WORDS: usize = 52;
const TAG_PAYMENT_HASH: u8 = 1;
const TAG_EXPIRY: u8 = 6;
const TAG_DESCRIPTION: u8 = 13;
const TAG_DESCRIPTION_HASH: u8 = 23;
const DEFAULT_EXPIRY_SECONDS: u64 = 3600;

fn validation(message: &'static str) -> Error {
    Error::new(ErrorKind::EventValidation, message)
}

/// Target of a zap request: a profile (`pubkey`) or an existing event.
#[allow(
    variant_size_differences,
    reason = "public API mirrors the spec: owned PublicKey vs borrowed Event"
)]
#[derive(Clone, Copy, Debug)]
pub enum ZapTarget<'a> {
    /// Profile zap — the recipient's public key.
    Profile(PublicKey),
    /// Event zap — addressable events (kinds 30000–39999) also emit `a`/`k`
    /// tags.
    Event(&'a Event),
}

/// Build the kind-9734 template (TS `makeZapRequest`).
///
/// # Errors
///
/// `EventValidation` on a non-positive or non-safe-integer `amount_msats`, an
/// empty `relays` list, or an addressable event without a `d` tag — the three
/// throws of the TS function.
pub fn zap_request(
    target: ZapTarget<'_>,
    amount_msats: u64,
    relays: &[RelayUrl],
    comment: &str,
    lnurl: Option<&str>,
) -> Result<EventBuilder> {
    if amount_msats == 0 || amount_msats > MAX_SAFE_INTEGER {
        return Err(validation("zap amount must be a positive integer (msats)"));
    }
    if relays.is_empty() {
        return Err(validation("relays tag requires one or more relays"));
    }
    let (recipient, event) = match target {
        ZapTarget::Profile(pubkey) => (pubkey, None),
        ZapTarget::Event(event) => (event.pubkey(), Some(event)),
    };
    let mut tags = Vec::with_capacity(8);
    tags.push(Tag::public_key(recipient, None, None));
    tags.push(Tag::custom("amount", [amount_msats.to_string()]));
    tags.push(Tag::custom("relays", relays.iter().map(RelayUrl::as_str)));
    if let Some(event) = event {
        tags.push(Tag::event(event.id(), None, None, None));
        if event.kind().is_addressable() {
            if event.tags().identifier().is_none() {
                return Err(validation("d tag not found"));
            }
            if let Some(address) = event.address() {
                tags.push(Tag::address(&address, None));
            }
        }
        tags.push(Tag::kind(event.kind()));
    }
    if let Some(lnurl) = lnurl.filter(|value| !value.is_empty()) {
        tags.push(Tag::custom("lnurl", [lnurl]));
    }
    Ok(EventBuilder::new(Kind::ZAP_REQUEST, comment).tags(tags))
}

/// `bech32::Bech32` without a code-length cap — real invoices exceed the
/// stock 1023 characters (TS `bech32.decode(pr, false)`); the checksum
/// constants are stock Bech32 (not Bech32m).
enum Bolt11Bech32 {}

impl Checksum for Bolt11Bech32 {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;
    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    const TARGET_RESIDUE: u32 = 1;
}

/// Decoded fields of a BOLT11 invoice — the subset NIP-57 validates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bolt11 {
    /// Amount in millisats from the `ln` HRP, when present and within the
    /// JS safe-integer range.
    pub amount_msats: Option<u64>,
    /// The `d` field, UTF-8 decoded; absent when missing or not valid UTF-8.
    pub description: Option<String>,
    /// The `h` field (description hash).
    pub description_hash: Option<[u8; 32]>,
    /// The `p` field — required; an invoice without one does not parse.
    pub payment_hash: [u8; 32],
    /// Invoice creation time (unix seconds).
    pub timestamp: u64,
    /// `x` field in seconds; defaults to 3600 (N8: values beyond 2^53−1 are
    /// ignored).
    pub expiry: u64,
}

fn words_to_int(words: &[Fe32]) -> Option<u64> {
    let mut value = 0u64;
    for &word in words {
        value = value
            .checked_mul(32)?
            .checked_add(u64::from(word.to_u8()))?;
    }
    Some(value)
}

fn fes_to_bytes(words: &[Fe32]) -> Vec<u8> {
    words.iter().copied().fes_to_bytes().collect()
}

fn amount_msats_from_hrp(hrp: &str) -> Option<u64> {
    let rest = hrp.strip_prefix("ln")?;
    let num = rest.trim_start_matches(|c: char| c.is_ascii_lowercase());
    let (digits, pico) = match num.as_bytes().last() {
        Some(&last @ (b'm' | b'u' | b'n' | b'p')) => (
            num.strip_suffix(char::from(last)).unwrap_or(num),
            Some(last),
        ),
        _ => (num, None),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    if n > MAX_SAFE_INTEGER {
        return None;
    }
    match pico {
        None => n
            .checked_mul(MSATS_PER_BTC)
            .filter(|m| *m <= MAX_SAFE_INTEGER),
        Some(b'm') => n
            .checked_mul(MSATS_PER_MILLI)
            .filter(|m| *m <= MAX_SAFE_INTEGER),
        Some(b'u') => n
            .checked_mul(MSATS_PER_MICRO)
            .filter(|m| *m <= MAX_SAFE_INTEGER),
        Some(b'n') => n
            .checked_mul(MSATS_PER_NANO)
            .filter(|m| *m <= MAX_SAFE_INTEGER),
        Some(_) => n.is_multiple_of(10).then_some(n / 10),
    }
}

/// Decode the tagged fields of a BOLT11 invoice.
///
/// Returns `None` for any malformed string or an invoice without a `p`
/// field — TS `parseBolt11` returns `null` the same way. The whole string is
/// lowercased first (`bech32` requires single case).
#[must_use]
pub fn parse_bolt11(pr: &str) -> Option<Bolt11> {
    let lowered = pr.to_lowercase();
    let checked = CheckedHrpstring::new::<Bolt11Bech32>(&lowered).ok()?;
    let hrp = checked.hrp();
    if !hrp.as_str().starts_with("ln") {
        return None;
    }
    let amount_msats = amount_msats_from_hrp(hrp.as_str());
    let words: Vec<Fe32> = checked.fe32_iter().collect();
    if words.len() < TIMESTAMP_WORDS + SIGNATURE_WORDS {
        return None;
    }
    let timestamp = words_to_int(words.get(..TIMESTAMP_WORDS)?)?;
    let mut description = None;
    let mut description_hash = None;
    let mut payment_hash: Option<[u8; 32]> = None;
    let mut expiry = DEFAULT_EXPIRY_SECONDS;
    let mut saw_expiry = false;
    let mut rest = words.get(TIMESTAMP_WORDS..words.len() - SIGNATURE_WORDS)?;
    while let Some((&[type_word, len_hi, len_lo], tail)) = rest.split_first_chunk::<3>() {
        let data_len = usize::from(len_hi.to_u8()) * 32 + usize::from(len_lo.to_u8());
        if tail.len() < data_len {
            break;
        }
        let (data, next) = tail.split_at(data_len);
        rest = next;
        match type_word.to_u8() {
            TAG_EXPIRY if !saw_expiry => {
                saw_expiry = true;
                expiry = words_to_int(data)
                    .filter(|x| *x <= MAX_SAFE_INTEGER)
                    .unwrap_or(expiry);
            }
            TAG_DESCRIPTION if description.is_none() => {
                description = String::from_utf8(fes_to_bytes(data)).ok();
            }
            TAG_PAYMENT_HASH if data_len == HASH_WORDS && payment_hash.is_none() => {
                payment_hash = <[u8; 32]>::try_from(fes_to_bytes(data).as_slice()).ok();
            }
            TAG_DESCRIPTION_HASH if data_len == HASH_WORDS && description_hash.is_none() => {
                description_hash = <[u8; 32]>::try_from(fes_to_bytes(data).as_slice()).ok();
            }
            _ => {}
        }
    }
    payment_hash.map(|payment_hash| Bolt11 {
        amount_msats,
        description,
        description_hash,
        payment_hash,
        timestamp,
        expiry,
    })
}

/// Why a zap receipt failed validation — `Display` is the TS `reason`
/// string verbatim.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZapRejection {
    /// Not a valid, signed kind-9735 event.
    InvalidReceipt,
    /// `receipt.pubkey !== nostrPubkey`.
    PubkeyMismatch,
    /// The `description` tag is not a valid signed kind-9734 zap request.
    InvalidZapRequest,
    /// The request has other than exactly one `p` tag.
    InvalidPCount,
    /// The request has more than one `e` tag.
    TooManyETags,
    /// The request has no non-empty `relays` tag.
    MissingRelays,
    /// An `a` tag does not parse or its kind is not addressable.
    InvalidA,
    /// The request has more than one `P` tag.
    TooManyRequestP,
    /// The request `P` value does not equal the receipt pubkey.
    RequestPMismatch,
    /// No `bolt11` tag on the receipt.
    MissingBolt11,
    /// The `bolt11` tag does not parse or has no `h` field.
    InvalidBolt11,
    /// `amount` on the request vs the invoice amount.
    AmountMismatch,
    /// SHA-256 of the `description` tag vs the invoice `h` field.
    DescriptionHashMismatch,
    /// `lnurl` on the request vs the expected LNURL (when both given).
    LnurlMismatch,
    /// SHA-256 of the `preimage` tag vs the invoice `p` field.
    PreimageMismatch,
    /// The receipt lacks the request's `p` tag.
    MissingP,
    /// The receipt lacks the request's `e` tag.
    MissingE,
    /// The receipt lacks the request's `a` tag.
    MissingA,
    /// A receipt `P` tag does not equal the request author's pubkey.
    ReceiptPMismatch,
}

impl fmt::Display for ZapRejection {
    /// The TS `reason` string verbatim.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidReceipt => "invalid receipt",
            Self::PubkeyMismatch => "pubkey mismatch",
            Self::InvalidZapRequest => "invalid zap request",
            Self::InvalidPCount => "invalid p count",
            Self::TooManyETags => "too many e tags",
            Self::MissingRelays => "missing relays",
            Self::InvalidA => "invalid a",
            Self::TooManyRequestP => "too many P tags",
            Self::RequestPMismatch => "request P mismatch",
            Self::MissingBolt11 => "missing bolt11",
            Self::InvalidBolt11 => "invalid bolt11",
            Self::AmountMismatch => "amount mismatch",
            Self::DescriptionHashMismatch => "description hash mismatch",
            Self::LnurlMismatch => "lnurl mismatch",
            Self::PreimageMismatch => "preimage mismatch",
            Self::MissingP => "missing p",
            Self::MissingE => "missing e",
            Self::MissingA => "missing a",
            Self::ReceiptPMismatch => "receipt P mismatch",
        })
    }
}

impl core::error::Error for ZapRejection {}

/// The validated zap request plus the settled amount, when any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidZapReceipt {
    /// The verified kind-9734 zap request embedded in `description`.
    pub request: Event,
    /// Settled millisats, or `None` when the invoice carries no amount.
    pub amount_msats: Option<u64>,
}

/// Decode the zap request embedded in a receipt's `description` tag (TS
/// `getZapRequestFromReceipt`): strict JSON `Event` decode, kind 9734,
/// signature verified. `None` on any failure.
#[must_use]
pub fn zap_request_from_receipt(receipt: &Event) -> Option<Event> {
    let raw = receipt.tags().first_value("description")?;
    let request = serde_json::from_str::<Event>(raw).ok()?;
    if request.kind() != Kind::ZAP_REQUEST || request.verify().is_err() {
        return None;
    }
    Some(request)
}

fn count_tags(tags: &Tags, name: &str) -> usize {
    tags.iter().filter(|tag| tag.name() == name).count()
}

fn has_hex_tag_value(tags: &Tags, name: &str, value: &str) -> bool {
    tags.iter().any(|tag| {
        tag.name() == name
            && tag
                .value()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(value))
    })
}

fn has_address_tag(tags: &Tags, value: &str) -> bool {
    let Ok(want) = value.parse::<EventAddress>() else {
        return false;
    };
    tags.iter().any(|tag| {
        if tag.name() != "a" {
            return false;
        }
        let Some(raw) = tag.value() else {
            return false;
        };
        let Ok(got) = raw.parse::<EventAddress>() else {
            return false;
        };
        got.kind() == want.kind()
            && got.pubkey() == want.pubkey()
            && got.identifier() == want.identifier()
    })
}

fn parse_msats_tag(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = value.parse().ok()?;
    (n <= MAX_SAFE_INTEGER).then_some(n)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Some(nibble(*hi)? * 16 + nibble(*lo)?))
        .collect()
}

/// Full NIP-57 receipt check (TS `validateZapReceipt`).
///
/// The receipt is a verified kind-9735 by `nostr_pubkey`, its `description`
/// embeds a structurally valid zap request, and the bolt11 invoice matches
/// that request. `lnurl`, when given, must match the request's `lnurl` tag
/// case-insensitively (TS `toLowerCase`).
///
/// # Errors
///
/// [`ZapRejection`] — the TS `reason` string verbatim.
pub fn validate_zap_receipt(
    receipt: &Event,
    nostr_pubkey: &PublicKey,
    lnurl: Option<&str>,
) -> core::result::Result<ValidZapReceipt, ZapRejection> {
    if receipt.kind() != Kind::ZAP || receipt.verify().is_err() {
        return Err(ZapRejection::InvalidReceipt);
    }
    if receipt.pubkey() != *nostr_pubkey {
        return Err(ZapRejection::PubkeyMismatch);
    }
    let Some(description_raw) = receipt.tags().first_value("description") else {
        return Err(ZapRejection::InvalidZapRequest);
    };
    let Some(request) = zap_request_from_receipt(receipt) else {
        return Err(ZapRejection::InvalidZapRequest);
    };
    if count_tags(request.tags(), "p") != 1 {
        return Err(ZapRejection::InvalidPCount);
    }
    if count_tags(request.tags(), "e") > 1 {
        return Err(ZapRejection::TooManyETags);
    }
    match request.tags().first_value("relays") {
        None | Some("") => return Err(ZapRejection::MissingRelays),
        _ => {}
    }
    for tag in request.tags() {
        if tag.name() != "a" {
            continue;
        }
        let Some(value) = tag.value() else {
            return Err(ZapRejection::InvalidA);
        };
        match value.parse::<EventAddress>() {
            Ok(address) if address.kind().is_addressable() => {}
            _ => return Err(ZapRejection::InvalidA),
        }
    }
    let request_p = count_tags(request.tags(), "P");
    if request_p > 1 {
        return Err(ZapRejection::TooManyRequestP);
    }
    if request_p == 1 {
        let valid = request
            .tags()
            .first_value("P")
            .is_some_and(|value| value.eq_ignore_ascii_case(&receipt.pubkey().to_hex()));
        if !valid {
            return Err(ZapRejection::RequestPMismatch);
        }
    }
    let Some(bolt11_tag) = receipt.tags().first_value("bolt11") else {
        return Err(ZapRejection::MissingBolt11);
    };
    let Some(bolt11) = parse_bolt11(bolt11_tag) else {
        return Err(ZapRejection::InvalidBolt11);
    };
    let Some(description_hash) = bolt11.description_hash else {
        return Err(ZapRejection::InvalidBolt11);
    };
    if let Some(amount_tag) = request.tags().first_value("amount") {
        match parse_msats_tag(amount_tag) {
            Some(msats) if bolt11.amount_msats == Some(msats) => {}
            _ => return Err(ZapRejection::AmountMismatch),
        }
    }
    if Sha256::digest(description_raw.as_bytes())[..] != description_hash[..] {
        return Err(ZapRejection::DescriptionHashMismatch);
    }
    if let (Some(request_lnurl), Some(lnurl)) = (request.tags().first_value("lnurl"), lnurl)
        && request_lnurl.to_lowercase() != lnurl.to_lowercase()
    {
        return Err(ZapRejection::LnurlMismatch);
    }
    if let Some(preimage_hex) = receipt.tags().first_value("preimage") {
        let Some(preimage) = decode_hex(preimage_hex) else {
            return Err(ZapRejection::PreimageMismatch);
        };
        if Sha256::digest(&preimage)[..] != bolt11.payment_hash[..] {
            return Err(ZapRejection::PreimageMismatch);
        }
    }
    let Some(recipient) = request.tags().first_value("p") else {
        return Err(ZapRejection::MissingP);
    };
    if !has_hex_tag_value(receipt.tags(), "p", recipient) {
        return Err(ZapRejection::MissingP);
    }
    if let Some(request_e) = request.tags().first_value("e")
        && !has_hex_tag_value(receipt.tags(), "e", request_e)
    {
        return Err(ZapRejection::MissingE);
    }
    for tag in request.tags() {
        if tag.name() != "a" {
            continue;
        }
        let Some(value) = tag.value() else {
            continue;
        };
        if !has_address_tag(receipt.tags(), value) {
            return Err(ZapRejection::MissingA);
        }
    }
    for tag in receipt.tags() {
        if tag.name() != "P" {
            continue;
        }
        match tag.value() {
            Some(value) if value.eq_ignore_ascii_case(&request.pubkey().to_hex()) => {}
            _ => return Err(ZapRejection::ReceiptPMismatch),
        }
    }
    Ok(ValidZapReceipt {
        request,
        amount_msats: bolt11.amount_msats,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use crate::{SecretKey, Timestamp, UnsignedEvent};

    use super::*;

    const SK: &str = "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45";

    fn event(kind: u16, tags: &[&[&str]]) -> Event {
        let keys = crate::Keys::new(SecretKey::from_hex(SK).unwrap());
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_700_000_000),
            Kind::new(kind),
            tags.iter()
                .map(|items| Tag::new(items.iter().map(|s| String::from(*s))).unwrap())
                .collect(),
            "",
        );
        keys.sign_event_with_aux(unsigned, &[7u8; 32]).unwrap()
    }

    fn relays() -> Vec<RelayUrl> {
        alloc::vec![RelayUrl::parse("wss://zap.example").unwrap()]
    }

    fn tag_strings(tags: &Tags) -> Vec<Vec<String>> {
        tags.iter().map(|tag| tag.as_slice().to_vec()).collect()
    }

    #[test]
    fn profile_zap_request_layout() {
        let recipient =
            PublicKey::from_hex("b1e2d3c4b5a6978899aabbccddeeff00112233445566778899aabbccddeeff00")
                .unwrap();
        let builder = zap_request(
            ZapTarget::Profile(recipient),
            21_000,
            &relays(),
            "thanks",
            Some("lnurl1xyz"),
        )
        .unwrap();
        let unsigned = builder.build_at(
            PublicKey::from_hex(SK).unwrap(),
            Timestamp::from_secs(1_700_000_000),
        );
        assert_eq!(
            tag_strings(unsigned.tags()),
            alloc::vec![
                alloc::vec![
                    "p".to_owned(),
                    "b1e2d3c4b5a6978899aabbccddeeff00112233445566778899aabbccddeeff00".to_owned()
                ],
                alloc::vec!["amount".to_owned(), "21000".to_owned()],
                alloc::vec!["relays".to_owned(), "wss://zap.example/".to_owned()],
                alloc::vec!["lnurl".to_owned(), "lnurl1xyz".to_owned()],
            ]
        );
    }

    #[test]
    fn event_zap_request_emits_e_a_k() {
        let target = event(30_023, &[&["d", "article-1"]]);
        let builder = zap_request(ZapTarget::Event(&target), 1, &relays(), "", None).unwrap();
        let unsigned = builder.build_at(
            PublicKey::from_hex(SK).unwrap(),
            Timestamp::from_secs(1_700_000_000),
        );
        let tags = tag_strings(unsigned.tags());
        assert_eq!(
            tags.get(3),
            Some(&alloc::vec!["e".to_owned(), target.id().to_hex()])
        );
        assert_eq!(
            tags.get(4),
            Some(&alloc::vec![
                "a".to_owned(),
                alloc::format!("30023:{}:article-1", target.pubkey().to_hex())
            ])
        );
        assert_eq!(
            tags.get(5),
            Some(&alloc::vec!["k".to_owned(), "30023".to_owned()])
        );
    }

    #[test]
    fn zap_request_rejections() {
        let pk = PublicKey::from_hex(SK).unwrap();
        assert!(zap_request(ZapTarget::Profile(pk), 0, &relays(), "", None).is_err());
        assert!(
            zap_request(
                ZapTarget::Profile(pk),
                MAX_SAFE_INTEGER + 1,
                &relays(),
                "",
                None
            )
            .is_err()
        );
        assert!(zap_request(ZapTarget::Profile(pk), 1, &[], "", None).is_err());
        let no_d = event(30_023, &[&["title", "x"]]);
        assert!(zap_request(ZapTarget::Event(&no_d), 1, &relays(), "", None).is_err());
    }

    #[test]
    fn hrp_amount_parsing() {
        assert_eq!(amount_msats_from_hrp("lnbc210n"), Some(21_000));
        assert_eq!(amount_msats_from_hrp("lnbc10m"), Some(1_000_000_000));
        assert_eq!(amount_msats_from_hrp("lnbc10u"), Some(1_000_000));
        assert_eq!(amount_msats_from_hrp("lnbc10n"), Some(1_000));
        assert_eq!(amount_msats_from_hrp("lnbc10p"), Some(1));
        assert_eq!(amount_msats_from_hrp("lnbc11p"), None);
        assert_eq!(amount_msats_from_hrp("lnbc"), None);
        assert_eq!(amount_msats_from_hrp("lnbc90071992547410n"), None);
        assert_eq!(amount_msats_from_hrp("xyz"), None);
        assert_eq!(amount_msats_from_hrp("lnbc1x"), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_msats_tag("21000"), Some(21_000));
        assert_eq!(parse_msats_tag("21k"), None);
        assert_eq!(parse_msats_tag(""), None);
        assert_eq!(decode_hex("Ab12").map(|v| v.len()), Some(2));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("éé"), None); // even byte length, non-ascii
        assert_eq!(ZapRejection::MissingA.to_string(), "missing a");
    }
}
