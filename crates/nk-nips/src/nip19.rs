//! NIP-19 bech32-encoded entities.
//!
//! `npub`, `nsec`, `note` carry a bare 32-byte payload; `nprofile`,
//! `nevent`, `naddr` carry a TLV record. Byte rules are identical to
//! `@qntx/nostr`'s `nips/nip19.ts` (and the `@scure/base` bech32 it wraps):
//! TLVs are written in descending type order, duplicate TLV types keep the
//! first value (relays keep all), identifier and relay bytes decode lossy
//! as UTF-8, and the whole string is at most [`BECH32_MAX_LEN`] characters.
//! All-lowercase and all-uppercase strings decode; mixed case is rejected.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{ByteIterExt, Checksum, Fe32, Fe32IterExt, Fe1024, Hrp};
use nk_core::{EventId, Kind, PublicKey, SecretKey};
use zeroize::Zeroize;

use crate::error::{Error, ErrorKind, Result};

/// Maximum bech32 string length accepted by [`decode`] (NIP-19).
pub const BECH32_MAX_LEN: usize = 5000;

/// `bech32::Bech32` with the NIP-19 length limit: the stock checksum type
/// caps codes at 1023 characters, NIP-19 allows 5000.
enum Nip19Bech32 {}

impl Checksum for Nip19Bech32 {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;
    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;
    const CODE_LENGTH: usize = BECH32_MAX_LEN;
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

const HRP_NPROFILE: Hrp = Hrp::parse_unchecked("nprofile");
const HRP_NEVENT: Hrp = Hrp::parse_unchecked("nevent");
const HRP_NADDR: Hrp = Hrp::parse_unchecked("naddr");
const HRP_NSEC: Hrp = Hrp::parse_unchecked("nsec");
const HRP_NPUB: Hrp = Hrp::parse_unchecked("npub");
const HRP_NOTE: Hrp = Hrp::parse_unchecked("note");

const TLV_SPECIAL: u8 = 0;
const TLV_RELAY: u8 = 1;
const TLV_AUTHOR: u8 = 2;
const TLV_KIND: u8 = 3;

fn nip19(message: impl Into<alloc::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Nip19, message)
}

/// Encodes `data` under `hrp` as a lowercase bech32 string.
fn encode_bech32(hrp: Hrp, data: &[u8]) -> String {
    data.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Nip19Bech32>(&hrp)
        .chars()
        .collect()
}

/// [`encode_bech32`] plus the NIP-19 length limit: a 32-byte payload never
/// reaches it, but TLV encoders can.
fn encode_bech32_tlv(hrp: Hrp, data: &[u8]) -> Result<String> {
    let code = encode_bech32(hrp, data);
    if code.len() > BECH32_MAX_LEN {
        return Err(nip19("bech32 string exceeds 5000 characters"));
    }
    Ok(code)
}

/// Parses and checksum-verifies `code`, returning the hrp and payload bytes.
fn decode_bech32(code: &str) -> Result<(Hrp, Vec<u8>)> {
    let checked = CheckedHrpstring::new::<Nip19Bech32>(code)
        .map_err(|e| nip19(format!("invalid bech32: {e}")))?;
    let fes: Vec<Fe32> = checked.fe32_iter().collect();
    // `@scure/base`'s canonical-padding rule: the trailing partial byte must
    // be shorter than one field element and carry only zero bits.
    let leftover = (fes.len() * 5) % 8;
    let last = fes.last().map_or(0, |fe| fe.to_u8());
    if leftover >= 5 || (leftover > 0 && last & ((1u8 << leftover) - 1) != 0) {
        return Err(nip19("invalid bech32: non-canonical padding"));
    }
    Ok((checked.hrp(), fes.iter().copied().fes_to_bytes().collect()))
}

/// A profile pointer (`nprofile`): a pubkey plus relay hints.
///
/// `relays` are stored verbatim — NIP-19 hints are opaque data, not
/// normalized [`nk_core::RelayUrl`]s.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProfilePointer {
    /// The profile owner's public key.
    pub pubkey: PublicKey,
    /// Relay hints, in wire order.
    pub relays: Vec<String>,
}

/// An event pointer (`nevent`): an event id plus relay, author, and kind
/// hints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventPointer {
    /// The pointed-to event's id.
    pub id: EventId,
    /// Relay hints, in wire order.
    pub relays: Vec<String>,
    /// Optional author hint.
    pub author: Option<PublicKey>,
    /// Optional kind hint.
    pub kind: Option<Kind>,
}

/// An address pointer (`naddr`): a replaceable-event coordinate plus relay
/// hints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddressPointer {
    /// The `d`-tag identifier; may be empty.
    pub identifier: String,
    /// The coordinate's author pubkey.
    pub pubkey: PublicKey,
    /// The coordinate's kind (0–65535).
    pub kind: Kind,
    /// Relay hints, in wire order.
    pub relays: Vec<String>,
}

/// A decoded NIP-19 entity.
///
/// `Secret` has no equality comparison ([`SecretKey`] is opaque), so the
/// enum does not implement `PartialEq`.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Entity {
    /// `nprofile`: profile pointer.
    Profile(ProfilePointer),
    /// `nevent`: event pointer.
    Event(EventPointer),
    /// `naddr`: address pointer.
    Address(AddressPointer),
    /// `nsec`: secret key.
    Secret(SecretKey),
    /// `npub`: public key.
    Public(PublicKey),
    /// `note`: event id.
    Note(EventId),
}

/// TLV records in wire order, keyed by type byte.
type Tlvs<'a> = BTreeMap<u8, Vec<&'a [u8]>>;

fn parse_tlv(data: &[u8]) -> Result<Tlvs<'_>> {
    let mut tlvs: Tlvs<'_> = BTreeMap::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some(&[ty, len]) = rest
            .get(..2)
            .and_then(|head| <&[u8; 2]>::try_from(head).ok())
        else {
            return Err(nip19("not enough data to read TLV"));
        };
        let Some((value, tail)) = rest
            .get(2..)
            .and_then(|body| body.split_at_checked(usize::from(len)))
        else {
            return Err(nip19(format!("not enough data to read on TLV {ty}")));
        };
        tlvs.entry(ty).or_default().push(value);
        rest = tail;
    }
    Ok(tlvs)
}

/// First value of TLV `ty` — duplicates keep the first (relays keep all).
fn first_tlv<'a>(tlvs: &'a Tlvs<'_>, ty: u8) -> Option<&'a [u8]> {
    tlvs.get(&ty).and_then(|vs| vs.first()).copied()
}

fn required_tlv<'a>(tlvs: &'a Tlvs<'_>, ty: u8, prefix: &str) -> Result<&'a [u8]> {
    first_tlv(tlvs, ty).ok_or_else(|| nip19(format!("missing TLV {ty} for {prefix}")))
}

/// First value of TLV `ty`, checked to be exactly `N` bytes.
fn tlv_bytes<const N: usize>(tlvs: &Tlvs<'_>, ty: u8, prefix: &str) -> Result<[u8; N]> {
    let value = required_tlv(tlvs, ty, prefix)?;
    value
        .try_into()
        .map_err(|_| nip19(format!("TLV {ty} should be {N} bytes")))
}

fn tlv_relays(tlvs: &Tlvs<'_>) -> Vec<String> {
    tlvs.get(&TLV_RELAY).map_or_else(Vec::new, |values| {
        values
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect()
    })
}

/// The kind TLV is a big-endian u32 on the wire but limited to the NIP-01
/// range 0–65535 on both encode and decode (ruling N1).
fn read_kind(tlvs: &Tlvs<'_>, ty: u8, prefix: &str) -> Result<Kind> {
    let raw = u32::from_be_bytes(tlv_bytes::<4>(tlvs, ty, prefix)?);
    u16::try_from(raw)
        .map(Kind::new)
        .map_err(|_| nip19(format!("invalid kind: {raw}")))
}

fn push_tlv(out: &mut Vec<u8>, ty: u8, value: &[u8]) -> Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| nip19("TLV value exceeds 255 bytes"))?;
    out.push(ty);
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

impl ProfilePointer {
    /// Encodes the pointer as an `nprofile1…` string.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip19`] when a relay hint exceeds 255 bytes.
    pub fn to_bech32(&self) -> Result<String> {
        let mut data = Vec::new();
        // TLVs are written in descending type order (3, 2, 1, 0).
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        push_tlv(&mut data, TLV_SPECIAL, self.pubkey.as_bytes())?;
        encode_bech32_tlv(HRP_NPROFILE, &data)
    }
}

impl EventPointer {
    /// Encodes the pointer as a `nevent1…` string.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip19`] when a relay hint exceeds 255 bytes.
    pub fn to_bech32(&self) -> Result<String> {
        let mut data = Vec::new();
        if let Some(kind) = self.kind {
            push_tlv(&mut data, TLV_KIND, &u32::from(kind.as_u16()).to_be_bytes())?;
        }
        if let Some(author) = self.author {
            push_tlv(&mut data, TLV_AUTHOR, author.as_bytes())?;
        }
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        push_tlv(&mut data, TLV_SPECIAL, self.id.as_bytes())?;
        encode_bech32_tlv(HRP_NEVENT, &data)
    }
}

impl AddressPointer {
    /// Encodes the pointer as a `naddr1…` string.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip19`] when the identifier or a relay hint exceeds 255
    /// bytes.
    pub fn to_bech32(&self) -> Result<String> {
        let mut data = Vec::new();
        push_tlv(
            &mut data,
            TLV_KIND,
            &u32::from(self.kind.as_u16()).to_be_bytes(),
        )?;
        push_tlv(&mut data, TLV_AUTHOR, self.pubkey.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        push_tlv(&mut data, TLV_SPECIAL, self.identifier.as_bytes())?;
        encode_bech32_tlv(HRP_NADDR, &data)
    }
}

impl Entity {
    /// Encodes the entity back to its bech32 form.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Nip19`] when a pointer's relay hint or identifier
    /// exceeds 255 bytes.
    pub fn to_bech32(&self) -> Result<String> {
        match self {
            Self::Profile(pointer) => pointer.to_bech32(),
            Self::Event(pointer) => pointer.to_bech32(),
            Self::Address(pointer) => pointer.to_bech32(),
            Self::Secret(secret) => Ok(encode_nsec(secret)),
            Self::Public(pubkey) => Ok(encode_npub(pubkey)),
            Self::Note(id) => Ok(encode_note(id)),
        }
    }
}

/// Encodes a public key as `npub1…`.
#[must_use]
pub fn encode_npub(pubkey: &PublicKey) -> String {
    // 32-byte payloads produce ~70 characters, always under the limit.
    encode_bech32(HRP_NPUB, pubkey.as_bytes())
}

/// Encodes a secret key as `nsec1…`; the raw bytes stay inside
/// [`SecretKey::with_secret_bytes`].
#[must_use]
pub fn encode_nsec(secret: &SecretKey) -> String {
    secret.with_secret_bytes(|bytes| encode_bech32(HRP_NSEC, bytes))
}

/// Encodes an event id as `note1…`.
#[must_use]
pub fn encode_note(id: &EventId) -> String {
    encode_bech32(HRP_NOTE, id.as_bytes())
}

/// Decodes a NIP-19 bech32 entity.
///
/// Accepts all-lowercase and all-uppercase strings; mixed case is
/// rejected. `nsec` payloads must be valid secp256k1 scalars (ruling N2).
///
/// # Errors
///
/// [`ErrorKind::Nip19`] on malformed bech32, an unknown prefix, a wrong
/// payload length, malformed TLVs, an out-of-range kind, or an invalid
/// secret scalar (with the [`nk_core`] error as `source`).
pub fn decode(code: &str) -> Result<Entity> {
    let (hrp, data) = decode_bech32(code)?;

    if hrp == HRP_NPROFILE {
        let tlvs = parse_tlv(&data)?;
        let pubkey = tlv_bytes::<32>(&tlvs, TLV_SPECIAL, "nprofile")?;
        Ok(Entity::Profile(ProfilePointer {
            pubkey: PublicKey::from_bytes(pubkey),
            relays: tlv_relays(&tlvs),
        }))
    } else if hrp == HRP_NEVENT {
        let tlvs = parse_tlv(&data)?;
        let id = tlv_bytes::<32>(&tlvs, TLV_SPECIAL, "nevent")?;
        let author = match first_tlv(&tlvs, TLV_AUTHOR) {
            Some(value) => Some(PublicKey::from_bytes(
                value
                    .try_into()
                    .map_err(|_| nip19("TLV 2 should be 32 bytes"))?,
            )),
            None => None,
        };
        let kind = match first_tlv(&tlvs, TLV_KIND) {
            Some(_) => Some(read_kind(&tlvs, TLV_KIND, "nevent")?),
            None => None,
        };
        Ok(Entity::Event(EventPointer {
            id: EventId::from_bytes(id),
            relays: tlv_relays(&tlvs),
            author,
            kind,
        }))
    } else if hrp == HRP_NADDR {
        let tlvs = parse_tlv(&data)?;
        let identifier = required_tlv(&tlvs, TLV_SPECIAL, "naddr")?;
        let pubkey = tlv_bytes::<32>(&tlvs, TLV_AUTHOR, "naddr")?;
        let kind = read_kind(&tlvs, TLV_KIND, "naddr")?;
        Ok(Entity::Address(AddressPointer {
            identifier: String::from_utf8_lossy(identifier).into_owned(),
            pubkey: PublicKey::from_bytes(pubkey),
            kind,
            relays: tlv_relays(&tlvs),
        }))
    } else if hrp == HRP_NSEC {
        // The decoded buffer is wiped once the scalar is validated and the
        // `SecretKey` built (#210); a bad scalar wraps the nk-core error.
        let mut data = data;
        let secret = if data.len() == 32 {
            SecretKey::from_slice(&data)
                .map_err(|e| Error::with_source(ErrorKind::Nip19, "invalid nsec scalar", e))
        } else {
            Err(nip19("nsec must be 32 bytes"))
        };
        data.zeroize();
        Ok(Entity::Secret(secret?))
    } else if hrp == HRP_NPUB {
        let bytes: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| nip19("npub must be 32 bytes"))?;
        Ok(Entity::Public(PublicKey::from_bytes(bytes)))
    } else if hrp == HRP_NOTE {
        let bytes: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| nip19("note must be 32 bytes"))?;
        Ok(Entity::Note(EventId::from_bytes(bytes)))
    } else {
        Err(nip19(format!("unknown prefix {}", hrp.as_str())))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::string::ToString;
    use alloc::vec;

    use core::error::Error as _;

    use nk_core::EventId;

    use super::*;

    const PK: [u8; 32] = [0x42; 32];
    const ID: [u8; 32] = [0x11; 32];

    fn pubkey() -> PublicKey {
        PublicKey::from_bytes(PK)
    }

    fn event_id() -> EventId {
        EventId::from_bytes(ID)
    }

    /// Encodes arbitrary bytes under an arbitrary hrp, for building inputs
    /// the public encoders cannot produce (bad TLVs, odd prefixes, padding).
    fn craft(hrp: &str, data: &[u8]) -> String {
        encode_bech32(Hrp::parse_unchecked(hrp), data)
    }

    #[test]
    fn nip19_checksum_matches_stock_bech32() {
        // The Nip19Bech32 constants are the Bech32 ones with CODE_LENGTH
        // lifted to 5000: short payloads must encode identically.
        let stock = bech32::encode::<bech32::Bech32>(HRP_NPUB, &PK).unwrap();
        assert_eq!(encode_npub(&pubkey()), stock);
    }

    #[test]
    fn npub_round_trip() {
        let code = encode_npub(&pubkey());
        assert!(code.starts_with("npub1"));
        let Entity::Public(decoded) = decode(&code).unwrap() else {
            panic!("expected npub entity");
        };
        assert_eq!(decoded, pubkey());
        assert_eq!(Entity::Public(pubkey()).to_bech32().unwrap(), code);
    }

    #[test]
    fn note_round_trip() {
        let code = encode_note(&event_id());
        assert!(code.starts_with("note1"));
        let Entity::Note(decoded) = decode(&code).unwrap() else {
            panic!("expected note entity");
        };
        assert_eq!(decoded, event_id());
        assert_eq!(Entity::Note(event_id()).to_bech32().unwrap(), code);
    }

    #[test]
    fn nsec_round_trip() {
        let secret = SecretKey::from_bytes([3; 32]).unwrap();
        let code = encode_nsec(&secret);
        assert!(code.starts_with("nsec1"));
        let Entity::Secret(decoded) = decode(&code).unwrap() else {
            panic!("expected nsec entity");
        };
        assert_eq!(decoded.with_secret_bytes(|b| *b), [3; 32]);
        assert_eq!(Entity::Secret(decoded).to_bech32().unwrap(), code);
    }

    #[test]
    fn nprofile_round_trip_with_relays() {
        let pointer = ProfilePointer {
            pubkey: pubkey(),
            relays: vec!["wss://r.example".to_owned(), "wss://例え.jp".to_owned()],
        };
        let code = pointer.to_bech32().unwrap();
        assert!(code.starts_with("nprofile1"));
        let Entity::Profile(decoded) = decode(&code).unwrap() else {
            panic!("expected nprofile entity");
        };
        assert_eq!(decoded, pointer);
    }

    #[test]
    fn nevent_round_trip_optional_fields() {
        let bare = EventPointer {
            id: event_id(),
            relays: Vec::new(),
            author: None,
            kind: None,
        };
        let Entity::Event(decoded) = decode(&bare.to_bech32().unwrap()).unwrap() else {
            panic!("expected nevent entity");
        };
        assert_eq!(decoded, bare);

        let full = EventPointer {
            id: event_id(),
            relays: vec!["wss://r.example".to_owned()],
            author: Some(pubkey()),
            kind: Some(Kind::new(65535)),
        };
        let code = full.to_bech32().unwrap();
        let Entity::Event(decoded_full) = decode(&code).unwrap() else {
            panic!("expected nevent entity");
        };
        assert_eq!(decoded_full, full);
    }

    #[test]
    fn naddr_round_trip() {
        let pointer = AddressPointer {
            identifier: "article".to_owned(),
            pubkey: pubkey(),
            kind: Kind::new(30023),
            relays: vec!["wss://r.example".to_owned()],
        };
        let Entity::Address(decoded) = decode(&pointer.to_bech32().unwrap()).unwrap() else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded, pointer);

        let empty = AddressPointer {
            identifier: String::new(),
            pubkey: pubkey(),
            kind: Kind::new(0),
            relays: Vec::new(),
        };
        let Entity::Address(decoded_empty) = decode(&empty.to_bech32().unwrap()).unwrap() else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded_empty, empty);
    }

    #[test]
    fn tlv_write_order_is_descending() {
        let pointer = EventPointer {
            id: event_id(),
            relays: vec!["r".to_owned()],
            author: Some(pubkey()),
            kind: Some(Kind::new(1)),
        };
        let (_, data) = decode_bech32(&pointer.to_bech32().unwrap()).unwrap();
        // Kind(3), author(2), relay(1), id(0).
        assert_eq!(data.first(), Some(&TLV_KIND));
        assert_eq!(data.get(6), Some(&TLV_AUTHOR));
        assert_eq!(data.get(40), Some(&TLV_RELAY));
        assert_eq!(data.get(43), Some(&TLV_SPECIAL));
    }

    #[test]
    fn decode_accepts_unsorted_tlv_and_first_value_wins() {
        // Ascending order with a duplicated TLV 0: the second id is ignored.
        let other = [0x99; 32];
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut data, TLV_SPECIAL, &other).unwrap();
        push_tlv(&mut data, TLV_RELAY, b"wss://a").unwrap();
        push_tlv(&mut data, TLV_RELAY, b"wss://b").unwrap();
        let Entity::Profile(decoded) = decode(&craft("nprofile", &data)).unwrap() else {
            panic!("expected nprofile entity");
        };
        assert_eq!(decoded.pubkey.as_bytes(), &ID);
        assert_eq!(decoded.relays, ["wss://a", "wss://b"]);
    }

    #[test]
    fn unknown_tlv_types_are_ignored() {
        let mut data = Vec::new();
        push_tlv(&mut data, 42, b"unknown").unwrap();
        push_tlv(&mut data, TLV_SPECIAL, &ID).unwrap();
        let Entity::Profile(decoded) = decode(&craft("nprofile", &data)).unwrap() else {
            panic!("expected nprofile entity");
        };
        assert_eq!(decoded.pubkey.as_bytes(), &ID);
    }

    #[test]
    fn lossy_utf8_in_identifier_and_relays() {
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_SPECIAL, &[0x66, 0x80]).unwrap(); // "f" + invalid
        push_tlv(&mut data, TLV_RELAY, &[0xff]).unwrap();
        push_tlv(&mut data, TLV_AUTHOR, &PK).unwrap();
        push_tlv(&mut data, TLV_KIND, &1u32.to_be_bytes()).unwrap();
        let Entity::Address(decoded) = decode(&craft("naddr", &data)).unwrap() else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded.identifier, "f\u{fffd}");
        assert_eq!(decoded.relays, ["\u{fffd}"]);
    }

    #[test]
    fn uppercase_decodes_mixed_case_rejected() {
        let lower = encode_npub(&pubkey());
        let upper = lower.to_uppercase();
        let Entity::Public(decoded) = decode(&upper).unwrap() else {
            panic!("expected npub entity");
        };
        assert_eq!(decoded, pubkey());
        let mut mixed = lower;
        mixed.replace_range(5..6, "P");
        assert_eq!(decode(&mixed).unwrap_err().kind(), ErrorKind::Nip19);
    }

    #[test]
    fn wrong_checksum_rejected() {
        let mut code = encode_npub(&pubkey());
        let last = code.pop().unwrap();
        code.push(if last == 'q' { 'p' } else { 'q' });
        assert_eq!(decode(&code).unwrap_err().kind(), ErrorKind::Nip19);
    }

    #[test]
    fn unknown_prefix_rejected() {
        let code = craft("nzzz", &[1, 2, 3]);
        let err = decode(&code).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Nip19);
        assert!(err.to_string().contains("unknown prefix"));
    }

    #[test]
    fn wrong_length_payloads_rejected() {
        for hrp in ["npub", "note", "nsec"] {
            let err = decode(&craft(hrp, &[0u8; 16])).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Nip19, "{hrp}");
        }
    }

    #[test]
    fn invalid_nsec_scalars_rejected_with_source() {
        for scalar in [[0u8; 32], [0xff; 32]] {
            let err = decode(&craft("nsec", &scalar)).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Nip19);
            assert!(err.source().is_some());
        }
    }

    #[test]
    fn kind_boundaries() {
        let pointer = AddressPointer {
            identifier: String::new(),
            pubkey: pubkey(),
            kind: Kind::new(65535),
            relays: Vec::new(),
        };
        decode(&pointer.to_bech32().unwrap()).unwrap();

        // 65536 on the wire is out of range (ruling N1).
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_SPECIAL, b"").unwrap();
        push_tlv(&mut data, TLV_AUTHOR, &PK).unwrap();
        push_tlv(&mut data, TLV_KIND, &65536u32.to_be_bytes()).unwrap();
        let err = decode(&craft("naddr", &data)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Nip19);
        assert!(err.to_string().contains("invalid kind"));

        // Same rejection on the optional nevent kind.
        let mut event_data = Vec::new();
        push_tlv(&mut event_data, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut event_data, TLV_KIND, &u32::MAX.to_be_bytes()).unwrap();
        assert_eq!(
            decode(&craft("nevent", &event_data)).unwrap_err().kind(),
            ErrorKind::Nip19
        );
    }

    #[test]
    fn malformed_tlv_rejected() {
        assert_eq!(
            decode(&craft("nprofile", &[1])).unwrap_err().kind(),
            ErrorKind::Nip19
        );
        // Declared length runs past the data.
        let err = decode(&craft("nprofile", &[TLV_RELAY, 9, 1, 2])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Nip19);
        // Missing TLV 0.
        let missing = decode(&craft("nprofile", &[])).unwrap_err();
        assert!(missing.to_string().contains("missing TLV 0"));
        let missing_two = decode(&craft("naddr", &[TLV_SPECIAL, 0])).unwrap_err();
        assert!(missing_two.to_string().contains("missing TLV 2"));
        // Wrong-length single-valued TLVs.
        let mut short = Vec::new();
        push_tlv(&mut short, TLV_SPECIAL, &[0u8; 16]).unwrap();
        assert_eq!(
            decode(&craft("nprofile", &short)).unwrap_err().kind(),
            ErrorKind::Nip19
        );
        let mut bad_author = Vec::new();
        push_tlv(&mut bad_author, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut bad_author, TLV_AUTHOR, &[0u8; 16]).unwrap();
        assert_eq!(
            decode(&craft("nevent", &bad_author)).unwrap_err().kind(),
            ErrorKind::Nip19
        );
        let mut bad_kind = Vec::new();
        push_tlv(&mut bad_kind, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut bad_kind, TLV_KIND, &[0u8; 2]).unwrap();
        assert_eq!(
            decode(&craft("nevent", &bad_kind)).unwrap_err().kind(),
            ErrorKind::Nip19
        );
    }

    #[test]
    fn relay_over_255_bytes_fails_to_encode() {
        let relay = format!("wss://{}", "a".repeat(300));
        let pointer = ProfilePointer {
            pubkey: pubkey(),
            relays: vec![relay.clone()],
        };
        assert_eq!(pointer.to_bech32().unwrap_err().kind(), ErrorKind::Nip19);
        let event = EventPointer {
            id: event_id(),
            relays: vec![relay],
            author: None,
            kind: None,
        };
        assert_eq!(event.to_bech32().unwrap_err().kind(), ErrorKind::Nip19);
        let address = AddressPointer {
            identifier: "x".repeat(300),
            pubkey: pubkey(),
            kind: Kind::new(1),
            relays: Vec::new(),
        };
        assert_eq!(address.to_bech32().unwrap_err().kind(), ErrorKind::Nip19);
    }

    #[test]
    fn length_boundary_5000() {
        // naddr payload of exactly 3117 bytes encodes to 5000 chars:
        // hrp(5) + sep(1) + ceil(3117*8/5) fes (4988) + checksum(6).
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_SPECIAL, b"d").unwrap();
        push_tlv(&mut data, TLV_AUTHOR, &PK).unwrap();
        push_tlv(&mut data, TLV_KIND, &1u32.to_be_bytes()).unwrap();
        while data.len() < 3117 {
            let room = 3117 - data.len();
            let vlen = room.saturating_sub(2).min(255);
            push_tlv(&mut data, 99, &vec![0x55; vlen]).unwrap();
        }
        assert_eq!(data.len(), 3117);
        let code = craft("naddr", &data);
        assert_eq!(code.len(), BECH32_MAX_LEN);
        assert!(decode(&code).is_ok());

        data.push(0);
        let over = craft("naddr", &data);
        assert_eq!(over.len(), BECH32_MAX_LEN + 1);
        assert_eq!(decode(&over).unwrap_err().kind(), ErrorKind::Nip19);
    }

    #[test]
    fn non_canonical_padding_rejected() {
        // A 32-byte payload encodes to 52 fes = 260 bits; the last fe holds
        // 1 data bit and 4 padding bits that must be zero. Setting a padding
        // bit keeps the payload bytes identical but must still be rejected —
        // `@scure/base` calls this "Non-zero padding".
        let mut fes: Vec<Fe32> = PK.iter().copied().bytes_to_fes().collect();
        let last = fes.last_mut().unwrap();
        *last = Fe32::try_from(last.to_u8() | 0b0001).unwrap();
        let code: String = fes
            .iter()
            .copied()
            .with_checksum::<Nip19Bech32>(&HRP_NPUB)
            .chars()
            .collect();
        assert_eq!(decode(&code).unwrap_err().kind(), ErrorKind::Nip19);
    }
}
