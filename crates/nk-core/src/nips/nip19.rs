//! NIP-19 bech32-encoded entities.
//!
//! `npub`, `nsec`, `note` carry a bare 32-byte payload; `nprofile`,
//! `nevent`, `naddr` carry a TLV record. TLVs are written in descending
//! type order, duplicate TLV types keep the first value (relays keep all),
//! identifier and relay bytes decode lossy as UTF-8, and the whole string
//! is at most [`BECH32_MAX_LEN`] characters. All-lowercase and
//! all-uppercase strings decode; mixed case is rejected.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/19.md>

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;
use core::str::FromStr;

use crate::{EventId, Kind, PublicKey, SecretKey};
use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{ByteIterExt, Checksum, Fe32, Fe32IterExt, Fe1024, Hrp};
use zeroize::Zeroizing;

/// Maximum bech32 string length accepted by decoders (NIP-19).
pub const BECH32_MAX_LEN: usize = 5000;

/// `bech32::Bech32` with the NIP-19 length limit: the stock checksum type
/// caps codes at 1023 characters, NIP-19 allows 5000. Shared with `nip49`
/// (`ncryptsec` uses the same long checksum).
pub(crate) enum Nip19Bech32 {}

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

/// Errors produced by NIP-19 bech32 encoding and decoding.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The string is not valid bech32 (bad charset, checksum, mixed case,
    /// non-canonical padding, or over [`BECH32_MAX_LEN`] characters).
    #[error("invalid bech32")]
    Bech32 {
        /// The decode failure.
        #[source]
        source: DecodeError,
    },
    /// The encoded string exceeds [`BECH32_MAX_LEN`] characters.
    #[error("bech32 string exceeds 5000 characters: {len}")]
    TooLong {
        /// The encoded length in characters.
        len: usize,
    },
    /// The human-readable prefix is not a NIP-19 prefix.
    #[error("unknown bech32 prefix {prefix}")]
    UnknownPrefix {
        /// The unrecognized prefix.
        prefix: String,
    },
    /// The string carries a different NIP-19 prefix than required.
    #[error("expected a {expected} string, got {found}")]
    UnexpectedPrefix {
        /// The required prefix.
        expected: &'static str,
        /// The prefix that was found.
        found: String,
    },
    /// A payload is not the required byte length.
    #[error("invalid length: expected {expected} bytes, got {found}")]
    InvalidLength {
        /// The required byte count.
        expected: usize,
        /// The actual byte count.
        found: usize,
    },
    /// The `nsec` payload is not a valid secp256k1 secret scalar.
    #[error("invalid secret key")]
    InvalidSecretKey,
    /// A required TLV record is absent.
    #[error("missing required {tlv}")]
    MissingTlv {
        /// The missing record, described by position.
        tlv: &'static str,
    },
    /// A TLV record or the TLV stream itself is malformed.
    #[error("invalid {tlv}")]
    InvalidTlv {
        /// The malformed record, described by position.
        tlv: &'static str,
    },
    /// A TLV value exceeds the 255-byte single-byte length field.
    #[error("TLV value exceeds 255 bytes: {len}")]
    TlvTooLong {
        /// The value length in bytes.
        len: usize,
    },
    /// The kind TLV does not fit the NIP-01 range 0–65535.
    #[error("kind {kind} is out of the 0-65535 range")]
    KindOutOfRange {
        /// The out-of-range wire value.
        kind: u32,
    },
}

/// The decode failure inside [`Error::Bech32`]: a checksum/format error
/// from the `bech32` crate or the non-canonical-padding check NIP-19 adds
/// on top.
#[derive(Debug)]
pub enum DecodeError {
    /// Bech32 encoding/decoding failure.
    Bech32(CheckedHrpstringError),
    /// Non-canonical or invalid padding.
    Padding,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bech32(error) => fmt::Display::fmt(error, f),
            Self::Padding => f.write_str("non-zero padding in bech32 payload"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Encodes `data` under `hrp` as a lowercase bech32 string.
pub(crate) fn encode_bech32(hrp: Hrp, data: &[u8]) -> String {
    data.iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Nip19Bech32>(&hrp)
        .chars()
        .collect()
}

/// [`encode_bech32`] plus the NIP-19 length limit: a 32-byte payload never
/// reaches it, but TLV encoders can.
fn encode_bech32_tlv(hrp: Hrp, data: &[u8]) -> Result<String, Error> {
    let code = encode_bech32(hrp, data);
    if code.len() > BECH32_MAX_LEN {
        return Err(Error::TooLong { len: code.len() });
    }
    Ok(code)
}

/// Parses and checksum-verifies `code`, returning the hrp and payload bytes.
/// Fails on any format, checksum, or canonical-padding violation.
pub(crate) fn decode_bech32(code: &str) -> Result<(Hrp, Vec<u8>), DecodeError> {
    let checked = CheckedHrpstring::new::<Nip19Bech32>(code).map_err(DecodeError::Bech32)?;
    let fes: Vec<Fe32> = checked.fe32_iter().collect();
    // Canonical-padding rule: the trailing partial byte must be shorter
    // than one field element and carry only zero bits.
    let leftover = (fes.len() * 5) % 8;
    let last = fes.last().map_or(0, |fe| fe.to_u8());
    if leftover >= 5 || (leftover > 0 && last & ((1u8 << leftover) - 1) != 0) {
        return Err(DecodeError::Padding);
    }
    Ok((checked.hrp(), fes.iter().copied().fes_to_bytes().collect()))
}

/// [`decode_bech32`] with the module error.
fn decode_nip19_bech32(code: &str) -> Result<(Hrp, Vec<u8>), Error> {
    decode_bech32(code).map_err(|e| Error::Bech32 { source: e })
}

/// A profile pointer (`nprofile`): a pubkey plus relay hints.
///
/// `relays` are stored verbatim — NIP-19 hints are opaque data, not
/// normalized [`crate::RelayUrl`]s.
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

impl Entity {
    /// The bech32 prefix this entity encodes under.
    const fn prefix(&self) -> &'static str {
        match self {
            Self::Profile(_) => "nprofile",
            Self::Event(_) => "nevent",
            Self::Address(_) => "naddr",
            Self::Secret(_) => "nsec",
            Self::Public(_) => "npub",
            Self::Note(_) => "note",
        }
    }
}

/// TLV records in wire order, keyed by type byte.
type Tlvs<'a> = BTreeMap<u8, Vec<&'a [u8]>>;

fn parse_tlv(data: &[u8]) -> Result<Tlvs<'_>, Error> {
    let mut tlvs: Tlvs<'_> = BTreeMap::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some(&[ty, len]) = rest
            .get(..2)
            .and_then(|head| <&[u8; 2]>::try_from(head).ok())
        else {
            return Err(Error::InvalidTlv { tlv: "TLV stream" });
        };
        let Some((value, tail)) = rest
            .get(2..)
            .and_then(|body| body.split_at_checked(usize::from(len)))
        else {
            return Err(Error::InvalidTlv { tlv: "TLV stream" });
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

fn required_tlv<'a>(tlvs: &'a Tlvs<'_>, ty: u8, tlv: &'static str) -> Result<&'a [u8], Error> {
    first_tlv(tlvs, ty).ok_or(Error::MissingTlv { tlv })
}

/// First value of TLV `ty`, checked to be exactly `N` bytes.
fn tlv_bytes<const N: usize>(tlvs: &Tlvs<'_>, ty: u8, tlv: &'static str) -> Result<[u8; N], Error> {
    let value = required_tlv(tlvs, ty, tlv)?;
    value.try_into().map_err(|_| Error::InvalidTlv { tlv })
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
/// range 0–65535 on both encode and decode.
fn read_kind(tlvs: &Tlvs<'_>, ty: u8, tlv: &'static str) -> Result<Kind, Error> {
    let raw = u32::from_be_bytes(tlv_bytes::<4>(tlvs, ty, tlv)?);
    u16::try_from(raw)
        .map(Kind::new)
        .map_err(|_| Error::KindOutOfRange { kind: raw })
}

fn push_tlv(out: &mut Vec<u8>, ty: u8, value: &[u8]) -> Result<(), Error> {
    let len = u8::try_from(value.len()).map_err(|_| Error::TlvTooLong { len: value.len() })?;
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
    /// [`Error::TlvTooLong`] when a relay hint exceeds 255 bytes;
    /// [`Error::TooLong`] when the encoded string exceeds
    /// [`BECH32_MAX_LEN`].
    pub fn to_bech32(&self) -> Result<String, Error> {
        let mut data = Vec::new();
        // TLVs are written in ascending type order (0 special, 1 relays).
        push_tlv(&mut data, TLV_SPECIAL, self.pubkey.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        encode_bech32_tlv(HRP_NPROFILE, &data)
    }

    /// Decodes an `nprofile1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other prefixes; the [`Error`] decode
    /// variants on malformed input.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Profile(pointer) => Ok(pointer),
            other => Err(Error::UnexpectedPrefix {
                expected: "nprofile",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

impl EventPointer {
    /// Encodes the pointer as a `nevent1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::TlvTooLong`] when a relay hint exceeds 255 bytes;
    /// [`Error::TooLong`] when the encoded string exceeds
    /// [`BECH32_MAX_LEN`].
    pub fn to_bech32(&self) -> Result<String, Error> {
        let mut data = Vec::new();
        // Ascending type order: 0 special, 1 relays, 2 author, 3 kind.
        push_tlv(&mut data, TLV_SPECIAL, self.id.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        if let Some(author) = self.author {
            push_tlv(&mut data, TLV_AUTHOR, author.as_bytes())?;
        }
        if let Some(kind) = self.kind {
            push_tlv(&mut data, TLV_KIND, &u32::from(kind.as_u16()).to_be_bytes())?;
        }
        encode_bech32_tlv(HRP_NEVENT, &data)
    }

    /// Decodes a `nevent1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other prefixes; the [`Error`] decode
    /// variants on malformed input.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Event(pointer) => Ok(pointer),
            other => Err(Error::UnexpectedPrefix {
                expected: "nevent",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

impl AddressPointer {
    /// Encodes the pointer as a `naddr1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::TlvTooLong`] when the identifier or a relay hint exceeds 255
    /// bytes; [`Error::TooLong`] when the encoded string exceeds
    /// [`BECH32_MAX_LEN`].
    pub fn to_bech32(&self) -> Result<String, Error> {
        let mut data = Vec::new();
        // Ascending type order: 0 special, 1 relays, 2 author, 3 kind.
        push_tlv(&mut data, TLV_SPECIAL, self.identifier.as_bytes())?;
        for relay in &self.relays {
            push_tlv(&mut data, TLV_RELAY, relay.as_bytes())?;
        }
        push_tlv(&mut data, TLV_AUTHOR, self.pubkey.as_bytes())?;
        push_tlv(
            &mut data,
            TLV_KIND,
            &u32::from(self.kind.as_u16()).to_be_bytes(),
        )?;
        encode_bech32_tlv(HRP_NADDR, &data)
    }

    /// Decodes an `naddr1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other prefixes; the [`Error`] decode
    /// variants on malformed input.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Address(pointer) => Ok(pointer),
            other => Err(Error::UnexpectedPrefix {
                expected: "naddr",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

impl Entity {
    /// Encodes the entity back to its bech32 form.
    ///
    /// # Errors
    ///
    /// [`Error::TlvTooLong`] when a pointer's relay hint or identifier
    /// exceeds 255 bytes; [`Error::TooLong`] when the encoded string
    /// exceeds [`BECH32_MAX_LEN`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nk_core::nips::nip19::Entity;
    /// use nk_core::PublicKey;
    ///
    /// let key = PublicKey::from_hex(
    ///     "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
    /// )
    /// .unwrap();
    /// let code = Entity::Public(key).to_bech32()?;
    /// assert_eq!(
    ///     code,
    ///     "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
    /// );
    /// assert_eq!(Entity::from_bech32(&code)?.to_bech32()?, code);
    /// # Ok::<(), nk_core::nips::nip19::Error>(())
    /// ```
    pub fn to_bech32(&self) -> Result<String, Error> {
        match self {
            Self::Profile(pointer) => pointer.to_bech32(),
            Self::Event(pointer) => pointer.to_bech32(),
            Self::Address(pointer) => pointer.to_bech32(),
            Self::Secret(secret) => Ok(secret.to_bech32()),
            Self::Public(pubkey) => Ok(pubkey.to_bech32()),
            Self::Note(id) => Ok(id.to_bech32()),
        }
    }

    /// Decodes a NIP-19 bech32 entity.
    ///
    /// Accepts all-lowercase and all-uppercase strings; mixed case is
    /// rejected. `nsec` payloads must be valid secp256k1 scalars.
    ///
    /// # Errors
    ///
    /// [`Error::Bech32`] on malformed bech32, [`Error::UnknownPrefix`] on
    /// an unrecognized prefix, [`Error::InvalidLength`] on a wrong payload
    /// length, [`Error::MissingTlv`]/[`Error::InvalidTlv`] on malformed
    /// TLVs, [`Error::KindOutOfRange`] on an out-of-range kind, and
    /// [`Error::InvalidSecretKey`] on an invalid secret scalar.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        // The drop guard wipes the decoded buffer on every path — `nsec`
        // payloads are secret key material.
        let (hrp, data) = decode_nip19_bech32(code)?;
        let data = Zeroizing::new(data);

        if hrp == HRP_NPROFILE {
            let tlvs = parse_tlv(&data)?;
            let pubkey = tlv_bytes::<32>(&tlvs, TLV_SPECIAL, "nprofile pubkey TLV")?;
            Ok(Self::Profile(ProfilePointer {
                pubkey: PublicKey::from_bytes(pubkey),
                relays: tlv_relays(&tlvs),
            }))
        } else if hrp == HRP_NEVENT {
            let tlvs = parse_tlv(&data)?;
            let id = tlv_bytes::<32>(&tlvs, TLV_SPECIAL, "nevent id TLV")?;
            let author = match first_tlv(&tlvs, TLV_AUTHOR) {
                Some(value) => Some(PublicKey::from_bytes(value.try_into().map_err(|_| {
                    Error::InvalidTlv {
                        tlv: "nevent author TLV",
                    }
                })?)),
                None => None,
            };
            let kind = match first_tlv(&tlvs, TLV_KIND) {
                Some(_) => Some(read_kind(&tlvs, TLV_KIND, "nevent kind TLV")?),
                None => None,
            };
            Ok(Self::Event(EventPointer {
                id: EventId::from_bytes(id),
                relays: tlv_relays(&tlvs),
                author,
                kind,
            }))
        } else if hrp == HRP_NADDR {
            let tlvs = parse_tlv(&data)?;
            let identifier = required_tlv(&tlvs, TLV_SPECIAL, "naddr identifier TLV")?;
            let pubkey = tlv_bytes::<32>(&tlvs, TLV_AUTHOR, "naddr pubkey TLV")?;
            let kind = read_kind(&tlvs, TLV_KIND, "naddr kind TLV")?;
            Ok(Self::Address(AddressPointer {
                identifier: String::from_utf8_lossy(identifier).into_owned(),
                pubkey: PublicKey::from_bytes(pubkey),
                kind,
                relays: tlv_relays(&tlvs),
            }))
        } else if hrp == HRP_NSEC {
            // A bad scalar surfaces as [`Error::InvalidSecretKey`]; the
            // `data` guard wipes the decoded bytes either way.
            let secret = if data.len() == 32 {
                SecretKey::from_slice(&data).map_err(|_| Error::InvalidSecretKey)
            } else {
                Err(Error::InvalidLength {
                    expected: 32,
                    found: data.len(),
                })
            };
            Ok(Self::Secret(secret?))
        } else if hrp == HRP_NPUB {
            let bytes: [u8; 32] = data
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidLength {
                    expected: 32,
                    found: data.len(),
                })?;
            Ok(Self::Public(PublicKey::from_bytes(bytes)))
        } else if hrp == HRP_NOTE {
            let bytes: [u8; 32] = data
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidLength {
                    expected: 32,
                    found: data.len(),
                })?;
            Ok(Self::Note(EventId::from_bytes(bytes)))
        } else {
            Err(Error::UnknownPrefix {
                prefix: hrp.as_str().to_owned(),
            })
        }
    }
}

impl FromStr for Entity {
    type Err = Error;

    /// Parses a NIP-19 bech32 entity — identical to
    /// [`Entity::from_bech32`].
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bech32(s)
    }
}

impl PublicKey {
    /// Encodes the public key as an `npub1…` string.
    #[must_use]
    pub fn to_bech32(self) -> String {
        encode_bech32(HRP_NPUB, self.as_bytes())
    }

    /// Decodes an `npub1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other NIP-19 prefixes; the [`Error`]
    /// decode variants on malformed input.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Public(pubkey) => Ok(pubkey),
            other => Err(Error::UnexpectedPrefix {
                expected: "npub",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

impl EventId {
    /// Encodes the event id as a `note1…` string.
    #[must_use]
    pub fn to_bech32(self) -> String {
        encode_bech32(HRP_NOTE, self.as_bytes())
    }

    /// Decodes a `note1…` string.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other NIP-19 prefixes; the [`Error`]
    /// decode variants on malformed input.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Note(id) => Ok(id),
            other => Err(Error::UnexpectedPrefix {
                expected: "note",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

impl SecretKey {
    /// Encodes the secret key as an `nsec1…` string; the raw bytes stay
    /// inside [`SecretKey::with_secret_bytes`].
    #[must_use]
    pub fn to_bech32(&self) -> String {
        self.with_secret_bytes(|bytes| encode_bech32(HRP_NSEC, bytes))
    }

    /// Decodes an `nsec1…` string. The payload must be a valid secp256k1
    /// secret scalar.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedPrefix`] for other NIP-19 prefixes;
    /// [`Error::InvalidLength`] when the payload is not 32 bytes;
    /// [`Error::InvalidSecretKey`] when it is not a valid scalar.
    pub fn from_bech32(code: &str) -> Result<Self, Error> {
        match Entity::from_bech32(code)? {
            Entity::Secret(secret) => Ok(secret),
            other => Err(Error::UnexpectedPrefix {
                expected: "nsec",
                found: other.prefix().to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::vec;

    use core::error::Error as _;

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
        assert_eq!(pubkey().to_bech32(), stock);
    }

    #[test]
    fn npub_round_trip() {
        let code = pubkey().to_bech32();
        assert!(code.starts_with("npub1"));
        let Entity::Public(decoded) = Entity::from_bech32(&code).unwrap() else {
            panic!("expected npub entity");
        };
        assert_eq!(decoded, pubkey());
        assert_eq!(Entity::Public(pubkey()).to_bech32().unwrap(), code);
        assert_eq!(PublicKey::from_bech32(&code).unwrap(), pubkey());
    }

    #[test]
    fn note_round_trip() {
        let code = event_id().to_bech32();
        assert!(code.starts_with("note1"));
        let Entity::Note(decoded) = Entity::from_bech32(&code).unwrap() else {
            panic!("expected note entity");
        };
        assert_eq!(decoded, event_id());
        assert_eq!(Entity::Note(event_id()).to_bech32().unwrap(), code);
        assert_eq!(EventId::from_bech32(&code).unwrap(), event_id());
    }

    #[test]
    fn nsec_round_trip() {
        let secret = SecretKey::from_bytes([3; 32]).unwrap();
        let code = secret.to_bech32();
        assert!(code.starts_with("nsec1"));
        let Entity::Secret(decoded) = Entity::from_bech32(&code).unwrap() else {
            panic!("expected nsec entity");
        };
        assert_eq!(decoded.with_secret_bytes(|b| *b), [3; 32]);
        assert_eq!(Entity::Secret(decoded).to_bech32().unwrap(), code);
        let key = SecretKey::from_bech32(&code).unwrap();
        assert_eq!(key.with_secret_bytes(|b| *b), [3; 32]);
    }

    #[test]
    fn nprofile_round_trip_with_relays() {
        let pointer = ProfilePointer {
            pubkey: pubkey(),
            relays: vec!["wss://r.example".to_owned(), "wss://例え.jp".to_owned()],
        };
        let code = pointer.to_bech32().unwrap();
        assert!(code.starts_with("nprofile1"));
        let Entity::Profile(decoded) = Entity::from_bech32(&code).unwrap() else {
            panic!("expected nprofile entity");
        };
        assert_eq!(decoded, pointer);
        assert_eq!(ProfilePointer::from_bech32(&code).unwrap(), pointer);
    }

    #[test]
    fn nevent_round_trip_optional_fields() {
        let bare = EventPointer {
            id: event_id(),
            relays: Vec::new(),
            author: None,
            kind: None,
        };
        let Entity::Event(decoded) = Entity::from_bech32(&bare.to_bech32().unwrap()).unwrap()
        else {
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
        let Entity::Event(decoded_full) = Entity::from_bech32(&code).unwrap() else {
            panic!("expected nevent entity");
        };
        assert_eq!(decoded_full, full);
        assert_eq!(EventPointer::from_bech32(&code).unwrap(), full);
    }

    #[test]
    fn naddr_round_trip() {
        let pointer = AddressPointer {
            identifier: "article".to_owned(),
            pubkey: pubkey(),
            kind: Kind::new(30023),
            relays: vec!["wss://r.example".to_owned()],
        };
        let Entity::Address(decoded) = Entity::from_bech32(&pointer.to_bech32().unwrap()).unwrap()
        else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded, pointer);

        let empty = AddressPointer {
            identifier: String::new(),
            pubkey: pubkey(),
            kind: Kind::new(0),
            relays: Vec::new(),
        };
        let Entity::Address(decoded_empty) =
            Entity::from_bech32(&empty.to_bech32().unwrap()).unwrap()
        else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded_empty, empty);
        assert_eq!(
            AddressPointer::from_bech32(&pointer.to_bech32().unwrap()).unwrap(),
            pointer
        );
    }

    #[test]
    fn entity_from_str_matches_from_bech32() {
        let code = pubkey().to_bech32();
        assert!(matches!(
            code.parse::<Entity>(),
            Ok(Entity::Public(pk)) if pk == pubkey()
        ));
    }

    #[test]
    fn typed_from_bech32_rejects_other_prefixes() {
        let pubkey_code = pubkey().to_bech32();
        assert!(matches!(
            EventId::from_bech32(&pubkey_code),
            Err(Error::UnexpectedPrefix {
                expected: "note",
                ..
            })
        ));
        assert!(matches!(
            SecretKey::from_bech32(&pubkey_code),
            Err(Error::UnexpectedPrefix {
                expected: "nsec",
                ..
            })
        ));
        assert!(matches!(
            ProfilePointer::from_bech32(&pubkey_code),
            Err(Error::UnexpectedPrefix {
                expected: "nprofile",
                ..
            })
        ));
        let note_code = event_id().to_bech32();
        assert!(matches!(
            PublicKey::from_bech32(&note_code),
            Err(Error::UnexpectedPrefix {
                expected: "npub",
                ..
            })
        ));
    }

    #[test]
    fn tlv_write_order_is_ascending() {
        let pointer = EventPointer {
            id: event_id(),
            relays: vec!["r".to_owned()],
            author: Some(pubkey()),
            kind: Some(Kind::new(1)),
        };
        let (_, data) = decode_nip19_bech32(&pointer.to_bech32().unwrap()).unwrap();
        // Id(0) at 0, relay(1) at 34, author(2) at 37, kind(3) at 71.
        assert_eq!(data.first(), Some(&TLV_SPECIAL));
        assert_eq!(data.get(34), Some(&TLV_RELAY));
        assert_eq!(data.get(37), Some(&TLV_AUTHOR));
        assert_eq!(data.get(71), Some(&TLV_KIND));
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
        let Entity::Profile(decoded) = Entity::from_bech32(&craft("nprofile", &data)).unwrap()
        else {
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
        let Entity::Profile(decoded) = Entity::from_bech32(&craft("nprofile", &data)).unwrap()
        else {
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
        let Entity::Address(decoded) = Entity::from_bech32(&craft("naddr", &data)).unwrap() else {
            panic!("expected naddr entity");
        };
        assert_eq!(decoded.identifier, "f\u{fffd}");
        assert_eq!(decoded.relays, ["\u{fffd}"]);
    }

    #[test]
    fn uppercase_decodes_mixed_case_rejected() {
        let lower = pubkey().to_bech32();
        let upper = lower.to_uppercase();
        let Entity::Public(decoded) = Entity::from_bech32(&upper).unwrap() else {
            panic!("expected npub entity");
        };
        assert_eq!(decoded, pubkey());
        let mut mixed = lower;
        mixed.replace_range(5..6, "P");
        assert!(matches!(
            Entity::from_bech32(&mixed),
            Err(Error::Bech32 { .. })
        ));
    }

    #[test]
    fn wrong_checksum_rejected() {
        let mut code = pubkey().to_bech32();
        let last = code.pop().unwrap();
        code.push(if last == 'q' { 'p' } else { 'q' });
        let err = Entity::from_bech32(&code).unwrap_err();
        assert!(matches!(err, Error::Bech32 { .. }));
        assert!(err.source().is_some());
    }

    #[test]
    fn unknown_prefix_rejected() {
        let code = craft("nzzz", &[1, 2, 3]);
        assert!(matches!(
            Entity::from_bech32(&code),
            Err(Error::UnknownPrefix { .. })
        ));
    }

    #[test]
    fn wrong_length_payloads_rejected() {
        for hrp in ["npub", "note", "nsec"] {
            assert!(
                matches!(
                    Entity::from_bech32(&craft(hrp, &[0u8; 16])),
                    Err(Error::InvalidLength {
                        expected: 32,
                        found: 16
                    })
                ),
                "{hrp}"
            );
        }
    }

    #[test]
    fn invalid_nsec_scalars_rejected() {
        for scalar in [[0u8; 32], [0xff; 32]] {
            assert!(matches!(
                Entity::from_bech32(&craft("nsec", &scalar)),
                Err(Error::InvalidSecretKey)
            ));
            assert!(matches!(
                SecretKey::from_bech32(&craft("nsec", &scalar)),
                Err(Error::InvalidSecretKey)
            ));
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
        Entity::from_bech32(&pointer.to_bech32().unwrap()).unwrap();

        // 65536 on the wire is out of range.
        let mut data = Vec::new();
        push_tlv(&mut data, TLV_SPECIAL, b"").unwrap();
        push_tlv(&mut data, TLV_AUTHOR, &PK).unwrap();
        push_tlv(&mut data, TLV_KIND, &65536u32.to_be_bytes()).unwrap();
        assert!(matches!(
            Entity::from_bech32(&craft("naddr", &data)),
            Err(Error::KindOutOfRange { kind: 65536 })
        ));

        // Same rejection on the optional nevent kind.
        let mut event_data = Vec::new();
        push_tlv(&mut event_data, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut event_data, TLV_KIND, &u32::MAX.to_be_bytes()).unwrap();
        assert!(matches!(
            Entity::from_bech32(&craft("nevent", &event_data)),
            Err(Error::KindOutOfRange { kind: u32::MAX })
        ));
    }

    #[test]
    fn malformed_tlv_rejected() {
        assert!(matches!(
            Entity::from_bech32(&craft("nprofile", &[1])),
            Err(Error::InvalidTlv { .. })
        ));
        // Declared length runs past the data.
        assert!(matches!(
            Entity::from_bech32(&craft("nprofile", &[TLV_RELAY, 9, 1, 2])),
            Err(Error::InvalidTlv { .. })
        ));
        // Missing required TLVs.
        assert!(matches!(
            Entity::from_bech32(&craft("nprofile", &[])),
            Err(Error::MissingTlv { .. })
        ));
        assert!(matches!(
            Entity::from_bech32(&craft("naddr", &[TLV_SPECIAL, 0])),
            Err(Error::MissingTlv { .. })
        ));
        // Wrong-length single-valued TLVs.
        let mut short = Vec::new();
        push_tlv(&mut short, TLV_SPECIAL, &[0u8; 16]).unwrap();
        assert!(matches!(
            Entity::from_bech32(&craft("nprofile", &short)),
            Err(Error::InvalidTlv { .. })
        ));
        let mut bad_author = Vec::new();
        push_tlv(&mut bad_author, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut bad_author, TLV_AUTHOR, &[0u8; 16]).unwrap();
        assert!(matches!(
            Entity::from_bech32(&craft("nevent", &bad_author)),
            Err(Error::InvalidTlv { .. })
        ));
        let mut bad_kind = Vec::new();
        push_tlv(&mut bad_kind, TLV_SPECIAL, &ID).unwrap();
        push_tlv(&mut bad_kind, TLV_KIND, &[0u8; 2]).unwrap();
        assert!(matches!(
            Entity::from_bech32(&craft("nevent", &bad_kind)),
            Err(Error::InvalidTlv { .. })
        ));
    }

    #[test]
    fn relay_over_255_bytes_fails_to_encode() {
        let relay = format!("wss://{}", "a".repeat(300));
        let pointer = ProfilePointer {
            pubkey: pubkey(),
            relays: vec![relay.clone()],
        };
        assert!(matches!(
            pointer.to_bech32(),
            Err(Error::TlvTooLong { len: 306 })
        ));
        let event = EventPointer {
            id: event_id(),
            relays: vec![relay],
            author: None,
            kind: None,
        };
        assert!(matches!(
            event.to_bech32(),
            Err(Error::TlvTooLong { len: 306 })
        ));
        let address = AddressPointer {
            identifier: "x".repeat(300),
            pubkey: pubkey(),
            kind: Kind::new(1),
            relays: Vec::new(),
        };
        assert!(matches!(
            address.to_bech32(),
            Err(Error::TlvTooLong { len: 300 })
        ));
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
        assert!(Entity::from_bech32(&code).is_ok());

        data.push(0);
        let over = craft("naddr", &data);
        assert_eq!(over.len(), BECH32_MAX_LEN + 1);
        assert!(matches!(
            Entity::from_bech32(&over),
            Err(Error::Bech32 { .. })
        ));
    }

    #[test]
    fn non_canonical_padding_rejected() {
        // A 32-byte payload encodes to 52 fes = 260 bits; the last fe holds
        // 1 data bit and 4 padding bits that must be zero. Setting a padding
        // bit keeps the payload bytes identical but must still be rejected.
        let mut fes: Vec<Fe32> = PK.iter().copied().bytes_to_fes().collect();
        let last = fes.last_mut().unwrap();
        *last = Fe32::try_from(last.to_u8() | 0b0001).unwrap();
        let code: String = fes
            .iter()
            .copied()
            .with_checksum::<Nip19Bech32>(&HRP_NPUB)
            .chars()
            .collect();
        assert!(matches!(
            Entity::from_bech32(&code),
            Err(Error::Bech32 { .. })
        ));
    }
}
