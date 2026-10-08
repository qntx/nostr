//! NIP-01 event kinds and their storage classification — the counterpart of
//! `@qntx/nostr`'s `core/kind.ts`.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A NIP-01 event kind (`0..=65535`), serialized as a bare JSON number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kind(u16);

/// The NIP-01 storage class of a kind.
///
/// The four classes are a closed set, so this enum is not `non_exhaustive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KindClass {
    /// Stored like a regular event.
    Regular,
    /// Latest per (pubkey, kind) wins.
    Replaceable,
    /// Not expected to be stored.
    Ephemeral,
    /// Parameterized replaceable: latest per (pubkey, kind, d-tag) wins.
    Addressable,
}

impl Kind {
    /// Kind 0: profile metadata.
    pub const METADATA: Self = Self(0);
    /// Kind 1: text note.
    pub const TEXT_NOTE: Self = Self(1);
    /// Kind 3: contacts.
    pub const CONTACTS: Self = Self(3);
    /// Kind 5: event deletion request.
    pub const EVENT_DELETION: Self = Self(5);
    /// Kind 6: repost.
    pub const REPOST: Self = Self(6);
    /// Kind 7: reaction.
    pub const REACTION: Self = Self(7);
    /// Kind 13: seal.
    pub const SEAL: Self = Self(13);
    /// Kind 14: private direct message (NIP-17).
    pub const PRIVATE_DIRECT_MESSAGE: Self = Self(14);
    /// Kind 16: generic repost.
    pub const GENERIC_REPOST: Self = Self(16);
    /// Kind 1059: gift wrap (NIP-59).
    pub const GIFT_WRAP: Self = Self(1059);
    /// Kind 9734: zap request (NIP-57).
    pub const ZAP_REQUEST: Self = Self(9734);
    /// Kind 9735: zap (NIP-57).
    pub const ZAP: Self = Self(9735);
    /// Kind 10000: mute list.
    pub const MUTE_LIST: Self = Self(10000);
    /// Kind 10001: pin list.
    pub const PIN_LIST: Self = Self(10001);
    /// Kind 10002: relay list (NIP-65).
    pub const RELAY_LIST: Self = Self(10002);
    /// Kind 10003: bookmark list.
    pub const BOOKMARK_LIST: Self = Self(10003);
    /// Kind 10012: favorite relays.
    pub const FAVORITE_RELAYS: Self = Self(10012);
    /// Kind 10030: user emoji list.
    pub const USER_EMOJI_LIST: Self = Self(10030);
    /// Kind 10050: direct message relay list (NIP-17).
    pub const DIRECT_MESSAGE_RELAYS_LIST: Self = Self(10050);
    /// Kind 10063: Blossom server list.
    pub const BLOSSOM_SERVER_LIST: Self = Self(10063);
    /// Kind 21059: ephemeral gift wrap (NIP-59).
    pub const GIFT_WRAP_EPHEMERAL: Self = Self(21059);
    /// Kind 22242: client authentication (NIP-42).
    pub const CLIENT_AUTH: Self = Self(22242);
    /// Kind 24133: Nostr Connect (NIP-46).
    pub const NOSTR_CONNECT: Self = Self(24133);
    /// Kind 24242: Blossom blobs authorization.
    pub const BLOBS_AUTH: Self = Self(24242);
    /// Kind 27235: HTTP auth (NIP-98).
    pub const HTTP_AUTH: Self = Self(27235);
    /// Kind 30002: relay sets.
    pub const RELAY_SETS: Self = Self(30002);
    /// Kind 30030: emoji set.
    pub const EMOJI_SET: Self = Self(30030);
    /// Kind 39089: starter pack.
    pub const STARTER_PACK: Self = Self(39089);

    /// Wraps a kind number.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// The wrapped kind number.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// NIP-01 regular ranges verbatim; kinds outside every defined range are
    /// still stored like regular events (see [`Kind::class`]).
    #[must_use]
    pub const fn is_regular(self) -> bool {
        let k = self.0;
        k == 1 || k == 2 || (k >= 4 && k < 45) || (k >= 1000 && k < 10000)
    }

    /// Replaceable: latest per (pubkey, kind) wins.
    #[must_use]
    pub const fn is_replaceable(self) -> bool {
        let k = self.0;
        k == 0 || k == 3 || (k >= 10000 && k < 20000)
    }

    /// Ephemeral: not expected to be stored.
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        let k = self.0;
        k >= 20000 && k < 30000
    }

    /// Addressable (parameterized replaceable): latest per (pubkey, kind,
    /// d-tag) wins.
    #[must_use]
    pub const fn is_addressable(self) -> bool {
        let k = self.0;
        k >= 30000 && k < 40000
    }

    /// The kind's NIP-01 storage class.
    ///
    /// NIP-01 leaves kinds 45–999 and 40000+ undefined rather than forbidden;
    /// relays store them like regular events, so they classify as
    /// [`KindClass::Regular`] even though [`Kind::is_regular`] is false.
    #[must_use]
    pub const fn class(self) -> KindClass {
        if self.is_replaceable() {
            KindClass::Replaceable
        } else if self.is_ephemeral() {
            KindClass::Ephemeral
        } else if self.is_addressable() {
            KindClass::Addressable
        } else {
            KindClass::Regular
        }
    }
}

impl From<u16> for Kind {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Kind> for u16 {
    fn from(kind: Kind) -> Self {
        kind.0
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;

    use super::*;

    #[test]
    fn boundary_kinds_classify_per_nip01() {
        let cases = [
            (0, KindClass::Replaceable),
            (1, KindClass::Regular),
            (3, KindClass::Replaceable),
            (4, KindClass::Regular),
            (44, KindClass::Regular),
            (45, KindClass::Regular),
            (999, KindClass::Regular),
            (1000, KindClass::Regular),
            (9999, KindClass::Regular),
            (10000, KindClass::Replaceable),
            (19999, KindClass::Replaceable),
            (20000, KindClass::Ephemeral),
            (29999, KindClass::Ephemeral),
            (30000, KindClass::Addressable),
            (39999, KindClass::Addressable),
            (40000, KindClass::Regular),
            (65535, KindClass::Regular),
        ];
        for (value, class) in cases {
            assert_eq!(Kind::new(value).class(), class, "kind {value}");
        }
    }

    #[test]
    fn undefined_ranges_are_regular_in_class_but_not_is_regular() {
        let regular = Kind::new(45);
        assert!(!regular.is_regular());
        assert_eq!(regular.class(), KindClass::Regular);
        let parameterized = Kind::new(40000);
        assert!(!parameterized.is_regular());
        assert_eq!(parameterized.class(), KindClass::Regular);
    }

    #[test]
    fn named_constants_match_the_ts_values() {
        let constants: [(Kind, u16); 28] = [
            (Kind::METADATA, 0),
            (Kind::TEXT_NOTE, 1),
            (Kind::CONTACTS, 3),
            (Kind::EVENT_DELETION, 5),
            (Kind::REPOST, 6),
            (Kind::REACTION, 7),
            (Kind::SEAL, 13),
            (Kind::PRIVATE_DIRECT_MESSAGE, 14),
            (Kind::GENERIC_REPOST, 16),
            (Kind::GIFT_WRAP, 1059),
            (Kind::ZAP_REQUEST, 9734),
            (Kind::ZAP, 9735),
            (Kind::MUTE_LIST, 10000),
            (Kind::PIN_LIST, 10001),
            (Kind::RELAY_LIST, 10002),
            (Kind::BOOKMARK_LIST, 10003),
            (Kind::FAVORITE_RELAYS, 10012),
            (Kind::USER_EMOJI_LIST, 10030),
            (Kind::DIRECT_MESSAGE_RELAYS_LIST, 10050),
            (Kind::BLOSSOM_SERVER_LIST, 10063),
            (Kind::GIFT_WRAP_EPHEMERAL, 21059),
            (Kind::CLIENT_AUTH, 22242),
            (Kind::NOSTR_CONNECT, 24133),
            (Kind::BLOBS_AUTH, 24242),
            (Kind::HTTP_AUTH, 27235),
            (Kind::RELAY_SETS, 30002),
            (Kind::EMOJI_SET, 30030),
            (Kind::STARTER_PACK, 39089),
        ];
        for (kind, value) in constants {
            assert_eq!(kind.as_u16(), value, "kind {value}");
        }
    }

    #[test]
    fn conversions_and_display() {
        let kind = Kind::from(30023_u16);
        assert_eq!(u16::from(kind), 30023);
        assert_eq!(kind.to_string(), "30023");
    }

    #[test]
    fn serde_is_a_bare_integer() {
        assert_eq!(serde_json::to_string(&Kind::TEXT_NOTE).unwrap(), "1");
        assert_eq!(
            serde_json::from_str::<Kind>("65535").unwrap(),
            Kind::new(65535)
        );
        serde_json::from_str::<Kind>("65536").unwrap_err();
        serde_json::from_str::<Kind>("1.5").unwrap_err();
        serde_json::from_str::<Kind>("\"1\"").unwrap_err();
    }
}
