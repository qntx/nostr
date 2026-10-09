//! NIP-42 relay authentication.
//!
//! [`auth_event`] builds the unsigned kind-22242 AUTH event template for a
//! relay's `AUTH` challenge — the caller signs it with `nk-core`'s `Keys` or
//! an nk-signer. [`is_auth_required`] recognizes the `auth-required:` CLOSED
//! reason prefix.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/42.md>

use nk_core::{EventBuilder, Kind, RelayUrl, Tag};

/// An unsigned NIP-42 AUTH event template.
///
/// Kind 22242 with `["relay", relay]` and `["challenge", challenge]` tags and
/// empty content; `created_at` is fixed by [`EventBuilder::build`] (`clock`
/// feature) or [`EventBuilder::build_at`]. Unlike the TS `makeAuthEvent` —
/// which takes any string — `relay` is a [`RelayUrl`], so the tag always
/// carries the normalized form.
pub fn auth_event(relay: &RelayUrl, challenge: &str) -> EventBuilder {
    EventBuilder::new(Kind::CLIENT_AUTH, "").tags([
        Tag::custom("relay", [relay.as_str()]),
        Tag::custom("challenge", [challenge]),
    ])
}

/// Whether a relay `CLOSED` reason requests NIP-42 authentication — the
/// `"auth-required:"` prefix, exactly as the TS `isAuthRequired`.
#[must_use]
pub fn is_auth_required(reason: &str) -> bool {
    reason.starts_with("auth-required:")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use nk_core::{PublicKey, Timestamp};

    use super::*;

    #[test]
    fn auth_event_shape() {
        let relay = RelayUrl::parse("wss://relay.example").unwrap();
        let event = auth_event(&relay, "abc123").build_at(
            PublicKey::from_hex("79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6")
                .unwrap(),
            Timestamp::from_secs(1_700_000_000),
        );
        assert_eq!(event.kind(), Kind::CLIENT_AUTH);
        assert_eq!(event.content(), "");
        assert_eq!(event.created_at(), Timestamp::from_secs(1_700_000_000));
        let tags: Vec<_> = event.tags().iter().map(Tag::as_slice).collect();
        assert_eq!(
            tags,
            [
                ["relay", relay.as_str()].as_slice(),
                ["challenge", "abc123"].as_slice(),
            ]
        );
    }

    #[test]
    fn relay_url_is_normalized() {
        let relay = RelayUrl::parse("WSS://RELAY.EXAMPLE:443").unwrap();
        assert_eq!(relay.as_str(), "wss://relay.example/");
        let event = auth_event(&relay, "").build_at(
            PublicKey::from_hex("79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6")
                .unwrap(),
            Timestamp::from_secs(0),
        );
        assert_eq!(
            event
                .tags()
                .iter()
                .next()
                .unwrap()
                .as_slice()
                .get(1)
                .map(String::as_str),
            Some("wss://relay.example/")
        );
    }

    #[test]
    fn auth_required_prefix() {
        assert!(is_auth_required("auth-required: take a ticket"));
        assert!(is_auth_required("auth-required:"));
        assert!(!is_auth_required("auth-required"));
        assert!(!is_auth_required(" auth-required: leading space"));
        assert!(!is_auth_required("restricted: nope"));
        assert!(!is_auth_required(""));
    }
}
