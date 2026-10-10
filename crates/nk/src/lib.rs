//! `nk` is the leaf protocol crate of the `nk-*` workspace: a
//! platform-neutral (`no_std` + `alloc`, sans-IO) implementation of the
//! nostr wire protocol — [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
//! core types plus every supported NIP module under [`nips`]. Core types are
//! re-exported flat at the crate root; there is no prelude.
//!
//! Every module owns an [`Error`](key::Error) enum describing its own
//! failure causes; the root exports no shared error type.
//!
//! # Features
//!
//! | feature | default | effect |
//! |---------|---------|--------|
//! | `std`   | yes     | OS facilities; global secp256k1 context; base for `clock`/`os-rng` |
//! | `clock` | yes     | `Timestamp::now` (wall clock; off on platforms without one) |
//! | `os-rng` | yes    | `SecretKey::generate`, `Keys::generate`, `Keys::sign_event` (OS entropy) |
//! | `nip04` | no      | legacy encrypted DMs (`nips::nip04::SharedSecret`, `encrypt`/`decrypt`) |
//! | `nip10` | no      | thread references (`parse_thread_tags`, `reply_tags`/`reply_to`); needs `nip19` |
//! | `nip13` | no      | proof of work (`pow`, `PowMiner`) |
//! | `nip17` | no      | private DMs (`chat_message_rumor`, `wrap_direct_message`); needs `nip59` |
//! | `nip19` | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) |
//! | `nip21` | no      | `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`); needs `nip19` |
//! | `nip27` | no      | content tokenizer (`parse_content`, `ContentBlock`); needs `nip19` |
//! | `nip42` | no      | relay auth (`auth_event`, `is_auth_required`) |
//! | `nip44` | no      | v2 authenticated payload encryption (`ConversationKey`, `encrypt`/`decrypt`) |
//! | `nip46` | no      | Nostr Connect URI + RPC codecs (`BunkerUri`, `NostrConnectUri`, `Request`/`Response`) |
//! | `nip49` | no      | `ncryptsec` secret-key encryption (`EncryptOptions`, `encrypt`/`decrypt`) |
//! | `nip51` | no      | lists (`parse_mute_list`, …, NIP-44 private tags); needs `nip44` |
//! | `nip57` | no      | Lightning zaps (`zap_request`, `parse_bolt11`, `validate_zap_receipt`) |
//! | `nip59` | no      | gift wrap (`Rumor`, `wrap`/`unwrap`, `seal`/`gift_wrap`); needs `nip44` |
//! | `nip65` | no      | relay lists (`parse_relay_list`, `relay_list`, `read_relays`/`write_relays`) |
//! | `nip98` | no      | HTTP auth (`auth_event`, `token`, `unpack_token`, `validate_auth_event`) |
//!
//! ```
//! use nk::{RelayUrl, Timestamp};
//!
//! let url = RelayUrl::parse("Relay.EXAMPLE")?;
//! assert_eq!(url.as_str(), "wss://relay.example/");
//! let _ = Timestamp::from_secs(1_700_000_000);
//! # Ok::<(), nk::url::Error>(())
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod limits;

pub mod builder;
pub(crate) mod canonical;
#[doc(hidden)]
pub mod detail;
pub mod event;
pub mod filter;
pub(crate) mod hex;
pub(crate) mod json;
pub mod key;
pub mod kind;
pub mod message;
pub mod tag;
pub mod time;
pub mod url;

pub mod nips;

pub use builder::{DeletionTarget, EventBuilder, ProfileMetadata};
pub use event::{Event, EventId, Signature, UnsignedEvent};
pub use filter::{Filter, SingleLetterTag, fingerprint};
pub use key::{Keys, PublicKey, SecretKey};
pub use kind::{Kind, KindClass};
pub use message::{ClientMessage, CountHll, CountResult, RelayMessage, SubscriptionId};
pub use tag::{EventAddress, Tag, Tags};
pub use time::Timestamp;
pub use url::RelayUrl;

// `criterion` is a dev-dependency consumed only by `benches/`; without this
// import the lib-test target reports it unused.
#[cfg(test)]
use criterion as _;

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DeletionTarget>();
    assert_send_sync::<Event>();
    assert_send_sync::<EventAddress>();
    assert_send_sync::<EventBuilder>();
    assert_send_sync::<EventId>();
    assert_send_sync::<Filter>();
    assert_send_sync::<Kind>();
    assert_send_sync::<KindClass>();
    assert_send_sync::<Keys>();
    assert_send_sync::<ProfileMetadata>();
    assert_send_sync::<PublicKey>();
    assert_send_sync::<RelayUrl>();
    assert_send_sync::<SecretKey>();
    assert_send_sync::<Signature>();
    assert_send_sync::<SingleLetterTag>();
    assert_send_sync::<Tag>();
    assert_send_sync::<Tags>();
    assert_send_sync::<Timestamp>();
    assert_send_sync::<UnsignedEvent>();
};
