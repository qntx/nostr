//! `nk-core` is the leaf protocol crate: a platform-neutral (`no_std` +
//! `alloc`, sans-IO) implementation of the nostr wire protocol —
//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
//! core types plus every supported NIP module under [`nips`]. Core types
//! are re-exported flat at the crate root; there is no prelude.
//!
//! Every module owns an [`Error`](key::Error) enum describing its own
//! failure causes; JSON parse failures surface as the shared [`JsonError`].
//!
//! # Features
//!
//! | feature | default | effect |
//! |---------|---------|--------|
//! | `std`   | yes     | OS facilities; global secp256k1 context; base for `clock`/`os-rng` |
//! | `clock` | yes     | `Timestamp::now` (wall clock; off on platforms without one) |
//! | `os-rng` | yes    | `SecretKey::generate`, `Keys::generate`, `SubscriptionId::generate`, [`SysRng`] |
//! | `nip04` | no      | legacy encrypted DMs (aes, cbc) |
//! | `nip44` | no      | v2 payload encryption (chacha20, hkdf, hmac); also enables `nips::nip17`, `nips::nip59` and the NIP-51 private-tag helpers |
//! | `nip49` | no      | `ncryptsec` secret-key encryption (scrypt, chacha20poly1305) |
//!
//! Every other NIP module is always compiled.
//!
//! ```
//! use nk_core::{RelayUrl, Timestamp};
//!
//! let url = RelayUrl::parse("Relay.EXAMPLE")?;
//! assert_eq!(url.as_str(), "wss://relay.example/");
//! let _ = Timestamp::from_secs(1_700_000_000);
//! # Ok::<(), nk_core::url::Error>(())
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use rand_core;

#[cfg(feature = "os-rng")]
pub use getrandom::SysRng;

pub mod limits;

pub mod event;
pub mod filter;
pub(crate) mod hex;
pub(crate) mod json;
pub mod key;
pub mod message;
pub mod time;
pub mod url;

pub mod nips;

#[cfg(test)]
pub(crate) mod testutil;

pub use event::{
    Coordinate, DeletionTarget, Event, EventBuilder, EventId, Kind, KindClass, Metadata, Tag, Tags,
    UnsignedEvent,
};
pub use filter::{Filter, SingleLetterTag, fingerprint};
pub use json::JsonError;
pub use key::{Keys, PublicKey, SecretKey, Signature};
pub use message::{ClientMessage, CountResult, Hll, RelayMessage, SubscriptionId};
pub use time::Timestamp;
pub use url::RelayUrl;

// `criterion` is a dev-dependency consumed only by `benches/`; without this
// import the lib-test target reports it unused.
#[cfg(test)]
use criterion as _;

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ClientMessage<'static>>();
    assert_send_sync::<Coordinate>();
    assert_send_sync::<CountResult>();
    assert_send_sync::<DeletionTarget>();
    assert_send_sync::<Event>();
    assert_send_sync::<EventBuilder>();
    assert_send_sync::<EventId>();
    assert_send_sync::<Filter>();
    assert_send_sync::<Hll>();
    assert_send_sync::<JsonError>();
    assert_send_sync::<Kind>();
    assert_send_sync::<KindClass>();
    assert_send_sync::<Keys>();
    assert_send_sync::<Metadata>();
    assert_send_sync::<PublicKey>();
    assert_send_sync::<RelayMessage<'static>>();
    assert_send_sync::<RelayUrl>();
    assert_send_sync::<SecretKey>();
    assert_send_sync::<Signature>();
    assert_send_sync::<SingleLetterTag>();
    assert_send_sync::<SubscriptionId>();
    assert_send_sync::<Tag>();
    assert_send_sync::<Tags>();
    assert_send_sync::<Timestamp>();
    assert_send_sync::<UnsignedEvent>();
};
