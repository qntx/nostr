//! The NIP implementations of `nk-core`: `nip04`/`nip44`/`nip49` sit behind
//! their extra dependencies (and `nip44` also enables `nip17`, `nip59` and
//! the NIP-51 private-tag helpers); every other NIP is always compiled.
//!
//! Platform-neutral (`no_std` + `alloc`, sans-IO) counterparts of
//! `@qntx/nostr`'s `nips` layer. `Error`/`ErrorKind`/`Result` here are the
//! NIP-layer error types; the crate-root modules each carry their own
//! error enum.

pub mod error;

#[cfg(any(feature = "nip04", feature = "nip44"))]
mod ecdh;
mod util;

#[cfg(feature = "nip04")]
pub mod nip04;
pub mod nip10;
pub mod nip13;
#[cfg(feature = "nip44")]
pub mod nip17;
pub mod nip19;
pub mod nip21;
pub mod nip27;
pub mod nip42;
#[cfg(feature = "nip44")]
pub mod nip44;
pub mod nip46;
#[cfg(feature = "nip49")]
pub mod nip49;
pub mod nip51;
pub mod nip57;
#[cfg(feature = "nip44")]
pub mod nip59;
pub mod nip65;
pub mod nip98;

pub use error::{Error, ErrorKind, Result};

// Consumed only by feature-gated NIP modules and tests; the underscore
// imports keep `unused_crate_dependencies` quiet under minimal features.
#[cfg(feature = "os-rng")]
use getrandom as _;
// `criterion` is a dev-dependency consumed only by `benches/`; without this
// import the lib-test target reports it unused.
#[cfg(test)]
use criterion as _;

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<ErrorKind>();

    assert_send_sync::<nip19::AddressPointer>();
    assert_send_sync::<nip19::Entity>();
    assert_send_sync::<nip19::EventPointer>();
    assert_send_sync::<nip19::ProfilePointer>();
    #[cfg(feature = "nip04")]
    assert_send_sync::<nip04::SharedSecret>();
    assert_send_sync::<nip13::PowMiner>();
    #[cfg(feature = "nip49")]
    {
        assert_send_sync::<nip49::EncryptedSecretKey>();
        assert_send_sync::<nip49::KeySecurity>();
    }
    {
        assert_send_sync::<nip51::MuteItem>();
        assert_send_sync::<nip51::BookmarkList>();
    }
    assert_send_sync::<nip21::NostrUri>();
    #[cfg(feature = "nip44")]
    {
        assert_send_sync::<nip44::ConversationKey>();
        assert_send_sync::<nip44::MessageKeys>();
    }
    assert_send_sync::<nip46::BunkerUri>();
    assert_send_sync::<nip46::Method>();
    assert_send_sync::<nip46::NostrConnectUri>();
    assert_send_sync::<nip46::Request>();
    assert_send_sync::<nip46::Response>();
};
