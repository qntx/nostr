//! The NIP implementations of `nk`, one feature-gated module per NIP.
//!
//! Platform-neutral (`no_std` + `alloc`, sans-IO) counterparts of
//! `@qntx/nostr`'s `nips` layer. `Error`/`ErrorKind`/`Result` here are the
//! NIP-layer error types; the crate-root modules each carry their own
//! error enum.
//!
//! ```
//! use nk::nips::ErrorKind;
//!
//! assert_eq!(ErrorKind::Nip19.to_string(), "nip19");
//! ```

pub mod error;

#[cfg(any(feature = "nip04", feature = "nip44"))]
mod ecdh;
#[cfg(any(feature = "nip27", feature = "nip46", feature = "nip98"))]
mod util;

#[cfg(feature = "nip04")]
pub mod nip04;
#[cfg(feature = "nip10")]
pub mod nip10;
#[cfg(feature = "nip13")]
pub mod nip13;
#[cfg(feature = "nip17")]
pub mod nip17;
#[cfg(feature = "nip19")]
pub mod nip19;
#[cfg(feature = "nip21")]
pub mod nip21;
#[cfg(feature = "nip27")]
pub mod nip27;
#[cfg(feature = "nip42")]
pub mod nip42;
#[cfg(feature = "nip44")]
pub mod nip44;
#[cfg(feature = "nip46")]
pub mod nip46;
#[cfg(feature = "nip49")]
pub mod nip49;
#[cfg(feature = "nip51")]
pub mod nip51;
#[cfg(feature = "nip57")]
pub mod nip57;
#[cfg(feature = "nip59")]
pub mod nip59;
#[cfg(feature = "nip65")]
pub mod nip65;
#[cfg(feature = "nip98")]
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

    #[cfg(feature = "nip19")]
    {
        assert_send_sync::<nip19::AddressPointer>();
        assert_send_sync::<nip19::Entity>();
        assert_send_sync::<nip19::EventPointer>();
        assert_send_sync::<nip19::ProfilePointer>();
    }
    #[cfg(feature = "nip04")]
    assert_send_sync::<nip04::SharedSecret>();
    #[cfg(feature = "nip13")]
    assert_send_sync::<nip13::PowMiner>();
    #[cfg(feature = "nip49")]
    {
        assert_send_sync::<nip49::EncryptOptions>();
        assert_send_sync::<nip49::KeySecurity>();
        assert_send_sync::<nip49::Decrypted>();
    }
    #[cfg(feature = "nip51")]
    {
        assert_send_sync::<nip51::MuteItem>();
        assert_send_sync::<nip51::BookmarkList>();
    }
    #[cfg(feature = "nip21")]
    assert_send_sync::<nip21::NostrUri>();
    #[cfg(feature = "nip44")]
    {
        assert_send_sync::<nip44::ConversationKey>();
        assert_send_sync::<nip44::MessageKeys>();
    }
    #[cfg(feature = "nip46")]
    {
        assert_send_sync::<nip46::BunkerUri>();
        assert_send_sync::<nip46::NostrConnectUri>();
        assert_send_sync::<nip46::Request>();
        assert_send_sync::<nip46::Response>();
    }
};
