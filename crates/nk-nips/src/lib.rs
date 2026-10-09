//! `nk-nips` hosts the NIP implementations of the `nk-*` workspace: the
//! platform-neutral (`no_std` + `alloc`, sans-IO) counterpart of
//! `@qntx/nostr`'s `nips` layer. Each NIP lives behind its own feature so
//! downstream crates compile only what they use.
//!
//! # Features
//!
//! | feature  | default | effect                                                     |
//! |----------|---------|------------------------------------------------------------|
//! | `std`    | yes     | OS facilities; base for `clock`/`os-rng`                    |
//! | `clock`  | yes     | wall-clock helpers where a NIP needs them                   |
//! | `os-rng` | yes     | OS entropy where a NIP needs it                             |
//! | `nip19`  | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) |
//!
//! ```
//! use nk_nips::ErrorKind;
//!
//! assert_eq!(ErrorKind::Nip19.to_string(), "nip19");
//! ```

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;

#[cfg(feature = "nip19")]
pub mod nip19;

pub use error::{Error, ErrorKind, Result};

// Dependencies consumed only by feature-gated NIP modules; the underscore
// imports keep `unused_crate_dependencies` quiet under minimal features.
use nk_core as _;
use zeroize as _;

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
};
