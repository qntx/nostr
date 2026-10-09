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
//! | `nip04`  | no      | legacy encrypted DMs (`SharedSecret`, `encrypt`/`decrypt`)       |
//! | `nip19`  | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) |
//! | `nip21`  | no      | `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`)                   |
//! | `nip44`  | no      | v2 authenticated payload encryption (`ConversationKey`, `encrypt`/`decrypt`) |
//! | `nip49`  | no      | `ncryptsec` secret-key encryption (`EncryptOptions`, `encrypt`/`decrypt`) |
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

#[cfg(any(feature = "nip04", feature = "nip44"))]
mod ecdh;

#[cfg(feature = "nip04")]
pub mod nip04;
#[cfg(feature = "nip19")]
pub mod nip19;
#[cfg(feature = "nip21")]
pub mod nip21;
#[cfg(feature = "nip44")]
pub mod nip44;
#[cfg(feature = "nip49")]
pub mod nip49;

pub use error::{Error, ErrorKind, Result};

// Consumed only by feature-gated NIP modules and tests; the underscore
// imports keep `unused_crate_dependencies` quiet under minimal features.
#[cfg(feature = "os-rng")]
use getrandom as _;
use nk_core as _;

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
    #[cfg(feature = "nip49")]
    {
        assert_send_sync::<nip49::EncryptOptions>();
        assert_send_sync::<nip49::KeySecurity>();
        assert_send_sync::<nip49::Decrypted>();
    }
    #[cfg(feature = "nip21")]
    assert_send_sync::<nip21::NostrUri>();
    #[cfg(feature = "nip44")]
    {
        assert_send_sync::<nip44::ConversationKey>();
        assert_send_sync::<nip44::MessageKeys>();
    }
};
