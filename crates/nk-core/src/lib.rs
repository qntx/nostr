//! `nk-core` is the leaf crate of the `nk-*` workspace: the platform-neutral
//! (`no_std` + `alloc`, sans-IO) counterpart of `@qntx/nostr`'s `core` layer.
//! Everything is re-exported flat at the crate root; there is no prelude.
//!
//! # Features
//!
//! | feature | default | effect |
//! |---------|---------|--------|
//! | `std`   | yes     | OS facilities; base for `clock` |
//! | `clock` | yes     | [`Timestamp::now`] (wall clock; off on platforms without one) |
//!
//! ```
//! use nk_core::{RelayUrl, Timestamp};
//!
//! fn relay(input: &str) -> Result<RelayUrl, nk_core::Error> {
//!     Ok(RelayUrl::parse(input)?)
//! }
//!
//! let url = relay("Relay.EXAMPLE")?;
//! assert_eq!(url.as_str(), "wss://relay.example/");
//! let _ = Timestamp::now();
//! # Ok::<(), nk_core::Error>(())
//! ```

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod limits;

pub(crate) mod hex;
pub mod time;
pub mod url;

pub use error::{Error, ErrorKind, Result};
pub use time::Timestamp;
pub use url::RelayUrl;

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<ErrorKind>();
    assert_send_sync::<Timestamp>();
    assert_send_sync::<RelayUrl>();
};
