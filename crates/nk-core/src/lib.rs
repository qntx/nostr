//! `nk-core` is the leaf crate of the `nk-*` workspace: the platform-neutral
//! (`no_std` + `alloc`, sans-IO) counterpart of `@qntx/nostr`'s `core` layer.
//! Everything is re-exported flat at the crate root; there is no prelude.
//!
//! # Features
//!
//! | feature | default | effect |
//! |---------|---------|--------|
//! | `std`   | yes     | OS facilities; base for `clock` |
//! | `clock` | yes     | `Timestamp::now` (wall clock; off on platforms without one) |
//!
//! ```
//! use nk_core::{RelayUrl, Timestamp};
//!
//! let url = RelayUrl::parse("Relay.EXAMPLE")?;
//! assert_eq!(url.as_str(), "wss://relay.example/");
//! let _ = Timestamp::from_secs(1_700_000_000);
//! # Ok::<(), nk_core::Error>(())
//! ```

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod limits;

pub mod event;
pub(crate) mod hex;
pub mod key;
pub mod kind;
pub mod tag;
pub mod time;
pub mod url;

pub use error::{Error, ErrorKind, Result};
pub use event::{Event, EventId, Signature, UnsignedEvent, cmp_newest_first, cmp_oldest_first};
pub use key::PublicKey;
pub use kind::{Kind, KindClass};
pub use tag::{EventAddress, Tag, Tags};
pub use time::Timestamp;
pub use url::RelayUrl;

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<ErrorKind>();
    assert_send_sync::<Event>();
    assert_send_sync::<EventAddress>();
    assert_send_sync::<EventId>();
    assert_send_sync::<Kind>();
    assert_send_sync::<KindClass>();
    assert_send_sync::<PublicKey>();
    assert_send_sync::<RelayUrl>();
    assert_send_sync::<Signature>();
    assert_send_sync::<Tag>();
    assert_send_sync::<Tags>();
    assert_send_sync::<Timestamp>();
    assert_send_sync::<UnsignedEvent>();
};
