#![cfg_attr(feature = "os-rng", doc = include_str!("../README.md"))]
#![cfg_attr(
    not(feature = "os-rng"),
    doc = "`nk-core` is the leaf protocol crate: a platform-neutral (`no_std` + `alloc`, sans-IO) implementation of the nostr wire protocol — NIP-01 core types plus every supported NIP module, verified byte-for-byte against `@qntx/nostr` through shared vectors. Build with the `os-rng` feature for the full crate guide."
)]
#![forbid(unsafe_code)]
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
pub mod signer;

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
pub use signer::{BoxFuture, NostrSigner, SignerBackendError, SignerError};
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
