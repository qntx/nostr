#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(
    unused_crate_dependencies,
    reason = "`nk` is a dev-dependency of itself so `tests/` can enable `test-util`; the lib target never uses it"
)]

pub mod gossip;
pub mod pool;
pub mod relay;

#[cfg(feature = "test-util")]
pub mod testing;
