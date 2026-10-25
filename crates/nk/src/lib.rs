#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![allow(
    unused_crate_dependencies,
    reason = "`nk` is a dev-dependency of itself so `tests/` can enable `test-util`; the lib target never uses it"
)]

/// A type-erased failure newtype: boxed source, `Display` passthrough.
macro_rules! erased_error {
    ($name:ident, $doc:literal, $new_doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name(Box<dyn std::error::Error + Send + Sync>);

        impl $name {
            #[doc = $new_doc]
            pub(crate) fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
                Self(Box::new(error))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.0.source()
            }
        }
    };
}

pub mod client;
pub mod gossip;
#[cfg(feature = "http")]
pub mod http;
pub mod nip46;
pub mod pool;
pub mod relay;

#[cfg(feature = "test-util")]
pub mod testing;

pub use nk_store as store;
