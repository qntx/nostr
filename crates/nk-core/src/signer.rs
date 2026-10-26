//! Signer abstraction (NIP-42/NIP-44-ready): any entity that can yield a
//! public key and sign events, without the key material living in this
//! crate.

use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use crate::{Event, PublicKey, UnsignedEvent};

/// A boxed, `Send` future — the trait's call shape.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A signer operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer does not implement this operation (default for the
    /// optional NIP-44/NIP-04 methods).
    Unsupported,
    /// The unsigned event's pubkey is not the signer's public key.
    PublicKeyMismatch,
    /// An opaque failure from the signer's backend.
    Backend(SignerBackendError),
}

/// The opaque boxed cause behind [`SignerError::Backend`]; any
/// `std::error::Error`-compatible source can be wrapped from outside the
/// crate (the `io::Error::other` precedent).
pub struct SignerBackendError(Box<dyn core::error::Error + Send + Sync + 'static>);

impl SignerBackendError {
    /// Wraps `e` as a backend failure.
    pub fn new<E>(e: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(e))
    }
}

impl fmt::Debug for SignerBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignerBackendError").field(&self.0).finish()
    }
}

impl fmt::Display for SignerBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for SignerBackendError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("signer does not support this operation"),
            Self::PublicKeyMismatch => f.write_str("unsigned event pubkey mismatch"),
            Self::Backend(e) => write!(f, "signer backend: {e}"),
        }
    }
}

impl core::error::Error for SignerError {}

/// An entity that can yield a public key and sign nostr events. Every
/// call is `async` so remote signers (NIP-46) can implement it.
pub trait NostrSigner: Send + Sync + fmt::Debug {
    /// The signer's public key.
    fn public_key(&self) -> BoxFuture<'_, Result<PublicKey, SignerError>>;

    /// Signs `unsigned` — the returned event's `id`/`sig` are computed by
    /// the signer.
    fn sign_event(&self, unsigned: UnsignedEvent) -> BoxFuture<'_, Result<Event, SignerError>>;

    /// NIP-44 encryption for `peer`. Default: unsupported.
    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let _ = (peer, text);
        Box::pin(async { Err(SignerError::Unsupported) })
    }

    /// NIP-44 decryption from `peer`. Default: unsupported.
    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let _ = (peer, text);
        Box::pin(async { Err(SignerError::Unsupported) })
    }

    /// NIP-04 encryption for `peer`. Default: unsupported.
    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let _ = (peer, text);
        Box::pin(async { Err(SignerError::Unsupported) })
    }

    /// NIP-04 decryption from `peer`. Default: unsupported.
    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let _ = (peer, text);
        Box::pin(async { Err(SignerError::Unsupported) })
    }
}

/// `Keys` is a local `NostrSigner` — aux randomness comes from the OS.
#[cfg(feature = "os-rng")]
impl NostrSigner for crate::Keys {
    fn public_key(&self) -> BoxFuture<'_, Result<PublicKey, SignerError>> {
        let pk = Self::public_key(self);
        Box::pin(async move { Ok(pk) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> BoxFuture<'_, Result<Event, SignerError>> {
        let mut rng = crate::SysRng;
        let out = self
            .sign_event(unsigned, &mut rng)
            .map_err(|e| SignerError::Backend(SignerBackendError::new(e)));
        Box::pin(async move { out })
    }

    #[cfg(feature = "nip44")]
    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let mut rng = crate::SysRng;
        let out = crate::nips::nip44::ConversationKey::derive(self.secret_key(), peer)
            .and_then(|k| k.encrypt(text, &mut rng))
            .map_err(|e| SignerError::Backend(SignerBackendError::new(e)));
        Box::pin(async move { out })
    }

    #[cfg(feature = "nip44")]
    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let out = crate::nips::nip44::ConversationKey::derive(self.secret_key(), peer)
            .and_then(|k| k.decrypt(text))
            .map_err(|e| SignerError::Backend(SignerBackendError::new(e)));
        Box::pin(async move { out })
    }

    #[cfg(feature = "nip04")]
    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let mut rng = crate::SysRng;
        let out = crate::nips::nip04::SharedSecret::derive(self.secret_key(), peer)
            .and_then(|k| k.encrypt(text, &mut rng))
            .map_err(|e| SignerError::Backend(SignerBackendError::new(e)));
        Box::pin(async move { out })
    }

    #[cfg(feature = "nip04")]
    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        text: &'a str,
    ) -> BoxFuture<'a, Result<String, SignerError>> {
        let out = crate::nips::nip04::SharedSecret::derive(self.secret_key(), peer)
            .and_then(|k| k.decrypt(text))
            .map_err(|e| SignerError::Backend(SignerBackendError::new(e)));
        Box::pin(async move { out })
    }
}

#[cfg(all(test, feature = "os-rng"))]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use super::*;
    use crate::{EventBuilder, Keys, Kind};

    #[cfg(feature = "os-rng")]
    fn assert_object_safe(_: &dyn NostrSigner) {}
    const fn assert_send_sync<T: Send + Sync>() {}

    #[cfg(feature = "os-rng")]
    #[test]
    fn object_safe_and_send_sync() {
        assert_send_sync::<Box<dyn NostrSigner>>();
        let k = Keys::generate().unwrap();
        let s: &dyn NostrSigner = &k;
        assert_object_safe(s);
    }

    /// Polls a ready future once — enough for synchronous signers.
    #[cfg(feature = "os-rng")]
    fn block_on<F: Future>(fut: F) -> F::Output {
        let w = std::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(w);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(v) => v,
            core::task::Poll::Pending => panic!("future pending"),
        }
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn keys_public_key_and_sign() {
        let k = Keys::generate().unwrap();
        assert!(block_on(NostrSigner::public_key(&k)).is_ok());
        let pk = Keys::public_key(&k);
        let unsigned = EventBuilder::new(Kind::new(1), "hi").build(pk);
        let event = block_on(NostrSigner::sign_event(&k, unsigned)).expect("sign");
        assert!(event.verify().is_ok());
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn unsupported_defaults() {
        struct NoNips;
        impl fmt::Debug for NoNips {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("NoNips")
            }
        }
        impl NostrSigner for NoNips {
            fn public_key(&self) -> BoxFuture<'_, Result<PublicKey, SignerError>> {
                Box::pin(core::future::ready(Err(SignerError::Unsupported)))
            }
            fn sign_event(&self, _: UnsignedEvent) -> BoxFuture<'_, Result<Event, SignerError>> {
                Box::pin(core::future::ready(Err(SignerError::Unsupported)))
            }
        }
        let s = NoNips;
        let k = Keys::generate().unwrap().public_key();
        assert!(matches!(
            block_on(s.nip44_encrypt(&k, "x")),
            Err(SignerError::Unsupported)
        ));
        assert!(matches!(
            block_on(s.nip04_decrypt(&k, "x")),
            Err(SignerError::Unsupported)
        ));
    }

    #[test]
    fn backend_error_wraps() {
        #[derive(Debug)]
        struct E;
        impl fmt::Display for E {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("backend blew up")
            }
        }
        impl core::error::Error for E {}
        let e = SignerError::Backend(SignerBackendError::new(E));
        let s = alloc::string::ToString::to_string(&e);
        assert!(s.contains("backend blew up"));
    }
}
