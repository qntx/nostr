//! `Rumor::wrap_with_signer`/`from_gift_wrap_with_signer` — the signer
//! paths with `Keys` as the `NostrSigner`, plus the vector unwrap cases.

#[cfg(all(feature = "nip44", feature = "os-rng"))]
mod signer {
    use core::fmt;

    use nk_core::nips::nip59::{Error, RandomScope, Rumor, Timestamps, WrapOptions};
    use nk_core::{
        BoxFuture, Event, EventBuilder, Keys, Kind, NostrSigner, PublicKey, SignerError, SysRng,
        Timestamp, UnsignedEvent,
    };
    use serde_json::Value;

    use crate::common::{block_on, unhex_arr};
    use nk_core::SecretKey;

    const JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/nip59/codec.json"
    ));

    fn key(n: u8) -> Keys {
        Keys::new(SecretKey::from_bytes([n; 32]).expect("key"))
    }

    fn rumor(author: &PublicKey) -> Rumor {
        Rumor::new(
            EventBuilder::new(Kind::new(14), "secret")
                .build_at(*author, Timestamp::from_secs(1_700_000_000)),
        )
    }

    fn options() -> WrapOptions {
        WrapOptions::new(Timestamps::Random {
            now: Timestamp::from_secs(1_800_000_000),
            scope: RandomScope::SealAndWrap,
        })
    }

    #[test]
    fn signer_wrap_opened_by_keys_unwrap() {
        let (alice, bob) = (key(11), key(12));
        let gift = block_on(rumor(&alice.public_key()).wrap_with_signer(
            &alice,
            &bob.public_key(),
            &options(),
            &mut SysRng,
        ))
        .expect("wrap");
        let back = Rumor::from_gift_wrap(&gift, &bob).expect("unwrap");
        assert_eq!(back.unsigned().content(), "secret");
    }

    #[test]
    fn keys_wrap_opened_by_signer_unwrap() {
        let (alice, bob) = (key(13), key(14));
        let gift = rumor(&alice.public_key())
            .wrap(&alice, &bob.public_key(), &options(), &mut SysRng)
            .expect("wrap");
        let back = block_on(Rumor::from_gift_wrap_with_signer(&gift, &bob)).expect("unwrap");
        assert_eq!(back.unsigned().content(), "secret");
    }

    #[test]
    fn signer_wrap_signer_unwrap() {
        let (alice, bob) = (key(15), key(16));
        let gift = block_on(rumor(&alice.public_key()).wrap_with_signer(
            &alice,
            &bob.public_key(),
            &options(),
            &mut SysRng,
        ))
        .expect("wrap");
        let back = block_on(Rumor::from_gift_wrap_with_signer(&gift, &bob)).expect("unwrap");
        assert_eq!(back.unsigned().content(), "secret");
    }

    #[test]
    fn wrap_with_signer_rejects_wrong_pubkey() {
        let (alice, bob) = (key(17), key(18));
        // The rumor is authored by alice, but `bob` is the signer.
        let err = block_on(rumor(&alice.public_key()).wrap_with_signer(
            &bob,
            &bob.public_key(),
            &options(),
            &mut SysRng,
        ))
        .expect_err("pubkey mismatch");
        assert!(matches!(err, Error::PubkeyMismatch), "{err}");
    }

    /// A signer whose NIP-44 step is unimplemented.
    struct NoNip44(Keys);

    impl fmt::Debug for NoNip44 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("NoNip44")
                .field(&self.0.public_key())
                .finish()
        }
    }

    impl NostrSigner for NoNip44 {
        fn public_key(&self) -> BoxFuture<'_, Result<PublicKey, SignerError>> {
            NostrSigner::public_key(&self.0)
        }

        fn sign_event(&self, unsigned: UnsignedEvent) -> BoxFuture<'_, Result<Event, SignerError>> {
            NostrSigner::sign_event(&self.0, unsigned)
        }
        // nip44_* fall back to the default `SignerError::Unsupported`.
    }

    #[test]
    fn wrap_with_signer_unsupported_signer() {
        let (alice, bob) = (key(19), key(20));
        let signer = NoNip44(alice.clone());
        let err = block_on(rumor(&alice.public_key()).wrap_with_signer(
            &signer,
            &bob.public_key(),
            &options(),
            &mut SysRng,
        ))
        .expect_err("unsupported");
        assert!(matches!(err, Error::Signer(_)), "{err}");
    }

    #[test]
    fn unwrap_with_signer_unsupported_signer() {
        let (alice, bob) = (key(21), key(22));
        let gift = rumor(&alice.public_key())
            .wrap(&alice, &bob.public_key(), &options(), &mut SysRng)
            .expect("wrap");
        let err = block_on(Rumor::from_gift_wrap_with_signer(&gift, &NoNip44(bob)))
            .expect_err("unsupported");
        assert!(matches!(err, Error::Signer(_)), "{err}");
    }

    /// The vector `unwrap` cases give the same verdict through the
    /// signer path as through the `Keys` path.
    #[test]
    fn unwrap_vector_cases_via_signer() {
        let doc: Value = serde_json::from_str(JSON).expect("vectors");
        for case in doc["unwrap"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("name");
            let gw: Event = serde_json::from_value(case["gift_wrap"].clone()).expect("gw");
            let recipient = Keys::new(
                SecretKey::from_bytes(
                    unhex_arr(case["recipient_secret_key"].as_str().expect("key")).expect("unhex"),
                )
                .expect("key"),
            );
            let local = Rumor::from_gift_wrap(&gw, &recipient);
            let via_signer = block_on(Rumor::from_gift_wrap_with_signer(&gw, &recipient));
            match (local, via_signer) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.unsigned().to_json(), b.unsigned().to_json(), "{name}");
                }
                (Err(_), Err(_)) => {}
                (local, via_signer) => {
                    panic!("{name}: divergent verdicts {local:?} {via_signer:?}")
                }
            }
        }
    }

    #[test]
    fn wrap_with_signer_future_is_send() {
        fn is_send<T: Send>(_: &T) {}
        let (alice, bob) = (key(23), key(24));
        let mut rng = SysRng;
        let options = options();
        let r = rumor(&alice.public_key());
        let pk = bob.public_key();
        let fut = r.wrap_with_signer(&alice, &pk, &options, &mut rng);
        is_send(&fut);
    }
}
