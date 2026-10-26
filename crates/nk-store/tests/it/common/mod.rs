//! Shared fixtures for the conformance suite and unit tests.

use nk_core::rand_core::{TryCryptoRng, TryRng};
use nk_core::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};

/// Deterministic test RNG: fills from a counter so signing needs no OS
/// entropy.
pub(crate) struct TestRng(u64);

impl TestRng {
    pub(crate) const fn new() -> Self {
        Self(0x9E37_79B9_7F4A_7C15)
    }
}

impl TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

pub(crate) fn alice() -> Keys {
    Keys::new(
        nk_core::SecretKey::from_rng(&mut TestRng::new())
            .unwrap_or_else(|_| panic!("SecretKey::from_rng")),
    )
}

pub(crate) fn bob() -> Keys {
    let mut rng = TestRng::new();
    let _ = nk_core::SecretKey::from_rng(&mut rng);
    Keys::new(
        nk_core::SecretKey::from_rng(&mut rng).unwrap_or_else(|_| panic!("SecretKey::from_rng")),
    )
}

pub(crate) fn sign(keys: &Keys, builder: EventBuilder, created_at: u64) -> Event {
    let unsigned = builder.build_at(keys.public_key(), Timestamp::from_secs(created_at));
    keys.sign_event(unsigned, &mut TestRng::new())
        .unwrap_or_else(|_| panic!("sign_event failed"))
}

pub(crate) fn note(keys: &Keys, content: &str, created_at: u64, tags: Vec<Tag>) -> Event {
    sign(
        keys,
        EventBuilder::new(Kind::new(1), content).tags(tags),
        created_at,
    )
}

pub(crate) fn replaceable(keys: &Keys, kind: u16, content: &str, created_at: u64) -> Event {
    sign(
        keys,
        EventBuilder::new(Kind::new(kind), content),
        created_at,
    )
}

pub(crate) fn addressable(
    keys: &Keys,
    kind: u16,
    d: &str,
    content: &str,
    created_at: u64,
) -> Event {
    sign(
        keys,
        EventBuilder::new(Kind::new(kind), content).tag(Tag::identifier(d)),
        created_at,
    )
}
