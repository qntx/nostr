//! Test-only helpers: a scripted RNG that emits a fixed 32-byte draw (the
//! BIP-340 auxiliary randomness), so signing tests stay deterministic
//! without exposing `*_with_aux` entry points.

/// A `TryCryptoRng` that fills `dest` by repeating `0` — deterministic but
/// never a valid scalar twice; used where the draw content is irrelevant.
///
/// For a fixed aux, `AuxRng(aux)` answers the first `try_fill_bytes` with
/// `aux` exactly.
pub(crate) struct AuxRng(pub(crate) [u8; 32]);

impl rand_core::TryRng for AuxRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        dest.copy_from_slice(&self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for AuxRng {}

/// `Keys::sign_event` with `aux` as the BIP-340 auxiliary randomness.
pub(crate) fn sign_with_aux(
    keys: &crate::key::Keys,
    unsigned: crate::event::UnsignedEvent,
    aux: [u8; 32],
) -> crate::event::Event {
    keys.sign_event(unsigned, &mut AuxRng(aux))
        .expect("AuxRng cannot fail")
}
