//! Helpers shared by the vector tests: hex codecs and value comparison.
//! There is no divergence registry: every case must pass as written.
//! A case with `"nonCanonicalJson": true` must be *rejected* by the strict
//! parser (TypeScript accepts it because `JSON.parse` erases the spelling).

#![allow(dead_code, reason = "each test module uses a subset")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::manual_is_multiple_of,
    reason = "a malformed fixture file must fail the test loudly"
)]

/// `true` when two JSON texts are semantically equal (key order is not
/// semantic); falls back to string equality on unparseable input.
pub(crate) fn json_eq(a: &str, b: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(a),
        serde_json::from_str::<serde_json::Value>(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Decodes hex of any case into a byte vector.
pub(crate) fn unhex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Decodes hex into a fixed-size array.
pub(crate) fn unhex_arr<const N: usize>(input: &str) -> Option<[u8; N]> {
    let bytes = unhex(input)?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// A `TryCryptoRng` that answers `try_fill_bytes` with `aux` (the BIP-340
/// auxiliary randomness draw of `sign_event`/`sign_id`).
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

/// A `TryCryptoRng` that answers `try_fill_bytes` from a scripted entropy
/// stream, consumed in draw order.
pub(crate) struct BytesRng(pub(crate) Vec<u8>);

impl rand_core::TryRng for BytesRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let n = dest.len();
        let take = self.0.drain(..n.min(self.0.len()));
        dest.copy_from_slice(&take.collect::<Vec<u8>>());
        Ok(())
    }
}

impl rand_core::TryCryptoRng for BytesRng {}

/// Lowercase hex of `bytes`.
pub(crate) fn hex_str(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4).into(), 16).unwrap());
        out.push(char::from_digit((b & 0x0f).into(), 16).unwrap());
    }
    out
}

#[cfg(feature = "os-rng")]
use std::future::Future;

/// Drives a future to completion — the `it` binary is std, no executor
/// dependency needed.
#[cfg(feature = "os-rng")]
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => return v,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}
