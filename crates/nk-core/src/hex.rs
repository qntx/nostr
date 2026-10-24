//! Hex codecs — a thin `pub(crate)` wrapper over `faster-hex`.
//! Caller input accepts mixed case; wire input is strict lowercase; encoding
//! is always lowercase.

use alloc::string::String;

use faster_hex::CheckCase;

/// Why a hex decode failed; kept private, callers map it onto a plain
/// `invalid hex` variant of their own error type.
#[derive(Debug)]
pub(crate) enum Error {
    /// The input length was not the required `2 * N`.
    Length,
    /// A character was not hexadecimal, or uppercase on the wire.
    Character,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length => f.write_str("invalid hex length"),
            Self::Character => f.write_str("invalid hex character"),
        }
    }
}

impl core::error::Error for Error {}

/// Decodes caller-provided hex (any case) into exactly `N` bytes.
pub(crate) fn decode_caller<const N: usize>(input: &str) -> Result<[u8; N], Error> {
    decode::<N>(input, CheckCase::None)
}

/// Decodes wire hex (lowercase only) into exactly `N` bytes.
pub(crate) fn decode_wire<const N: usize>(input: &str) -> Result<[u8; N], Error> {
    decode::<N>(input, CheckCase::Lower)
}

fn decode<const N: usize>(input: &str, case: CheckCase) -> Result<[u8; N], Error> {
    faster_hex::hex_decode_array_with_case::<N>(input.as_bytes(), case).map_err(|error| match error
    {
        faster_hex::Error::InvalidChar { .. } => Error::Character,
        _ => Error::Length,
    })
}

/// Encodes bytes as a lowercase hex string.
pub(crate) fn encode(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

/// Encodes into `buf` (exactly `2 * bytes.len()` long); the error path is
/// unreachable and yields an empty string rather than panicking.
pub(crate) fn encode_slice<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    match faster_hex::hex_encode(bytes, buf) {
        Ok(encoded) => encoded,
        Err(_) => "",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use super::*;

    #[test]
    fn decode_caller_accepts_mixed_case() {
        assert_eq!(
            decode_caller::<4>("00ffAAbb").unwrap(),
            [0x00, 0xff, 0xaa, 0xbb]
        );
    }

    #[test]
    fn decode_wire_rejects_uppercase() {
        assert!(decode_wire::<4>("00FF").is_err());
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(decode_caller::<4>("012").is_err());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_wire::<4>("00ffaa").is_err());
    }

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0xde, 0xad]), "dead");
    }
}
