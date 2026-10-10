//! Constant-time hex codecs — a thin `pub(crate)` wrapper over `base16ct`.
//! Caller input accepts mixed case; wire input is strict lowercase; encoding
//! is always lowercase.

use base16ct::{lower, mixed};

use crate::error::{Error, ErrorKind, Result};

/// Decodes caller-provided hex (any case) into exactly `N` bytes.
///
/// # Errors
///
/// `ErrorKind::Hex` when the length is not `2 * N` or a character is not hex.
pub(crate) fn decode_caller<const N: usize>(input: &str) -> Result<[u8; N]> {
    if input.len() != 2 * N {
        return Err(Error::new(ErrorKind::Hex, "invalid hex length"));
    }
    let mut out = [0u8; N];
    mixed::decode(input, &mut out)
        .map_err(|error| Error::with_source(ErrorKind::Hex, "invalid hex input", error))?;
    Ok(out)
}

/// Decodes wire hex (lowercase only) into exactly `N` bytes.
///
/// # Errors
///
/// `ErrorKind::Hex` when the length is not `2 * N`, a character is not hex,
/// or a character is uppercase.
pub(crate) fn decode_wire<const N: usize>(input: &str) -> Result<[u8; N]> {
    if input.len() != 2 * N {
        return Err(Error::new(ErrorKind::Hex, "invalid hex length"));
    }
    let mut out = [0u8; N];
    lower::decode(input, &mut out)
        .map_err(|error| Error::with_source(ErrorKind::Hex, "invalid wire hex", error))?;
    Ok(out)
}

/// Encodes bytes as a lowercase hex string.
pub(crate) fn encode<const N: usize>(bytes: &[u8; N]) -> alloc::string::String {
    lower::encode_string(bytes)
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
        assert_eq!(
            decode_wire::<4>("00ffAAbb").unwrap_err().kind(),
            ErrorKind::Hex
        );
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert_eq!(
            decode_caller::<4>("fff").unwrap_err().kind(),
            ErrorKind::Hex
        );
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            decode_caller::<4>("00ff").unwrap_err().kind(),
            ErrorKind::Hex
        );
    }

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0xab, 0xcd]), "abcd");
    }
}
