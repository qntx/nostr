//! Constant-time hex codecs — a thin `pub(crate)` wrapper over `base16ct`.
//! Caller input accepts mixed case; wire input is strict lowercase; encoding
//! is always lowercase.

use base16ct::{lower, mixed};

/// Decodes caller-provided hex (any case) into exactly `N` bytes.
///
/// # Errors
///
/// [`base16ct::Error`] when the length is not `2 * N` or a character is not
/// hex; the caller's module maps it onto its own `Error` variant.
pub(crate) fn decode_caller<const N: usize>(input: &str) -> Result<[u8; N], base16ct::Error> {
    if input.len() != 2 * N {
        return Err(base16ct::Error::InvalidLength);
    }
    let mut out = [0u8; N];
    mixed::decode(input, &mut out)?;
    Ok(out)
}

/// Decodes wire hex (lowercase only) into exactly `N` bytes.
///
/// # Errors
///
/// [`base16ct::Error`] when the length is not `2 * N`, a character is not
/// hex, or a character is uppercase.
pub(crate) fn decode_wire<const N: usize>(input: &str) -> Result<[u8; N], base16ct::Error> {
    if input.len() != 2 * N {
        return Err(base16ct::Error::InvalidLength);
    }
    let mut out = [0u8; N];
    lower::decode(input, &mut out)?;
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
