//! Protocol byte/character limits shared by the wire types.

/// Maximum length of a subscription id in characters (NIP-01: 1–64 chars).
pub const SUBSCRIPTION_ID_MAX_CHARS: usize = 64;

/// `Number.MAX_SAFE_INTEGER` — the inclusive upper bound for wire integers.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
