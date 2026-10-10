//! Crate-private helpers shared by the NIP modules — currently the JS
//! whitespace class used by nip46 (`String.prototype.trim`), nip98
//! (the `\s` in the `Nostr ` scheme regex), and nip27 (the `\s` in the
//! URL-run stop set).

/// The whitespace class of JS `\s`/`String.prototype.trim()`: Unicode
/// `White_Space` minus U+0085 (NEL, not in JS `\s`) plus U+FEFF (BOM, which
/// is).
pub(crate) const fn is_js_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c != '\u{85}' && c.is_whitespace())
}

/// `String.prototype.trim()` under the JS whitespace class — nip46 only;
/// nip98 needs the predicate itself for `\s+`.
#[cfg(feature = "nip46")]
pub(crate) fn trim_js(input: &str) -> &str {
    input.trim_matches(is_js_whitespace)
}
