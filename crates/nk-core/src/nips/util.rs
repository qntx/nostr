//! Crate-private helpers shared by the NIP modules — the JS whitespace
//! class kept only for nip27's URL-run stop set (`\s`); every other
//! canonicalization site is ASCII whitespace (6c).

/// The whitespace class of JS `\s`/`String.prototype.trim()`: Unicode
/// `White_Space` minus U+0085 (NEL, not in JS `\s`) plus U+FEFF (BOM, which
/// is).
pub(crate) const fn is_js_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c != '\u{85}' && c.is_whitespace())
}
