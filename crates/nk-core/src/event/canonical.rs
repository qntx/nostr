//! The canonical JSON writer shared by event hashing and wire
//! serialization.
//!
//! Escapes `"` and `\`, uses the `\b \f \n \r \t` short forms, writes every
//! other U+0000–U+001F as lowercase `\u00xx`, and leaves everything else as
//! raw UTF-8. It borrows the event fields and writes into either a `String`
//! or the SHA-256 hasher with no intermediate buffer — `serde_json` cannot
//! do this under `no_std`.

use alloc::string::String;

use sha2::{Digest, Sha256};

use super::{Event, EventParts, UnsignedEvent};
use crate::hex;

/// Output target for canonical serialization.
pub(crate) trait Sink {
    /// Appends a UTF-8 chunk.
    fn push_str(&mut self, s: &str);
}

impl Sink for String {
    fn push_str(&mut self, s: &str) {
        self.push_str(s);
    }
}

impl Sink for Sha256 {
    fn push_str(&mut self, s: &str) {
        Digest::update(self, s.as_bytes());
    }
}

/// Appends one ASCII character through a 4-byte stack buffer — the hasher
/// only ever sees slice updates.
fn push_char(c: char, out: &mut impl Sink) {
    let mut buf = [0u8; 4];
    out.push_str(c.encode_utf8(&mut buf));
}

/// Writes `bytes` as lowercase hex through a stack buffer, 64 bytes at a
/// time so arbitrarily long inputs (the 256-byte NIP-45 sketch) fit.
pub(crate) fn push_hex(bytes: &[u8], out: &mut impl Sink) {
    let mut buf = [0u8; 128];
    for chunk in bytes.chunks(64) {
        out.push_str(hex::encode_slice(chunk, &mut buf));
    }
}

/// Writes `n` as decimal digits (a `u64` needs at most 20) filled from
/// the right of a stack buffer, then pushed as one slice.
pub(crate) fn push_u64(n: u64, out: &mut impl Sink) {
    let mut buf = [0u8; 20];
    let mut value = n;
    let mut written = 0;
    for slot in buf.iter_mut().rev() {
        *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        written += 1;
        if value == 0 {
            break;
        }
    }
    out.push_str(core::str::from_utf8(buf.get(buf.len() - written..).unwrap_or(&[])).unwrap_or(""));
}

/// Writes `c` (below U+0020, a single UTF-8 byte) as a `\u00xx` escape.
fn push_control_escape(c: char, out: &mut impl Sink) {
    let mut buf = [0u8; 2];
    out.push_str("\\u00");
    out.push_str(hex::encode_slice(&[c as u8], &mut buf));
}

/// Writes `s` as a JSON string with the canonical escaping rules, flushing
/// maximal unescaped runs as single slices.
pub(crate) fn push_json_string(s: &str, out: &mut impl Sink) {
    push_char('"', out);
    let mut run_start = 0;
    for (i, c) in s.char_indices() {
        if c != '"' && c != '\\' && c >= '\u{20}' {
            continue;
        }
        out.push_str(s.get(run_start..i).unwrap_or_default());
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => push_control_escape(c, out),
        }
        run_start = i + c.len_utf8();
    }
    out.push_str(s.get(run_start..).unwrap_or_default());
    push_char('"', out);
}

/// Writes one tag as a JSON string array.
fn push_tag(tag: &super::Tag, out: &mut impl Sink) {
    push_char('[', out);
    for (i, item) in tag.as_slice().iter().enumerate() {
        if i > 0 {
            push_char(',', out);
        }
        push_json_string(item, out);
    }
    push_char(']', out);
}

/// Writes a tag list as a JSON array of string arrays.
pub(crate) fn push_tags(tags: &super::Tags, out: &mut impl Sink) {
    push_char('[', out);
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            push_char(',', out);
        }
        push_tag(tag, out);
    }
    push_char(']', out);
}

/// Writes the canonical event serialization over a borrowed field view —
/// the caller allocates nothing.
pub(crate) fn write_event(parts: &EventParts<'_>, out: &mut impl Sink) {
    out.push_str("[0,\"");
    push_hex(parts.pubkey.as_bytes(), out);
    out.push_str("\",");
    push_u64(parts.created_at.as_secs(), out);
    push_char(',', out);
    push_u64(u64::from(parts.kind.as_u16()), out);
    push_char(',', out);
    push_tags(parts.tags, out);
    push_char(',', out);
    push_json_string(parts.content, out);
    push_char(']', out);
}

/// Writes the unsigned event wire object in field order `pubkey`,
/// `created_at`, `kind`, `tags`, `content`.
pub(crate) fn write_unsigned(event: &UnsignedEvent, out: &mut impl Sink) {
    out.push_str("{\"pubkey\":\"");
    push_hex(event.pubkey().as_bytes(), out);
    out.push_str("\",\"created_at\":");
    push_u64(event.created_at().as_secs(), out);
    out.push_str(",\"kind\":");
    push_u64(u64::from(event.kind().as_u16()), out);
    out.push_str(",\"tags\":");
    push_tags(event.tags(), out);
    out.push_str(",\"content\":");
    push_json_string(event.content(), out);
    push_char('}', out);
}

/// Writes the signed event wire object in field order `id`, `pubkey`,
/// `created_at`, `kind`, `tags`, `content`, `sig` — the string that ends up
/// inside NIP-18 repost content.
pub(crate) fn write_signed(event: &Event, out: &mut impl Sink) {
    out.push_str("{\"id\":\"");
    push_hex(event.id().as_bytes(), out);
    out.push_str("\",\"pubkey\":\"");
    push_hex(event.pubkey().as_bytes(), out);
    out.push_str("\",\"created_at\":");
    push_u64(event.created_at().as_secs(), out);
    out.push_str(",\"kind\":");
    push_u64(u64::from(event.kind().as_u16()), out);
    out.push_str(",\"tags\":");
    push_tags(event.tags(), out);
    out.push_str(",\"content\":");
    push_json_string(event.content(), out);
    out.push_str(",\"sig\":\"");
    push_hex(event.sig().as_bytes(), out);
    out.push_str("\"}");
}
