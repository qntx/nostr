//! The canonical JSON writer shared by event hashing and filter
//! serialization.
//!
//! Escapes exactly like `JSON.stringify` (`\"`, `\\`, the `\b \f \n \r \t`
//! short forms, every other U+0000–U+001F as lowercase `\u00xx`, everything
//! else as raw UTF-8) and writes into either a `String` or the SHA-256 hasher
//! with no intermediate buffer — `serde_json` cannot do this under `no_std`.

use alloc::string::String;

use sha2::{Digest, Sha256};

use crate::event::{Event, UnsignedEvent};

/// Output target for canonical serialization.
pub(crate) trait Sink {
    /// Appends a UTF-8 chunk.
    fn push_str(&mut self, s: &str);
    /// Appends one ASCII character.
    fn push_char(&mut self, c: char);
}

impl Sink for String {
    fn push_str(&mut self, s: &str) {
        self.push_str(s);
    }

    fn push_char(&mut self, c: char) {
        self.push(c);
    }
}

impl Sink for Sha256 {
    fn push_str(&mut self, s: &str) {
        Digest::update(self, s.as_bytes());
    }

    fn push_char(&mut self, c: char) {
        let mut buf = [0u8; 4];
        Digest::update(self, c.encode_utf8(&mut buf).as_bytes());
    }
}

fn hex_digit(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + (nibble - 10))
    }
}

/// Writes `bytes` as lowercase hex.
pub(crate) fn push_hex(bytes: &[u8], out: &mut impl Sink) {
    for byte in bytes {
        out.push_char(hex_digit(byte >> 4));
        out.push_char(hex_digit(byte & 0x0f));
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
    out.push_str("\\u00");
    for byte in c.encode_utf8(&mut [0; 4]).bytes() {
        out.push_char(hex_digit(byte >> 4));
        out.push_char(hex_digit(byte & 0x0f));
    }
}

/// Writes `s` as a JSON string with `JSON.stringify` escaping, flushing
/// maximal unescaped runs as single slices.
pub(crate) fn push_json_string(s: &str, out: &mut impl Sink) {
    out.push_char('"');
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
    out.push_char('"');
}

/// Writes one tag as a JSON string array.
fn push_tag(tag: &crate::tag::Tag, out: &mut impl Sink) {
    out.push_char('[');
    for (i, item) in tag.as_slice().iter().enumerate() {
        if i > 0 {
            out.push_char(',');
        }
        push_json_string(item, out);
    }
    out.push_char(']');
}

/// Writes a tag list as a JSON array of string arrays.
pub(crate) fn push_tags(tags: &crate::tag::Tags, out: &mut impl Sink) {
    out.push_char('[');
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            out.push_char(',');
        }
        push_tag(tag, out);
    }
    out.push_char(']');
}

/// Writes the canonical event serialization.
pub(crate) fn write_event(event: &UnsignedEvent, out: &mut impl Sink) {
    out.push_str("[0,\"");
    push_hex(event.pubkey().as_bytes(), out);
    out.push_str("\",");
    push_u64(event.created_at().as_secs(), out);
    out.push_char(',');
    push_u64(u64::from(event.kind().as_u16()), out);
    out.push_char(',');
    push_tags(event.tags(), out);
    out.push_char(',');
    push_json_string(event.content(), out);
    out.push_char(']');
}

/// Writes the signed event wire object — `JSON.stringify(event)` in
/// field order `id`, `pubkey`, `created_at`, `kind`, `tags`,
/// `content`, `sig` (NIP-18 repost content).
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
