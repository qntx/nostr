//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
//! subscription filters: matching, intrinsic limit bounds, and the
//! canonical serialization used by REQ coalescing.
//!
//! List fields are sorted, deduplicated boxed slices; matching binary
//! searches them and allocates nothing.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::event::{Event, EventId, Kind, canonical};
use crate::hex;
use crate::json::{self, JsonError, WireHexList, WireInt, WireU16List};
use crate::key::PublicKey;
use crate::limits::MAX_SAFE_INTEGER;
use crate::time::Timestamp;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// A constrained filter field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// `ids`.
    Ids,
    /// `authors`.
    Authors,
    /// `kinds`.
    Kinds,
    /// A `#<letter>` tag condition.
    Tag(char),
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ids => f.write_str("ids"),
            Self::Authors => f.write_str("authors"),
            Self::Kinds => f.write_str("kinds"),
            Self::Tag(letter) => write!(f, "#{letter}"),
        }
    }
}

/// Why a filter operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A tag-condition key is not a single ASCII letter.
    #[error("invalid tag letter: {letter:?} is not a single ASCII letter")]
    InvalidTagLetter {
        /// The offending character.
        letter: char,
    },
    /// A list field was given no values — empty lists are invalid both on
    /// the wire and at construction.
    #[error("empty filter list: {field}")]
    EmptyList {
        /// The constrained field.
        field: Field,
    },
    /// A `#e`/`#p` caller value is not 64-char hex.
    #[error("invalid #{letter} value: not 64-char hex")]
    InvalidTagValue {
        /// The tag-condition letter (`e` or `p`).
        letter: char,
    },
}

/// A NIP-01 single-letter tag condition key (`a`–`z`, `A`–`Z`).
///
/// Multi-letter `#xx` keys are outside the protocol and never reach this
/// type; deserialization drops them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SingleLetterTag(u8);

impl SingleLetterTag {
    /// Wraps `letter` when it is an ASCII letter.
    #[must_use]
    pub const fn new(letter: char) -> Option<Self> {
        match letter {
            'a'..='z' | 'A'..='Z' => Some(Self(letter as u8)),
            _ => None,
        }
    }

    /// The letter as a `char`.
    #[must_use]
    pub const fn as_char(self) -> char {
        self.0 as char
    }
}

impl TryFrom<char> for SingleLetterTag {
    type Error = Error;

    fn try_from(letter: char) -> Result<Self> {
        Self::new(letter).ok_or(Error::InvalidTagLetter { letter })
    }
}

impl fmt::Display for SingleLetterTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// The sorted `#x` conditions: letter keys in order, each with a sorted
/// value list.
type TagConditions = Box<[(SingleLetterTag, Box<[Box<str>]>)]>;

/// A NIP-01 filter.
///
/// List fields are non-empty sets: `None` leaves the field unconstrained
/// and the setters reject empty iterators, so an empty list can never
/// exist in a filter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Filter {
    ids: Option<Box<[EventId]>>,
    authors: Option<Box<[PublicKey]>>,
    kinds: Option<Box<[Kind]>>,
    tags: TagConditions,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
    limit: Option<u64>,
    search: Option<Box<str>>,
}

impl Filter {
    /// An unconstrained filter (matches every event).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts to these event ids.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyList`] when `ids` is empty.
    pub fn ids<I>(mut self, ids: I) -> Result<Self>
    where
        I: IntoIterator<Item = EventId>,
    {
        let ids = sorted_dedup(ids);
        if ids.is_empty() {
            return Err(Error::EmptyList { field: Field::Ids });
        }
        self.ids = Some(ids);
        Ok(self)
    }

    /// Restricts to these author public keys.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyList`] when `authors` is empty.
    pub fn authors<I>(mut self, authors: I) -> Result<Self>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let authors = sorted_dedup(authors);
        if authors.is_empty() {
            return Err(Error::EmptyList {
                field: Field::Authors,
            });
        }
        self.authors = Some(authors);
        Ok(self)
    }

    /// Restricts to these kinds.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyList`] when `kinds` is empty.
    pub fn kinds<I>(mut self, kinds: I) -> Result<Self>
    where
        I: IntoIterator<Item = Kind>,
    {
        let kinds = sorted_dedup(kinds);
        if kinds.is_empty() {
            return Err(Error::EmptyList {
                field: Field::Kinds,
            });
        }
        self.kinds = Some(kinds);
        Ok(self)
    }

    /// Adds a single-letter tag condition: an event matches only when one of
    /// its `letter` tags carries a value in `values` (`#e`/`#p` values are
    /// ASCII-lowercased on store).
    ///
    /// # Errors
    ///
    /// [`Error::EmptyList`] when `values` is empty;
    /// [`Error::InvalidTagValue`] when a `#e`/`#p` value is not 64-char hex.
    pub fn tag<I, S>(mut self, letter: SingleLetterTag, values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let values = tag_value_list(letter, values)?;
        let mut tags = self.tags.into_vec();
        match tags.binary_search_by_key(&letter, |(name, _)| *name) {
            Ok(index) => {
                if let Some(slot) = tags.get_mut(index) {
                    slot.1 = values;
                }
            }
            Err(index) => tags.insert(index, (letter, values)),
        }
        self.tags = tags.into_boxed_slice();
        Ok(self)
    }

    /// Earliest `created_at`, inclusive.
    #[must_use]
    pub const fn since(mut self, since: Timestamp) -> Self {
        self.since = Some(since);
        self
    }

    /// Latest `created_at`, inclusive.
    #[must_use]
    pub const fn until(mut self, until: Timestamp) -> Self {
        self.until = Some(until);
        self
    }

    /// Relay-side truncation hint; not a matching predicate.
    #[must_use]
    pub const fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// NIP-50 full-text search. Relays interpret it; local matching ignores
    /// it.
    #[must_use]
    pub fn search<S>(mut self, query: S) -> Self
    where
        S: Into<String>,
    {
        self.search = Some(query.into().into_boxed_str());
        self
    }

    /// The sorted id set, if constrained.
    #[must_use]
    pub fn get_ids(&self) -> Option<&[EventId]> {
        self.ids.as_deref()
    }

    /// The sorted author set, if constrained.
    #[must_use]
    pub fn get_authors(&self) -> Option<&[PublicKey]> {
        self.authors.as_deref()
    }

    /// The sorted kind set, if constrained.
    #[must_use]
    pub fn get_kinds(&self) -> Option<&[Kind]> {
        self.kinds.as_deref()
    }

    /// The sorted value list of a tag condition, if present (never
    /// empty).
    #[must_use]
    pub fn tag_values(&self, letter: SingleLetterTag) -> Option<&[Box<str>]> {
        self.tags
            .binary_search_by_key(&letter, |(name, _)| *name)
            .ok()
            .and_then(|index| self.tags.get(index))
            .map(|(_, values)| &**values)
    }

    /// The single-letter tag condition keys, in order.
    pub fn tag_letters(&self) -> impl Iterator<Item = SingleLetterTag> + '_ {
        self.tags.iter().map(|(letter, _)| *letter)
    }

    /// The inclusive lower `created_at` bound, if any.
    #[must_use]
    pub const fn get_since(&self) -> Option<Timestamp> {
        self.since
    }

    /// The inclusive upper `created_at` bound, if any.
    #[must_use]
    pub const fn get_until(&self) -> Option<Timestamp> {
        self.until
    }

    /// The relay-side truncation hint, if set.
    #[must_use]
    pub const fn get_limit(&self) -> Option<u64> {
        self.limit
    }

    /// The NIP-50 search query, if set.
    #[must_use]
    pub fn get_search(&self) -> Option<&str> {
        self.search.as_deref()
    }

    /// Local NIP-01 match; `search` is ignored. Allocates nothing.
    ///
    /// `#e`/`#p` conditions compare the stored (lowercased) filter values
    /// against the event tag value verbatim; `since`/`until` bounds are
    /// inclusive.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if self
            .ids
            .as_ref()
            .is_some_and(|ids| ids.binary_search(&event.id()).is_err())
        {
            return false;
        }
        if self
            .kinds
            .as_ref()
            .is_some_and(|kinds| kinds.binary_search(&event.kind()).is_err())
        {
            return false;
        }
        if self
            .authors
            .as_ref()
            .is_some_and(|authors| authors.binary_search(&event.pubkey()).is_err())
        {
            return false;
        }
        for (letter, values) in &self.tags {
            if !tag_value_hit(*letter, values, event) {
                return false;
            }
        }
        if self.since.is_some_and(|since| event.created_at() < since) {
            return false;
        }
        if self.until.is_some_and(|until| event.created_at() > until) {
            return false;
        }
        true
    }

    /// Intrinsic upper bound implied by the filter alone; `None` when
    /// unbounded.
    ///
    /// For kinds that are all replaceable or addressable and a non-empty
    /// author set, the bound is `authors * kinds * (#d or 1)` — lists are
    /// already deduplicated.
    #[must_use]
    pub fn limit_bound(&self) -> Option<usize> {
        let mut limit = self.ids.as_deref().map(<[_]>::len);
        if let Some(hint) = self.limit {
            let hint = usize::try_from(hint).unwrap_or(usize::MAX);
            limit = Some(limit.map_or(hint, |cur| cur.min(hint)));
        }
        if let (Some(kinds), Some(authors)) = (&self.kinds, &self.authors) {
            let all_replaceable = kinds
                .iter()
                .all(|kind| kind.is_replaceable() || kind.is_addressable());
            if all_replaceable {
                let per_author = self.tag_values(SingleLetterTag(b'd')).map_or(1, <[_]>::len);
                let bound = authors
                    .len()
                    .saturating_mul(kinds.len())
                    .saturating_mul(per_author);
                limit = Some(limit.map_or(bound, |cur| cur.min(bound)));
            }
        }
        limit
    }

    /// The canonical serialization: keys in UTF-16 sort order (`#`
    /// conditions first), `None` fields omitted, hex lists
    /// lowercase-sorted, kinds ascending, tag values sorted by UTF-16 code
    /// units — the stored order, so this writes straight through.
    pub(crate) fn write_canonical(&self, out: &mut impl canonical::Sink) {
        out.push_str("{");
        let mut needs_comma = false;
        for (letter, values) in &self.tags {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"#");
            let mut buf = [0u8; 4];
            out.push_str(letter.as_char().encode_utf8(&mut buf));
            out.push_str("\":");
            push_str_array(values, out);
        }
        if let Some(authors) = &self.authors {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"authors\":");
            push_hex_array(authors.iter().map(PublicKey::as_bytes), out);
        }
        if let Some(ids) = &self.ids {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"ids\":");
            push_hex_array(ids.iter().map(EventId::as_bytes), out);
        }
        if let Some(kinds) = &self.kinds {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"kinds\":");
            push_u16_array(kinds.iter().map(|kind| kind.as_u16()), out);
        }
        if let Some(limit) = self.limit {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"limit\":");
            canonical::push_u64(limit, out);
        }
        if let Some(search) = &self.search {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"search\":");
            canonical::push_json_string(search, out);
        }
        if let Some(since) = self.since {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"since\":");
            canonical::push_u64(since.as_secs(), out);
        }
        if let Some(until) = self.until {
            push_field_sep(&mut needs_comma, out);
            out.push_str("\"until\":");
            canonical::push_u64(until.as_secs(), out);
        }
        out.push_str("}");
    }

    /// The wire JSON object — the canonical serialization.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    /// Parses the wire JSON object.
    ///
    /// # Errors
    ///
    /// [`JsonError`] on any malformed input; the message names the
    /// offending field.
    pub fn from_json(json: &str) -> json::Result<Self> {
        serde_json::from_str(json).map_err(JsonError::from)
    }
}

fn push_field_sep(needs_comma: &mut bool, out: &mut impl canonical::Sink) {
    if *needs_comma {
        out.push_str(",");
    }
    *needs_comma = true;
}

fn push_str_array(values: &[Box<str>], out: &mut impl canonical::Sink) {
    out.push_str("[");
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push_str(",");
        }
        canonical::push_json_string(value, out);
    }
    out.push_str("]");
}

fn push_hex_array<'a>(items: impl Iterator<Item = &'a [u8; 32]>, out: &mut impl canonical::Sink) {
    out.push_str("[");
    for (i, bytes) in items.enumerate() {
        if i > 0 {
            out.push_str(",");
        }
        out.push_str("\"");
        canonical::push_hex(bytes, out);
        out.push_str("\"");
    }
    out.push_str("]");
}

fn push_u16_array(items: impl Iterator<Item = u16>, out: &mut impl canonical::Sink) {
    out.push_str("[");
    for (i, value) in items.enumerate() {
        if i > 0 {
            out.push_str(",");
        }
        canonical::push_u64(u64::from(value), out);
    }
    out.push_str("]");
}

/// Sorts and deduplicates into a boxed slice.
fn sorted_dedup<T: Ord, I: IntoIterator<Item = T>>(items: I) -> Box<[T]> {
    let mut items: Vec<T> = items.into_iter().collect();
    items.sort_unstable();
    items.dedup();
    items.into_boxed_slice()
}

/// UTF-16 code units of `s` (a char is one unit below U+10000, a surrogate
/// pair above).
fn utf16_units(s: &str) -> impl Iterator<Item = u16> + '_ {
    s.chars().flat_map(|c| {
        let mut buf = [0u16; 2];
        let n = c.encode_utf16(&mut buf).len();
        [buf[0], buf[1]].into_iter().take(n)
    })
}

/// One tag condition: some `letter` tag on `event` must carry a value in
/// `values`. (`#e`/`#p` are already stored lowercase; the event-side value
/// compares case-sensitively.) Found by binary search.
fn tag_value_hit(letter: SingleLetterTag, values: &[Box<str>], event: &Event) -> bool {
    event.tags().iter().any(|tag| {
        if tag.name().as_bytes() != [letter.0] {
            return false;
        }
        let Some(value) = tag.value() else {
            return false;
        };
        values
            .binary_search_by(|stored| utf16_units(stored).cmp(utf16_units(value)))
            .is_ok()
    })
}

/// `#e`/`#p` values are ASCII-lowercased and must be 64-char hex; other
/// letters stay verbatim. Sorted by UTF-16 code units — the canonical
/// serialization order, which is also the binary-search order.
fn tag_value_list<I, S>(letter: SingleLetterTag, values: I) -> Result<Box<[Box<str>]>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let hex = matches!(letter.as_char(), 'e' | 'p');
    let mut values: Vec<Box<str>> = values
        .into_iter()
        .map(|value| {
            let value: String = value.into();
            if hex {
                value.to_ascii_lowercase().into_boxed_str()
            } else {
                value.into_boxed_str()
            }
        })
        .collect();
    if values.is_empty() {
        return Err(Error::EmptyList {
            field: Field::Tag(letter.as_char()),
        });
    }
    if hex {
        for value in &values {
            hex::decode_wire::<32>(value).map_err(|_| Error::InvalidTagValue {
                letter: letter.as_char(),
            })?;
        }
    }
    values.sort_by(|a, b| utf16_units(a).cmp(utf16_units(b)));
    values.dedup();
    Ok(values.into_boxed_slice())
}

/// Parses a `#x` object key into a [`SingleLetterTag`]; `None` for
/// non-`#` keys, multi-letter keys, and non-letter keys — NIP-01 ignores
/// all three shapes.
fn single_letter_key(key: &str) -> Option<SingleLetterTag> {
    let letter = key.strip_prefix('#')?;
    let mut chars = letter.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    SingleLetterTag::new(c)
}

impl<'de> Deserialize<'de> for Filter {
    /// Wire-filter rules: keys are unique; `ids`/`authors` are arrays of
    /// 64-char lowercase hex, `kinds` plain integers in `0..=65535`,
    /// `since`/`until`/`limit` plain non-negative integers, `search` a
    /// string, `#<letter>` arrays of strings (`#e`/`#p` lowercase 64-hex).
    /// Every list must be non-empty. Multi-letter `#` keys and unknown
    /// non-`#` keys are dropped; wrong types fail.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FilterVisitor;

        impl<'de> Visitor<'de> for FilterVisitor {
            type Value = Filter;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a NIP-01 filter object")
            }

            #[allow(
                clippy::excessive_nesting,
                reason = "a strict visitor is a loop over tagged fields"
            )]
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Filter, M::Error> {
                let mut seen = Vec::new();
                let mut filter = Filter::default();
                while let Some(key) = json::next_key(&mut map, &mut seen)? {
                    match key.as_ref() {
                        "ids" => {
                            let list = map.next_value::<WireHexList<32, true>>()?.0;
                            if list.is_empty() {
                                return Err(serde::de::Error::custom(Error::EmptyList {
                                    field: Field::Ids,
                                }));
                            }
                            filter.ids =
                                Some(sorted_dedup(list.into_iter().map(EventId::from_bytes)));
                        }
                        "authors" => {
                            let list = map.next_value::<WireHexList<32, true>>()?.0;
                            if list.is_empty() {
                                return Err(serde::de::Error::custom(Error::EmptyList {
                                    field: Field::Authors,
                                }));
                            }
                            filter.authors =
                                Some(sorted_dedup(list.into_iter().map(PublicKey::from_bytes)));
                        }
                        "kinds" => {
                            let list = map.next_value::<WireU16List>()?.0;
                            if list.is_empty() {
                                return Err(serde::de::Error::custom(Error::EmptyList {
                                    field: Field::Kinds,
                                }));
                            }
                            filter.kinds = Some(sorted_dedup(list.into_iter().map(Kind::new)));
                        }
                        "since" => {
                            filter.since = Some(Timestamp::from_secs(
                                map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0,
                            ));
                        }
                        "until" => {
                            filter.until = Some(Timestamp::from_secs(
                                map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0,
                            ));
                        }
                        "limit" => {
                            filter.limit = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0);
                        }
                        "search" => {
                            filter.search = Some(map.next_value::<String>()?.into_boxed_str());
                        }
                        _ => {
                            if let Some(letter) = single_letter_key(&key) {
                                let raw = map.next_value::<Vec<String>>()?;
                                // `#e`/`#p` are 64-hex protocol text:
                                // lowercase only, nothing else.
                                if matches!(letter.as_char(), 'e' | 'p') {
                                    for value in &raw {
                                        hex::decode_wire::<32>(value)
                                            .map_err(serde::de::Error::custom)?;
                                    }
                                }
                                let values = tag_value_list(letter, raw)
                                    .map_err(serde::de::Error::custom)?;
                                match filter.tags.binary_search_by_key(&letter, |(l, _)| *l) {
                                    Ok(index) => {
                                        if let Some(slot) = filter.tags.get_mut(index) {
                                            slot.1 = values;
                                        }
                                    }
                                    Err(index) => {
                                        let mut tags = filter.tags.into_vec();
                                        tags.insert(index, (letter, values));
                                        filter.tags = tags.into_boxed_slice();
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                }
                Ok(filter)
            }
        }

        deserializer.deserialize_map(FilterVisitor)
    }
}

/// Tag values serialized in stored (UTF-16) order.
struct StrList<'a>(&'a [Box<str>]);

impl Serialize for StrList<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|value| &**value))
    }
}

impl Serialize for Filter {
    /// The canonical wire form: keys in UTF-16 sort order with `#`
    /// conditions first — the stored order, identical to
    /// [`|f| { let mut out = String::new(); f.write_canonical(&mut out); out }`].
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut len = self.tags.len();
        for present in [
            self.ids.is_some(),
            self.authors.is_some(),
            self.kinds.is_some(),
            self.limit.is_some(),
            self.search.is_some(),
            self.since.is_some(),
            self.until.is_some(),
        ] {
            len += usize::from(present);
        }
        let mut map = serializer.serialize_map(Some(len))?;
        for (letter, values) in &self.tags {
            map.serialize_entry(&alloc::format!("#{letter}"), &StrList(values))?;
        }
        if let Some(authors) = &self.authors {
            map.serialize_entry("authors", authors)?;
        }
        if let Some(ids) = &self.ids {
            map.serialize_entry("ids", ids)?;
        }
        if let Some(kinds) = &self.kinds {
            map.serialize_entry("kinds", kinds)?;
        }
        if let Some(limit) = self.limit {
            map.serialize_entry("limit", &limit)?;
        }
        if let Some(search) = &self.search {
            map.serialize_entry("search", search)?;
        }
        if let Some(since) = self.since {
            map.serialize_entry("since", &since)?;
        }
        if let Some(until) = self.until {
            map.serialize_entry("until", &until)?;
        }
        map.end()
    }
}

/// Canonical identity for REQ coalescing: each filter canonically
/// serialized, the strings sorted by UTF-16 code units and joined with `,`
/// inside `[...]`.
#[must_use]
pub fn fingerprint(filters: &[Filter]) -> String {
    let mut parts: Vec<String> = filters
        .iter()
        .map(|f| {
            let mut out = String::new();
            f.write_canonical(&mut out);
            out
        })
        .collect();
    parts.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let mut out = String::from("[");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(part);
    }
    out.push(']');
    out
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail by panicking")]

    use alloc::string::ToString;
    use alloc::vec;
    use core::hash::{Hash, Hasher};

    use alloc::vec::Vec;
    use serde_json::json;

    use super::*;

    const PK: &str = "90a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23";
    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn pubkey() -> PublicKey {
        PublicKey::from_hex(PK).unwrap()
    }

    fn event(tags: &[&[&str]], kind: u16, created_at: u64) -> Event {
        serde_json::from_value::<Event>(json!({
            "id": ID_A,
            "pubkey": PK,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": "x",
            "sig": "c".repeat(128),
        }))
        .unwrap()
    }

    fn letter(c: char) -> SingleLetterTag {
        SingleLetterTag::new(c).unwrap()
    }

    #[test]
    fn single_letter_tag_accepts_only_ascii_letters() {
        assert!(SingleLetterTag::new('a').is_some());
        assert!(SingleLetterTag::new('Z').is_some());
        assert!(SingleLetterTag::new('0').is_none());
        assert!(SingleLetterTag::new('#').is_none());
        assert!(SingleLetterTag::new('é').is_none());
        assert_eq!(letter('e').as_char(), 'e');
        assert_eq!(letter('A').to_string(), "A");
        assert_eq!(SingleLetterTag::try_from('p').unwrap(), letter('p'));
        assert!(matches!(
            SingleLetterTag::try_from('-'),
            Err(Error::InvalidTagLetter { letter: '-' })
        ));
    }

    #[test]
    fn builders_and_accessors() {
        let filter = Filter::new()
            .ids([EventId::from_hex(ID_A).unwrap()])
            .unwrap()
            .authors([pubkey()])
            .unwrap()
            .kinds([Kind::TEXT_NOTE])
            .unwrap()
            .tag(letter('t'), ["nostr"])
            .unwrap()
            .since(Timestamp::from_secs(10))
            .until(Timestamp::from_secs(20))
            .limit(5)
            .search("q");
        assert_eq!(filter.get_ids().map(<[_]>::len), Some(1));
        assert_eq!(filter.get_authors().map(<[_]>::len), Some(1));
        assert_eq!(filter.get_kinds().map(<[_]>::len), Some(1));
        assert_eq!(filter.tag_values(letter('t')).map(<[_]>::len), Some(1));
        assert_eq!(filter.tag_letters().collect::<Vec<_>>(), vec![letter('t')]);
        assert_eq!(filter.get_since(), Some(Timestamp::from_secs(10)));
        assert_eq!(filter.get_until(), Some(Timestamp::from_secs(20)));
        assert_eq!(filter.get_limit(), Some(5));
        assert_eq!(filter.get_search(), Some("q"));
    }

    #[test]
    fn tag_builder_lowercases_e_and_p_values() {
        let filter = Filter::new()
            .tag(letter('e'), [ID_A.to_uppercase()])
            .unwrap()
            .tag(letter('t'), ["NoStr"])
            .unwrap();
        assert!(
            filter
                .tag_values(letter('e'))
                .is_some_and(|v| v.iter().any(|s| &**s == ID_A))
        );
        assert!(
            filter
                .tag_values(letter('t'))
                .is_some_and(|v| v.iter().any(|s| &**s == "NoStr"))
        );
    }

    #[test]
    fn matches_ids_kinds_authors_and_bounds() {
        let event = event(&[&["t", "nostr"]], 1, 1000);
        assert!(Filter::new().matches(&event));
        assert!(
            Filter::new()
                .ids([EventId::from_hex(ID_A).unwrap()])
                .unwrap()
                .matches(&event)
        );
        assert!(Filter::new().kinds([Kind::new(1)]).unwrap().matches(&event));
        assert!(!Filter::new().kinds([Kind::new(2)]).unwrap().matches(&event));
        assert!(Filter::new().authors([pubkey()]).unwrap().matches(&event));
        assert!(
            Filter::new()
                .since(Timestamp::from_secs(1000))
                .until(Timestamp::from_secs(1000))
                .matches(&event)
        );
        assert!(
            !Filter::new()
                .since(Timestamp::from_secs(1001))
                .matches(&event)
        );
        assert!(
            !Filter::new()
                .until(Timestamp::from_secs(999))
                .matches(&event)
        );
        assert!(Filter::new().search("anything").matches(&event));
    }

    #[test]
    fn matches_tag_conditions() {
        let bare = event(&[&["t"]], 1, 1);
        let event = event(&[&["t", "nostr"], &["d", "post"]], 1, 1);
        assert!(
            Filter::new()
                .tag(letter('t'), ["nostr"])
                .unwrap()
                .matches(&event)
        );
        assert!(
            !Filter::new()
                .tag(letter('t'), ["other"])
                .unwrap()
                .matches(&event)
        );
        assert!(
            !Filter::new()
                .tag(letter('x'), ["nostr"])
                .unwrap()
                .matches(&event)
        );
        // A valueless tag never satisfies a # condition.
        assert!(
            !Filter::new()
                .tag(letter('t'), ["nostr"])
                .unwrap()
                .matches(&bare)
        );
    }

    #[test]
    fn matches_e_and_p_lowercases_filter_side_only() {
        let ev = event(
            &[&["e", &ID_A.to_uppercase()], &["p", &PK.to_uppercase()]],
            1,
            1,
        );
        // Filter values are lowercased on build; the event-side value
        // compares case-sensitively (vectors/core/filter-match.json).
        assert!(
            !Filter::new()
                .tag(letter('e'), [ID_A.to_uppercase()])
                .unwrap()
                .matches(&ev)
        );
        assert!(!Filter::new().tag(letter('p'), [PK]).unwrap().matches(&ev));
        let lower = event(&[&["e", ID_A], &["p", PK]], 1, 1);
        assert!(
            Filter::new()
                .tag(letter('e'), [ID_A.to_uppercase()])
                .unwrap()
                .matches(&lower)
        );
        assert!(
            Filter::new()
                .tag(letter('p'), [PK])
                .unwrap()
                .matches(&lower)
        );
        // Non-hex letters stay case sensitive.
        let ev_t = event(&[&["t", "Nostr"]], 1, 1);
        assert!(
            !Filter::new()
                .tag(letter('t'), ["nostr"])
                .unwrap()
                .matches(&ev_t)
        );
    }

    #[test]
    fn limit_bound_counts_unique_values() {
        assert_eq!(Filter::new().limit_bound(), None);
        assert_eq!(
            Filter::new()
                .ids([
                    EventId::from_hex(ID_A).unwrap(),
                    EventId::from_hex(ID_A).unwrap()
                ])
                .unwrap()
                .limit_bound(),
            Some(1)
        );
        assert_eq!(
            Filter::new()
                .ids([EventId::from_hex(ID_A).unwrap()])
                .unwrap()
                .limit(10)
                .limit_bound(),
            Some(1)
        );
        assert_eq!(Filter::new().limit(10).limit_bound(), Some(10));
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(0), Kind::new(3)])
                .unwrap()
                .authors([pubkey()])
                .unwrap()
                .limit_bound(),
            Some(2)
        );
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(30023)])
                .unwrap()
                .authors([pubkey()])
                .unwrap()
                .tag(letter('d'), ["a", "b"])
                .unwrap()
                .limit_bound(),
            Some(2)
        );
        // Regular kinds get no replaceable bound.
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(1)])
                .unwrap()
                .authors([pubkey()])
                .unwrap()
                .limit_bound(),
            None
        );
        assert_eq!(
            Filter::new()
                .limit(5)
                .kinds([Kind::new(0), Kind::new(3)])
                .unwrap()
                .authors([pubkey()])
                .unwrap()
                .limit_bound(),
            Some(2)
        );
    }

    #[test]
    fn canonical_json_matches_ts_key_and_value_order() {
        let filter = Filter::new()
            .tag(letter('a'), ["x"])
            .unwrap()
            .tag(letter('A'), ["y"])
            .unwrap()
            .authors([pubkey()])
            .unwrap()
            .ids([EventId::from_hex(ID_A).unwrap()])
            .unwrap()
            .kinds([Kind::new(3), Kind::new(1)])
            .unwrap()
            .limit(2)
            .search("s")
            .since(Timestamp::from_secs(4))
            .until(Timestamp::from_secs(5));
        assert_eq!(
            filter.to_json(),
            alloc::format!(
                "{{\"#A\":[\"y\"],\"#a\":[\"x\"],\"authors\":[\"{PK}\"],\"ids\":[\"{ID_A}\"],\"kinds\":[1,3],\"limit\":2,\"search\":\"s\",\"since\":4,\"until\":5}}"
            )
        );
        assert_eq!(serde_json::to_string(&filter).unwrap(), filter.to_json());
    }

    #[test]
    fn canonical_json_sorts_tag_values_by_utf16() {
        // UTF-16 order: "z" (0x007A) < "😀" (0xD83D) < "\u{FFFD}" (0xFFFD);
        // UTF-8 order would put "\u{FFFD}" before "😀".
        let filter = Filter::new()
            .tag(letter('t'), ["\u{FFFD}", "😀", "z"])
            .unwrap();
        assert_eq!(filter.to_json(), "{\"#t\":[\"z\",\"😀\",\"\u{FFFD}\"]}");
    }

    #[test]
    fn empty_lists_are_rejected_at_construction() {
        assert_eq!(Filter::new().to_json(), "{}");
        assert!(matches!(
            Filter::new().ids([]),
            Err(Error::EmptyList { field: Field::Ids })
        ));
        assert!(matches!(
            Filter::new().authors([]),
            Err(Error::EmptyList {
                field: Field::Authors
            })
        ));
        assert!(matches!(
            Filter::new().kinds([]),
            Err(Error::EmptyList {
                field: Field::Kinds
            })
        ));
        assert!(matches!(
            Filter::new().tag(letter('t'), Vec::<String>::new()),
            Err(Error::EmptyList {
                field: Field::Tag(_)
            })
        ));
        assert!(matches!(
            Filter::new().tag(letter('e'), ["nothex"]),
            Err(Error::InvalidTagValue { .. })
        ));
        assert!(
            Filter::new()
                .tag(letter('e'), [&ID_A.to_uppercase()])
                .is_ok()
        );
        assert!(Filter::new().tag(letter('t'), ["nothex"]).is_ok());
    }

    #[test]
    fn deserialize_accepts_wire_rules() {
        let filter: Filter = serde_json::from_value(json!({
            "ids": [ID_A],
            "authors": [PK],
            "kinds": [1, 0],
            "since": 5,
            "until": 9,
            "limit": 3,
            "search": "q",
            "#e": [ID_A],
            "#custom": ["dropped"],
            "#9": ["dropped"],
            "unknown": { "kept": false }
        }))
        .unwrap();
        assert_eq!(
            filter
                .get_ids()
                .map(|s| s.contains(&EventId::from_hex(ID_A).unwrap())),
            Some(true)
        );
        assert_eq!(
            filter.get_authors().map(|s| s.contains(&pubkey())),
            Some(true)
        );
        assert_eq!(filter.get_kinds().map(<[_]>::len), Some(2));
        assert_eq!(
            filter
                .tag_values(letter('e'))
                .map(|s| s.iter().any(|v| &**v == ID_A)),
            Some(true)
        );
        assert_eq!(filter.tag_letters().count(), 1);
        assert_eq!(filter.get_since(), Some(Timestamp::from_secs(5)));
        assert_eq!(filter.get_limit(), Some(3));
        assert_eq!(filter.get_search(), Some("q"));
    }

    #[test]
    fn deserialize_rejects_wrong_types() {
        for raw in [
            json!({"ids": ["zz"]}),
            json!({"ids": ["a".repeat(63)]}),
            json!({"ids": [1]}),
            json!({"ids": "abc"}),
            json!({"authors": [1]}),
            json!({"kinds": [65536]}),
            json!({"kinds": [-1]}),
            json!({"kinds": [1.5]}),
            json!({"since": -1}),
            json!({"since": "x"}),
            json!({"until": 1.5}),
            json!({"limit": -1}),
            json!({"limit": "x"}),
            json!({"search": 1}),
            json!({"#e": "x"}),
            json!({"#t": [1]}),
            json!({"ids": []}),
            json!({"authors": []}),
            json!({"kinds": []}),
            json!({"#t": []}),
            json!({"#e": []}),
        ] {
            assert!(
                serde_json::from_value::<Filter>(raw.clone()).is_err(),
                "expected rejection: {raw}"
            );
        }
    }

    #[test]
    fn fingerprint_sorts_serialized_filters_by_utf16() {
        // "😀" sorts before "\u{FFFD}" under UTF-16 code units.
        let filters = [
            Filter::new().tag(letter('t'), ["\u{FFFD}"]).unwrap(),
            Filter::new().tag(letter('t'), ["😀"]).unwrap(),
        ];
        assert_eq!(
            fingerprint(&filters),
            "[{\"#t\":[\"😀\"]},{\"#t\":[\"\u{FFFD}\"]}]"
        );
        // Filter order does not matter.
        let swapped: Vec<Filter> = filters.iter().rev().cloned().collect();
        assert_eq!(fingerprint(&swapped), fingerprint(&filters));
        assert_eq!(fingerprint(&[]), "[]");
    }

    #[test]
    fn fingerprint_of_parsed_filter_is_canonical() {
        let filter = Filter::new()
            .ids([EventId::from_hex(ID_A).unwrap()])
            .unwrap();
        assert_eq!(
            fingerprint(&[filter]),
            "[{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}]"
        );
        // Uppercase wire hex is invalid, never repaired into an equivalent.
        assert!(serde_json::from_value::<Filter>(json!({"ids": [ID_A.to_uppercase()]})).is_err());
        assert!(serde_json::from_value::<Filter>(json!({"#e": [ID_A.to_uppercase()]})).is_err());
        assert!(serde_json::from_value::<Filter>(json!({"authors": [PK.to_uppercase()]})).is_err());
    }

    #[test]
    fn hash_covers_every_field() {
        // `BTreeMap` has no `Hash`; the impl hashes the ordered entries.
        struct Len(u64);
        impl Hasher for Len {
            fn write(&mut self, bytes: &[u8]) {
                self.0 = self.0.wrapping_add(bytes.len() as u64);
            }
            fn finish(&self) -> u64 {
                self.0
            }
        }
        let filter = Filter::new()
            .kinds([Kind::TEXT_NOTE])
            .unwrap()
            .tag(letter('t'), ["gm"])
            .unwrap()
            .search("gm");
        let mut a = Len(0);
        filter.hash(&mut a);
        let mut b = Len(0);
        filter.clone().hash(&mut b);
        assert_eq!(a.finish(), b.finish());
        let mut different = Len(0);
        Filter::new().hash(&mut different);
        assert_ne!(a.finish(), different.finish());
    }
}
