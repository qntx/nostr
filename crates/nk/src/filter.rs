//! [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
//! subscription filters: matching, intrinsic limit bounds, and the
//! canonical serialization used by REQ coalescing.

use alloc::borrow::Cow;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use serde::de::{Error as DeError, IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical::{self, Sink};
use crate::detail::JsonSource;
use crate::event::{Event, EventId};
use crate::json::{
    self, Captured, MAX_SAFE_INTEGER, WireHexList, WireInt, WireStr, WireStrList, WireU16List,
};
use crate::key::PublicKey;
use crate::kind::Kind;
use crate::time::Timestamp;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

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
    /// The wire JSON is malformed or fails a NIP-01 filter rule; the source
    /// message names the offending field.
    #[error("invalid JSON")]
    InvalidJson(#[source] JsonSource),
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

/// A NIP-01 filter. List fields are sets: `None` leaves the field
/// unconstrained while an empty set matches nothing.
///
/// `#e`/`#p` values are normalized to lowercase at construction and
/// deserialization; matching compares event tag values case-insensitively.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    ids: Option<BTreeSet<EventId>>,
    authors: Option<BTreeSet<PublicKey>>,
    kinds: Option<BTreeSet<Kind>>,
    tags: BTreeMap<SingleLetterTag, BTreeSet<String>>,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
    limit: Option<usize>,
    search: Option<String>,
}

/// `BTreeMap` has no `Hash` impl; hash the ordered entries instead.
impl Hash for Filter {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ids.hash(state);
        self.authors.hash(state);
        self.kinds.hash(state);
        self.tags.len().hash(state);
        for (letter, values) in &self.tags {
            letter.hash(state);
            values.hash(state);
        }
        self.since.hash(state);
        self.until.hash(state);
        self.limit.hash(state);
        self.search.hash(state);
    }
}

impl Filter {
    /// An unconstrained filter (matches every event).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts to these event ids.
    #[must_use]
    pub fn ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.ids = Some(ids.into_iter().collect());
        self
    }

    /// Restricts to these author public keys.
    #[must_use]
    pub fn authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.authors = Some(authors.into_iter().collect());
        self
    }

    /// Restricts to these kinds.
    #[must_use]
    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        self.kinds = Some(kinds.into_iter().collect());
        self
    }

    /// Adds a single-letter tag condition: an event matches only when one of
    /// its `letter` tags carries a value in `values` (`#e`/`#p` values are
    /// stored lowercase).
    #[must_use]
    pub fn tag<I, S>(mut self, letter: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set = tag_value_set(letter, values);
        self.tags.insert(letter, set);
        self
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
    pub const fn limit(mut self, limit: usize) -> Self {
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
        self.search = Some(query.into());
        self
    }

    /// The id set, if constrained.
    #[must_use]
    pub const fn ids_set(&self) -> Option<&BTreeSet<EventId>> {
        self.ids.as_ref()
    }

    /// The author set, if constrained.
    #[must_use]
    pub const fn authors_set(&self) -> Option<&BTreeSet<PublicKey>> {
        self.authors.as_ref()
    }

    /// The kind set, if constrained.
    #[must_use]
    pub const fn kinds_set(&self) -> Option<&BTreeSet<Kind>> {
        self.kinds.as_ref()
    }

    /// The value set of a tag condition, if present (possibly empty).
    #[must_use]
    pub fn tag_values(&self, letter: SingleLetterTag) -> Option<&BTreeSet<String>> {
        self.tags.get(&letter)
    }

    /// The single-letter tag condition keys, in order.
    pub fn tag_letters(&self) -> impl Iterator<Item = SingleLetterTag> + '_ {
        self.tags.keys().copied()
    }

    /// The inclusive lower `created_at` bound, if any.
    #[must_use]
    pub const fn since_bound(&self) -> Option<Timestamp> {
        self.since
    }

    /// The inclusive upper `created_at` bound, if any.
    #[must_use]
    pub const fn until_bound(&self) -> Option<Timestamp> {
        self.until
    }

    /// The relay-side truncation hint, if set.
    #[must_use]
    pub const fn limit_value(&self) -> Option<usize> {
        self.limit
    }

    /// The NIP-50 search query, if set.
    #[must_use]
    pub fn search_query(&self) -> Option<&str> {
        self.search.as_deref()
    }

    /// Local NIP-01 match; `search` is ignored.
    ///
    /// `#e`/`#p` conditions compare the event tag value and the filter
    /// values case-insensitively; `since`/`until` bounds are inclusive.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if self
            .ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(&event.id()))
        {
            return false;
        }
        if self
            .kinds
            .as_ref()
            .is_some_and(|kinds| !kinds.contains(&event.kind()))
        {
            return false;
        }
        if self
            .authors
            .as_ref()
            .is_some_and(|authors| !authors.contains(&event.pubkey()))
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

    /// True when `event` matches any of `filters` (NIP-01 OR semantics).
    #[must_use]
    pub fn matches_any(filters: &[Self], event: &Event) -> bool {
        filters.iter().any(|filter| filter.matches(event))
    }

    /// Intrinsic upper bound implied by the filter alone; `None` when
    /// unbounded.
    ///
    /// For kinds that are all replaceable or addressable and a non-empty
    /// author set, the bound is `authors * kinds * (#d or 1)` — sets are
    /// already deduplicated.
    #[must_use]
    pub fn limit_bound(&self) -> Option<usize> {
        if self.ids.as_ref().is_some_and(BTreeSet::is_empty)
            || self.kinds.as_ref().is_some_and(BTreeSet::is_empty)
            || self.authors.as_ref().is_some_and(BTreeSet::is_empty)
        {
            return Some(0);
        }
        let mut limit = self.ids.as_ref().map(BTreeSet::len);
        if let Some(hint) = self.limit {
            limit = Some(limit.map_or(hint, |cur| cur.min(hint)));
        }
        if let (Some(kinds), Some(authors)) = (&self.kinds, &self.authors) {
            let all_replaceable = kinds
                .iter()
                .all(|kind| kind.is_replaceable() || kind.is_addressable());
            if all_replaceable {
                let per_author = self
                    .tags
                    .get(&SingleLetterTag(b'd'))
                    .map_or(1, |values| values.len().max(1));
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
    /// units.
    pub(crate) fn write_canonical(&self, out: &mut impl Sink) {
        out.push_char('{');
        let mut needs_comma = false;
        for (letter, values) in &self.tags {
            push_field_sep(&mut needs_comma, out);
            out.push_char('"');
            out.push_char('#');
            out.push_char(letter.as_char());
            out.push_str("\":");
            push_str_array(&sorted_tag_values(values), out);
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
            canonical::push_u64(u64::try_from(limit).unwrap_or(u64::MAX), out);
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
        out.push_char('}');
    }

    /// The canonical serialization as a `String` (see the `serde` impl);
    /// used by [`fingerprint`].
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    /// The wire JSON object — the canonical serialization.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.canonical_json()
    }

    /// Parses the wire JSON object.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] on any malformed input; the source message
    /// names the offending field.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::InvalidJson(JsonSource(e)))
    }
}

fn push_field_sep(needs_comma: &mut bool, out: &mut impl Sink) {
    if *needs_comma {
        out.push_char(',');
    }
    *needs_comma = true;
}

/// Tag values emitted in canonical order — UTF-16 code units, which
/// differs from the `BTreeSet` (UTF-8) order for non-BMP characters.
fn sorted_tag_values(values: &BTreeSet<String>) -> Vec<&str> {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    sorted
}

fn push_str_array(values: &[&str], out: &mut impl Sink) {
    out.push_char('[');
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push_char(',');
        }
        canonical::push_json_string(value, out);
    }
    out.push_char(']');
}

fn push_hex_array<'a>(items: impl Iterator<Item = &'a [u8; 32]>, out: &mut impl Sink) {
    out.push_char('[');
    for (i, bytes) in items.enumerate() {
        if i > 0 {
            out.push_char(',');
        }
        out.push_char('"');
        canonical::push_hex(bytes, out);
        out.push_char('"');
    }
    out.push_char(']');
}

fn push_u16_array(items: impl Iterator<Item = u16>, out: &mut impl Sink) {
    out.push_char('[');
    for (i, value) in items.enumerate() {
        if i > 0 {
            out.push_char(',');
        }
        canonical::push_u64(u64::from(value), out);
    }
    out.push_char(']');
}

/// One tag condition: some `letter` tag on `event` must carry a value in
/// `values` (case-insensitive for `e`/`p`).
fn tag_value_hit(letter: SingleLetterTag, values: &BTreeSet<String>, event: &Event) -> bool {
    event.tags().iter().any(|tag| {
        if tag.name().as_bytes() != [letter.0] {
            return false;
        }
        let Some(value) = tag.value() else {
            return false;
        };
        if matches!(letter.as_char(), 'e' | 'p') {
            return values.contains(value.to_lowercase().as_str());
        }
        values.contains(value)
    })
}

/// Lowercases `#e`/`#p` values; all other letters keep their case.
fn tag_value_set<I, S>(letter: SingleLetterTag, values: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let lowercase = matches!(letter.as_char(), 'e' | 'p');
    values
        .into_iter()
        .map(|value| {
            let value: String = value.into();
            if lowercase {
                value.to_lowercase()
            } else {
                value
            }
        })
        .collect()
}

/// Tag values serialized in UTF-16 order.
struct Utf16Values<'a>(&'a BTreeSet<String>);

impl Serialize for Utf16Values<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(sorted_tag_values(self.0))
    }
}

impl Serialize for Filter {
    /// The canonical wire form: keys in UTF-16 sort order with `#`
    /// conditions first.
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
            map.serialize_entry(
                &alloc::format!("#{}", letter.as_char()),
                &Utf16Values(values),
            )?;
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

/// Reads a wire-filter object (see [`Filter::deserialize`]). Each known
/// field is captured leniently into a per-key slot so a duplicate key's
/// last value wins even when an earlier value was invalid; unknown keys
/// drain via `IgnoredAny`.
fn read_filter<'de, M: MapAccess<'de>>(mut map: M) -> Result<Filter, M::Error> {
    let mut ids = None;
    let mut authors = None;
    let mut kinds = None;
    let mut since = None;
    let mut until = None;
    let mut limit = None;
    let mut search = None;
    let mut tags = BTreeMap::new();
    while let Some(key) = map.next_key::<Cow<'de, str>>()? {
        match key.as_ref() {
            "ids" => ids = Some(map.next_value::<WireHexList<32, false>>()?.0),
            "authors" => authors = Some(map.next_value::<WireHexList<32, false>>()?.0),
            "kinds" => kinds = Some(map.next_value::<WireU16List>()?.0),
            "since" => since = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0),
            "until" => until = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0),
            "limit" => limit = Some(map.next_value::<WireInt<MAX_SAFE_INTEGER>>()?.0),
            "search" => search = Some(map.next_value::<WireStr>()?.0),
            _ => {
                if let Some(letter) = single_letter_key(&key) {
                    tags.insert(letter, map.next_value::<WireStrList>()?.0);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
    }
    Ok(Filter {
        ids: opt_hex_set(ids, "ids", EventId::from_bytes)?,
        authors: opt_hex_set(authors, "authors", PublicKey::from_bytes)?,
        kinds: kinds
            .map(|captured| json::finish_opt(captured, "kinds"))
            .transpose()?
            .map(|kinds| kinds.into_iter().map(Kind::new).collect()),
        since: opt_timestamp(since, "since")?,
        until: opt_timestamp(until, "until")?,
        limit: opt_limit(limit)?,
        search: search
            .map(|captured| json::finish_opt(captured, "search"))
            .transpose()?,
        tags: build_tag_sets(tags)?,
    })
}

/// Converts a captured hex-list (any case, decoded at capture) into a
/// typed set.
fn opt_hex_set<T: Ord, E: DeError>(
    slot: Option<Captured<Vec<[u8; 32]>>>,
    field: &'static str,
    build: fn([u8; 32]) -> T,
) -> Result<Option<BTreeSet<T>>, E> {
    Ok(slot
        .map(|captured| json::finish_opt(captured, field))
        .transpose()?
        .map(|bytes| bytes.into_iter().map(build).collect()))
}

/// Converts a captured safe integer into a `Timestamp`.
fn opt_timestamp<E: DeError>(
    slot: Option<Captured<u64>>,
    field: &'static str,
) -> Result<Option<Timestamp>, E> {
    Ok(slot
        .map(|captured| json::finish_opt(captured, field))
        .transpose()?
        .map(Timestamp::from_secs))
}

/// Converts a captured safe integer into a `usize` limit.
fn opt_limit<E: DeError>(slot: Option<Captured<u64>>) -> Result<Option<usize>, E> {
    slot.map(|captured| json::finish_opt(captured, "limit"))
        .transpose()?
        .map(|value| usize::try_from(value).map_err(|_| E::custom("limit out of range")))
        .transpose()
}

/// Converts the captured `#<letter>` lists into tag-condition sets.
fn build_tag_sets<E: DeError>(
    captured: BTreeMap<SingleLetterTag, Captured<Vec<String>>>,
) -> Result<BTreeMap<SingleLetterTag, BTreeSet<String>>, E> {
    captured
        .into_iter()
        .map(|(letter, slot)| {
            let raw = json::finish_opt(slot, &alloc::format!("#{letter}"))?;
            Ok((letter, tag_value_set(letter, raw)))
        })
        .collect()
}

impl<'de> Deserialize<'de> for Filter {
    /// Wire-filter rules: `ids`/`authors` are
    /// arrays of 64-char hex (any case, stored lowercase), `kinds` integers
    /// in `0..=65535`, `since`/`until`/`limit` non-negative integers,
    /// `search` a string, `#<letter>` arrays of strings (`#e`/`#p`
    /// lowercased). Multi-letter `#` keys and unknown non-`#` keys are
    /// dropped; wrong types fail.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FilterVisitor;

        impl<'de> Visitor<'de> for FilterVisitor {
            type Value = Filter;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a NIP-01 filter object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Filter, M::Error> {
                read_filter(map)
            }
        }

        deserializer.deserialize_map(FilterVisitor)
    }
}

/// Canonical identity for REQ coalescing: each filter canonically
/// serialized, the strings sorted by UTF-16 code units and joined with `,`
/// inside `[...]`.
#[must_use]
pub fn fingerprint(filters: &[Filter]) -> String {
    let mut parts: Vec<String> = filters.iter().map(Filter::canonical_json).collect();
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
            .authors([pubkey()])
            .kinds([Kind::TEXT_NOTE])
            .tag(letter('t'), ["nostr"])
            .since(Timestamp::from_secs(10))
            .until(Timestamp::from_secs(20))
            .limit(5)
            .search("q");
        assert_eq!(filter.ids_set().map(BTreeSet::len), Some(1));
        assert_eq!(filter.authors_set().map(BTreeSet::len), Some(1));
        assert_eq!(filter.kinds_set().map(BTreeSet::len), Some(1));
        assert_eq!(filter.tag_values(letter('t')).map(BTreeSet::len), Some(1));
        assert_eq!(filter.tag_letters().collect::<Vec<_>>(), vec![letter('t')]);
        assert_eq!(filter.since_bound(), Some(Timestamp::from_secs(10)));
        assert_eq!(filter.until_bound(), Some(Timestamp::from_secs(20)));
        assert_eq!(filter.limit_value(), Some(5));
        assert_eq!(filter.search_query(), Some("q"));
    }

    #[test]
    fn tag_builder_lowercases_e_and_p_values() {
        let filter = Filter::new()
            .tag(letter('e'), [ID_A.to_uppercase()])
            .tag(letter('t'), ["NoStr"]);
        assert!(
            filter
                .tag_values(letter('e'))
                .is_some_and(|v| v.contains(ID_A))
        );
        assert!(
            filter
                .tag_values(letter('t'))
                .is_some_and(|v| v.contains("NoStr"))
        );
    }

    #[test]
    fn matches_ids_kinds_authors_and_bounds() {
        let event = event(&[&["t", "nostr"]], 1, 1000);
        assert!(Filter::new().matches(&event));
        assert!(
            Filter::new()
                .ids([EventId::from_hex(ID_A).unwrap()])
                .matches(&event)
        );
        assert!(!Filter::new().ids([]).matches(&event));
        assert!(Filter::new().kinds([Kind::new(1)]).matches(&event));
        assert!(!Filter::new().kinds([Kind::new(2)]).matches(&event));
        assert!(Filter::new().authors([pubkey()]).matches(&event));
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
        assert!(Filter::new().tag(letter('t'), ["nostr"]).matches(&event));
        assert!(!Filter::new().tag(letter('t'), ["other"]).matches(&event));
        assert!(
            !Filter::new()
                .tag(letter('t'), Vec::<String>::new())
                .matches(&event)
        );
        assert!(!Filter::new().tag(letter('x'), ["nostr"]).matches(&event));
        // A valueless tag never satisfies a # condition.
        assert!(!Filter::new().tag(letter('t'), ["nostr"]).matches(&bare));
    }

    #[test]
    fn matches_e_and_p_case_insensitively() {
        let ev = event(
            &[&["e", &ID_A.to_uppercase()], &["p", &PK.to_uppercase()]],
            1,
            1,
        );
        assert!(
            Filter::new()
                .tag(letter('e'), [ID_A.to_uppercase()])
                .matches(&ev)
        );
        assert!(Filter::new().tag(letter('p'), [PK]).matches(&ev));
        // Non-hex letters stay case sensitive.
        let ev_t = event(&[&["t", "Nostr"]], 1, 1);
        assert!(!Filter::new().tag(letter('t'), ["nostr"]).matches(&ev_t));
    }

    #[test]
    fn matches_any_is_or() {
        let event = event(&[], 1, 1);
        assert!(Filter::matches_any(
            &[Filter::new().kinds([Kind::new(2)]), Filter::new()],
            &event
        ));
        assert!(!Filter::matches_any(
            &[Filter::new().kinds([Kind::new(2)])],
            &event
        ));
        assert!(!Filter::matches_any(&[], &event));
    }

    #[test]
    fn limit_bound_counts_unique_values() {
        assert_eq!(Filter::new().limit_bound(), None);
        assert_eq!(Filter::new().ids([]).limit_bound(), Some(0));
        assert_eq!(Filter::new().kinds([]).limit_bound(), Some(0));
        assert_eq!(Filter::new().authors([]).limit_bound(), Some(0));
        assert_eq!(
            Filter::new()
                .ids([
                    EventId::from_hex(ID_A).unwrap(),
                    EventId::from_hex(ID_A).unwrap()
                ])
                .limit_bound(),
            Some(1)
        );
        assert_eq!(
            Filter::new()
                .ids([EventId::from_hex(ID_A).unwrap()])
                .limit(10)
                .limit_bound(),
            Some(1)
        );
        assert_eq!(Filter::new().limit(10).limit_bound(), Some(10));
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(0), Kind::new(3)])
                .authors([pubkey()])
                .limit_bound(),
            Some(2)
        );
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(30023)])
                .authors([pubkey()])
                .tag(letter('d'), ["a", "b"])
                .limit_bound(),
            Some(2)
        );
        // Regular kinds get no replaceable bound.
        assert_eq!(
            Filter::new()
                .kinds([Kind::new(1)])
                .authors([pubkey()])
                .limit_bound(),
            None
        );
        assert_eq!(
            Filter::new()
                .limit(5)
                .kinds([Kind::new(0), Kind::new(3)])
                .authors([pubkey()])
                .limit_bound(),
            Some(2)
        );
    }

    #[test]
    fn canonical_json_matches_ts_key_and_value_order() {
        let filter = Filter::new()
            .tag(letter('a'), ["x"])
            .tag(letter('A'), ["y"])
            .authors([pubkey()])
            .ids([EventId::from_hex(ID_A).unwrap()])
            .kinds([Kind::new(3), Kind::new(1)])
            .limit(2)
            .search("s")
            .since(Timestamp::from_secs(4))
            .until(Timestamp::from_secs(5));
        assert_eq!(
            filter.canonical_json(),
            alloc::format!(
                "{{\"#A\":[\"y\"],\"#a\":[\"x\"],\"authors\":[\"{PK}\"],\"ids\":[\"{ID_A}\"],\"kinds\":[1,3],\"limit\":2,\"search\":\"s\",\"since\":4,\"until\":5}}"
            )
        );
        assert_eq!(
            serde_json::to_string(&filter).unwrap(),
            filter.canonical_json()
        );
    }

    #[test]
    fn canonical_json_sorts_tag_values_by_utf16() {
        // UTF-16 order: "z" (0x007A) < "😀" (0xD83D) < "\u{FFFD}" (0xFFFD);
        // UTF-8 order would put "\u{FFFD}" before "😀".
        let filter = Filter::new().tag(letter('t'), ["\u{FFFD}", "😀", "z"]);
        assert_eq!(
            filter.canonical_json(),
            "{\"#t\":[\"z\",\"😀\",\"\u{FFFD}\"]}"
        );
    }

    #[test]
    fn canonical_json_omits_none_and_keeps_empty_sets() {
        assert_eq!(Filter::new().canonical_json(), "{}");
        assert_eq!(Filter::new().ids([]).canonical_json(), "{\"ids\":[]}");
        assert_eq!(
            Filter::new()
                .tag(letter('t'), Vec::<String>::new())
                .canonical_json(),
            "{\"#t\":[]}"
        );
    }

    #[test]
    fn deserialize_accepts_wire_rules() {
        let filter: Filter = serde_json::from_value(json!({
            "ids": [ID_A.to_uppercase()],
            "authors": [PK.to_uppercase()],
            "kinds": [1, 0],
            "since": 5,
            "until": 9,
            "limit": 3,
            "search": "q",
            "#e": [ID_A.to_uppercase()],
            "#custom": ["dropped"],
            "#9": ["dropped"],
            "unknown": { "kept": false }
        }))
        .unwrap();
        assert_eq!(
            filter
                .ids_set()
                .map(|s| s.contains(&EventId::from_hex(ID_A).unwrap())),
            Some(true)
        );
        assert_eq!(
            filter.authors_set().map(|s| s.contains(&pubkey())),
            Some(true)
        );
        assert_eq!(filter.kinds_set().map(BTreeSet::len), Some(2));
        assert_eq!(
            filter.tag_values(letter('e')).map(|s| s.contains(ID_A)),
            Some(true)
        );
        assert_eq!(filter.tag_letters().count(), 1);
        assert_eq!(filter.since_bound(), Some(Timestamp::from_secs(5)));
        assert_eq!(filter.limit_value(), Some(3));
        assert_eq!(filter.search_query(), Some("q"));
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
            Filter::new().tag(letter('t'), ["\u{FFFD}"]),
            Filter::new().tag(letter('t'), ["😀"]),
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
    fn fingerprint_dedupes_semantically_identical_filters() {
        let lower = Filter::new().ids([EventId::from_hex(ID_A).unwrap()]);
        let mixed: Filter = serde_json::from_value(json!({"ids": [ID_A.to_uppercase()]})).unwrap();
        assert_eq!(
            fingerprint(core::slice::from_ref(&lower)),
            fingerprint(&[mixed])
        );
        assert_eq!(
            fingerprint(&[lower]),
            "[{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}]"
        );
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
            .tag(letter('t'), ["gm"])
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
