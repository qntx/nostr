//! Sans-IO NIP-65/NIP-17 routing: an LRU over `PublicKey -> Routes`
//! that turns filters into per-relay plans. The `Client` wraps it in a
//! mutex; callers driving [`crate::pool::RelayPool`] directly use it
//! as-is.

use std::collections::{BTreeMap, HashSet};

use hashlink::LruCache;
use nk_core::nips::nip17::DmRelayList;
use nk_core::nips::nip65::RelayList;
use nk_core::{Event, EventId, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag, Timestamp};

/// The `p` tag letter, const-evaluated (`'p'` is always a valid letter).
pub(crate) const P_TAG: SingleLetterTag = match SingleLetterTag::new('p') {
    Some(t) => t,
    None => unreachable!(),
};

/// Tunables for [`Gossip`]. `#[non_exhaustive]` — construct via
/// `Default::default()` and mutate the fields:
///
/// ```
/// let mut opts = nk::gossip::GossipOptions::default();
/// opts.max_relays_per_pubkey = 2;
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct GossipOptions {
    /// Cap on tracked pubkeys — the LRU evicts the least-recently used.
    pub max_pubkeys: usize,
    /// Relays kept per list, in list order.
    pub max_relays_per_pubkey: usize,
    /// Keep insecure `ws://` URLs from third-party lists. Default
    /// `false`: gossip-sourced relays are untrusted, so plain `ws://`
    /// (except `.onion`) is dropped before dedupe — the key falls back
    /// to the caller's own relays. TS `isInsecureRelayUrl`.
    pub allow_insecure: bool,
}

impl Default for GossipOptions {
    fn default() -> Self {
        Self {
            max_pubkeys: 10_000,
            max_relays_per_pubkey: 4,
            allow_insecure: false,
        }
    }
}

/// A list's version — NIP-01 replaceable ordering: `created_at` first,
/// then the lower `id` wins a tie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Version {
    created_at: Timestamp,
    id: EventId,
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    /// `self > other` when `self` is the newer list.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.created_at
            .cmp(&other.created_at)
            // Lower id wins at equal timestamps.
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// One pubkey's relay routing — the 10002 outbox/inbox list plus the
/// 10050 DM list, each with its own version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routes {
    write: Vec<RelayUrl>,
    read: Vec<RelayUrl>,
    dm: Vec<RelayUrl>,
    relay_list: Option<Version>,
    dm_list: Option<Version>,
}

impl Routes {
    /// Where this pubkey publishes (their outbox).
    #[must_use]
    pub fn write(&self) -> &[RelayUrl] {
        &self.write
    }

    /// Where this pubkey reads (their inbox).
    #[must_use]
    pub fn read(&self) -> &[RelayUrl] {
        &self.read
    }

    /// Where this pubkey receives DMs (kind 10050).
    #[must_use]
    pub fn dm(&self) -> &[RelayUrl] {
        &self.dm
    }
}

/// A `route` result: per-relay filter plans plus the leftover filters
/// that no relay claimed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Routing {
    /// Filters per relay — one `REQ` per relay.
    pub per_relay: BTreeMap<RelayUrl, Vec<Filter>>,
    /// Filters nobody claimed — send to fallback relays or drop.
    pub remainder: Vec<Filter>,
}

/// `route(..)` errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A remainder exists but no fallback relays were given.
    #[error("unrouted filters with no fallback relays")]
    NoFallback,
}

impl Routing {
    /// Merges the remainder into every fallback relay's plan, keeping
    /// the routed relays' filters untouched.
    ///
    /// # Errors
    ///
    /// [`Error::NoFallback`] when `remainder` is non-empty and
    /// `fallback` is empty.
    pub fn with_fallback(
        self,
        fallback: &[RelayUrl],
    ) -> Result<BTreeMap<RelayUrl, Vec<Filter>>, Error> {
        let Self {
            mut per_relay,
            remainder,
        } = self;
        if remainder.is_empty() {
            return Ok(per_relay);
        }
        if fallback.is_empty() {
            return Err(Error::NoFallback);
        }
        let mut seen = HashSet::with_capacity(fallback.len());
        for url in fallback {
            if !seen.insert(url.clone()) {
                continue;
            }
            per_relay
                .entry(url.clone())
                .or_default()
                .extend(remainder.iter().cloned());
        }
        Ok(per_relay)
    }
}

/// The routing table: an LRU over `PublicKey -> Routes`, sized by
/// [`GossipOptions`].
pub struct Gossip {
    routes: LruCache<PublicKey, Routes>,
    max_relays: usize,
    allow_insecure: bool,
}

impl Gossip {
    /// An empty table sized by `options`.
    #[must_use]
    pub fn new(options: GossipOptions) -> Self {
        let GossipOptions {
            max_pubkeys,
            max_relays_per_pubkey,
            allow_insecure,
        } = options;
        Self {
            routes: LruCache::new(max_pubkeys),
            max_relays: max_relays_per_pubkey,
            allow_insecure,
        }
    }

    /// Absorbs a relay-list event; `false` when the kind isn't a list
    /// kind, the list is unparseable, or the stored version is already
    /// newer. Non-list and unparseable events never create an entry —
    /// the caller feeds every event, so routing noise must not evict
    /// real routes. The 10002 and 10050 tracks never clobber each other.
    pub fn ingest(&mut self, event: &Event) -> bool {
        let version = Version {
            created_at: event.created_at(),
            id: event.id(),
        };
        let pubkey = event.pubkey();
        let allow = self.allow_insecure;
        let keep = move |u: &&RelayUrl| allow || secure(u);
        // Version check and parse come before any write: inserting into a
        // full LRU evicts, so only a winning, parseable list may touch it.
        let stored = self.routes.peek(&pubkey);
        match event.kind() {
            Kind::RELAY_LIST => {
                if stored.is_some_and(|r| r.relay_list.is_some_and(|v| v >= version)) {
                    return false;
                }
                let Ok(list) = RelayList::try_from(event) else {
                    return false;
                };
                let routes = self.routes.entry(pubkey).or_insert_with(Routes::default);
                routes.write = take(list.write().filter(keep).cloned(), self.max_relays);
                routes.read = take(list.read().filter(keep).cloned(), self.max_relays);
                routes.relay_list = Some(version);
                true
            }
            Kind::DIRECT_MESSAGE_RELAYS_LIST => {
                if stored.is_some_and(|r| r.dm_list.is_some_and(|v| v >= version)) {
                    return false;
                }
                let Ok(list) = DmRelayList::try_from(event) else {
                    return false;
                };
                let routes = self.routes.entry(pubkey).or_insert_with(Routes::default);
                routes.dm = take(list.relays().iter().filter(keep).cloned(), self.max_relays);
                routes.dm_list = Some(version);
                true
            }
            _ => false,
        }
    }

    /// The stored routes for `pubkey`, refreshing recency.
    pub fn routes(&mut self, pubkey: &PublicKey) -> Option<&Routes> {
        self.routes.get(pubkey)
    }

    /// Forgets `pubkey`; `false` when it wasn't tracked.
    pub fn remove(&mut self, pubkey: &PublicKey) -> bool {
        self.routes.remove(pubkey).is_some()
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// Tracked pubkeys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The per-relay filter plan for `filters`.
    ///
    /// Authors narrow by outbox (write) relays; `#p` narrows by inbox
    /// (read) relays; a filter with both goes whole to the union of the
    /// routed relays, and is the remainder when any key is unrouted.
    /// Everything else is the remainder as-is.
    #[must_use]
    pub fn route(&mut self, filters: &[Filter]) -> Routing {
        let mut routing = Routing::default();
        for filter in filters {
            self.route_one(filter.clone(), &mut routing);
        }
        routing
    }

    /// One filter → per-relay plans + remainder.
    fn route_one(&mut self, filter: Filter, routing: &mut Routing) {
        let authors: Vec<PublicKey> = filter.get_authors().unwrap_or(&[]).to_vec();
        let p_hex: Vec<String> = filter
            .tag_values(P_TAG)
            .unwrap_or(&[])
            .iter()
            .map(|s| (**s).to_owned())
            .collect();
        let has_authors = !authors.is_empty();
        let has_p = !p_hex.is_empty();
        match (has_authors, has_p) {
            (true, false) => self.narrow_authors(filter, &authors, routing),
            (false, true) => self.narrow_p(filter, &p_hex, routing),
            (true, true) => self.broad(filter, &authors, &p_hex, routing),
            (false, false) => routing.remainder.push(filter),
        }
    }

    /// Authors narrowed to their write relays — one filter per relay
    /// carrying every author routed there (relays cap filters per REQ).
    /// Unrouted authors land in a narrowed remainder (the original
    /// filter when nothing routed).
    fn narrow_authors(&mut self, filter: Filter, authors: &[PublicKey], routing: &mut Routing) {
        let mut unrouted: Vec<PublicKey> = Vec::new();
        let mut per_relay: BTreeMap<RelayUrl, Vec<PublicKey>> = BTreeMap::new();
        for &key in authors {
            let relays = self.routes.get(&key).map_or(&[][..], |r| r.write());
            if relays.is_empty() {
                unrouted.push(key);
                continue;
            }
            for relay in relays {
                per_relay.entry(relay.clone()).or_default().push(key);
            }
        }
        let any_routed = !per_relay.is_empty();
        for (relay, group) in per_relay {
            routing
                .per_relay
                .entry(relay)
                .or_default()
                .push(filter.clone().authors(group));
        }
        if !unrouted.is_empty() {
            routing.remainder.push(if any_routed {
                filter.authors(unrouted)
            } else {
                filter
            });
        }
    }

    /// `#p` values narrowed to their read relays — one filter per relay
    /// carrying every routed value. Unrouted values (unparseable or
    /// without routes) land in a narrowed remainder.
    fn narrow_p(&mut self, filter: Filter, values: &[String], routing: &mut Routing) {
        let mut unrouted: Vec<String> = Vec::new();
        let mut per_relay: BTreeMap<RelayUrl, Vec<String>> = BTreeMap::new();
        for value in values {
            let relays = PublicKey::from_wire_hex(value)
                .ok()
                .and_then(|key| self.routes.get(&key).map(Routes::read))
                .unwrap_or_default();
            if relays.is_empty() {
                unrouted.push(value.clone());
                continue;
            }
            for relay in relays {
                per_relay
                    .entry(relay.clone())
                    .or_default()
                    .push(value.clone());
            }
        }
        let any_routed = !per_relay.is_empty();
        for (relay, group) in per_relay {
            routing
                .per_relay
                .entry(relay)
                .or_default()
                .push(filter.clone().tag(P_TAG, group));
        }
        if !unrouted.is_empty() {
            routing.remainder.push(if any_routed {
                filter.tag(P_TAG, unrouted)
            } else {
                filter
            });
        }
    }

    /// Both authors and `#p`: the whole filter goes to every routed
    /// relay; any unrouted key also makes it the remainder.
    fn broad(
        &mut self,
        filter: Filter,
        authors: &[PublicKey],
        p_hex: &[String],
        routing: &mut Routing,
    ) {
        let mut relays = HashSet::new();
        let mut any_unrouted = false;
        for &key in authors {
            let hit = self.union_relays(&key);
            if hit.is_empty() {
                any_unrouted = true;
            }
            relays.extend(hit);
        }
        for value in p_hex {
            let hit = PublicKey::from_wire_hex(value)
                .ok()
                .map_or_else(Vec::new, |key| self.union_relays(&key));
            if hit.is_empty() {
                any_unrouted = true;
            }
            relays.extend(hit);
        }
        for url in relays {
            routing
                .per_relay
                .entry(url)
                .or_default()
                .push(filter.clone());
        }
        if any_unrouted {
            routing.remainder.push(filter);
        }
    }

    /// Write + read relays for `key` (empty when unrouted).
    fn union_relays(&mut self, key: &PublicKey) -> Vec<RelayUrl> {
        self.routes
            .get(key)
            .map(|r| r.write.iter().chain(r.read.iter()).cloned().collect())
            .unwrap_or_default()
    }

    /// The relays to publish `event` to: the author's outbox, each `p`
    /// tag's inbox, then up to 5 `e`/`a` relay hints — deduplicated, in
    /// that order.
    #[must_use]
    pub fn publish_relays(&mut self, event: &Event) -> Vec<RelayUrl> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut push = |url: &RelayUrl| -> bool {
            if !seen.insert(url.clone()) {
                return false;
            }
            out.push(url.clone());
            true
        };
        if let Some(r) = self.routes.get(&event.pubkey()) {
            for url in r.write() {
                push(url);
            }
        }
        for tag in event.tags() {
            if tag.name() != "p" {
                continue;
            }
            let Some(hex) = tag.value() else {
                continue;
            };
            let Ok(pubkey) = PublicKey::from_wire_hex(hex) else {
                continue;
            };
            let Some(r) = self.routes.get(&pubkey) else {
                continue;
            };
            for url in r.read() {
                push(url);
            }
        }
        let mut hints = 0;
        for tag in event.tags() {
            if hints >= 5 {
                break;
            }
            if !matches!(tag.name(), "e" | "a") {
                continue;
            }
            let items = tag.as_slice();
            let Some(hint) = items.get(2) else {
                continue;
            };
            let Ok(url) = RelayUrl::parse(hint) else {
                continue;
            };
            // A hint counts only when it adds a new URL — duplicates of
            // the outbox/inbox or earlier hints don't use a slot.
            if push(&url) {
                hints += 1;
            }
        }
        out
    }
}

/// Insecure means `ws://` on a non-`.onion` host — the TS
/// `isInsecureRelayUrl` rule (every `RelayUrl` normalizes to `ws://` or
/// `wss://`, so only `ws` needs the check).
fn secure(url: &RelayUrl) -> bool {
    if !url.as_str().starts_with("ws://") {
        return true;
    }
    let Ok(parsed) = url::Url::parse(url.as_str()) else {
        return true;
    };
    parsed
        .host_str()
        .is_some_and(|host| host.to_ascii_lowercase().ends_with(".onion"))
}

/// First `n` unique relays in list order — dedup before truncation so
/// duplicates can't burn slots.
fn take(iter: impl Iterator<Item = RelayUrl>, n: usize) -> Vec<RelayUrl> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for url in iter {
        if out.len() >= n {
            break;
        }
        if seen.insert(url.clone()) {
            out.push(url);
        }
    }
    out
}

impl std::fmt::Debug for Gossip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gossip")
            .field("pubkeys", &self.routes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use nk_core::nips::nip65::{RelayList, RelayListItem, RelayMarker};
    use nk_core::rand_core::UnwrapErr;
    use nk_core::{EventBuilder, Keys, Kind, SecretKey, SysRng, Tag};

    use super::*;

    fn keys(n: u8) -> Keys {
        Keys::new(SecretKey::from_bytes([n; 32]).expect("key"))
    }

    fn sign(k: &Keys, builder: EventBuilder, at: Timestamp) -> Event {
        k.sign_event(builder.build_at(k.public_key(), at), &mut UnwrapErr(SysRng))
            .expect("sign")
    }

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).expect("url")
    }

    /// A kind-10002 signed by `k` with `(write_urls, read_urls)`.
    fn list_10002(k: &Keys, at: Timestamp, write: &[&str], read: &[&str]) -> Event {
        let items: Vec<RelayListItem> = write
            .iter()
            .map(|u| RelayListItem {
                url: url(u),
                marker: RelayMarker::Write,
            })
            .chain(read.iter().map(|u| RelayListItem {
                url: url(u),
                marker: RelayMarker::Read,
            }))
            .collect();
        sign(k, EventBuilder::from(RelayList::new(items)), at)
    }

    fn list_10050(k: &Keys, at: Timestamp, urls: &[&str]) -> Event {
        sign(
            k,
            EventBuilder::from(DmRelayList::from_urls(urls).expect("list")),
            at,
        )
    }

    const T1: Timestamp = Timestamp::from_secs(1_000);
    const T2: Timestamp = Timestamp::from_secs(2_000);

    #[test]
    fn ingest_tracks_write_read_dm() {
        let k = keys(1);
        let mut g = Gossip::new(GossipOptions::default());
        assert!(g.ingest(&list_10002(
            &k,
            T1,
            &["wss://w1", "wss://w2"],
            &["wss://r1"]
        )));
        assert!(g.ingest(&list_10050(&k, T1, &["wss://d1"])));
        let r = g.routes(&k.public_key()).expect("routes");
        assert_eq!(r.write(), &[url("wss://w1"), url("wss://w2")]);
        assert_eq!(r.read(), &[url("wss://r1")]);
        assert_eq!(r.dm(), &[url("wss://d1")]);
    }

    #[test]
    fn ingest_ignores_older_list() {
        let k = keys(2);
        let mut g = Gossip::new(GossipOptions::default());
        assert!(g.ingest(&list_10002(&k, T2, &["wss://new"], &[])));
        // Older list loses.
        assert!(!g.ingest(&list_10002(&k, T1, &["wss://old"], &[])));
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("wss://new")]
        );
    }

    #[test]
    fn ingest_equal_timestamp_lower_id_wins() {
        // Two lists at the same timestamp; the lower event id is newer.
        let k = keys(3);
        let mut g = Gossip::new(GossipOptions::default());
        let hi = list_10002(&k, T1, &["wss://hi"], &[]);
        let lo = list_10002(&k, T1, &["wss://lo"], &[]);
        let (older, newer) = if lo.id() < hi.id() {
            (hi, lo)
        } else {
            (lo, hi)
        };
        assert!(g.ingest(&newer));
        assert!(!g.ingest(&older));
    }

    #[test]
    fn ingest_10050_never_clobbers_10002() {
        let k = keys(4);
        let mut g = Gossip::new(GossipOptions::default());
        assert!(g.ingest(&list_10002(&k, T1, &["wss://w1"], &["wss://r1"])));
        assert!(g.ingest(&list_10050(&k, T1, &["wss://d1"])));
        let r = g.routes(&k.public_key()).expect("routes");
        assert_eq!(r.write(), &[url("wss://w1")]);
        assert_eq!(r.read(), &[url("wss://r1")]);
        assert_eq!(r.dm(), &[url("wss://d1")]);
    }

    #[test]
    fn ingest_truncates_to_max_relays() {
        let k = keys(5);
        let mut g = Gossip::new(GossipOptions {
            max_pubkeys: 10,
            max_relays_per_pubkey: 2,
            allow_insecure: false,
        });
        assert!(g.ingest(&list_10002(
            &k,
            T1,
            &["wss://a", "wss://b", "wss://c", "wss://d"],
            &[],
        )));
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("wss://a"), url("wss://b")]
        );
    }

    #[test]
    fn route_authors_narrows_per_relay() {
        let k1 = keys(6);
        let k2 = keys(7);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k1, T1, &["wss://a", "wss://b"], &[]));
        let r = g.route(&[Filter::new().authors([k1.public_key(), k2.public_key()])]);
        // k1 narrows into both write relays; k2 is unrouted.
        let got = r.per_relay[&url("wss://a")][0]
            .get_authors()
            .expect("authors");
        assert_eq!(got, &[k1.public_key()]);
        assert_eq!(r.per_relay.len(), 2, "a and b");
        let rem = r.remainder[0].get_authors().expect("remainder authors");
        assert_eq!(rem, &[k2.public_key()]);
    }

    #[test]
    fn route_p_only_narrows_read_relays() {
        let k = keys(8);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k, T1, &[], &["wss://r1"]));
        let filter = Filter::new().tag(
            SingleLetterTag::new('p').expect("p"),
            [k.public_key().to_hex()],
        );
        let r = g.route(&[filter]);
        let got = r.per_relay[&url("wss://r1")][0]
            .tag_values(SingleLetterTag::new('p').expect("p"))
            .expect("p");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref(), k.public_key().to_hex().as_str());
        assert_eq!(r.remainder, vec![]);
    }

    #[test]
    fn route_both_unions_write_and_read() {
        let k = keys(9);
        let other = keys(10);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k, T1, &["wss://w1"], &[]));
        g.ingest(&list_10002(&other, T1, &[], &["wss://r1"]));
        let filter = Filter::new().authors([k.public_key()]).tag(
            SingleLetterTag::new('p').expect("p"),
            [other.public_key().to_hex()],
        );
        let r = g.route(&[filter]);
        assert!(r.per_relay.contains_key(&url("wss://w1")));
        assert!(r.per_relay.contains_key(&url("wss://r1")));
        assert_eq!(r.remainder, vec![]);
    }

    #[test]
    fn route_both_remainder_on_unrouted_key() {
        let k = keys(11);
        let other = keys(12);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k, T1, &["wss://w1"], &[]));
        let filter = Filter::new().authors([k.public_key()]).tag(
            SingleLetterTag::new('p').expect("p"),
            [other.public_key().to_hex()],
        );
        let r = g.route(&[filter]);
        assert!(r.per_relay.contains_key(&url("wss://w1")));
        assert_eq!(r.remainder.len(), 1, "unrouted p key -> whole filter");
    }

    #[test]
    fn route_neither_is_remainder() {
        let mut g = Gossip::new(GossipOptions::default());
        let filter = Filter::new().kinds([Kind::new(1)]);
        let r = g.route(std::slice::from_ref(&filter));
        assert!(r.per_relay.is_empty());
        assert_eq!(r.remainder, vec![filter]);
    }

    #[test]
    fn route_merges_filters_for_same_relay() {
        let k1 = keys(13);
        let k2 = keys(14);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k1, T1, &["wss://a"], &[]));
        g.ingest(&list_10002(&k2, T1, &["wss://a"], &[]));
        let r = g.route(&[Filter::new().authors([k1.public_key(), k2.public_key()])]);
        let filters = &r.per_relay[&url("wss://a")];
        assert_eq!(filters.len(), 1, "one REQ per relay");
        let mut want = [k1.public_key(), k2.public_key()];
        want.sort_unstable();
        assert_eq!(filters[0].get_authors().expect("authors"), &want[..]);
    }

    #[test]
    fn route_invalid_p_is_unrouted() {
        let mut g = Gossip::new(GossipOptions::default());
        let filter = Filter::new().tag(SingleLetterTag::new('p').expect("p"), ["nothex"]);
        let r = g.route(&[filter]);
        assert!(r.per_relay.is_empty());
        assert_eq!(r.remainder.len(), 1);
    }

    #[test]
    fn with_fallback_merges_dedupes() {
        let mut routing = Routing::default();
        let a = url("wss://a");
        routing.per_relay.insert(a.clone(), vec![Filter::new()]);
        routing.remainder.push(Filter::new().kinds([Kind::new(7)]));
        let out = routing
            .with_fallback(&[url("wss://b"), url("wss://b")])
            .expect("fallback");
        assert_eq!(out[&url("wss://b")].len(), 1, "deduped fallback");
        assert_eq!(out[&a].len(), 1);
    }

    #[test]
    fn with_fallback_errors_on_empty() {
        let routing = Routing {
            remainder: vec![Filter::new()],
            ..Routing::default()
        };
        assert!(matches!(routing.with_fallback(&[]), Err(Error::NoFallback)));
    }

    #[test]
    fn publish_relays_orders_and_caps_hints() {
        let author = keys(15);
        let pkey = keys(16);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&author, T1, &["wss://w1", "wss://w2"], &[]));
        g.ingest(&list_10002(&pkey, T1, &[], &["wss://r1"]));
        // 6 hints — only the first 5 count.
        let mut tags = vec![Tag::public_key(pkey.public_key(), None, None)];
        for i in 1..=6 {
            tags.push(Tag::custom(
                "e",
                [format!("{i:064}"), format!("wss://h{i}")],
            ));
        }
        let ev = sign(
            &author,
            EventBuilder::new(Kind::new(1), "post").tags(tags),
            T2,
        );
        let got = g.publish_relays(&ev);
        assert_eq!(
            got,
            vec![
                url("wss://w1"),
                url("wss://w2"),
                url("wss://r1"),
                url("wss://h1"),
                url("wss://h2"),
                url("wss://h3"),
                url("wss://h4"),
                url("wss://h5"),
            ],
            "author outbox, p inbox, 5 hints"
        );
    }

    #[test]
    fn insecure_ws_url_is_dropped() {
        let k = keys(26);
        let mut g = Gossip::new(GossipOptions::default());
        assert!(g.ingest(&list_10002(&k, T1, &["ws://127.0.0.1:7777"], &[])));
        let r = g.routes(&k.public_key()).expect("routes");
        assert!(r.write().is_empty(), "ws:// dropped -> empty routes");
        let routing = g.route(&[Filter::new().authors([k.public_key()])]);
        assert!(routing.per_relay.is_empty());
        assert_eq!(routing.remainder.len(), 1, "unrouted key -> remainder");
    }

    #[test]
    fn onion_ws_url_is_kept() {
        let k = keys(27);
        let mut g = Gossip::new(GossipOptions::default());
        assert!(g.ingest(&list_10002(&k, T1, &["ws://abcdefghij.onion"], &[])));
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("ws://abcdefghij.onion")]
        );
    }

    #[test]
    fn allow_insecure_keeps_ws() {
        let k = keys(28);
        let mut g = Gossip::new(GossipOptions {
            allow_insecure: true,
            ..GossipOptions::default()
        });
        assert!(g.ingest(&list_10002(&k, T1, &["ws://127.0.0.1:7777"], &[])));
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("ws://127.0.0.1:7777")]
        );
    }

    #[test]
    fn remove_clear_len() {
        let k = keys(17);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&k, T1, &["wss://a"], &[]));
        assert_eq!(g.len(), 1);
        assert!(g.remove(&k.public_key()));
        assert!(!g.remove(&k.public_key()));
        assert!(g.is_empty());
        g.ingest(&list_10002(&k, T1, &["wss://a"], &[]));
        g.clear();
        assert!(g.is_empty());
    }

    #[test]
    fn non_list_events_never_create_entries() {
        let k = keys(18);
        let mut g = Gossip::new(GossipOptions {
            max_pubkeys: 2,
            max_relays_per_pubkey: 4,
            allow_insecure: true,
        });
        g.ingest(&list_10002(&k, T1, &["wss://keep"], &[]));
        for i in 26..126u8 {
            let other = keys(i);
            let noise = sign(&other, EventBuilder::new(Kind::new(1), "noise"), T2);
            assert!(!g.ingest(&noise));
        }
        assert_eq!(g.len(), 1, "only the list entry survives");
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("wss://keep")]
        );
    }

    #[test]
    fn authors_sharing_a_relay_share_one_filter() {
        let k1 = keys(19);
        let k2 = keys(20);
        let k3 = keys(21);
        let mut g = Gossip::new(GossipOptions::default());
        for k in [&k1, &k2, &k3] {
            g.ingest(&list_10002(k, T1, &["wss://shared"], &[]));
        }
        let r =
            g.route(&[Filter::new().authors([k1.public_key(), k2.public_key(), k3.public_key()])]);
        let filters = &r.per_relay[&url("wss://shared")];
        assert_eq!(filters.len(), 1, "one REQ per relay");
        let mut want = [k1.public_key(), k2.public_key(), k3.public_key()];
        want.sort_unstable();
        assert_eq!(filters[0].get_authors().expect("authors"), &want[..]);
        assert_eq!(r.remainder, vec![]);
    }

    #[test]
    fn dedup_reclaims_slot() {
        let k = keys(23);
        let mut g = Gossip::new(GossipOptions {
            max_pubkeys: 10,
            max_relays_per_pubkey: 3,
            allow_insecure: false,
        });
        // With truncate-first: [a,a,b] -> dedup [a,b]. Dedup-first: [a,b,c].
        assert!(g.ingest(&list_10002(
            &k,
            T1,
            &["wss://a", "wss://a", "wss://b", "wss://c"],
            &[],
        )));
        assert_eq!(
            g.routes(&k.public_key()).expect("routes").write(),
            &[url("wss://a"), url("wss://b"), url("wss://c")],
            "c reclaims the slot the duplicate burned"
        );
    }

    #[test]
    fn duplicate_hint_does_not_use_a_slot() {
        let author = keys(24);
        let pkey = keys(25);
        let mut g = Gossip::new(GossipOptions::default());
        g.ingest(&list_10002(&author, T1, &["wss://w1"], &[]));
        g.ingest(&list_10002(&pkey, T1, &[], &["wss://r1"]));
        // 6 hint tags but hint #1 duplicates the outbox — 5 unique remain.
        let mut tags = vec![Tag::public_key(pkey.public_key(), None, None)];
        tags.push(Tag::custom("e", ["00".repeat(32), "wss://w1".to_owned()]));
        for i in 1..=5 {
            tags.push(Tag::custom(
                "e",
                [format!("{i:064}"), format!("wss://h{i}")],
            ));
        }
        let ev = sign(
            &author,
            EventBuilder::new(Kind::new(1), "post").tags(tags),
            T2,
        );
        let got = g.publish_relays(&ev);
        assert_eq!(
            got,
            vec![
                url("wss://w1"),
                url("wss://r1"),
                url("wss://h1"),
                url("wss://h2"),
                url("wss://h3"),
                url("wss://h4"),
                url("wss://h5"),
            ],
            "the outbox dup frees a slot for h5"
        );
    }
}
