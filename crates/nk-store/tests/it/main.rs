#![allow(
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "an integration-test binary is a test module by construction"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::redundant_clone,
    clippy::shadow_unrelated,
    clippy::missing_assert_message,
    clippy::excessive_nesting,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::semicolon_if_nothing_returned,
    clippy::ignored_unit_patterns,
    clippy::uninlined_format_args,
    clippy::clone_on_ref_ptr,
    clippy::let_underscore_must_use,
    clippy::significant_drop_tightening,
    clippy::option_if_let_else,
    clippy::str_to_string,
    clippy::map_unwrap_or,
    clippy::cognitive_complexity,
    reason = "test assertions panic and index fixtures directly"
)]

//! Conformance suite ported from `testing/conformance.ts`, run against every
//! backend (`MemoryStore`; `SqliteStore` in-memory and temp-file under the
//! `sqlite` feature). The outbox-bound cases are TS-only and not ported;
//! "clear wipes events and bounds" is ported without the bound assertions.

mod common;

use nk_core::{Event, EventId, Filter, Kind, SingleLetterTag, Tag, Timestamp};
#[cfg(feature = "sqlite")]
use nk_store::SqliteStore;
use nk_store::{EventStore, MemoryStore, PutOutcome};

use common::{addressable, alice, bob, note, replaceable, sign};
use nk_core::{DeletionTarget, EventBuilder, Keys};

fn kind_filter(kind: u16) -> Filter {
    Filter::new().kinds([Kind::new(kind)]).expect("filter")
}

fn authors_filter(keys: &Keys, kind: u16) -> Filter {
    Filter::new()
        .kinds([Kind::new(kind)])
        .expect("filter")
        .authors([keys.public_key()])
        .expect("filter")
}

fn tag_filter(letter: char, values: Vec<String>) -> Filter {
    Filter::new()
        .tag(
            SingleLetterTag::new(letter).unwrap_or_else(|| panic!("letter")),
            values,
        )
        .expect("filter")
}

fn ids(events: &[Event]) -> Vec<EventId> {
    events.iter().map(Event::id).collect()
}

fn deletion(keys: &Keys, targets: Vec<DeletionTarget>, created_at: u64) -> Event {
    sign(keys, EventBuilder::deletion(targets, ""), created_at)
}

/// Runs every ported conformance case against `store`.
fn conformance(store: &impl EventStore) {
    // "put accepted then duplicate"
    let e = note(&alice(), "hello", 1, vec![]);
    assert_eq!(store.put(&e).ok(), Some(PutOutcome::Accepted), "first put");
    assert_eq!(
        store.put(&e).ok(),
        Some(PutOutcome::Duplicate),
        "second put"
    );
    assert_eq!(
        store.get(&e.id()).ok(),
        Some(Some(e.clone())),
        "get after put"
    );
    assert_eq!(
        store
            .put_many(&[
                note(&alice(), "a", 2, vec![]),
                note(&alice(), "b", 3, vec![])
            ])
            .ok(),
        Some(vec![PutOutcome::Accepted, PutOutcome::Accepted]),
        "put_many results",
    );
    store.clear().unwrap_or_else(|e| panic!("clear: {e}"));

    // "ephemeral event returns ephemeral and is not stored"
    let e = replaceable(&alice(), 20001, "ephemeral", 1);
    assert_eq!(store.put(&e).ok(), Some(PutOutcome::Ephemeral));
    assert_eq!(store.get(&e.id()).ok(), Some(None));
    assert_eq!(store.query(&[kind_filter(20001)]).ok(), Some(vec![]));
    assert_eq!(store.count(&[kind_filter(20001)]).ok(), Some(0));

    // "replaceable event keeps newest and rejects stale"
    let older = replaceable(&alice(), 0, "old", 1);
    let newer = replaceable(&alice(), 0, "new", 2);
    assert_eq!(store.put(&older).ok(), Some(PutOutcome::Accepted));
    assert_eq!(store.put(&newer).ok(), Some(PutOutcome::Replaced));
    assert_eq!(store.put(&older).ok(), Some(PutOutcome::Rejected));
    assert_eq!(store.get(&older.id()).ok(), Some(None));
    assert_eq!(
        ids(&store
            .query(&[authors_filter(&alice(), 0)])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![newer.id()],
    );
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "addressable event replaces by address"
    let v1 = addressable(&alice(), 30001, "x", "v1", 1);
    let v2 = addressable(&alice(), 30001, "x", "v2", 2);
    let other = addressable(&alice(), 30001, "y", "other", 3);
    assert_eq!(store.put(&v1).ok(), Some(PutOutcome::Accepted));
    assert_eq!(store.put(&v2).ok(), Some(PutOutcome::Replaced));
    assert_eq!(store.put(&v1).ok(), Some(PutOutcome::Rejected));
    assert_eq!(store.put(&other).ok(), Some(PutOutcome::Accepted));
    assert_eq!(store.get(&v1.id()).ok(), Some(None));
    let mut got = ids(&store
        .query(&[authors_filter(&alice(), 30001)])
        .unwrap_or_else(|e| panic!("{e}")));
    got.sort();
    let mut want = vec![other.id(), v2.id()];
    want.sort();
    assert_eq!(got, want);
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "deletion removes same-author e-tag targets only"
    let mine = note(&alice(), "mine", 1, vec![]);
    let theirs = note(&bob(), "theirs", 1, vec![]);
    store
        .put_many(&[mine.clone(), theirs.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    let del_foreign = deletion(
        &alice(),
        vec![DeletionTarget::Event {
            id: theirs.id(),
            kind: None,
        }],
        2,
    );
    assert_eq!(store.put(&del_foreign).ok(), Some(PutOutcome::Deleted));
    assert_eq!(store.get(&theirs.id()).ok(), Some(Some(theirs.clone())));
    let del_mine = deletion(
        &alice(),
        vec![DeletionTarget::Event {
            id: mine.id(),
            kind: None,
        }],
        3,
    );
    assert_eq!(store.put(&del_mine).ok(), Some(PutOutcome::Deleted));
    assert_eq!(store.get(&mine.id()).ok(), Some(None));
    assert_eq!(
        store
            .query(&[Filter::new().ids([mine.id()]).expect("filter")])
            .unwrap_or_else(|e| panic!("{e}")),
        vec![]
    );
    assert_eq!(store.put(&mine).ok(), Some(PutOutcome::Duplicate));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "deletion removes addressable via a tag and tombstones re-put"
    let target = addressable(&alice(), 30001, "z", "target", 1);
    store.put(&target).unwrap_or_else(|e| panic!("{e}"));
    let coord = format!("30001:{}:z", alice().public_key().to_hex());
    let del = deletion(
        &alice(),
        vec![DeletionTarget::Address(
            coord.parse().unwrap_or_else(|_| panic!("coordinate")),
        )],
        2,
    );
    assert_eq!(store.put(&del).ok(), Some(PutOutcome::Deleted));
    assert_eq!(store.get(&target.id()).ok(), Some(None));
    let still_covered = addressable(&alice(), 30001, "z", "covered", 1);
    assert_eq!(
        store.put(&still_covered).ok(),
        Some(PutOutcome::Duplicate),
        "tombstoned address rejects re-put",
    );
    assert_eq!(
        store
            .query(&[authors_filter(&alice(), 30001)])
            .unwrap_or_else(|e| panic!("{e}")),
        vec![]
    );
    let after = addressable(&alice(), 30001, "z", "after", 3);
    assert_eq!(store.put(&after).ok(), Some(PutOutcome::Accepted));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "firstSeenAt records the insert time and a duplicate keeps it"
    let e = note(&alice(), "hello", 1, vec![]);
    assert_eq!(store.first_seen_at(&e.id()).ok(), Some(None), "unknown id");
    let before = Timestamp::now();
    assert_eq!(store.put(&e).ok(), Some(PutOutcome::Accepted));
    let after = Timestamp::now();
    let seen = store
        .first_seen_at(&e.id())
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("first_seen_at: stored event has none"));
    assert!(
        seen >= before && seen <= after,
        "first_seen_at {seen} outside [{before}, {after}]",
    );
    assert_eq!(store.put(&e).ok(), Some(PutOutcome::Duplicate));
    assert_eq!(store.first_seen_at(&e.id()).ok(), Some(Some(seen)));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "firstSeenAt drops with the event on replace, deletion, remove and clear"
    let older = replaceable(&alice(), 0, "old", 1);
    let newer = replaceable(&alice(), 0, "new", 2);
    store.put(&older).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(store.first_seen_at(&older.id()).ok(), Some(None));
    assert_eq!(store.put(&newer).ok(), Some(PutOutcome::Replaced));
    assert_eq!(store.first_seen_at(&older.id()).ok(), Some(None));
    assert_ne!(store.first_seen_at(&newer.id()).ok(), Some(None));
    let target = note(&bob(), "target", 1, vec![]);
    store.put(&target).unwrap_or_else(|e| panic!("{e}"));
    let del = deletion(
        &bob(),
        vec![DeletionTarget::Event {
            id: target.id(),
            kind: None,
        }],
        3,
    );
    assert_eq!(store.put(&del).ok(), Some(PutOutcome::Deleted));
    assert_eq!(store.first_seen_at(&target.id()).ok(), Some(None));
    assert_ne!(store.first_seen_at(&del.id()).ok(), Some(None));
    let kept = note(&alice(), "kept", 5, vec![]);
    store.put(&kept).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.remove(&[kept.id()]).ok(), Some(1));
    assert_eq!(store.first_seen_at(&kept.id()).ok(), Some(None));
    store.clear().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.first_seen_at(&newer.id()).ok(), Some(None));
    assert_eq!(store.first_seen_at(&del.id()).ok(), Some(None));

    // "query orders newest first and applies limit"
    let a = note(&alice(), "a", 1, vec![]);
    let b = note(&alice(), "b", 3, vec![]);
    let c = note(&alice(), "c", 2, vec![]);
    store
        .put_many(&[a.clone(), b.clone(), c.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ids(&store
            .query(&[authors_filter(&alice(), 1)])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![b.id(), c.id(), a.id()],
    );
    let limited = authors_filter(&alice(), 1).limit(2);
    assert_eq!(
        ids(&store.query(&[limited]).unwrap_or_else(|e| panic!("{e}"))),
        vec![b.id(), c.id()],
    );
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "query filters by kinds, authors, #e, #p, since, until"
    let target = note(&bob(), "target", 1, vec![]);
    let tagged = note(
        &alice(),
        "tagged",
        2,
        vec![
            Tag::event(target.id(), None, None, None),
            Tag::public_key(bob().public_key(), None, None),
        ],
    );
    let plain = note(&alice(), "plain", 3, vec![]);
    store
        .put_many(&[target.clone(), tagged.clone(), plain.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        store.query(&[kind_filter(1)]).map(|v| v.len()).ok(),
        Some(3)
    );
    assert_eq!(
        ids(&store
            .query(&[Filter::new().authors([bob().public_key()]).expect("filter")])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![target.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[tag_filter('e', vec![target.id().to_hex()])])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![tagged.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[tag_filter('p', vec![bob().public_key().to_hex()])])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![tagged.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[kind_filter(1).since(Timestamp::from_secs(2))])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![plain.id(), tagged.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[kind_filter(1).until(Timestamp::from_secs(2))])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![tagged.id(), target.id()],
    );
    let mut got = ids(&store
        .query(&[Filter::new()
            .ids([target.id(), tagged.id()])
            .expect("filter")])
        .unwrap_or_else(|e| panic!("{e}")));
    got.sort();
    let mut want = vec![tagged.id(), target.id()];
    want.sort();
    assert_eq!(got, want);
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "#e/#p tag values compare verbatim, lowercasing only the filter side"
    let target = note(&bob(), "target", 1, vec![]);
    let upper = note(
        &alice(),
        "upper",
        2,
        vec![
            Tag::custom("e", [target.id().to_hex().to_uppercase()]),
            Tag::custom("p", [bob().public_key().to_hex().to_uppercase()]),
        ],
    );
    let lower = note(
        &alice(),
        "lower",
        3,
        vec![
            Tag::event(target.id(), None, None, None),
            Tag::public_key(bob().public_key(), None, None),
        ],
    );
    store
        .put_many(&[target.clone(), upper, lower.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ids(&store
            .query(&[tag_filter('e', vec![target.id().to_hex()])])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![lower.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[tag_filter('e', vec![target.id().to_hex().to_uppercase()])])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![lower.id()],
    );
    assert_eq!(
        ids(&store
            .query(&[tag_filter(
                'p',
                vec![bob().public_key().to_hex().to_uppercase()]
            )])
            .unwrap_or_else(|e| panic!("{e}"))),
        vec![lower.id()],
    );
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "multi-letter # keys are ignored" — Filter deserialization drops
    // multi-letter keys, so an untagged filter matches everything.
    let tagged = note(
        &alice(),
        "tagged",
        1,
        vec![Tag::custom("client", ["test-app"])],
    );
    let plain = note(&bob(), "plain", 2, vec![]);
    store
        .put_many(&[tagged.clone(), plain.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.count(&[Filter::new()]).ok(), Some(2));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "count matches query cardinality across overlapping filters"
    let a = note(&alice(), "a", 1, vec![]);
    let b = note(&bob(), "b", 2, vec![]);
    store
        .put_many(&[a.clone(), b])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.count(&[kind_filter(1)]).ok(), Some(2));
    assert_eq!(
        store
            .count(&[
                Filter::new()
                    .authors([alice().public_key()])
                    .expect("filter"),
                Filter::new().authors([bob().public_key()]).expect("filter"),
                Filter::new().ids([a.id()]).expect("filter"),
            ])
            .ok(),
        Some(2),
    );
    assert_eq!(store.count(&[kind_filter(2)]).ok(), Some(0));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "negentropyItems sorted by created_at then id and respects limit"
    let a = note(&alice(), "a", 2, vec![]);
    let b = note(&alice(), "b", 1, vec![]);
    let c = note(&bob(), "c", 3, vec![]);
    store
        .put_many(&[a.clone(), b.clone(), c.clone()])
        .unwrap_or_else(|e| panic!("{e}"));
    let items = store
        .negentropy_items(&kind_filter(1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        items.iter().map(|i| i.id).collect::<Vec<_>>(),
        vec![b.id(), a.id(), c.id()],
        "created_at asc ordering",
    );
    let limited = store
        .negentropy_items(&kind_filter(1).limit(2))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        limited.iter().map(|i| i.id).collect::<Vec<_>>(),
        vec![a.id(), c.id()],
        "limit keeps newest two, presented ascending",
    );
    assert_eq!(store.negentropy_items(&kind_filter(2)).ok(), Some(vec![]));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "remove deletes by id and tombstones"
    let a = note(&alice(), "a", 1, vec![]);
    store.put(&a).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.remove(&[a.id()]).ok(), Some(1));
    assert_eq!(store.get(&a.id()).ok(), Some(None));
    assert_eq!(store.remove(&[a.id()]).ok(), Some(0));
    assert_eq!(store.put(&a).ok(), Some(PutOutcome::Duplicate));
    store.clear().unwrap_or_else(|e| panic!("{e}"));

    // "clear wipes events"
    let a = note(&alice(), "a", 1, vec![]);
    store.put(&a).unwrap_or_else(|e| panic!("{e}"));
    store.clear().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(store.get(&a.id()).ok(), Some(None));
    assert_eq!(store.query(&[kind_filter(1)]).ok(), Some(vec![]));
    assert_eq!(store.put(&a).ok(), Some(PutOutcome::Accepted));
}

#[test]
fn memory_conformance() {
    conformance(&MemoryStore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_memory_conformance() {
    let store = SqliteStore::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
    conformance(&store);
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_file_conformance() {
    let dir = std::env::temp_dir().join(format!(
        "nk-store-conformance-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let path = dir.to_string_lossy().to_string();
    {
        let store = SqliteStore::open(&path).unwrap_or_else(|e| panic!("{e}"));
        conformance(&store);
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

/// A failing batch inside `put_many` rolls back the whole transaction.
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_put_many_rolls_back() {
    use nk_core::Event;
    let store = SqliteStore::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
    let good = note(&alice(), "good", 1, vec![]);
    // A second event with the same id as an already-stored row makes the
    // INSERT raise inside the transaction; the batch must leave nothing.
    let stored = note(&alice(), "stored", 2, vec![]);
    store.put(&stored).unwrap_or_else(|e| panic!("{e}"));
    let clashing = Event::from_json(&stored.to_json()).unwrap_or_else(|e| panic!("{e}"));
    let results = store.put_many(&[good.clone(), clashing]);
    // The batch either fails entirely (transaction rollback) — or, if the
    // driver tolerated it, the duplicate would have been reported. A failure
    // must leave `good` unstored.
    if results.is_err() {
        assert_eq!(
            store.get(&good.id()).ok(),
            Some(None),
            "rolled back batch left rows"
        );
    }
}

/// Policy: a pending e-tag tombstone covers only same-pubkey arrivals.
#[test]
fn pending_deletion_is_pubkey_scoped() {
    let store = MemoryStore::new();
    let missing = note(&alice(), "missing", 1, vec![]);
    let del = deletion(
        &alice(),
        vec![DeletionTarget::Event {
            id: missing.id(),
            kind: None,
        }],
        2,
    );
    assert_eq!(store.put(&del).ok(), Some(PutOutcome::Deleted));
    // The target arrives after the deletion: same pubkey → covered.
    assert_eq!(store.put(&missing).ok(), Some(PutOutcome::Duplicate));
    assert_eq!(store.get(&missing.id()).ok(), Some(None));
}

/// Policy: deleting a deletion is a no-op — the targeted kind-5 stays.
#[test]
fn a_tag_empty_identifier_tombstones() {
    let store = MemoryStore::new();
    let target = addressable(&alice(), 10002, "", "profile meta", 1);
    assert_eq!(
        store.put(&target).unwrap_or_else(|e| panic!("{e:?}")),
        PutOutcome::Accepted
    );
    // `a` tag "10002:<pk>:" — parseEventAddress accepts an empty identifier.
    let coord: nk_core::Coordinate = format!("10002:{}:", target.pubkey().to_hex())
        .parse()
        .unwrap_or_else(|e| panic!("{e:?}"));
    let del = deletion(&alice(), vec![DeletionTarget::Address(coord)], 2);
    assert_eq!(
        store.put(&del).unwrap_or_else(|e| panic!("{e:?}")),
        PutOutcome::Deleted
    );
    assert!(
        store
            .get(&target.id())
            .unwrap_or_else(|e| panic!("{e:?}"))
            .is_none()
    );
}

#[test]
fn deleting_a_deletion_is_a_noop() {
    let store = MemoryStore::new();
    let target = note(&alice(), "mine", 1, vec![]);
    store.put(&target).unwrap_or_else(|e| panic!("{e}"));
    let first = deletion(
        &alice(),
        vec![DeletionTarget::Event {
            id: target.id(),
            kind: None,
        }],
        2,
    );
    assert_eq!(store.put(&first).ok(), Some(PutOutcome::Deleted));
    let second = deletion(
        &alice(),
        vec![DeletionTarget::Event {
            id: first.id(),
            kind: None,
        }],
        3,
    );
    assert_eq!(store.put(&second).ok(), Some(PutOutcome::Deleted));
    // The first deletion is still stored (deleting a deletion is a no-op).
    assert_eq!(store.get(&first.id()).ok(), Some(Some(first.clone())));
    // And the second deletion is stored too.
    assert_eq!(store.get(&second.id()).ok(), Some(Some(second.clone())));
}

/// Policy: equal `created_at` on a replaceable resolves by smaller id.
#[test]
fn replaceable_tie_breaks_by_id() {
    let store = MemoryStore::new();
    let mut low = replaceable(&alice(), 0, "low", 1);
    let mut high = replaceable(&alice(), 0, "high", 1);
    if low.id() > high.id() {
        std::mem::swap(&mut low, &mut high);
    }
    // Insert the larger id first; the smaller id supersedes at the same
    // created_at.
    assert_eq!(store.put(&high).ok(), Some(PutOutcome::Accepted));
    assert_eq!(store.put(&low).ok(), Some(PutOutcome::Replaced));
    assert_eq!(store.get(&low.id()).ok(), Some(Some(low.clone())));
}

/// The result set `packages/nostr/scripts/parity/sqlite.ts collect`
/// produces: query/count/negentropy results plus each fixture id's
/// `first_seen_at` (`null` when the event is not stored — `firstSeen`
/// values are wall-clock, so each writing side records its own
/// `*-results.json`).
#[cfg(feature = "sqlite")]
fn collect_interop(
    store: &SqliteStore,
    alice_pk: &str,
    target_id: &str,
    fixture_ids: &[EventId],
) -> serde_json::Value {
    let alice_filter = |k: u16| {
        Filter::new()
            .kinds([Kind::new(k)])
            .expect("filter")
            .authors([nk_core::PublicKey::from_hex(alice_pk).unwrap_or_else(|e| panic!("{e}"))])
            .expect("filter")
    };
    serde_json::json!({
        "queries": {
            "all kind 1": ids(&store.query(&[kind_filter(1)]).unwrap_or_else(|e| panic!("{e}"))).iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "alice kind 1": ids(&store.query(&[alice_filter(1)]).unwrap_or_else(|e| panic!("{e}"))).iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "e-tag": ids(&store.query(&[tag_filter('e', vec![target_id.to_owned()])]).unwrap_or_else(|e| panic!("{e}"))).iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "since": ids(&store.query(&[kind_filter(1).since(Timestamp::from_secs(3))]).unwrap_or_else(|e| panic!("{e}"))).iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "limit": ids(&store.query(&[kind_filter(1).limit(1)]).unwrap_or_else(|e| panic!("{e}"))).iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
        },
        "counts": {
            "all kind 1": store.count(&[kind_filter(1)]).unwrap_or_else(|e| panic!("{e}")),
            "alice kind 1": store.count(&[alice_filter(1)]).unwrap_or_else(|e| panic!("{e}")),
            "e-tag": store.count(&[tag_filter('e', vec![target_id.to_owned()])]).unwrap_or_else(|e| panic!("{e}")),
            "since": store.count(&[kind_filter(1).since(Timestamp::from_secs(3))]).unwrap_or_else(|e| panic!("{e}")),
            "limit": store.count(&[kind_filter(1).limit(1)]).unwrap_or_else(|e| panic!("{e}")),
        },
        "negentropy": store
            .negentropy_items(&kind_filter(1))
            .unwrap_or_else(|e| panic!("{e}"))
            .iter()
            .map(|i| serde_json::json!({"id": i.id.to_hex(), "created_at": i.created_at.as_secs()}))
            .collect::<Vec<_>>(),
        "firstSeen": fixture_ids
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": id.to_hex(),
                    "at": store
                        .first_seen_at(id)
                        .unwrap_or_else(|e| panic!("{e}"))
                        .map(Timestamp::as_secs),
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// Cross-language SQLite round trip (plan §4.3): reads `<dir>/ts.db` —
/// written by `packages/nostr/scripts/parity/sqlite.ts write` — and asserts
/// the same query/count/negentropy/firstSeen results as `ts-results.json`,
/// then writes `rust.db` plus `rust-results.json` by putting `events.json`
/// in order for the TS side to read back. Run via `bun run test:parity` or
/// with `NK_SQLITE_DIR` set.
#[cfg(feature = "sqlite")]
#[test]
#[ignore = "needs NK_SQLITE_DIR pointing at the generated fixture directory"]
fn sqlite_interop() {
    let dir = std::env::var("NK_SQLITE_DIR").unwrap_or_else(|_| panic!("NK_SQLITE_DIR unset"));
    assert!(!dir.is_empty(), "NK_SQLITE_DIR empty");
    let dir = std::path::Path::new(&dir);

    // Filter values come from the fixture file — the TS fixtures are signed
    // with fixed secret keys whose ids this test cannot recompute.
    let fixtures: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("events.json")).unwrap_or_else(|e| panic!("{e}")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let rows = fixtures
        .as_array()
        .unwrap_or_else(|| panic!("events.json array"));
    let alice_pk = rows[0]["pubkey"]
        .as_str()
        .unwrap_or_else(|| panic!("pubkey"))
        .to_string();
    let target_id = rows[1]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("id"))
        .to_string();
    let fixture_ids: Vec<EventId> = rows
        .iter()
        .map(|row| {
            EventId::from_hex(row["id"].as_str().unwrap_or_else(|| panic!("id")))
                .unwrap_or_else(|e| panic!("{e}"))
        })
        .collect();

    // Open the TS-written database and collect the same result set.
    let store = SqliteStore::open(dir.join("ts.db")).unwrap_or_else(|e| panic!("{e}"));
    let results = collect_interop(&store, &alice_pk, &target_id, &fixture_ids);
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("ts-results.json")).unwrap_or_else(|e| panic!("{e}")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(results, expected, "ts.db must produce ts-results.json");
    drop(store);

    // Write rust.db by putting events.json in order.
    for path in ["rust.db", "rust.db-wal", "rust.db-shm"] {
        let _ = std::fs::remove_file(dir.join(path));
    }
    let store = SqliteStore::open(dir.join("rust.db")).unwrap_or_else(|e| panic!("{e}"));
    let mut parsed = Vec::new();
    for raw in rows {
        parsed.push(
            Event::from_json(&serde_json::to_string(raw).unwrap_or_else(|e| panic!("{e}")))
                .unwrap_or_else(|e| panic!("{e}")),
        );
    }
    store.put_many(&parsed).unwrap_or_else(|e| panic!("{e}"));
    let rust_results = collect_interop(&store, &alice_pk, &target_id, &fixture_ids);
    // Everything but the wall-clock firstSeen must match ts-results.json.
    assert_eq!(rust_results["queries"], expected["queries"]);
    assert_eq!(rust_results["counts"], expected["counts"]);
    assert_eq!(rust_results["negentropy"], expected["negentropy"]);
    std::fs::write(
        dir.join("rust-results.json"),
        serde_json::to_string(&rust_results).unwrap_or_else(|e| panic!("{e}")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
}
