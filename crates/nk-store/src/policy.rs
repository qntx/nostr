//! Shared insertion/deletion policy — the single source both backends call
//! so put semantics cannot drift. A port of `decidePut` / `planDeletion` /
//! `DeletionState.covers` / `coordinateRemovals` minus the winner-watermark
//! bookkeeping, which has no Rust consumer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use nk_core::{Coordinate, Event, EventId, Kind, PublicKey, Timestamp};

use crate::PutOutcome;

/// The addressable coordinate of a replaceable/addressable event; `None`
/// for regular and ephemeral kinds.
pub(crate) fn coordinate_of(event: &Event) -> Option<Coordinate> {
    event.address()
}

/// The event metadata a put decision needs — never the owned event.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Stored {
    /// The stored event's author.
    pub(crate) pubkey: PublicKey,
    /// The stored event's kind.
    pub(crate) kind: Kind,
}

impl Stored {
    /// Projects a stored event to its decision-relevant fields.
    pub(crate) const fn of(event: &Event) -> Self {
        Self {
            pubkey: event.pubkey(),
            kind: event.kind(),
        }
    }
}

/// A kind-5 deletion plan.
#[derive(Debug)]
pub(crate) struct DeletionPlan {
    /// Stored, same-pubkey, non-kind-5 target ids to remove immediately.
    pub(crate) remove_ids: Vec<EventId>,
    /// Referenced ids not in the store — remembered with the deleting
    /// event's pubkey until the target arrives (`id → deletion pubkey`).
    pub(crate) pending_ids: Vec<(EventId, PublicKey)>,
    /// Coordinates tombstoned up to `until` (the deletion's `created_at`).
    pub(crate) coordinates: Vec<(Coordinate, Timestamp)>,
}

/// Plans a kind-5 event per NIP-09:
/// `e` tags remove only stored, same-pubkey, non-kind-5 targets; unknown
/// targets become pending keyed by the deletion's pubkey; `a` tags tombstone
/// coordinates only when the coordinate pubkey equals the deletion's pubkey;
/// a deletion targeting a deletion is a no-op.
pub(crate) fn plan_deletion(
    deletion: &Event,
    stored: &impl Fn(&EventId) -> Option<Stored>,
) -> DeletionPlan {
    let mut plan = DeletionPlan {
        remove_ids: Vec::new(),
        pending_ids: Vec::new(),
        coordinates: Vec::new(),
    };
    let mut seen_ids: HashSet<EventId> = HashSet::new();
    let mut seen_coords: HashSet<Coordinate> = HashSet::new();
    for tag in deletion.tags() {
        let Some(value) = tag.value() else {
            continue;
        };
        if tag.name() == "e" {
            let Ok(id) = EventId::from_hex(value) else {
                continue;
            };
            if !seen_ids.insert(id) {
                continue;
            }
            match stored(&id) {
                None => plan.pending_ids.push((id, deletion.pubkey())),
                Some(existing)
                    if existing.kind.as_u16() == 5 || existing.pubkey != deletion.pubkey() => {}
                Some(_) => plan.remove_ids.push(id),
            }
            continue;
        }
        if tag.name() == "a" {
            let Ok(coordinate) = Coordinate::from_str(value) else {
                continue;
            };
            if coordinate.pubkey() != deletion.pubkey() {
                continue;
            }
            if seen_coords.insert(coordinate.clone()) {
                plan.coordinates.push((coordinate, deletion.created_at()));
            }
        }
    }
    plan
}

/// In-memory NIP-09 tombstones, shared with the memory backend.
#[derive(Debug, Default)]
pub(crate) struct DeletionState {
    /// Directly deleted event ids.
    pub(crate) ids: BTreeSet<EventId>,
    /// `id → deleting pubkey`: pending tombstones (cover only same-pubkey
    /// arrivals).
    pub(crate) pending: HashMap<EventId, PublicKey>,
    /// `coordinate → max until`.
    pub(crate) coordinates: BTreeMap<Coordinate, Timestamp>,
}

impl DeletionState {
    /// Whether `event` is covered by a tombstone.
    pub(crate) fn covers(&self, event: &Event) -> bool {
        if self.ids.contains(&event.id()) {
            return true;
        }
        if event.kind().as_u16() == 5 {
            return false;
        }
        if self
            .pending
            .get(&event.id())
            .is_some_and(|pk| *pk == event.pubkey())
        {
            return true;
        }
        let Some(coordinate) = coordinate_of(event) else {
            return false;
        };
        self.coordinates
            .get(&coordinate)
            .is_some_and(|until| event.created_at() <= *until)
    }

    /// Folds a deletion plan into the state: covered ids become direct
    /// tombstones, unknown ones pending, coordinates keep the max `until`.
    pub(crate) fn absorb(&mut self, plan: &DeletionPlan) {
        for id in &plan.remove_ids {
            self.ids.insert(*id);
            self.pending.remove(id);
        }
        for (id, pubkey) in &plan.pending_ids {
            if !self.ids.contains(id) {
                self.pending.insert(*id, *pubkey);
            }
        }
        for (key, until) in &plan.coordinates {
            let prev = self
                .coordinates
                .get(key)
                .copied()
                .unwrap_or_else(|| Timestamp::from_secs(0));
            self.coordinates.insert(key.clone(), prev.max(*until));
        }
    }
}

/// What a backend looks up to decide one put — metadata only, never an
/// owned event.
pub(crate) trait Lookup {
    /// Tombstone state.
    fn deletion(&self) -> &DeletionState;
    /// The stored event's decision fields, by id.
    fn stored(&self, id: &EventId) -> Option<Stored>;
    /// The current replaceable/addressable winner for `coordinate` as
    /// `(created_at, id)`, if any.
    fn replaceable(&self, coordinate: &Coordinate) -> Option<(Timestamp, EventId)>;
}

/// The decided outcome of one put.
#[derive(Debug)]
pub(crate) enum PutDecision {
    /// Report the outcome without inserting.
    Skip(PutOutcome),
    /// Tombstone `id` and report the outcome (a re-put of a covered event).
    Tombstone(PutOutcome),
    /// Process a kind-5: absorb the plan, remove ids, store the deletion.
    Delete { plan: DeletionPlan },
    /// Insert the event, replacing `replace_id` when given.
    Insert {
        /// The outcome to report.
        outcome: PutOutcome,
        /// The stored incumbent to remove before inserting.
        replace_id: Option<EventId>,
    },
}

/// Decides one put — the shared policy, applied in the reference order:
/// duplicate → kind-5 → covered → ephemeral → replaceable → insert.
pub(crate) fn decide_put(event: &Event, lookup: &impl Lookup) -> PutDecision {
    if lookup.deletion().ids.contains(&event.id()) || lookup.stored(&event.id()).is_some() {
        return PutDecision::Skip(PutOutcome::Duplicate);
    }
    if event.kind().as_u16() == 5 {
        let plan = plan_deletion(event, &|id| lookup.stored(id));
        return PutDecision::Delete { plan };
    }
    if lookup.deletion().covers(event) {
        return PutDecision::Tombstone(PutOutcome::Duplicate);
    }
    if event.kind().is_ephemeral() {
        return PutDecision::Skip(PutOutcome::Ephemeral);
    }
    if let Some(coordinate) = coordinate_of(event)
        && let Some((prev_created_at, prev_id)) = lookup.replaceable(&coordinate)
    {
        // `supersedes` order: newer created_at, then smaller id — without
        // materializing the stored event.
        let supersedes = event.created_at() > prev_created_at
            || (event.created_at() == prev_created_at && event.id() < prev_id);
        if prev_id != event.id() && !supersedes {
            return PutDecision::Skip(PutOutcome::Rejected);
        }
        return PutDecision::Insert {
            outcome: PutOutcome::Replaced,
            replace_id: Some(prev_id),
        };
    }
    PutDecision::Insert {
        outcome: PutOutcome::Accepted,
        replace_id: None,
    }
}

/// The current stored winner for each tombstoned coordinate whose
/// `created_at` is not newer than `until` — ids to remove now.
pub(crate) fn coordinate_removals(
    coordinates: &[(Coordinate, Timestamp)],
    replaceable: &impl Fn(&Coordinate) -> Option<(Timestamp, EventId)>,
) -> Vec<EventId> {
    coordinates
        .iter()
        .filter_map(|(key, until)| {
            replaceable(key).and_then(|(created_at, id)| (created_at <= *until).then_some(id))
        })
        .collect()
}
