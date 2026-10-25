//! The crate-private NIP-77 state machine: one negentropy session per
//! NEG-OPEN. The relay session stays protocol-routing only; sync logic
//! lives here so the `negentropy` crate never escapes the crate.

use negentropy::{Id, Negentropy, NegentropyStorageVector};

use super::{Error, NegentropyError, Result};

/// TS `DEFAULT_FRAME_SIZE_LIMIT` — matches `packages/nostr/src/nips/nip77.ts`.
pub(crate) const FRAME_SIZE_LIMIT: u64 = 60_000;

/// What a relay wants after `reconcile`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Ids we hold that the relay lacks (we should push them).
    pub have: Vec<nk_core::EventId>,
    /// Ids the relay holds that we lack (we should pull them).
    pub need: Vec<nk_core::EventId>,
}

/// One `NEG-MSG` round's outcome.
pub(crate) enum Round {
    /// The sync continues — send this reply (hex).
    Next(String),
    /// The terminal round — the final have/need sets.
    Done(Reconciliation),
}

/// One live NEG-OPEN session.
pub(crate) struct NegSession {
    neg: Negentropy<'static, NegentropyStorageVector>,
    /// Accumulated across every round — the crate appends each call;
    /// moved into `Round::Done`.
    have: Vec<Id>,
    need: Vec<Id>,
}

impl NegSession {
    /// Seals `items` into a storage vector, opens a session, and
    /// initiates — returns the `NEG-OPEN` payload (hex).
    ///
    /// # Errors
    ///
    /// [`Error::Negentropy`] when the item set cannot be sealed.
    pub(crate) fn start(
        items: &[(nk_core::Timestamp, nk_core::EventId)],
    ) -> Result<(Self, String)> {
        Self::start_with_limit(items, FRAME_SIZE_LIMIT)
    }

    /// `start` with an explicit frame limit — the small-frame test seam.
    ///
    /// # Errors
    ///
    /// [`Error::Negentropy`] when the item set cannot be sealed.
    pub(crate) fn start_with_limit(
        items: &[(nk_core::Timestamp, nk_core::EventId)],
        frame_size_limit: u64,
    ) -> Result<(Self, String)> {
        let mut storage = NegentropyStorageVector::with_capacity(items.len());
        for (ts, id) in items {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(id.as_bytes());
            storage
                .insert(ts.as_secs(), Id::from_byte_array(bytes))
                .map_err(|e| Error::Negentropy(NegentropyError::new(e)))?;
        }
        storage
            .seal()
            .map_err(|e| Error::Negentropy(NegentropyError::new(e)))?;
        let neg = Negentropy::owned(storage, frame_size_limit)
            .map_err(|e| Error::Negentropy(NegentropyError::new(e)))?;
        let mut session = Self {
            neg,
            have: Vec::new(),
            need: Vec::new(),
        };
        let message = session
            .neg
            .initiate()
            .map_err(|e| Error::Negentropy(NegentropyError::new(e)))?;
        Ok((session, hex_lower(&message)))
    }

    /// One `NEG-MSG` round: `Next(hex)` to continue, `Done` with the
    /// final reconciliation when finished.
    ///
    /// # Errors
    ///
    /// [`Error::Negentropy`] on a codec failure — the round is terminal.
    pub(crate) fn on_msg(&mut self, hex: &str) -> Result<Round> {
        let bytes = hex_bytes(hex)?;
        let next = self
            .neg
            .reconcile_with_ids(&bytes, &mut self.have, &mut self.need)
            .map_err(|e| Error::Negentropy(NegentropyError::new(e)))?;
        match next {
            Some(msg) => Ok(Round::Next(hex_lower(&msg))),
            None => Ok(Round::Done(Reconciliation {
                have: ids_to_events(core::mem::take(&mut self.have)),
                need: ids_to_events(core::mem::take(&mut self.need)),
            })),
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    faster_hex::hex_string(bytes)
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>> {
    faster_hex::hex_decode_vec(hex.as_bytes())
        .map_err(|e| Error::Negentropy(NegentropyError::new(e)))
}

impl std::fmt::Debug for NegSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegSession").finish_non_exhaustive()
    }
}

fn ids_to_events(ids: Vec<Id>) -> Vec<nk_core::EventId> {
    ids.into_iter()
        .map(|id| nk_core::EventId::from_bytes(*id.as_bytes()))
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use negentropy::{Id, Negentropy, NegentropyStorageVector};

    use super::*;

    /// A `(Timestamp, EventId)` pair — a fresh id per index.
    fn item(n: u64) -> (nk_core::Timestamp, nk_core::EventId) {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        (
            nk_core::Timestamp::from_secs(n),
            nk_core::EventId::from_bytes(b),
        )
    }

    /// A server-side negentropy over `items`.
    fn server_neg(
        items: &[(nk_core::Timestamp, nk_core::EventId)],
    ) -> Negentropy<'static, NegentropyStorageVector> {
        let mut storage = NegentropyStorageVector::new();
        for (ts, id) in items {
            storage
                .insert(ts.as_secs(), Id::from_byte_array(*id.as_bytes()))
                .unwrap();
        }
        storage.seal().unwrap();
        Negentropy::owned(storage, 60_000).unwrap()
    }

    /// Drives a client `NegSession` against a server to completion,
    /// returning rounds + the final reconciliation.
    fn run(
        mut client: NegSession,
        first: &str,
        srv: &mut Negentropy<'static, NegentropyStorageVector>,
    ) -> (usize, Reconciliation) {
        let mut rounds = 0;
        let mut query = hex_bytes(first).unwrap();
        loop {
            rounds += 1;
            let reply = hex_lower(&srv.reconcile(&query).unwrap());
            match client.on_msg(&reply).unwrap() {
                Round::Next(next) => query = hex_bytes(&next).unwrap(),
                Round::Done(out) => return (rounds, out),
            }
        }
    }

    #[test]
    fn disjoint_sets_produce_exact_have_need() {
        let ours = vec![item(1), item(2)];
        let theirs = vec![item(3), item(4)];
        let (client, first) = NegSession::start(&ours).unwrap();
        let mut srv = server_neg(&theirs);
        let (rounds, mut rec) = run(client, &first, &mut srv);
        assert!(rounds >= 1);
        rec.have.sort();
        rec.need.sort();
        assert_eq!(rec.have, vec![item(1).1, item(2).1]);
        assert_eq!(rec.need, vec![item(3).1, item(4).1]);
    }

    #[test]
    fn overlapping_sets_split_have_need() {
        let shared = item(5);
        let ours = vec![shared, item(1)];
        let theirs = vec![shared, item(9)];
        let (client, first) = NegSession::start(&ours).unwrap();
        let mut srv = server_neg(&theirs);
        let (_, mut rec) = run(client, &first, &mut srv);
        rec.have.sort();
        rec.need.sort();
        assert_eq!(rec.have, vec![item(1).1]);
        assert_eq!(rec.need, vec![item(9).1]);
    }

    #[test]
    fn identical_and_empty_sets_reconcile() {
        let same = vec![item(1), item(2)];
        let (c1, f1) = NegSession::start(&same).unwrap();
        let mut s1 = server_neg(&same);
        let (_, rec1) = run(c1, &f1, &mut s1);
        assert_eq!(rec1, Reconciliation::default());

        let (c2, f2) = NegSession::start(&[]).unwrap();
        let mut s2 = server_neg(&[]);
        let (_, rec2) = run(c2, &f2, &mut s2);
        assert_eq!(rec2, Reconciliation::default());
    }

    #[test]
    fn small_frame_limit_forces_multiple_rounds() {
        // 200 items per side at 4 096 bytes — one round can't cover
        // the set, so the sync must take several `NEG-MSG`s.
        let ours: Vec<_> = (1..=200).map(item).collect();
        let theirs: Vec<_> = (201..=400).map(item).collect();
        let (client, first) = NegSession::start_with_limit(&ours, 4_096).unwrap();
        let mut srv = server_neg(&theirs);
        let (rounds, rec) = run(client, &first, &mut srv);
        assert!(rounds > 1, "expected >1 round, got {rounds}");
        assert_eq!(rec.have.len(), 200);
        assert_eq!(rec.need.len(), 200);
    }

    #[test]
    fn odd_hex_is_an_error() {
        let (mut client, _) = NegSession::start(&[]).unwrap();
        assert!(client.on_msg("abc").is_err());
    }
}
