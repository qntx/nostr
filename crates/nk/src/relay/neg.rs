//! The crate-private NIP-77 state machine: one negentropy session per
//! NEG-OPEN. The relay session stays protocol-routing only; sync logic
//! lives here so the `negentropy` crate never escapes the crate.

use negentropy::{Id, Negentropy, NegentropyStorageVector};

use super::{Error, Result};

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

/// One live NEG-OPEN session.
pub(crate) struct NegSession {
    neg: Negentropy<'static, NegentropyStorageVector>,
    /// Terminal: `reconcile_with_ids` returned `None` — done.
    done: bool,
    /// Accumulated across every round — the crate appends each call.
    have: Vec<Id>,
    need: Vec<Id>,
}

impl NegSession {
    /// Seals `items` into a storage vector and opens a session.
    pub(crate) fn new(items: &[(nk_core::Timestamp, nk_core::EventId)]) -> Result<Self> {
        Self::with_limit(items, FRAME_SIZE_LIMIT)
    }

    /// Opens a session with an explicit frame limit (test seam).
    pub(crate) fn with_limit(
        items: &[(nk_core::Timestamp, nk_core::EventId)],
        frame_size_limit: u64,
    ) -> Result<Self> {
        let mut storage = NegentropyStorageVector::with_capacity(items.len());
        for (ts, id) in items {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(id.as_bytes());
            storage
                .insert(ts.as_secs(), Id::from_byte_array(bytes))
                .map_err(|e| Error::Transport(super::TransportError::new(e)))?;
        }
        storage
            .seal()
            .map_err(|e| Error::Transport(super::TransportError::new(e)))?;
        let neg = Negentropy::owned(storage, frame_size_limit)
            .map_err(|e| Error::Transport(super::TransportError::new(e)))?;
        Ok(Self {
            neg,
            done: false,
            have: Vec::new(),
            need: Vec::new(),
        })
    }

    /// The `NEG-OPEN` initial message (hex).
    pub(crate) fn initiate(&mut self) -> Result<String> {
        let msg = self
            .neg
            .initiate()
            .map_err(|e| Error::Transport(super::TransportError::new(e)))?;
        Ok(hex_lower(&msg))
    }

    /// One `NEG-MSG` round: returns `Ok(Some(next_hex))` to continue,
    /// `Ok(None)` with the final reconciliation in `out` when done.
    pub(crate) fn on_msg(&mut self, hex: &str, out: &mut Reconciliation) -> Result<Option<String>> {
        let bytes = hex_bytes(hex)?;
        let next = self
            .neg
            .reconcile_with_ids(&bytes, &mut self.have, &mut self.need)
            .map_err(|e| Error::Transport(super::TransportError::new(e)))?;
        if let Some(msg) = next {
            return Ok(Some(hex_lower(&msg)));
        }
        self.done = true;
        out.have = ids_to_events(core::mem::take(&mut self.have));
        out.need = ids_to_events(core::mem::take(&mut self.need));
        Ok(None)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| char::from(HEX.get(usize::from(n)).copied().unwrap_or(b'0')))
        .collect()
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Transport(super::TransportError::new(
            std::io::Error::other("odd-length negentropy hex"),
        )));
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or(())
        })
        .collect::<std::result::Result<Vec<u8>, ()>>()
        .map_err(|()| {
            Error::Transport(super::TransportError::new(std::io::Error::other(
                "invalid negentropy hex",
            )))
        })
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
        client: &mut NegSession,
        srv: &mut Negentropy<'static, NegentropyStorageVector>,
    ) -> (usize, Reconciliation) {
        let mut rounds = 0;
        let mut out = Reconciliation::default();
        let mut query = hex_bytes(&client.initiate().unwrap()).unwrap();
        loop {
            rounds += 1;
            let reply = hex_lower(&srv.reconcile(&query).unwrap());
            match client.on_msg(&reply, &mut out).unwrap() {
                Some(next) => query = hex_bytes(&next).unwrap(),
                None => return (rounds, out),
            }
        }
    }

    #[test]
    fn disjoint_sets_produce_exact_have_need() {
        let ours = vec![item(1), item(2)];
        let theirs = vec![item(3), item(4)];
        let mut client = NegSession::new(&ours).unwrap();
        let mut srv = server_neg(&theirs);
        let (rounds, mut rec) = run(&mut client, &mut srv);
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
        let mut client = NegSession::new(&ours).unwrap();
        let mut srv = server_neg(&theirs);
        let (_, mut rec) = run(&mut client, &mut srv);
        rec.have.sort();
        rec.need.sort();
        assert_eq!(rec.have, vec![item(1).1]);
        assert_eq!(rec.need, vec![item(9).1]);
    }

    #[test]
    fn identical_and_empty_sets_reconcile() {
        let same = vec![item(1), item(2)];
        let mut c1 = NegSession::new(&same).unwrap();
        let mut s1 = server_neg(&same);
        let (_, rec1) = run(&mut c1, &mut s1);
        assert_eq!(rec1, Reconciliation::default());

        let mut c2 = NegSession::new(&[]).unwrap();
        let mut s2 = server_neg(&[]);
        let (_, rec2) = run(&mut c2, &mut s2);
        assert_eq!(rec2, Reconciliation::default());
    }

    #[test]
    fn small_frame_limit_forces_multiple_rounds() {
        // 200 items per side at 4 096 bytes — one round can't cover
        // the set, so the sync must take several `NEG-MSG`s.
        let ours: Vec<_> = (1..=200).map(item).collect();
        let theirs: Vec<_> = (201..=400).map(item).collect();
        let mut client = NegSession::with_limit(&ours, 4_096).unwrap();
        let mut srv = server_neg(&theirs);
        let (rounds, rec) = run(&mut client, &mut srv);
        assert!(rounds > 1, "expected >1 round, got {rounds}");
        assert_eq!(rec.have.len(), 200);
        assert_eq!(rec.need.len(), 200);
    }

    #[test]
    fn odd_hex_is_an_error() {
        let mut client = NegSession::new(&[]).unwrap();
        drop(client.initiate());
        let mut out = Reconciliation::default();
        assert!(client.on_msg("abc", &mut out).is_err());
    }
}
