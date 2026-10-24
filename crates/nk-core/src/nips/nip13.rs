//! NIP-13 proof of work.
//!
//! `pow` counts the leading zero bits of an event id. [`PowMiner`] is the
//! sans-IO counterpart of the TS `minePow`: the caller supplies the current
//! time and a per-call attempt budget and decides where the loop runs and
//! when it stops (dropping the miner cancels it). The result event's tags are
//! the original tags plus `["nonce", "<n>", "<difficulty>"]`, and `created_at`
//! follows the supplied `now` — the nonce counter restarts at 1 whenever the
//! second changes.
//!
//! The canonical JSON is serialized once per second, not per attempt: the
//! SHA-256 state is paused right before the nonce digits and cloned per
//! attempt, then fed the digits and a fixed tail. The split point is computed
//! from the known tail length — never by searching the JSON.
//!
//! @see <https://github.com/nostr-protocol/nips/blob/master/13.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{EventId, Tag, Timestamp, UnsignedEvent};
use sha2::{Digest, Sha256};

/// The leading zero bits of `id` — the TS `getPow`, `0..=256`.
#[must_use]
pub fn pow(id: &EventId) -> u32 {
    let mut count = 0u32;
    for &byte in id.as_bytes() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// A paused NIP-13 mining session.
///
/// `mine(now, budget)` performs at most `budget` hash attempts; when the
/// `now` second differs from the one currently being mined, `created_at`
/// advances to `now` and the nonce counter restarts at 1. The miner keeps its
/// state between calls, so a caller can spread a search over as many calls as
/// it likes.
#[derive(Clone)]
pub struct PowMiner {
    unsigned: UnsignedEvent,
    difficulty: u32,
    /// The `created_at` second `state`/`tail` were built for.
    second: Timestamp,
    /// Nonce value of the last attempt within `second`.
    counter: u64,
    /// SHA-256 state paused immediately before the nonce digits; `None`
    /// until the first successful `rebuild`.
    state: Option<Sha256>,
    /// `","<difficulty>"]],<content-json>]` — the constant bytes after the
    /// nonce digits.
    tail: Vec<u8>,
}

impl PowMiner {
    /// Starts a mining session for `unsigned` at `difficulty` — the same
    /// scale as [`pow`].
    #[must_use]
    pub const fn new(unsigned: UnsignedEvent, difficulty: u32) -> Self {
        Self {
            second: unsigned.created_at(),
            unsigned,
            difficulty,
            counter: 0,
            state: None,
            tail: Vec::new(),
        }
    }

    /// Runs at most `budget` attempts, returning the mined event and its id
    /// once `pow(id) >= difficulty`, or `None` when the budget ran out.
    #[must_use]
    pub fn mine(&mut self, now: Timestamp, budget: u64) -> Option<(UnsignedEvent, EventId)> {
        if self.state.is_none() || now != self.second {
            self.rebuild(now)?;
        }
        for _ in 0..budget {
            self.counter = self.counter.checked_add(1)?;
            let mut hasher = self.state.clone()?;
            let mut digits = [0u8; 20];
            hasher.update(write_u64(self.counter, &mut digits));
            hasher.update(&self.tail);
            let id = EventId::from_bytes(hasher.finalize().into());
            if pow(&id) >= self.difficulty {
                return Some((self.event(), id));
            }
        }
        None
    }

    /// Rebuilds the paused prefix state and tail for `second` and resets the
    /// nonce counter. Returns `None` when the split point sanity check fails
    /// — impossible for a canonical serialization this module produces, but
    /// the code admits no panics.
    fn rebuild(&mut self, second: Timestamp) -> Option<()> {
        self.second = second;
        self.counter = 0;
        let difficulty = self.difficulty.to_string();
        let nonce = Tag::custom("nonce", [String::new(), difficulty.clone()]);
        let mut tags = self.unsigned.tags().clone();
        tags.push(nonce);

        // `canonical` ends with `["nonce","","<diff>"]],<content-json>]`: the
        // head stops at the opening quote of the nonce value and the tail is
        // `","<diff>"]],<content-json>]`. The tail length is known without
        // searching the JSON: a probe with the same tags and an empty
        // content shares the head, and its tail is `""` (2 bytes) longer
        // than `10 + difficulty.len()`.
        let probe = UnsignedEvent::new(
            self.unsigned.pubkey(),
            second,
            self.unsigned.kind(),
            tags.clone(),
            self.unsigned.content(),
        );
        let canonical = probe.canonical_json();
        let probe_empty = UnsignedEvent::new(
            self.unsigned.pubkey(),
            second,
            self.unsigned.kind(),
            tags,
            "",
        );
        let head_len = probe_empty
            .canonical_json()
            .len()
            .checked_sub(10 + difficulty.len())?;
        let (head, tail) = canonical.as_bytes().split_at_checked(head_len)?;
        if !head.ends_with(b"\"nonce\",\"") || !tail.starts_with(b"\",\"") {
            return None;
        }

        let mut state = Sha256::new();
        state.update(head);
        self.state = Some(state);
        self.tail.clear();
        self.tail.extend_from_slice(tail);
        Some(())
    }

    /// The result event: the original fields, `created_at` at the mined
    /// second, and the appended `["nonce", "<counter>", "<difficulty>"]` tag.
    fn event(&self) -> UnsignedEvent {
        let mut tags = self.unsigned.tags().clone();
        tags.push(Tag::custom(
            "nonce",
            [self.counter.to_string(), self.difficulty.to_string()],
        ));
        UnsignedEvent::new(
            self.unsigned.pubkey(),
            self.second,
            self.unsigned.kind(),
            tags,
            self.unsigned.content(),
        )
    }
}

impl core::fmt::Debug for PowMiner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PowMiner")
            .field("unsigned", &self.unsigned)
            .field("difficulty", &self.difficulty)
            .field("second", &self.second)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

/// Writes `n`'s decimal digits into `buf` and returns the used tail slice.
fn write_u64(n: u64, buf: &mut [u8; 20]) -> &[u8] {
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
    buf.get(buf.len() - written..).unwrap_or(&[])
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PowMiner>();
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]
mod tests {
    use crate::{Kind, PublicKey, Tags};

    use super::*;

    fn unsigned() -> UnsignedEvent {
        UnsignedEvent::new(
            PublicKey::from_hex("79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6")
                .unwrap(),
            Timestamp::from_secs(0),
            Kind::TEXT_NOTE,
            Tags::from_iter([Tag::custom("t", ["pow"])]),
            "It's just me mining my own business",
        )
    }

    #[test]
    fn pow_counts_leading_zero_bits() {
        let mut bytes = [0xffu8; 32];
        assert_eq!(pow(&EventId::from_bytes(bytes)), 0);
        bytes[0] = 0x01;
        assert_eq!(pow(&EventId::from_bytes(bytes)), 7);
        bytes[0] = 0;
        bytes[1] = 0x80;
        assert_eq!(pow(&EventId::from_bytes(bytes)), 8);
        bytes = [0u8; 32];
        assert_eq!(pow(&EventId::from_bytes(bytes)), 256);
        // The NIP-13 worked example id.
        let id =
            EventId::from_hex("000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358")
                .unwrap();
        assert_eq!(pow(&id), 21);
    }

    #[test]
    fn mined_id_is_the_canonical_hash() {
        let mut miner = PowMiner::new(unsigned(), 8);
        let (event, id) = miner.mine(Timestamp::from_secs(0), 100_000).unwrap();
        assert!(pow(&id) >= 8);
        assert_eq!(id, event.id());
        let nonce = event
            .tags()
            .iter()
            .find(|tag| tag.name() == "nonce")
            .unwrap();
        assert_eq!(nonce.as_slice().get(2).map(String::as_str), Some("8"));
        assert_eq!(event.created_at(), Timestamp::from_secs(0));
    }

    #[test]
    fn counter_resets_when_the_second_changes() {
        let mut miner = PowMiner::new(unsigned(), 4);
        assert!(miner.mine(Timestamp::from_secs(1), 100).is_some());
        let (event, _) = miner.mine(Timestamp::from_secs(2), 1_000).unwrap();
        assert_eq!(event.created_at(), Timestamp::from_secs(2));
        let nonce = event
            .tags()
            .iter()
            .find(|tag| tag.name() == "nonce")
            .unwrap();
        let n: u64 = nonce.as_slice().get(1).unwrap().parse().unwrap();
        assert!(n >= 1);
    }

    #[test]
    fn split_budgets_reach_the_same_nonce() {
        // Mining in many small `mine` calls reaches the same nonce as a
        // single call: the counter survives between calls.
        fn nonce_of(event: &UnsignedEvent) -> String {
            event
                .tags()
                .iter()
                .find(|tag| tag.name() == "nonce")
                .unwrap()
                .as_slice()
                .get(1)
                .unwrap()
                .clone()
        }
        let mut whole = PowMiner::new(unsigned(), 12);
        let target = whole
            .mine(Timestamp::from_secs(0), 1_000_000)
            .map(|(event, _)| nonce_of(&event));
        let mut split = PowMiner::new(unsigned(), 12);
        let got = (0..1_000)
            .find_map(|_| split.mine(Timestamp::from_secs(0), 1_000))
            .map(|(event, _)| nonce_of(&event));
        assert_eq!(target, got);
    }

    #[test]
    fn mined_event_differs_only_by_nonce_and_time() {
        let source = unsigned();
        let mut miner = PowMiner::new(source.clone(), 4);
        let (event, _) = miner.mine(Timestamp::from_secs(9), 10_000).unwrap();
        assert_eq!(event.pubkey(), source.pubkey());
        assert_eq!(event.kind(), source.kind());
        assert_eq!(event.content(), source.content());
        assert_eq!(
            event.tags().iter().count(),
            source.tags().iter().count() + 1
        );
    }
}
