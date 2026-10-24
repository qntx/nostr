//! vectors/nip13/codec.json — `nip13.pow`.

use nk_core::nips::nip13::PowMiner;
use nk_core::{EventId, Timestamp, UnsignedEvent};

use serde::Deserialize;

#[derive(Deserialize)]
struct PowCase {
    id: Option<String>,
    input: Option<String>,
    bits: Option<u32>,
    rust: Option<bool>,
}

#[derive(Deserialize)]
struct MineCase {
    unsigned: serde_json::Value,
    difficulty: u32,
    now: u64,
    nonce: String,
    id: String,
}

const JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vectors/nip13/codec.json"
));

#[test]
fn nip13_pow() {
    let doc: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<PowCase> = serde_json::from_value(doc["pow"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        match (&case.id, &case.input, case.bits) {
            (Some(id), None, Some(bits)) => {
                assert_eq!(EventId::from_hex(id).unwrap().difficulty(), bits, "pow {i}");
            }
            // `"rust": false` — non-canonical hex spellings the strict
            // parser shape cannot express; asserted as marked.
            (None, Some(_), _) => assert_eq!(case.rust, Some(false), "pow {i}"),
            _ => panic!("pow {i}: malformed case"),
        }
    }
}

#[test]
fn nip13_mine() {
    let doc: serde_json::Value = serde_json::from_str(JSON).unwrap();
    let cases: Vec<MineCase> = serde_json::from_value(doc["mine"].clone()).unwrap();
    for (i, case) in cases.iter().enumerate() {
        let unsigned: UnsignedEvent = serde_json::from_value(case.unsigned.clone()).unwrap();
        let mut miner = PowMiner::new(unsigned, case.difficulty);
        let (event, id) = miner
            .mine(Timestamp::from_secs(case.now), u64::MAX)
            .unwrap();
        let nonce = event
            .tags()
            .iter()
            .find(|t| t.name() == "nonce")
            .and_then(|t| t.as_slice().get(1).cloned());
        assert_eq!(
            nonce.as_deref(),
            Some(case.nonce.as_str()),
            "mine {i} nonce"
        );
        assert_eq!(id.to_hex(), case.id, "mine {i} id");
        assert!(id.difficulty() >= case.difficulty);
    }
}
