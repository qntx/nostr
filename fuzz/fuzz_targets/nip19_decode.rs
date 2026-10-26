#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::nips::nip19::Entity;

fuzz_target!(|data: &str| {
    // Decode; on success encode → decode must round-trip to the same entity.
    if let Ok(entity) = Entity::from_bech32(data)
        && let Ok(encoded) = entity.to_bech32()
    {
        let reparsed = Entity::from_bech32(&encoded);
        assert!(reparsed.is_ok(), "re-encoded entity must re-decode");
        assert!(
            reparsed.ok().and_then(|e| e.to_bech32().ok()).as_deref() == Some(encoded.as_str()),
            "encode/decode must round-trip"
        );
    }
});
