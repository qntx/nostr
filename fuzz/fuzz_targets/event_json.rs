#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::Event;

fuzz_target!(|data: &str| {
    // Parse; on success the wire re-encode must re-parse to an equal event
    // and the canonical output must be stable.
    if let Ok(event) = Event::from_json(data) {
        let wire = event.to_json();
        let reparsed = Event::from_json(&wire);
        assert!(reparsed.is_ok(), "re-encoded wire JSON must re-parse");
        assert!(reparsed.ok() == Some(event), "re-parse must equal the original");
    }
});
