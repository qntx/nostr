#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::Filter;

fuzz_target!(|data: &str| {
    // Parse → canonical JSON → parse must be an idempotent fixed point.
    if let Ok(filter) = Filter::from_json(data) {
        let canonical = filter.canonical_json();
        let reparsed = Filter::from_json(&canonical);
        assert!(reparsed.is_ok(), "canonical filter JSON must re-parse");
        assert_eq!(reparsed.ok().map(|f| f.canonical_json()), Some(canonical));
    }
});
