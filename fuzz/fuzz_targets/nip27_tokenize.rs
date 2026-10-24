#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::nips::nip27::{ContentBlock, ParseOptions, parse_content};

fuzz_target!(|data: &str| {
    let blocks = parse_content(data, None, ParseOptions::default());
    // Non-empty input always produces at least one block.
    assert!(data.is_empty() || !blocks.is_empty());
    let mut covered = String::new();
    let mut all_text = true;
    for block in &blocks {
        if let ContentBlock::Text(t) = block {
            // Every text block is a non-empty slice of the input.
            assert!(!t.is_empty());
            assert!(data.contains(&*t));
            covered.push_str(t);
        } else {
            all_text = false;
        }
    }
    // When nothing tokenizes, the text blocks are the whole input.
    if all_text {
        assert_eq!(covered, data);
    }
});
