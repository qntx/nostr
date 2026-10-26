#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::RelayMessage;

fuzz_target!(|data: &str| {
    if let Ok(message) = RelayMessage::from_json(data) {
        let wire = message.to_json();
        let reparsed = RelayMessage::from_json(&wire);
        assert!(reparsed.is_ok(), "re-encoded relay message must re-parse");
        assert!(reparsed.ok().map(|m| m.to_json()).as_deref() == Some(wire.as_str()));
    }
});
