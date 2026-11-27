#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::RelayMessage;

fuzz_target!(|data: &str| {
    if let Ok(message) = RelayMessage::from_json(data) {
        let wire = message.to_json();
        let reparsed = RelayMessage::from_json(&wire);
        assert!(reparsed.is_ok(), "re-encoded relay message must re-parse");
        assert!(reparsed.ok().map(|m| m.to_json()).as_deref() == Some(wire.as_str()));

        // Trailing elements are ignored: `,0` inserted before the final `]` of
        // the accepted input must still parse to the same wire form.
        if let Some(head) = data.trim_end().strip_suffix(']') {
            let with_extra = format!("{head},0]");
            let extra = RelayMessage::from_json(&with_extra)
                .expect("a trailing element must not break parsing");
            assert_eq!(extra.to_json(), wire);
        }
    }
});
