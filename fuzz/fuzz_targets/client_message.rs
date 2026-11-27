#![no_main]

use libfuzzer_sys::fuzz_target;
use nk_core::ClientMessage;

fuzz_target!(|data: &str| {
    if let Ok(message) = ClientMessage::from_json(data) {
        let wire = message.to_json();
        let reparsed = ClientMessage::from_json(&wire);
        assert!(reparsed.is_ok(), "re-encoded client message must re-parse");
        assert!(reparsed.ok().map(|m| m.to_json()).as_deref() == Some(wire.as_str()));

        // Trailing elements are ignored: `,0` inserted before the final `]` of
        // the accepted input must still parse to the same wire form. REQ/COUNT
        // are variadic (a trailing `0` is just another filter) so they skip it.
        if !matches!(
            message,
            ClientMessage::Req { .. } | ClientMessage::Count { .. }
        ) && let Some(head) = data.trim_end().strip_suffix(']')
        {
            let with_extra = format!("{head},0]");
            let extra = ClientMessage::from_json(&with_extra)
                .expect("a trailing element must not break parsing");
            assert_eq!(extra.to_json(), wire);
        }
    }
});
