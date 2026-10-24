# nk

The `nk-*` workspace SDK: a single-relay client on top of `nk-core`.

`relay::Relay` drives one WebSocket — subscribe, fetch, publish, and close —
while `relay::session` keeps the protocol state machine sans-IO.

```rust,no_run
use nk::relay::{FetchOutcome, Relay, RelayOptions, RelayStatus};
use nk_core::{Filter, RelayUrl};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = Relay::new(
        &RelayUrl::parse("wss://relay.damus.io")?,
        RelayOptions::default(),
    );
    assert_eq!(relay.status(), RelayStatus::Disconnected);
    // Connects lazily on first use; fetch ends at EOSE, CLOSED, or timeout.
    let outcome: FetchOutcome = relay
        .fetch(vec![Filter::new().limit(1)], Duration::from_secs(5))
        .await?;
    let _ = outcome.events.len();
    relay.close().await;
    Ok(())
}
```
