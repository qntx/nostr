# nk

The `nk-*` workspace SDK on top of `nk-core`: relays, pools, gossip
routing, and the client that composes them with an event store.

`client::Client` composes the pool, the gossip routing table and the
event store — the main entry point:

```rust,no_run
use nk::client::{Client, ClientOptions};
use nk_core::{EventBuilder, Filter, Keys, Kind, SingleLetterTag, Timestamp};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = ClientOptions::default();
    options.relays = vec![nk_core::RelayUrl::parse("wss://relay.damus.io")?];
    options.signer = Some(Arc::new(Keys::generate()?));
    let client = Client::new(options);

    client
        .hydrate(&[Keys::generate()?.public_key()], Duration::from_secs(10))
        .await?;
    let out = client
        .fetch(vec![Filter::new().limit(1)], Duration::from_secs(10))
        .await?;
    let _ = out.events.len();
    let note = client
        .sign(EventBuilder::new(Kind::new(1), "hello"))
        .await?;
    client.publish(&note).await?;
    client.close().await;
    Ok(())
}
```

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

`pool::RelayPool` fans out across relays — one shared `Relay` per URL,
concurrent operations, per-relay results:

```rust,no_run
use nk::pool::RelayPool;
use nk::relay::RelayOptions;
use nk_core::nips::nip65::{RelayList, RelayListItem, RelayMarker};
use nk_core::{EventBuilder, Filter, Keys, RelayUrl, SysRng, Timestamp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = RelayPool::new(RelayOptions::default());
    let urls = [
        RelayUrl::parse("wss://relay.damus.io")?,
        RelayUrl::parse("wss://nos.lol")?,
    ];
    // Read across all of them at once.
    let out = pool
        .fetch(&urls, vec![Filter::new()], std::time::Duration::from_secs(5))
        .await?;
    assert_eq!(out.relays.len(), 2);
    // Or publish to all of them, per-relay outcome included.
    let keys = Keys::generate()?;
    let unsigned =
        EventBuilder::text_note("hi").build_at(keys.public_key(), Timestamp::now());
    let event = keys.sign_event(unsigned, &mut SysRng)?;
    let results = pool.publish(&urls, &event).await;
    assert_eq!(results.len(), 2);
    Ok(())
}
```

`gossip::Gossip` is a sans-IO NIP-65 routing table — ingest relay lists
and turn filters into per-relay plans for `fetch_routed`/`subscribe_routed`:

```rust,no_run
use nk::gossip::{Gossip, GossipOptions};
use nk::pool::RelayPool;
use nk::relay::RelayOptions;
use nk_core::nips::nip65::{RelayList, RelayListItem, RelayMarker};
use nk_core::{EventBuilder, Filter, Keys, RelayUrl, SysRng, Timestamp};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = Keys::generate()?;
    // Publish a relay list naming the pool's relays as the outbox.
    let list = RelayList::new(vec![RelayListItem {
        url: RelayUrl::parse("wss://relay.damus.io")?,
        marker: RelayMarker::Write,
    }]);
    let unsigned =
        EventBuilder::from(list).build_at(keys.public_key(), Timestamp::now());
    let list = keys.sign_event(unsigned, &mut SysRng)?;
    let mut gossip = Gossip::new(GossipOptions::default());
    assert!(gossip.ingest(&list));
    let routing = gossip.route(&[Filter::new().authors([keys.public_key()])]);
    let plan = routing.with_fallback(&[RelayUrl::parse("wss://nos.lol")?])?;
    let pool = RelayPool::new(RelayOptions::default());
    let out = pool
        .fetch_routed(plan, std::time::Duration::from_secs(5))
        .await;
    let _ = out.events.len();
    Ok(())
}
```
