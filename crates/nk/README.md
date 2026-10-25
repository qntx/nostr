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
    let routing = gossip.route(&[Filter::new().authors([keys.public_key()]).expect("filter")]);
    let plan = routing.with_fallback(&[RelayUrl::parse("wss://nos.lol")?])?;
    let pool = RelayPool::new(RelayOptions::default());
    let out = pool
        .fetch_routed(plan, std::time::Duration::from_secs(5))
        .await;
    let _ = out.events.len();
    Ok(())
}
```

`nip46::RemoteSigner` is a `NostrSigner` that delegates to a remote
signer (NIP-46 bunker): the client key is local and disposable, the
user key never leaves the bunker:

```rust,no_run
use std::str::FromStr;
use std::sync::Arc;

use nk::client::{Client, ClientOptions};
use nk::nip46::{RemoteSigner, RemoteSignerOptions};
use nk_core::nips::nip46::BunkerUri;
use nk_core::Keys;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bunker =
        BunkerUri::from_str("bunker://<remote-pubkey>?relay=wss://relay.damus.io")?;
    let signer = RemoteSigner::connect(
        &bunker,
        Keys::generate()?,
        RemoteSignerOptions::default(),
    )
    .await?;
    // Persist `signer.bunker_uri()` and the client keys to `attach` later.
    let mut options = ClientOptions::default();
    options.signer = Some(Arc::new(signer.clone()));
    let client = Client::new(options);
    client.close().await;
    signer.logout().await?;
    Ok(())
}
```

The `http` feature adds `http::HttpClient`: plain-HTTP APIs over
hyper-util + rustls — NIP-11 relay information and NIP-05 lookup.
Redirects are never followed; NIP-05 requires an exact 200:

```rust,no_run
#[cfg(feature = "http")]
async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;

    use nk::http::{HttpClient, HttpOptions};
    use nk_core::RelayUrl;
    use nk_core::nips::nip05::Nip05Address;

    let http = HttpClient::new(HttpOptions::default())?;
    let info = http.relay_information(&RelayUrl::parse("wss://relay.damus.io")?).await?;
    println!("supported_nips: {:?}", info.supported_nips);
    let address = Nip05Address::from_str("somebody@example.com")?;
    if let Some(profile) = http.nip05_profile(&address).await? {
        println!("{} -> {} at {:?}", address, profile.pubkey.to_hex(), profile.relays);
    }
    Ok(())
}
```

The same client carries Blossom (BUD-01/02/04/06): sign a kind
`24242` `Authorization` and `upload` — the server hash is verified
against the bytes:

```rust,no_run
#[cfg(feature = "http")]
async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;

    use nk::http::{HttpClient, HttpOptions};
    use nk_core::nips::blossom::{AuthVerb, Authorization, Server};
    use nk_core::rand_core::UnwrapErr;
    use nk_core::{EventBuilder, Keys, SysRng, Timestamp};

    let http = HttpClient::new(HttpOptions::default())?;
    let server = Server::from_str("https://cdn.example.com")?;
    let keys = Keys::generate()?;
    let template = Authorization::new(
        AuthVerb::Upload,
        Timestamp::from_secs(Timestamp::now().as_secs() + 3600),
    )
    .message("Upload a blob")?;
    let auth = keys.sign_event(
        EventBuilder::from(template).build(keys.public_key()),
        &mut UnwrapErr(SysRng),
    )?;
    let descriptor = http
        .upload(&server, b"blob bytes".to_vec(), Some("text/plain"), &auth)
        .await?;
    println!("stored at {} ({} bytes)", descriptor.url, descriptor.size);
    Ok(())
}
```
