//! Integration tests: `Relay` + `Subscription` against `testing::MockRelay`.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    clippy::indexing_slicing,
    clippy::match_same_arms,
    missing_docs,
    unused_crate_dependencies,
    reason = "test code panics loudly on failure; dev-deps pull the whole feature graph"
)]

use std::time::Duration;

use futures_util::StreamExt;
use nk::relay::{CloseReason, FetchEnd, Relay, RelayOptions, RelayStatus, SubscriptionEvent};
use std::sync::Arc;

use nk::testing::MockRelay;
use nk_core::{Event, EventBuilder, Filter, Keys, Kind, SecretKey, Timestamp};

pub(crate) fn keys() -> Keys {
    Keys::new(SecretKey::from_bytes([9; 32]).expect("fixed key"))
}

pub(crate) fn event(content: &str, kind: u16) -> Event {
    keys()
        .sign_event(
            EventBuilder::new(Kind::new(kind), content)
                .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000)),
            &mut nk_core::rand_core::UnwrapErr(nk_core::SysRng),
        )
        .expect("sign")
}

pub(crate) async fn mock_and_relay_with(f: impl Fn(&mut RelayOptions)) -> (MockRelay, Relay) {
    let mock = MockRelay::start().await.expect("mock");
    let mut opts = RelayOptions::default();
    f(&mut opts);
    let relay = Relay::new(&mock.url(), opts);
    (mock, relay)
}

pub(crate) async fn mock_and_relay() -> (MockRelay, Relay) {
    let mock = MockRelay::start().await.expect("mock");
    let relay = Relay::new(&mock.url(), RelayOptions::default());
    (mock, relay)
}

/// A URL pointing at a port nobody listens on — connect always fails.
pub(crate) async fn dead_url() -> nk_core::RelayUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    nk_core::RelayUrl::parse(&format!("ws://{addr}")).expect("url")
}

/// The second string element of a `["<verb>","<id>",...]` wire frame.
pub(crate) fn req_id(frame: &str) -> &str {
    let start = frame.find(r#"",""#).map(|i| i + 3).expect("frame id");
    let rest = &frame[start..];
    let end = rest.find('"').expect("id end");
    &rest[..end]
}

/// A listener that accepts TCP and never answers the WebSocket
/// handshake — connect stalls until `connect_timeout`. The returned
/// task keeps the accepted sockets alive for the test's duration.
pub(crate) async fn blackhole_url() -> (nk_core::RelayUrl, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = nk_core::RelayUrl::parse(&format!("ws://{}", listener.local_addr().expect("addr")))
        .expect("url");
    let hold = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            // Hold the accepted socket open without answering the
            // WebSocket handshake — the client stalls at connect.
            tokio::spawn(async move {
                std::future::pending::<()>().await;
                drop(stream);
            });
        }
    });
    (url, hold)
}

mod client;
mod pool;
mod relay;
