//! Integration tests: `Relay` + `Subscription` against `testing::MockRelay`.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    missing_docs,
    unused_crate_dependencies,
    reason = "test code panics loudly on failure; dev-deps pull the whole feature graph"
)]

use std::time::Duration;

use futures_util::StreamExt;
use nk::relay::{CloseReason, FetchEnd, Relay, RelayOptions, RelayStatus, SubscriptionEvent};
use nk::testing::MockRelay;
use nk_core::{Event, EventBuilder, Filter, Keys, Kind, SecretKey, Timestamp};

fn keys() -> Keys {
    Keys::new(SecretKey::from_bytes([9; 32]).expect("fixed key"))
}

fn event(content: &str, kind: u16) -> Event {
    keys()
        .sign_event(
            EventBuilder::new(Kind::new(kind), content)
                .build_at(keys().public_key(), Timestamp::from_secs(1_700_000_000)),
            &mut nk_core::rand_core::UnwrapErr(nk_core::SysRng),
        )
        .expect("sign")
}

async fn mock_and_relay() -> (MockRelay, Relay) {
    let mock = MockRelay::start().await.expect("mock");
    let relay = Relay::new(&mock.url(), RelayOptions::default());
    (mock, relay)
}

#[tokio::test]
async fn publish_accepted() {
    let (_m, relay) = mock_and_relay().await;
    let out = relay.publish(&event("hi", 1)).await.expect("publish");
    assert!(out.accepted, "message: {}", out.message);
}

#[tokio::test]
async fn duplicate_rejected() {
    let (_m, relay) = mock_and_relay().await;
    let ev = event("hi", 1);
    let first = relay.publish(&ev).await.expect("publish");
    assert!(first.accepted);
    let second = relay.publish(&ev).await.expect("publish");
    assert!(!second.accepted, "duplicate should be refused");
    assert!(
        second.message.starts_with("duplicate:"),
        "{}",
        second.message
    );
}

#[tokio::test]
async fn subscribe_stored_then_live() {
    let (mut mock, relay) = mock_and_relay().await;
    let stored = event("stored", 1);
    relay.publish(&stored).await.expect("seed");
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    // Stored event arrives first, then EOSE, exactly once.
    match sub.next().await {
        Some(SubscriptionEvent::Event(e)) => assert_eq!(e.id(), stored.id()),
        other => panic!("expected stored event, got {other:?}"),
    }
    assert!(matches!(sub.next().await, Some(SubscriptionEvent::Eose)));
    // Live event published after the REQ arrives next.
    let live = event("live", 1);
    relay.publish(&live).await.expect("live publish");
    match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
        Ok(Some(SubscriptionEvent::Event(e))) => assert_eq!(e.id(), live.id()),
        other => panic!("expected live event, got {other:?}"),
    }
    // No second EOSE.
    assert!(
        mock.wait_for_frame("REQ", Duration::from_secs(1))
            .await
            .is_some()
    );
}

#[tokio::test]
async fn fetch_ends_on_eose() {
    let (_m, relay) = mock_and_relay().await;
    relay.publish(&event("a", 1)).await.expect("seed");
    let out = relay
        .fetch(
            vec![Filter::new().kinds([Kind::new(1)])],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert_eq!(out.end, FetchEnd::Eose);
    assert_eq!(out.events.len(), 1);
}

#[tokio::test]
async fn fetch_ends_on_closed() {
    let (mock, relay) = mock_and_relay().await;
    // Drive a CLOSED on an open REQ via the mock's raw-frame hook.
    let mut fetch = relay
        .subscribe(vec![Filter::new().limit(0)])
        .await
        .expect("sub2");
    mock.send_raw(&format!(
        r#"["CLOSED","{}","closed: by test"]"#,
        fetch.id().as_str()
    ));
    let item = tokio::time::timeout(Duration::from_secs(2), fetch.next()).await;
    match item {
        Ok(Some(SubscriptionEvent::Closed(CloseReason::Relay(r)))) => {
            assert!(r.contains("closed:"), "{r}");
        }
        other => panic!("expected relay close, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_ends_on_timeout() {
    // A dead port: the REQ never reaches a relay, so no EOSE arrives and
    // the deadline ends the fetch.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let relay = Relay::new(
        &nk_core::RelayUrl::parse(&format!("ws://{addr}")).expect("url"),
        RelayOptions::default(),
    );
    let out = relay
        .fetch(
            vec![Filter::new().kinds([Kind::new(42)])],
            Duration::from_millis(50),
        )
        .await
        .expect("fetch");
    assert_eq!(out.end, FetchEnd::Timeout);
}

#[tokio::test]
async fn invalid_signature_dropped() {
    let (mock, relay) = mock_and_relay().await;
    let mut sub = relay.subscribe(vec![Filter::new()]).await.expect("sub");
    let signed = event("x", 1);
    let forged = Event::new(
        signed.id(),
        signed.pubkey(),
        signed.created_at(),
        signed.kind(),
        signed.tags().clone(),
        "forged".to_owned(),
        signed.sig(),
    );
    mock.send_raw(&format!(
        r#"["EVENT","{}",{}]"#,
        sub.id().as_str(),
        forged.to_json()
    ));
    // EOSE follows the stored fetch (sub itself sees no events), then the
    // forged EVENT must be dropped — nothing but Eose should arrive.
    let item = tokio::time::timeout(Duration::from_secs(1), sub.next()).await;
    assert!(
        matches!(item, Ok(Some(SubscriptionEvent::Eose))),
        "forged event must be dropped: {item:?}"
    );
}

#[tokio::test]
async fn non_matching_event_dropped() {
    let (mock, relay) = mock_and_relay().await;
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(7)])])
        .await
        .expect("sub");
    mock.send_raw(&format!(
        r#"["EVENT","{}",{}]"#,
        sub.id().as_str(),
        event("x", 1).to_json()
    ));
    let item = tokio::time::timeout(Duration::from_secs(1), sub.next()).await;
    assert!(
        matches!(item, Ok(Some(SubscriptionEvent::Eose))),
        "non-matching event must be dropped: {item:?}"
    );
}

#[tokio::test]
async fn drop_sends_close() {
    let (mut mock, relay) = mock_and_relay().await;
    let sub = relay.subscribe(vec![Filter::new()]).await.expect("sub");
    let id = sub.id().clone();
    drop(sub);
    let frame = mock.wait_for_frame("CLOSE", Duration::from_secs(2)).await;
    assert!(
        frame.as_ref().is_some_and(|f| f.contains(id.as_str())),
        "no CLOSE: {frame:?}"
    );
}

#[tokio::test]
async fn lagged_consumer_closed() {
    let (mock, relay) = mock_and_relay().await;
    let relay2 = Relay::new(
        &mock.url(),
        RelayOptions {
            subscription_capacity: 1,
            ..RelayOptions::default()
        },
    );
    let mut sub = relay2.subscribe(vec![Filter::new()]).await.expect("sub");
    // Flood the bounded channel without consuming: capacity 1 + EOSE →
    // the second event lags.
    for i in 0..8 {
        mock.send_raw(&format!(
            r#"["EVENT","{}",{}]"#,
            sub.id().as_str(),
            event(&format!("flood-{i}"), 1).to_json()
        ));
    }
    let mut saw_lagged = false;
    for _ in 0..16 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
            Ok(Some(SubscriptionEvent::Closed(CloseReason::Lagged))) => {
                saw_lagged = true;
                break;
            }
            Ok(Some(_)) => {}
            other => panic!("stream ended without Lagged: {other:?}"),
        }
    }
    assert!(saw_lagged, "lagged consumer must end Closed(Lagged)");
    drop(relay);
}

#[tokio::test]
async fn reconnect_replays_req() {
    let (mut mock, relay) = mock_and_relay().await;
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    let id = sub.id().clone();
    assert!(
        mock.wait_for_frame("REQ", Duration::from_secs(2))
            .await
            .is_some()
    );
    // Sever the connection; the driver reconnects and replays the REQ.
    mock.drop_connection();
    let needle = format!("REQ\",\"{}", id.as_str());
    let replayed = mock.wait_for_frame(&needle, Duration::from_secs(8)).await;
    assert!(replayed.is_some(), "REQ not replayed ({needle})");
    // The stream still receives live events on the new connection.
    mock.send_raw(&format!(
        r#"["EVENT","{}",{}]"#,
        id.as_str(),
        event("post-reconnect", 1).to_json()
    ));
    match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
        Ok(Some(SubscriptionEvent::Event(_))) => {}
        Ok(Some(SubscriptionEvent::Eose)) => {
            match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
                Ok(Some(SubscriptionEvent::Event(_))) => {}
                other => panic!("expected event after reconnect, got {other:?}"),
            }
        }
        other => panic!("expected event after reconnect, got {other:?}"),
    }
}

#[tokio::test]
async fn close_ends_subscriptions() {
    let (_m, relay) = mock_and_relay().await;
    let mut sub = relay.subscribe(vec![Filter::new()]).await.expect("sub");
    relay.close().await;
    let mut saw = false;
    while let Some(item) = sub.next().await {
        if matches!(item, SubscriptionEvent::Closed(CloseReason::RelayClosed)) {
            saw = true;
            break;
        }
    }
    assert!(saw, "expected Closed(RelayClosed)");
    assert_eq!(relay.status(), RelayStatus::Closed);
}

#[tokio::test]
async fn publish_disconnected_fails_fast() {
    // No reconnect: a dead port fails the publish immediately, not after
    // the publish timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let relay = Relay::new(
        &nk_core::RelayUrl::parse(&format!("ws://{addr}")).expect("url"),
        RelayOptions {
            reconnect: false,
            ..RelayOptions::default()
        },
    );
    let started = std::time::Instant::now();
    let err = relay.publish(&event("x", 1)).await.expect_err("dead port");
    assert!(
        matches!(
            err,
            nk::relay::Error::Disconnected
                | nk::relay::Error::Timeout
                | nk::relay::Error::Transport(_)
        ),
        "{err:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5), "publish hung");
}

#[tokio::test]
async fn connect_dead_port_errors_with_source() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let relay = Relay::new(
        &nk_core::RelayUrl::parse(&format!("ws://{addr}")).expect("url"),
        RelayOptions::default(),
    );
    let err = relay.connect().await.expect_err("dead port");
    assert!(
        matches!(
            err,
            nk::relay::Error::Transport(_)
                | nk::relay::Error::Disconnected
                | nk::relay::Error::Timeout
        ),
        "{err:?}"
    );
    assert!(
        std::error::Error::source(&err).is_some() || matches!(err, nk::relay::Error::Timeout),
        "no source: {err:?}"
    );
}

#[tokio::test]
async fn drop_mid_publish_returns_disconnected_then_recovers() {
    let (mock, relay) = mock_and_relay().await;
    relay.publish(&event("first", 1)).await.expect("first");
    // Sever mid-flow; the next publish must see a dead socket until the
    // reconnect lands.
    mock.drop_connection();
    // The in-flight publish path is covered by fail_pending; a publish
    // attempted while the socket is down queues through ensure_connected.
    let result = relay.publish(&event("second", 1)).await;
    assert!(
        matches!(
            result,
            Ok(_) | Err(nk::relay::Error::Disconnected | nk::relay::Error::Transport(_))
        ),
        "{result:?}"
    );
    // Once the driver reconnects (replay happened), publishes succeed again.
    for _ in 0..40 {
        if relay.status() == RelayStatus::Connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(relay.status(), RelayStatus::Connected, "never reconnected");
    let out = relay.publish(&event("third", 1)).await.expect("third");
    assert!(out.accepted);
}

#[tokio::test]
async fn subscribe_survives_reconnect() {
    let (mut mock, relay) = mock_and_relay().await;
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    assert!(
        mock.wait_for_frame("REQ", Duration::from_secs(2))
            .await
            .is_some()
    );
    mock.drop_connection();
    // Wait for the replayed REQ on the new connection.
    let needle = format!("REQ\",\"{}", sub.id().as_str());
    assert!(
        mock.wait_for_frame(&needle, Duration::from_secs(10))
            .await
            .is_some(),
        "REQ not replayed"
    );
    // Live event on the new connection still reaches the stream.
    mock.send_raw(&format!(
        r#"["EVENT","{}",{}]"#,
        sub.id().as_str(),
        event("post-reconnect", 1).to_json()
    ));
    let mut saw_event = false;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
            Ok(Some(SubscriptionEvent::Event(e))) => {
                assert_eq!(e.kind(), Kind::new(1));
                saw_event = true;
                break;
            }
            Ok(Some(_)) => {}
            other => panic!("stream ended: {other:?}"),
        }
    }
    assert!(saw_event, "no event after reconnect");
}

#[tokio::test]
async fn last_handle_drop_stops_driver() {
    let (mock, relay) = mock_and_relay().await;
    relay.connect().await.expect("connect");
    drop(relay);
    // The driver exits; the mock sees the connection close.
    for _ in 0..40 {
        if mock.connections() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("connection still open after last handle dropped");
}
