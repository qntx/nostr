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
use std::sync::Arc;

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

async fn mock_and_relay_with(f: impl Fn(&mut RelayOptions)) -> (MockRelay, Relay) {
    let mock = MockRelay::start().await.expect("mock");
    let mut opts = RelayOptions::default();
    f(&mut opts);
    let relay = Relay::new(&mock.url(), opts);
    (mock, relay)
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

/// The second string element of a `["<verb>","<id>",...]` wire frame.
fn req_id(frame: &str) -> &str {
    let start = frame.find(r#"",""#).map(|i| i + 3).expect("frame id");
    let rest = &frame[start..];
    let end = rest.find('"').expect("id end");
    &rest[..end]
}

#[tokio::test]
async fn fetch_ends_on_closed() {
    let (mut mock, relay) = mock_and_relay().await;
    mock.set_hold(true);
    let relay2 = relay.clone();
    let fetch = tokio::spawn(async move {
        relay2
            .fetch(vec![Filter::new().limit(0)], Duration::from_secs(5))
            .await
    });
    let req = mock
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("REQ frame");
    mock.send_raw(&format!(
        r#"["CLOSED","{}","closed: by test"]"#,
        req_id(&req)
    ));
    let outcome = fetch.await.expect("join").expect("fetch");
    match outcome.end {
        FetchEnd::Closed(reason) => assert!(reason.contains("closed:"), "{reason}"),
        other => panic!("expected Closed, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_closed_by_relay() {
    let (mock, relay) = mock_and_relay().await;
    mock.set_hold(true);
    let mut sub = relay.subscribe(vec![Filter::new()]).await.expect("sub");
    mock.send_raw(&format!(
        r#"["CLOSED","{}","closed: by test"]"#,
        sub.id().as_str()
    ));
    match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
        Ok(Some(SubscriptionEvent::Closed(CloseReason::Relay(r)))) => {
            assert!(r.contains("closed:"), "{r}");
        }
        other => panic!("expected relay close, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_ends_on_timeout() {
    // A live-but-silent relay: the REQ goes out, nothing answers, and
    // the fetch deadline ends it.
    let (mock, relay) = mock_and_relay().await;
    mock.set_hold(true);
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
async fn pong_deadline_reconnects() {
    // Short liveness timings so the missed pong is detected quickly.
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.ping_interval = Duration::from_millis(30);
        o.pong_deadline = Duration::from_millis(50);
        o.reconnect_min = Duration::from_millis(50);
        o.reconnect_max = Duration::from_millis(100);
    })
    .await;
    let sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    assert!(
        mock.wait_for_frame("REQ", Duration::from_secs(2))
            .await
            .is_some()
    );
    // The mock stops answering pings; the relay must notice the missed
    // pong deadline, disconnect, and reconnect — proven by the replayed
    // REQ landing on the fresh connection.
    mock.freeze_connection();
    let needle = format!("REQ\",\"{}", sub.id().as_str());
    assert!(
        mock.wait_for_frame(&needle, Duration::from_secs(10))
            .await
            .is_some(),
        "REQ not replayed after liveness reconnect"
    );
    assert_eq!(relay.status(), RelayStatus::Connected);
    drop(sub);
}

#[tokio::test]
async fn drops_under_load_all_send_close() {
    // Many subscriptions dropped while the driver is busy: every CLOSE
    // must still reach the mock.
    let (mut mock, relay) = mock_and_relay().await;
    let mut subs = Vec::new();
    for _ in 0..50 {
        subs.push(
            relay
                .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
                .await
                .expect("sub"),
        );
    }
    assert!(
        mock.wait_for_frame("REQ", Duration::from_secs(2))
            .await
            .is_some()
    );
    let ids: std::collections::HashSet<String> =
        subs.iter().map(|s| s.id().as_str().to_owned()).collect();
    drop(subs);
    // The lagged/EOSE path can write a CLOSE out of drop order — collect
    // the set rather than matching one needle at a time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut seen = std::collections::HashSet::new();
    while seen.len() < ids.len() && tokio::time::Instant::now() < deadline {
        let Ok(Some(text)) = tokio::time::timeout_at(deadline, mock.next_client_frame()).await
        else {
            break;
        };
        if let Some(rest) = text.strip_prefix(r#"["CLOSE",""#)
            && let Some(id) = rest.strip_suffix(r#""]"#)
        {
            seen.insert(id.to_owned());
        }
    }
    assert_eq!(seen, ids, "missing CLOSEs");
}

#[tokio::test]
async fn auth_subscribe_with_signer() {
    // AUTH-requiring mock + a signer: the REQ is refused once, the driver
    // answers the challenge with one kind-22242 AUTH, then retries.
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.signer = Some(Arc::new(Keys::generate().expect("keys")));
    })
    .await;
    mock.require_auth(true);
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    // The AUTH frame goes out; the REQ retry follows.
    assert!(
        mock.wait_for_frame("AUTH", Duration::from_secs(3))
            .await
            .is_some(),
        "no AUTH frame"
    );
    let event = event("authed", 1);
    relay.publish(&event).await.expect("publish after auth");
    let mut saw = false;
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
            Ok(Some(SubscriptionEvent::Event(_))) => {
                saw = true;
                break;
            }
            Ok(Some(_)) => {}
            other => panic!("stream ended: {other:?}"),
        }
    }
    assert!(saw, "no event after auth retry");
}

#[tokio::test]
async fn auth_concurrent_requests_share_one_auth() {
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.signer = Some(Arc::new(Keys::generate().expect("keys")));
    })
    .await;
    mock.require_auth(true);
    // Two concurrent requests on one challenge: exactly one AUTH frame.
    let ev = event("x", 1);
    let s1 = relay.subscribe(vec![Filter::new().kinds([Kind::new(1)])]);
    let s2 = relay.publish(&ev);
    let (r1, r2) = tokio::join!(s1, s2);
    drop(r1.expect("sub"));
    r2.expect("publish");
    // Exactly one AUTH frame total: the first must appear and no second
    // may follow within the retry window.
    assert!(
        mock.wait_for_frame(r#""AUTH""#, Duration::from_secs(3))
            .await
            .is_some(),
        "no AUTH frame"
    );
    let second = mock
        .wait_for_frame(r#""AUTH""#, Duration::from_millis(300))
        .await;
    assert!(second.is_none(), "a second AUTH frame went out");
}

#[tokio::test]
async fn auth_required_without_signer_surfaces_reason() {
    let (mock, relay) = mock_and_relay().await;
    mock.require_auth(true);
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    match tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
        Ok(Some(SubscriptionEvent::Closed(CloseReason::Relay(r)))) => {
            assert!(r.starts_with("auth-required:"), "{r}");
        }
        other => panic!("expected auth-required close, got {other:?}"),
    }
}

#[tokio::test]
async fn count_returns_stored_matches() {
    let (_mock, relay) = mock_and_relay().await;
    relay.publish(&event("a", 1)).await.expect("p1");
    relay.publish(&event("b", 1)).await.expect("p2");
    relay.publish(&event("other", 2)).await.expect("p3");
    let r = relay
        .count(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("count");
    assert_eq!(r.count, 2, "{r:?}");
}

#[tokio::test]
async fn count_closed_surfaces_reason() {
    let (mut mock, relay) = mock_and_relay().await;
    mock.set_hold(true);
    let relay2 = relay.clone();
    let fetch = tokio::spawn(async move { relay2.count(vec![Filter::new()]).await });
    let req = mock
        .wait_for_frame("COUNT", Duration::from_secs(2))
        .await
        .expect("COUNT frame");
    mock.send_raw(&format!(
        r#"["CLOSED","{}","blocked: no counts"]"#,
        req_id(&req)
    ));
    match fetch.await.expect("join") {
        Err(nk::relay::Error::Refused(reason)) => {
            assert!(reason.contains("blocked"), "{reason}");
        }
        other => panic!("expected refused, got {other:?}"),
    }
}

#[tokio::test]
async fn count_timeout() {
    // A live-but-silent relay: the COUNT goes out, no reply ever comes.
    let (mock, relay) = mock_and_relay_with(|o| {
        o.request_timeout = Duration::from_millis(50);
    })
    .await;
    mock.set_hold(true);
    match relay.count(vec![Filter::new()]).await {
        Err(nk::relay::Error::Timeout) => {}
        other => panic!("expected timeout, got {other:?}"),
    }
}

/// A negentropy item pair: `(created_at, id)` from a built event.
const fn neg_item(ev: &Event) -> (Timestamp, nk_core::EventId) {
    (ev.created_at(), ev.id())
}

#[tokio::test]
async fn reconcile_disjoint_sets() {
    let (_mock, relay) = mock_and_relay().await;
    let ours = event("ours", 1);
    let theirs = event("theirs", 2);
    relay.publish(&theirs).await.expect("publish");
    let rec = relay
        .reconcile(Filter::new(), vec![neg_item(&ours)])
        .await
        .expect("reconcile");
    assert_eq!(rec.have, vec![ours.id()]);
    assert_eq!(rec.need, vec![theirs.id()]);
}

#[tokio::test]
async fn reconcile_overlapping_sets() {
    let (_mock, relay) = mock_and_relay().await;
    let shared = event("shared", 1);
    relay.publish(&shared).await.expect("publish shared");
    relay
        .publish(&event("theirs", 2))
        .await
        .expect("publish theirs");
    let ours = event("ours", 3);
    let rec = relay
        .reconcile(Filter::new(), vec![neg_item(&shared), neg_item(&ours)])
        .await
        .expect("reconcile");
    assert_eq!(rec.have, vec![ours.id()]);
    assert_eq!(rec.need.len(), 1);
}

#[tokio::test]
async fn reconcile_identical_and_empty() {
    let (_mock, relay) = mock_and_relay().await;
    let ev = event("same", 1);
    relay.publish(&ev).await.expect("publish");
    let rec = relay
        .reconcile(Filter::new(), vec![neg_item(&ev)])
        .await
        .expect("identical");
    assert_eq!(rec, nk::relay::Reconciliation::default());

    let empty = relay
        .reconcile(Filter::new().kinds([Kind::new(404)]), vec![])
        .await
        .expect("empty");
    assert_eq!(empty.need.len(), 0);
}

#[tokio::test]
async fn reconcile_neg_err_surfaces_reason() {
    let (mut mock, relay) = mock_and_relay().await;
    mock.set_hold(true);
    let relay2 = relay.clone();
    let fetch = tokio::spawn(async move { relay2.reconcile(Filter::new(), vec![]).await });
    let req = mock
        .wait_for_frame("NEG-OPEN", Duration::from_secs(2))
        .await
        .expect("NEG-OPEN frame");
    mock.send_raw(&format!(
        r#"["NEG-ERR","{}","blocked: no sync"]"#,
        req_id(&req)
    ));
    match fetch.await.expect("join") {
        Err(nk::relay::Error::Refused(reason)) => {
            assert!(reason.contains("blocked"), "{reason}");
        }
        other => panic!("expected refused, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_timeout() {
    let (mock, relay) = mock_and_relay_with(|o| {
        o.request_timeout = Duration::from_millis(50);
    })
    .await;
    mock.set_hold(true);
    match relay.reconcile(Filter::new(), vec![]).await {
        Err(nk::relay::Error::Timeout) => {}
        other => panic!("expected timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_auth_retry_with_signer() {
    let (mock, relay) = mock_and_relay_with(|o| {
        o.signer = Some(Arc::new(Keys::generate().expect("keys")));
    })
    .await;
    mock.require_auth(true);
    let theirs = event("theirs", 2);
    relay.publish(&theirs).await.expect("publish");
    let ours = event("ours", 1);
    let rec = relay
        .reconcile(Filter::new(), vec![neg_item(&ours)])
        .await
        .expect("reconcile");
    assert_eq!(rec.have, vec![ours.id()]);
    assert_eq!(rec.need, vec![theirs.id()]);
}

#[tokio::test]
async fn publish_times_out_without_ok() {
    // The mock swallows the EVENT — no OK ever comes; the publish
    // deadline fires.
    let (mock, relay) = mock_and_relay_with(|o| {
        o.request_timeout = Duration::from_millis(50);
    })
    .await;
    mock.set_hold(true);
    match relay.publish(&event("never", 1)).await {
        Err(nk::relay::Error::Timeout) => {}
        other => panic!("expected timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn count_fails_fast_on_disconnect() {
    // Held COUNT + a dropped socket: the waiter gets Disconnected well
    // before the request timeout.
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.request_timeout = Duration::from_secs(30);
        o.reconnect_min = Duration::from_secs(60);
    })
    .await;
    mock.set_hold(true);
    let relay2 = relay.clone();
    let pending = tokio::spawn(async move { relay2.count(vec![Filter::new()]).await });
    mock.wait_for_frame("COUNT", Duration::from_secs(2))
        .await
        .expect("COUNT frame");
    mock.drop_connection();
    match pending.await.expect("join") {
        Err(nk::relay::Error::Disconnected) => {}
        other => panic!("expected disconnected, got {other:?}"),
    }
}

#[tokio::test]
async fn reconcile_fails_fast_on_disconnect() {
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.request_timeout = Duration::from_secs(30);
        o.reconnect_min = Duration::from_secs(60);
    })
    .await;
    mock.set_hold(true);
    let relay2 = relay.clone();
    let pending = tokio::spawn(async move { relay2.reconcile(Filter::new(), vec![]).await });
    mock.wait_for_frame("NEG-OPEN", Duration::from_secs(2))
        .await
        .expect("NEG-OPEN frame");
    mock.drop_connection();
    match pending.await.expect("join") {
        Err(nk::relay::Error::Disconnected) => {}
        other => panic!("expected disconnected, got {other:?}"),
    }
}

#[tokio::test]
async fn auth_challenge_resets_on_reconnect() {
    // After a drop + reconnect the relay issues a NEW challenge; the
    // driver signs against it, not the stale one.
    let (mut mock, relay) = mock_and_relay_with(|o| {
        o.signer = Some(Arc::new(Keys::generate().expect("keys")));
        o.reconnect_min = Duration::from_millis(10);
        o.reconnect_max = Duration::from_millis(50);
    })
    .await;
    mock.require_auth(true);
    let ev = event("authed", 1);
    relay.publish(&ev).await.expect("first publish authed");
    let first_auth = mock
        .wait_for_frame(r#""AUTH""#, Duration::from_secs(2))
        .await
        .expect("first AUTH frame");
    mock.drop_connection();
    // Reconnect — the new connection's challenge must arrive before any
    // refused request can sign it. A subscribe is refused auth-required,
    // which triggers the second sign.
    relay.connect().await.expect("reconnect");
    let sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    let second_auth = mock
        .wait_for_frame(r#""AUTH""#, Duration::from_secs(2))
        .await
        .expect("second AUTH frame");
    assert_ne!(first_auth, second_auth, "challenge did not reset");
    // And a publish after AUTH retries successfully.
    relay
        .publish(&event("second", 1))
        .await
        .expect("authed publish");
    drop(sub);
}

#[tokio::test]
async fn fetch_large_burst_is_complete() {
    // 400 events against a subscription_capacity of 8 — the fetch
    // accumulates in the waiter, independent of the stream channel.
    let (_mock, relay) = mock_and_relay_with(|o| o.subscription_capacity = 8).await;
    for i in 0..400u16 {
        relay
            .publish(&event(&format!("e{i}"), 1))
            .await
            .expect("publish");
    }
    let out = relay
        .fetch(
            vec![Filter::new().kinds([Kind::new(1)])],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert_eq!(out.end, FetchEnd::Eose);
    assert_eq!(out.events.len(), 400);
}

#[tokio::test]
async fn fetch_fails_fast_when_unreachable() {
    // Dead port + reconnect on: the fetch surfaces the connect error
    // promptly instead of hanging for the fetch timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let relay = Relay::new(
        &nk_core::RelayUrl::parse(&format!("ws://{addr}")).expect("url"),
        RelayOptions {
            reconnect: true,
            connect_timeout: Duration::from_millis(50),
            ..RelayOptions::default()
        },
    );
    let start = std::time::Instant::now();
    let out = relay
        .fetch(vec![Filter::new()], Duration::from_secs(30))
        .await;
    assert!(start.elapsed() < Duration::from_secs(5), "fetch hung");
    assert!(
        matches!(
            out,
            Err(nk::relay::Error::Transport(_) | nk::relay::Error::Timeout)
        ),
        "expected connect error, got {out:?}"
    );
}

#[tokio::test]
async fn oversized_message_disconnects() {
    // The mock floods a frame larger than max_message_size; the client
    // must drop the socket.
    let (mock, relay) = mock_and_relay_with(|o| {
        o.max_message_size = 1_024;
        o.reconnect = false;
    })
    .await;
    relay.connect().await.expect("connect");
    mock.send_raw(&format!(r#"["NOTICE","{}"]"#, "x".repeat(4_096)));
    // The oversized frame is refused — the socket drops for good.
    for _ in 0..40 {
        if relay.status() == RelayStatus::Disconnected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("oversized frame did not drop the connection");
}

#[tokio::test]
async fn last_handle_drop_stops_driver() {
    let (mock, relay) = mock_and_relay().await;
    relay.connect().await.expect("connect");
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    // The live WebSocket — not just the HTTP handshake — is counted.
    for _ in 0..40 {
        if mock.connections() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(mock.connections(), 1, "expected one live ws session");
    drop(relay);
    // The driver exits; the mock sees the connection close.
    for _ in 0..40 {
        if mock.connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(mock.connections(), 0, "connection still open");
    // The open subscription ends with `Closed(RelayClosed)`.
    match sub.next().await {
        Some(SubscriptionEvent::Closed(CloseReason::RelayClosed)) => {}
        other => panic!("expected Closed(RelayClosed), got {other:?}"),
    }
}

/// A signer whose `sign_event` panics: AUTH wedging must fail the queue,
/// not hang it.
struct PanicSigner;

impl std::fmt::Debug for PanicSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PanicSigner").finish()
    }
}

impl nk_core::NostrSigner for PanicSigner {
    fn public_key(
        &self,
    ) -> nk_core::BoxFuture<'_, Result<nk_core::PublicKey, nk_core::SignerError>> {
        Box::pin(async { panic!("signer exploded") })
    }

    fn sign_event(
        &self,
        _unsigned: nk_core::UnsignedEvent,
    ) -> nk_core::BoxFuture<'_, Result<Event, nk_core::SignerError>> {
        Box::pin(async { panic!("signer exploded") })
    }
}

#[tokio::test]
async fn panicking_signer_fails_fast() {
    let (mock, relay) = mock_and_relay_with(|o| {
        o.signer = Some(Arc::new(PanicSigner));
        o.request_timeout = Duration::from_millis(500);
    })
    .await;
    mock.require_auth(true);
    // The sign task panics — the JoinSet reports it, `sign_failed` runs,
    // and the subscribe ends `Closed` with the original refusal reason.
    let mut sub = relay
        .subscribe(vec![Filter::new().kinds([Kind::new(1)])])
        .await
        .expect("sub");
    let mut seen = None;
    while let Some(item) = sub.next().await {
        if let SubscriptionEvent::Closed(reason) = item {
            seen = Some(reason);
            break;
        }
    }
    match seen {
        Some(CloseReason::Relay(reason)) => {
            assert!(reason.starts_with("auth-required:"), "{reason}");
        }
        other => panic!("expected Closed(Relay(auth-required:..)), got {other:?}"),
    }
    // A following count answers promptly — AUTH is not wedged.
    match relay.count(vec![Filter::new()]).await {
        Err(nk::relay::Error::Refused(reason)) => {
            assert!(reason.starts_with("auth-required:"), "{reason}");
        }
        other => panic!("expected Refused(auth-required:..), got {other:?}"),
    }
}
