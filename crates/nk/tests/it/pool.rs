//! `RelayPool` tests against `testing::MockRelay`.

use super::*;
use nk::gossip::{Gossip, GossipOptions};
use nk::pool::{PoolEvent, RelayPool};
use nk::relay::{Error as RelayError, Reconciliation};
use nk_core::rand_core::UnwrapErr;
use nk_core::{EventBuilder, SecretKey, SysRng, Tag, Timestamp};
use nk_store::EventStore;
use std::collections::BTreeSet;

async fn pool(f: impl Fn(&mut RelayOptions)) -> (MockRelay, MockRelay, RelayPool) {
    let mock_a = MockRelay::start().await.expect("mock a");
    let mock_b = MockRelay::start().await.expect("mock b");
    let mut options = RelayOptions::default();
    f(&mut options);
    (mock_a, mock_b, RelayPool::new(options))
}

fn urls(a: &MockRelay, b: &MockRelay) -> [nk_core::RelayUrl; 2] {
    [a.url(), b.url()]
}

#[tokio::test]
async fn relay_is_shared_per_url() {
    let (mock, _mock_b, pool) = pool(|_| {}).await;
    let base = mock.url();
    // A differently-spelled-but-equal URL hits the same relay.
    let upper =
        nk_core::RelayUrl::parse(&base.as_str().to_uppercase().replacen("WS://", "ws://", 1))
            .expect("upper url");
    let r1 = pool.relay(&base);
    let r2 = pool.relay(&upper);
    r1.connect().await.expect("connect");
    r2.connect().await.expect("connect2");
    assert_eq!(mock.connections(), 1);
}

#[tokio::test]
async fn closed_relay_is_replaced() {
    let (mock, _mock_b, pool) = pool(|_| {}).await;
    let first = pool.relay(&mock.url());
    first.close().await;
    let second = pool.relay(&mock.url());
    let out = second.publish(&event("after", 1)).await.expect("publish");
    assert!(out.accepted);
}

#[tokio::test]
async fn fetch_merges_and_dedups() {
    let (mock_a, mock_b, pool) = pool(|_| {}).await;
    let x = event("x", 1);
    let y = event("y", 1);
    let z = event("z", 1);
    mock_a.store().put(&x).expect("seed x");
    mock_a.store().put(&y).expect("seed y");
    mock_b.store().put(&x).expect("seed x");
    mock_b.store().put(&z).expect("seed z");
    let out = pool
        .fetch(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert_eq!(out.events.len(), 3);
    let mut sorted = out.events.clone();
    sorted.sort_by(Event::cmp_newest_first);
    assert_eq!(out.events, sorted);
    assert!(out.relays.values().all(|r| matches!(r, Ok(FetchEnd::Eose))));
}

#[tokio::test]
async fn fetch_isolates_failing_relay() {
    let (mock_a, _mock_b, pool) = pool(|o| o.reconnect = false).await;
    mock_a.store().put(&event("live", 1)).expect("seed");
    let dead = dead_url().await;
    let out = pool
        .fetch(
            &[mock_a.url(), dead.clone()],
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert_eq!(out.events.len(), 1);
    assert!(matches!(out.relays[&mock_a.url()], Ok(FetchEnd::Eose)));
    assert!(out.relays[&dead].is_err());
}

#[tokio::test]
async fn publish_reports_per_relay() {
    let (mock_a, mock_b, pool) = pool(|o| o.reconnect = false).await;
    let dead = dead_url().await;
    let ev = event("pub", 1);
    let out = pool
        .publish(&[mock_a.url(), mock_b.url(), dead.clone()], &ev)
        .await;
    assert_eq!(out.len(), 3);
    assert!(out[&mock_a.url()].as_ref().is_ok_and(|o| o.accepted));
    assert!(out[&mock_b.url()].as_ref().is_ok_and(|o| o.accepted));
    assert!(out[&dead].is_err());
}

#[tokio::test]
async fn count_and_reconcile_per_relay() {
    let (mock_a, mock_b, pool) = pool(|_| {}).await;
    let e1 = event("one", 1);
    let e2 = event("two", 1);
    mock_a.store().put(&e1).expect("seed");
    mock_b.store().put(&e1).expect("seed");
    mock_b.store().put(&e2).expect("seed");
    let counts = pool
        .count(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("count");
    assert_eq!(counts[&mock_a.url()].as_ref().expect("a").count, 1);
    assert_eq!(counts[&mock_b.url()].as_ref().expect("b").count, 2);
    // Empty on both sides — an exact sync result.
    let out = pool
        .reconcile(
            &urls(&mock_a, &mock_b),
            Filter::new().kinds([Kind::new(1)]).expect("filter"),
            vec![],
        )
        .await;
    assert!(out.values().all(
        |r| matches!(r, Ok(Reconciliation { have, need }) if have.is_empty() && !need.is_empty())
    ));
}

#[tokio::test]
async fn empty_filters_rejected() {
    let (mock_a, _mock_b, pool) = pool(|_| {}).await;
    let urls = [mock_a.url()];
    assert!(matches!(
        pool.subscribe(&urls, vec![]).await,
        Err(RelayError::InvalidFilters)
    ));
    assert!(matches!(
        pool.fetch(&urls, vec![], Duration::from_secs(1)).await,
        Err(RelayError::InvalidFilters)
    ));
    assert!(matches!(
        pool.count(&urls, vec![]).await,
        Err(RelayError::InvalidFilters)
    ));
}

#[tokio::test]
async fn subscribe_dedups_and_aggregates_eose() {
    let (mock_a, mock_b, pool) = pool(|_| {}).await;
    let x = event("x", 1);
    mock_a.store().put(&x).expect("seed");
    mock_b.store().put(&x).expect("seed");
    let mut sub = pool
        .subscribe(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("sub");
    let mut events = 0;
    let mut eoses = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(3), sub.next())
            .await
            .expect("item")
        {
            Some(PoolEvent::Event { .. }) => events += 1,
            Some(PoolEvent::Eose) => {
                eoses += 1;
                break;
            }
            Some(_) => {}
            None => panic!("stream ended before Eose"),
        }
    }
    assert_eq!(events, 1, "one deduped event");
    assert_eq!(eoses, 1, "one aggregate eose");
    // Live event — one more Event, no second Eose.
    let w = event("w", 1);
    pool.publish(&urls(&mock_a, &mock_b), &w).await;
    match tokio::time::timeout(Duration::from_secs(2), sub.next())
        .await
        .expect("w")
    {
        Some(PoolEvent::Event { event, .. }) => assert_eq!(event.id(), w.id()),
        other => panic!("expected live event, got {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(200), sub.next())
            .await
            .is_err(),
        "no second Eose"
    );
}

#[tokio::test]
async fn subscribe_eose_waits_for_every_relay() {
    let (mut mock_a, mock_b, pool) = pool(|_| {}).await;
    let x = event("x", 1);
    mock_b.store().put(&x).expect("seed");
    mock_a.set_hold(true);
    let mut sub = pool
        .subscribe(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("sub");
    // A's REQ must arrive (held) before we judge anything.
    let req = mock_a
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("a req");
    // Drain every item until a 300ms quiet period — a premature
    // aggregate `Eose` would surface inside this loop.
    loop {
        match tokio::time::timeout(Duration::from_millis(300), sub.next()).await {
            Err(_) => break,
            Ok(Some(PoolEvent::Eose)) => {
                panic!("aggregate EOSE before every relay answered");
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("stream ended while A is still open"),
        }
    }
    mock_a.send_raw(&format!(r#"["EOSE","{}"]"#, req_id(&req)));
    mock_a.set_hold(false);
    let mut got_eose = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("item")
        {
            Some(PoolEvent::Eose) => {
                got_eose = true;
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(got_eose, "aggregate Eose after every relay answered");
}

#[tokio::test]
async fn subscribe_opens_relays_concurrently() {
    // Two blackholes: TCP accepts, the WS handshake is never answered —
    // each connect stalls for `connect_timeout`. Concurrent opens take
    // ~300ms; sequential would be >= 600ms.
    let (url_a, _hold_a) = blackhole_url().await;
    let (url_b, _hold_b) = blackhole_url().await;
    let pool = RelayPool::new({
        let mut o = RelayOptions::default();
        o.reconnect = false;
        o.connect_timeout = Duration::from_millis(300);
        o
    });
    let start = std::time::Instant::now();
    let mut sub = pool
        .subscribe(&[url_a, url_b], vec![Filter::new()])
        .await
        .expect("sub");
    let mut failed = 0;
    while let Some(item) = sub.next().await {
        if let PoolEvent::Failed { .. } = item {
            failed += 1;
        }
    }
    assert_eq!(failed, 2, "both relays failed");
    assert!(
        start.elapsed() < Duration::from_millis(550),
        "sequential opens: {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn subscribe_relay_closed_then_stream_ends() {
    let (mut mock_a, mock_b, pool) = pool(|_| {}).await;
    let mut sub = pool
        .subscribe(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("sub");
    let req_a = mock_a
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("a req");
    mock_a.send_raw(&format!(r#"["CLOSED","{}","blocked: no"]"#, req_id(&req_a)));
    let mut saw_closed_a = false;
    let mut saw_closed_b = false;
    let mut saw_eose = false;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("item")
        {
            Some(PoolEvent::Closed { relay, reason }) if relay == mock_a.url() => {
                assert!(matches!(reason, CloseReason::Relay(_)));
                saw_closed_a = true;
            }
            Some(PoolEvent::Closed { relay, reason }) if relay == mock_b.url() => {
                assert_eq!(reason, CloseReason::RelayClosed);
                saw_closed_b = true;
            }
            Some(PoolEvent::Eose) => saw_eose = true,
            Some(_) => {}
            None => break,
        }
        // Close only once the aggregate Eose has already surfaced —
        // otherwise a late Eose can legitimately queue behind Closed(B)
        // and the post-break `None` check races.
        if saw_closed_a && saw_eose && !saw_closed_b {
            pool.close().await;
        }
        if saw_closed_b {
            break;
        }
    }
    assert!(saw_closed_a && saw_closed_b);
    // Both relays are closed — the merged stream must end.
    assert!(sub.next().await.is_none());
}

#[tokio::test]
async fn subscribe_reports_failed_relay() {
    let (mock_a, _mock_b, pool) = pool(|o| o.reconnect = false).await;
    mock_a.store().put(&event("x", 1)).expect("seed");
    let dead = dead_url().await;
    let mut sub = pool
        .subscribe(
            &[mock_a.url(), dead.clone()],
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("sub");
    match sub.next().await {
        Some(PoolEvent::Failed { relay, error }) => {
            assert_eq!(relay, dead);
            drop(error);
        }
        other => panic!("expected Failed first, got {other:?}"),
    }
    let mut got_event = false;
    let mut got_eose = false;
    for _ in 0..6 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("item")
        {
            Some(PoolEvent::Event { .. }) => got_event = true,
            Some(PoolEvent::Eose) => {
                got_eose = true;
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(got_event && got_eose);
}

#[tokio::test]
async fn drop_pool_subscription_closes_every_relay() {
    let (mut mock_a, mut mock_b, pool) = pool(|_| {}).await;
    let sub = pool
        .subscribe(
            &urls(&mock_a, &mock_b),
            vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
        )
        .await
        .expect("sub");
    let req_a = mock_a
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("a req");
    let req_b = mock_b
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("b req");
    drop(sub);
    let closes: [(MockRelay, String); 2] = [(mock_a, req_a), (mock_b, req_b)];
    for (mut mock, req) in closes {
        let needle = format!(r#"CLOSE","{}"#, req_id(&req));
        mock.wait_for_frame(&needle, Duration::from_secs(3))
            .await
            .unwrap_or_else(|| panic!("CLOSE for {} not received", req_id(&req)));
    }
}

#[tokio::test]
async fn remove_and_statuses() {
    let (mock_a, mock_b, pool) = pool(|_| {}).await;
    drop(pool.relay(&mock_a.url()));
    drop(pool.relay(&mock_b.url()));
    let map = pool.statuses();
    assert_eq!(map.keys().collect::<BTreeSet<_>>().len(), 2);
    assert!(pool.remove(&mock_a.url()).await);
    assert!(!pool.statuses().contains_key(&mock_a.url()));
    assert!(!pool.remove(&mock_a.url()).await);
}

#[tokio::test]
async fn fetch_routed_sends_per_relay_filters() {
    let (mut mock_a, mut mock_b, pool) = pool(|_| {}).await;
    let x = event("x", 1);
    let z = event("z", 7);
    mock_a.store().put(&x).expect("seed");
    mock_b.store().put(&z).expect("seed");
    // Plan: A gets kind 1, B gets kind 7 — each relay sees only its own.
    let mut plan = std::collections::BTreeMap::new();
    plan.insert(
        mock_a.url(),
        vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
    );
    plan.insert(
        mock_b.url(),
        vec![Filter::new().kinds([Kind::new(7)]).expect("filter")],
    );
    let out = pool.fetch_routed(plan, Duration::from_secs(5)).await;
    let req_a = mock_a
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("a req");
    let req_b = mock_b
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("b req");
    assert!(req_a.contains(r#""kinds":[1]"#), "{req_a}");
    assert!(req_b.contains(r#""kinds":[7]"#), "{req_b}");
    let mut ids: Vec<_> = out.events.iter().map(Event::id).collect();
    ids.sort();
    let mut want = vec![x.id(), z.id()];
    want.sort();
    assert_eq!(ids, want);
    assert!(out.relays.values().all(|r| matches!(r, Ok(FetchEnd::Eose))));
}

#[tokio::test]
async fn subscribe_routed_empty_list_fails_that_relay() {
    let (mock_a, mock_b, pool) = pool(|_| {}).await;
    mock_a.store().put(&event("x", 1)).expect("seed");
    let mut plan = std::collections::BTreeMap::new();
    plan.insert(
        mock_a.url(),
        vec![Filter::new().kinds([Kind::new(1)]).expect("filter")],
    );
    plan.insert(mock_b.url(), vec![]);
    let mut sub = pool.subscribe_routed(plan).await;
    let mut got_failed = false;
    let mut got_event = false;
    let mut got_eose = false;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("item")
        {
            Some(PoolEvent::Failed { relay, error }) if relay == mock_b.url() => {
                assert!(matches!(error, RelayError::InvalidFilters));
                got_failed = true;
            }
            Some(PoolEvent::Event { .. }) => got_event = true,
            Some(PoolEvent::Eose) => {
                got_eose = true;
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(got_failed && got_event && got_eose);
}

#[tokio::test]
async fn gossip_route_drives_routed_fetch() {
    let (mut mock_a, mock_b, pool) = pool(|_| {}).await;
    // Author X (signs with [7;32]) has a 10002 pointing at A; author
    // Y (the shared keys, [9;32]) is unknown.
    let xk = Keys::new(SecretKey::from_bytes([7; 32]).expect("key"));
    let x = xk
        .sign_event(
            EventBuilder::new(Kind::new(1), "x")
                .build_at(xk.public_key(), Timestamp::from_secs(1_700_000_000)),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign x");
    let y = event("y", 1);
    mock_a.store().put(&x).expect("seed x");
    mock_b.store().put(&y).expect("seed y");
    let list = xk
        .sign_event(
            EventBuilder::new(Kind::new(10002), "")
                .tags([Tag::custom("r", [mock_a.url().as_str()])])
                .build_at(xk.public_key(), Timestamp::from_secs(1_700_000_000)),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign");
    let x_pub = xk.public_key();
    let mut g = Gossip::new({
        let mut o = GossipOptions::default();
        o.allow_insecure = true;
        o
    });
    assert!(g.ingest(&list));
    let y_pub = Keys::new(SecretKey::from_bytes([9; 32]).expect("key")).public_key();
    let routing = g.route(&[Filter::new().authors([x_pub, y_pub]).expect("filter")]);
    let plan = routing.with_fallback(&[mock_b.url()]).expect("plan");
    assert!(plan.contains_key(&mock_a.url()), "X routes to A");
    assert!(plan.contains_key(&mock_b.url()), "Y falls back to B");
    let out = pool.fetch_routed(plan, Duration::from_secs(5)).await;
    assert_eq!(out.events.len(), 2);
    let req_a = mock_a
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("a req");
    assert!(req_a.contains(&x_pub.to_hex()), "A's REQ carries X only");
    assert!(!req_a.contains(&y_pub.to_hex()), "A's REQ must not carry Y");
}
