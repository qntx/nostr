//! `Client` integration tests — mocks via `testing::MockRelay`.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use nk::client::{Client, ClientOptions, Error as ClientError};
use nk::store::EventStore;
use nk::testing::MockRelay;
use nk_core::{
    Event, EventBuilder, EventId, Filter, Keys, Kind, RelayUrl, SecretKey, SysRng, Tag, Timestamp,
    rand_core::UnwrapErr,
};

use crate::keys;

fn signing_keys(n: u8) -> Keys {
    Keys::new(SecretKey::from_bytes([n; 32]).expect("key"))
}

fn sign(k: &Keys, builder: EventBuilder, at: Timestamp) -> Event {
    k.sign_event(builder.build_at(k.public_key(), at), &mut UnwrapErr(SysRng))
        .expect("sign")
}

fn relay_list(k: &Keys, at: Timestamp, entries: &[(&RelayUrl, &str)]) -> Event {
    sign(
        k,
        EventBuilder::new(Kind::RELAY_LIST, "").tags(
            entries
                .iter()
                .map(|(u, m)| Tag::custom("r", [u.as_str(), *m])),
        ),
        at,
    )
}

fn dm_list(k: &Keys, at: Timestamp, urls: &[&RelayUrl]) -> Event {
    sign(
        k,
        EventBuilder::new(Kind::DIRECT_MESSAGE_RELAYS_LIST, "")
            .tags(urls.iter().map(|u| Tag::custom("relay", [u.as_str()]))),
        at,
    )
}

fn client(relays: Vec<RelayUrl>, f: impl Fn(&mut ClientOptions)) -> Client {
    let mut options = ClientOptions::default();
    options.relays = relays;
    options.gossip.allow_insecure = true;
    f(&mut options);
    Client::new(options)
}

const T: Timestamp = Timestamp::from_secs(1_700_000_000);

#[tokio::test]
async fn publish_targets_outbox_inbox_and_defaults() {
    let mut mock_a = MockRelay::start().await.expect("a");
    let mut mock_b = MockRelay::start().await.expect("b");
    let mut mock_d = MockRelay::start().await.expect("d");
    let author = signing_keys(7);
    let recip = signing_keys(8);
    let client = client(vec![mock_d.url()], |_| {});
    // Observe the routing lists: X writes at A, R reads at B.
    client
        .observe(&relay_list(&author, T, &[(&mock_a.url(), "write")]))
        .await
        .expect("observe X");
    client
        .observe(&relay_list(&recip, T, &[(&mock_b.url(), "read")]))
        .await
        .expect("observe R");
    let note = sign(
        &author,
        EventBuilder::new(Kind::new(1), "hi").tags([Tag::public_key(
            recip.public_key(),
            None,
            None,
        )]),
        T,
    );
    let out = client.publish(&note).await.expect("publish");
    assert!(
        out.values().all(|r| matches!(r, Ok(o) if o.accepted)),
        "{out:?}"
    );
    for (mock, name) in [(&mut mock_a, "A"), (&mut mock_b, "B"), (&mut mock_d, "D")] {
        let frame = mock
            .wait_for_frame("EVENT", Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{name} got no EVENT"));
        assert!(frame.contains(&note.id().to_hex()), "{name}: {frame}");
    }
    client.flush().await.expect("flush");
    let stored = client.query(vec![Filter::new()]).await.expect("query");
    assert!(stored.iter().any(|e| e.id() == note.id()));
}

#[tokio::test]
async fn publish_without_targets_is_no_relays() {
    let c = client(vec![], |_| {});
    let ev = sign(&keys(), EventBuilder::new(Kind::new(1), "x"), T);
    assert!(matches!(c.publish(&ev).await, Err(ClientError::NoRelays)));
}

#[tokio::test]
async fn fetch_routes_known_author_and_falls_back() {
    let mock_a = MockRelay::start().await.expect("a");
    let mut mock_d = MockRelay::start().await.expect("d");
    let author_x = signing_keys(7);
    let author_y = signing_keys(9);
    let x_ev = sign(&author_x, EventBuilder::new(Kind::new(1), "from-x"), T);
    let y_ev = sign(&author_y, EventBuilder::new(Kind::new(1), "from-y"), T);
    mock_a.store().put(&x_ev).expect("seed x");
    mock_d.store().put(&y_ev).expect("seed y");
    let client = client(vec![mock_d.url()], |_| {});
    client
        .observe(&relay_list(&author_x, T, &[(&mock_a.url(), "write")]))
        .await
        .expect("observe");
    let out = client
        .fetch(
            vec![
                Filter::new()
                    .authors([author_x.public_key(), author_y.public_key()])
                    .expect("filter"),
            ],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    let mut ids: Vec<_> = out.events.iter().map(Event::id).collect();
    ids.sort();
    let mut want = [x_ev.id(), y_ev.id()];
    want.sort();
    assert_eq!(ids, want);
    client.flush().await.expect("flush");
    let stored = client.query(vec![Filter::new()]).await.expect("query");
    assert!(stored.iter().any(|e| e.id() == x_ev.id()));
    assert!(stored.iter().any(|e| e.id() == y_ev.id()));
    // D's REQ carried only Y (the unrouted author).
    let req = mock_d
        .wait_for_frame("REQ", Duration::from_secs(2))
        .await
        .expect("d req");
    assert!(req.contains(&author_y.public_key().to_hex()), "{req}");
    assert!(!req.contains(&author_x.public_key().to_hex()), "{req}");
}

#[tokio::test]
async fn hydrate_loads_lists_from_defaults() {
    let mock_a = MockRelay::start().await.expect("a");
    let mock_d = MockRelay::start().await.expect("d");
    let author_x = signing_keys(7);
    mock_d
        .store()
        .put(&relay_list(&author_x, T, &[(&mock_a.url(), "write")]))
        .expect("seed 10002");
    mock_d
        .store()
        .put(&dm_list(&author_x, T, &[&mock_a.url()]))
        .expect("seed 10050");
    let c = client(vec![mock_d.url()], |_| {});
    c.hydrate(&[author_x.public_key()], Duration::from_secs(5))
        .await
        .expect("hydrate");
    let routes = c.routes(&author_x.public_key()).expect("routes");
    assert_eq!(routes.write(), &[mock_a.url()]);
    assert_eq!(routes.dm(), &[mock_a.url()]);
}

#[tokio::test]
async fn observe_rejects_invalid_signature() {
    let c = client(vec![], |_| {});
    // Tamper with a signed event's content — id and sig no longer
    // match, so verification fails.
    let ev = sign(&keys(), EventBuilder::new(Kind::new(1), "ok"), T);
    let bad =
        Event::from_json(&ev.to_json().replace(r#""ok""#, r#""tampered""#)).expect("deserialize");
    assert!(matches!(
        c.observe(&bad).await,
        Err(ClientError::InvalidEvent)
    ));
}

#[tokio::test]
async fn sign_requires_signer() {
    let c = client(vec![], |_| {});
    assert!(matches!(
        c.sign(EventBuilder::new(Kind::new(1), "x")).await,
        Err(ClientError::NoSigner)
    ));
    let k: Arc<dyn nk_core::NostrSigner> = Arc::new(signing_keys(7));
    let authed = client(vec![], move |o| o.signer = Some(Arc::clone(&k)));
    let signed = authed
        .sign(EventBuilder::new(Kind::new(1), "x"))
        .await
        .expect("sign");
    signed.verify().expect("verified");
    assert_eq!(signed.pubkey(), signing_keys(7).public_key());
}

#[tokio::test]
async fn persist_false_leaves_store_empty() {
    let d = MockRelay::start().await.expect("d");
    let ev = sign(&keys(), EventBuilder::new(Kind::new(1), "x"), T);
    d.store().put(&ev).expect("seed");
    let c = client(vec![d.url()], |o| o.persist = false);
    c.fetch(vec![Filter::new()], Duration::from_secs(5))
        .await
        .expect("fetch");
    let stored = c.query(vec![Filter::new()]).await.expect("query");
    assert_eq!(stored, Vec::<Event>::new());
}

#[tokio::test]
async fn closed_client_rejects_calls() {
    let c = client(vec![], |_| {});
    c.close().await;
    let ev = sign(&keys(), EventBuilder::new(Kind::new(1), "x"), T);
    assert!(matches!(
        c.fetch(vec![Filter::new()], Duration::from_secs(1)).await,
        Err(ClientError::Closed)
    ));
    assert!(matches!(c.publish(&ev).await, Err(ClientError::Closed)));
    assert!(matches!(
        c.hydrate(&[keys().public_key()], Duration::from_secs(1))
            .await,
        Err(ClientError::Closed)
    ));
}

#[tokio::test]
async fn insecure_gossip_url_falls_back() {
    let mock_a = MockRelay::start().await.expect("a");
    let mock_d = MockRelay::start().await.expect("d");
    let author_x = signing_keys(7);
    let x_ev = sign(&author_x, EventBuilder::new(Kind::new(1), "x"), T);
    mock_d.store().put(&x_ev).expect("seed");
    // allow_insecure: false — X's ws:// list is dropped, fetch falls
    // back to the default D.
    let mut options = ClientOptions::default();
    options.relays = vec![mock_d.url()];
    options.gossip.allow_insecure = false;
    let c = Client::new(options);
    c.observe(&relay_list(&author_x, T, &[(&mock_a.url(), "write")]))
        .await
        .expect("observe");
    let out = c
        .fetch(
            vec![
                Filter::new()
                    .authors([author_x.public_key()])
                    .expect("filter"),
            ],
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert!(out.events.iter().any(|e| e.id() == x_ev.id()));
    assert!(out.relays.contains_key(&mock_d.url()), "default relay used");
}

#[tokio::test]
async fn subscribe_routes_and_ingests_live() {
    let mut mock_a = MockRelay::start().await.expect("a");
    let mock_d = MockRelay::start().await.expect("d");
    let author_x = signing_keys(7);
    let client = client(vec![mock_d.url()], |_| {});
    client
        .observe(&relay_list(&author_x, T, &[(&mock_a.url(), "write")]))
        .await
        .expect("observe");
    let mut sub = client
        .subscribe(vec![
            Filter::new()
                .authors([author_x.public_key()])
                .expect("filter"),
        ])
        .await
        .expect("subscribe");
    // Only A got the REQ (X is routed; the default sees nothing).
    let req = mock_a
        .wait_for_frame("REQ", Duration::from_secs(5))
        .await
        .expect("a req");
    assert!(req.contains(&author_x.public_key().to_hex()), "{req}");
    // Publish through the pool onto A — the live stream yields it.
    let note = sign(&author_x, EventBuilder::new(Kind::new(1), "live"), T);
    client.pool().publish(&[mock_a.url()], &note).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, sub.next()).await {
            Ok(Some(nk::pool::PoolEvent::Event { event, .. })) => {
                assert_eq!(event.id(), note.id());
                break;
            }
            Ok(Some(_)) => {} // Eose / relay ends — keep polling
            _ => panic!("stream ended without the event"),
        }
    }
    client.flush().await.expect("flush");
    let stored = client.query(vec![Filter::new()]).await.expect("query");
    assert!(stored.iter().any(|e| e.id() == note.id()));
}

#[tokio::test]
async fn subscribe_ingests_relay_list_into_gossip() {
    let mock_d = MockRelay::start().await.expect("d");
    let author_x = signing_keys(7);
    let client = client(vec![mock_d.url()], |_| {});
    let mut sub = client
        .subscribe_to(
            [&mock_d.url()],
            vec![Filter::new().kinds([Kind::RELAY_LIST]).expect("filter")],
        )
        .await
        .expect("subscribe");
    // A live 10002 through the stream updates routes() with no observe.
    let list = relay_list(&author_x, T, &[(&mock_d.url(), "write")]);
    client.pool().publish(&[mock_d.url()], &list).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            client
                .routes(&author_x.public_key())
                .is_none_or(|r| r.write().is_empty())
                || client
                    .routes(&author_x.public_key())
                    .is_some_and(|r| r.write() == [mock_d.url()])
        );
        if client
            .routes(&author_x.public_key())
            .is_some_and(|r| r.write() == [mock_d.url()])
        {
            break;
        }
        match tokio::time::timeout_at(deadline, sub.next()).await {
            Ok(Some(_)) => {}
            _ => panic!("stream ended before the list arrived"),
        }
    }
    assert_eq!(
        client
            .routes(&author_x.public_key())
            .expect("routes")
            .write(),
        [mock_d.url()]
    );
}

#[tokio::test]
async fn subscribe_closed_and_empty_errors() {
    let client = client(vec![], |_| {});
    assert!(matches!(
        client.subscribe(vec![]).await,
        Err(ClientError::InvalidFilters)
    ));
    assert!(matches!(
        client.subscribe(vec![Filter::new()]).await,
        Err(ClientError::NoRelays)
    ));
    assert!(matches!(
        client
            .subscribe_to(std::iter::empty::<&RelayUrl>(), vec![Filter::new()])
            .await,
        Err(ClientError::NoRelays)
    ));
    client.close().await;
    assert!(matches!(
        client.subscribe(vec![Filter::new()]).await,
        Err(ClientError::Closed)
    ));
}

fn ids(events: &[Event]) -> Vec<EventId> {
    let mut v: Vec<_> = events.iter().map(Event::id).collect();
    v.sort();
    v
}

#[tokio::test]
async fn sync_down_downloads_missing() {
    let mock = MockRelay::start().await.expect("mock");
    let ev_a = sign(&keys(), EventBuilder::new(Kind::new(1), "a"), T);
    let ev_b = sign(&keys(), EventBuilder::new(Kind::new(1), "b"), T);
    mock.store().put(&ev_a).expect("a");
    mock.store().put(&ev_b).expect("b");
    let client = client(vec![mock.url()], |_| {});
    let report = client
        .sync_with(
            &mock.url(),
            Filter::new(),
            nk::client::SyncOptions::default(),
        )
        .await
        .expect("sync");
    let want = ids(&[ev_a.clone(), ev_b.clone()]);
    assert_eq!(ids(&[]), ids(&[]));
    let mut got_need = report.need.clone();
    got_need.sort();
    let mut got_recv = report.received.clone();
    got_recv.sort();
    assert_eq!(got_need, want);
    assert_eq!(got_recv, want);
    assert_eq!(report.have, Vec::<EventId>::new());
    let stored = client.query(vec![Filter::new()]).await.expect("query");
    assert_eq!(ids(&stored), want);
}

#[tokio::test]
async fn sync_up_uploads_local_only() {
    let mock = MockRelay::start().await.expect("mock");
    let ev_c = sign(&keys(), EventBuilder::new(Kind::new(1), "c"), T);
    let client = client(vec![mock.url()], |_| {});
    client.store().put(&ev_c).expect("put");
    let mut options = nk::client::SyncOptions::default();
    options.direction = nk::client::SyncDirection::Up;
    let report = client
        .sync_with(&mock.url(), Filter::new(), options)
        .await
        .expect("sync");
    assert_eq!(report.sent, vec![ev_c.id()]);
    assert_eq!(report.received, Vec::<EventId>::new());
    assert_eq!(
        mock.store().query(&[Filter::new()]).expect("q").len(),
        1,
        "mock has C"
    );
}

#[tokio::test]
async fn sync_both_exchanges() {
    let mock = MockRelay::start().await.expect("mock");
    let ev_a = sign(&keys(), EventBuilder::new(Kind::new(1), "a"), T);
    let ev_c = sign(&keys(), EventBuilder::new(Kind::new(1), "c"), T);
    mock.store().put(&ev_a).expect("a");
    let client = client(vec![mock.url()], |_| {});
    client.store().put(&ev_c).expect("put");
    let mut options = nk::client::SyncOptions::default();
    options.direction = nk::client::SyncDirection::Both;
    let report = client
        .sync_with(&mock.url(), Filter::new(), options)
        .await
        .expect("sync");
    assert_eq!(report.sent, vec![ev_c.id()]);
    assert_eq!(report.received, vec![ev_a.id()]);
    let stored = client.query(vec![Filter::new()]).await.expect("query");
    assert!(stored.iter().any(|e| e.id() == ev_a.id()));
    assert!(
        mock.store()
            .query(&[Filter::new()])
            .expect("q")
            .iter()
            .any(|e| e.id() == ev_c.id())
    );
}

#[tokio::test]
async fn sync_dry_run_transfers_nothing() {
    let mock = MockRelay::start().await.expect("mock");
    let ev_a = sign(&keys(), EventBuilder::new(Kind::new(1), "a"), T);
    let ev_c = sign(&keys(), EventBuilder::new(Kind::new(1), "c"), T);
    mock.store().put(&ev_a).expect("a");
    let client = client(vec![mock.url()], |_| {});
    client.store().put(&ev_c).expect("put");
    let mut options = nk::client::SyncOptions::default();
    options.dry_run = true;
    options.direction = nk::client::SyncDirection::Both;
    let report = client
        .sync_with(&mock.url(), Filter::new(), options)
        .await
        .expect("sync");
    assert_eq!(report.have, vec![ev_c.id()]);
    assert_eq!(report.need, vec![ev_a.id()]);
    assert!(report.sent.is_empty() && report.received.is_empty());
    assert!(
        client
            .query(vec![Filter::new()])
            .await
            .expect("query")
            .iter()
            .all(|e| e.id() != ev_a.id())
    );
}

#[tokio::test]
async fn sync_persist_false_reports_but_does_not_store() {
    let mock = MockRelay::start().await.expect("mock");
    let ev_a = sign(&keys(), EventBuilder::new(Kind::new(1), "a"), T);
    mock.store().put(&ev_a).expect("a");
    let client = client(vec![mock.url()], |o| o.persist = false);
    let report = client
        .sync_with(
            &mock.url(),
            Filter::new(),
            nk::client::SyncOptions::default(),
        )
        .await
        .expect("sync");
    assert_eq!(report.received, vec![ev_a.id()]);
    assert_eq!(
        client.query(vec![Filter::new()]).await.expect("query"),
        Vec::<Event>::new()
    );
}

#[tokio::test]
async fn sync_over_default_relays_reports_each() {
    let m1 = MockRelay::start().await.expect("m1");
    let m2 = MockRelay::start().await.expect("m2");
    let client = client(vec![m1.url(), m2.url()], |_| {});
    let out = client
        .sync(Filter::new(), nk::client::SyncOptions::default())
        .await
        .expect("sync");
    assert_eq!(out.len(), 2);
    assert!(out[&m1.url()].is_ok() && out[&m2.url()].is_ok());
}

#[tokio::test]
async fn sync_closed_and_no_relays() {
    let no_relays = client(vec![], |_| {});
    assert!(matches!(
        no_relays
            .sync(Filter::new(), nk::client::SyncOptions::default())
            .await,
        Err(ClientError::NoRelays)
    ));
    let closed = client(vec![], |_| {});
    closed.close().await;
    assert!(matches!(
        closed
            .sync_with(
                &RelayUrl::parse("ws://127.0.0.1:1").expect("url"),
                Filter::new(),
                nk::client::SyncOptions::default()
            )
            .await,
        Err(ClientError::Closed)
    ));
}
