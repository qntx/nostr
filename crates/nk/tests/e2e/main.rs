//! End-to-end tests against a real nosfry relay (`run.sh` pins the
//! binary; `NK_E2E_RELAY` carries the URL).
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

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use nk::pool::RelayPool;
use nk::relay::{FetchEnd, Relay, RelayOptions, SubscriptionEvent};
use nk_core::{
    Event, EventBuilder, Filter, Keys, Kind, NostrSigner, RelayUrl, SingleLetterTag, SysRng, Tag,
    Timestamp, rand_core::UnwrapErr,
};

fn url() -> RelayUrl {
    RelayUrl::parse(&std::env::var("NK_E2E_RELAY").expect("NK_E2E_RELAY")).expect("url")
}

/// A unique `t` tag value so runs don't see each other's events.
fn unique_tag() -> String {
    keys().public_key().to_hex()
}

fn keys() -> Keys {
    Keys::generate().expect("keys")
}

fn relay(opts: impl Fn(&mut RelayOptions)) -> Relay {
    let mut options = RelayOptions::default();
    opts(&mut options);
    Relay::new(&url(), options)
}

fn event(tag: &str, content: &str, kind: u16, signer: &Keys) -> Event {
    let unsigned = EventBuilder::new(Kind::new(kind), content)
        .tags([Tag::new(["t", tag]).expect("tag")])
        .build_at(signer.public_key(), Timestamp::now());
    signer
        .sign_event(unsigned, &mut UnwrapErr(SysRng))
        .expect("sign")
}

/// Publishes `ev` and asserts the relay stored it.
async fn publish_ok(r: &Relay, ev: &Event) {
    let out = r.publish(ev).await.expect("publish");
    assert!(out.accepted, "setup publish refused: {out:?}");
}

fn protected_event(tag: &str, signer: &Keys) -> Event {
    let unsigned = EventBuilder::new(Kind::new(1), "protected")
        .tags([
            Tag::new(["t", tag]).expect("tag"),
            Tag::new(["-"]).expect("tag"),
        ])
        .build_at(signer.public_key(), Timestamp::now());
    signer
        .sign_event(unsigned, &mut UnwrapErr(SysRng))
        .expect("sign")
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn publish_then_fetch() {
    let tag = unique_tag();
    let ev = event(&tag, "hello", 1, &keys());
    let r = relay(|_| {});
    publish_ok(&r, &ev).await;
    let out = r
        .fetch(
            vec![Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()])],
            Duration::from_secs(10),
        )
        .await
        .expect("fetch");
    assert!(matches!(out.end, FetchEnd::Eose));
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].id(), ev.id());
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn duplicate_publish() {
    let tag = unique_tag();
    let ev = event(&tag, "dup", 1, &keys());
    let r = relay(|_| {});
    publish_ok(&r, &ev).await;
    let dup = r.publish(&ev).await.expect("second");
    // nosfry: accepted=true, message "duplicate: have this event".
    assert!(dup.accepted, "expected accepted duplicate, got {dup:?}");
    assert!(dup.message.starts_with("duplicate:"), "{dup:?}");
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn live_subscription() {
    let tag = unique_tag();
    let ev = event(&tag, "live", 1, &keys());
    let r = relay(|_| {});
    let mut sub = r
        .subscribe(vec![
            Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]),
        ])
        .await
        .expect("sub");
    match tokio::time::timeout(Duration::from_secs(5), sub.next())
        .await
        .expect("item")
    {
        Some(SubscriptionEvent::Eose) => {}
        other => panic!("expected Eose, got {other:?}"),
    }
    // A second Relay handle on the same URL — a separate connection.
    let r2 = relay(|_| {});
    publish_ok(&r2, &ev).await;
    match tokio::time::timeout(Duration::from_secs(5), sub.next())
        .await
        .expect("live item")
    {
        Some(SubscriptionEvent::Event(e)) => assert_eq!(e.id(), ev.id()),
        other => panic!("expected live Event, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn count_matches() {
    let tag = unique_tag();
    let k = keys();
    let r = relay(|_| {});
    for content in ["a", "b", "c"] {
        publish_ok(&r, &event(&tag, content, 1, &k)).await;
    }
    let result = r
        .count(vec![Filter::new().tag(
            SingleLetterTag::new('t').expect("letter"),
            [tag.as_str()],
        )])
        .await
        .expect("count");
    assert_eq!(result.count, 3);
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn reconcile_have_need() {
    let tag = unique_tag();
    let k = keys();
    let r = relay(|_| {});
    let mut relay_items = Vec::new();
    for content in ["a", "b", "c"] {
        let ev = event(&tag, content, 1, &k);
        publish_ok(&r, &ev).await;
        relay_items.push((ev.created_at(), ev.id()));
    }
    // Local set: [a, b, x] where x is a random id at now.
    let xk = keys();
    let x = xk
        .sign_event(
            EventBuilder::new(Kind::new(1), "x").build_at(xk.public_key(), Timestamp::now()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign")
        .id();
    let items = vec![relay_items[0], relay_items[1], (Timestamp::now(), x)];
    let out = r
        .reconcile(
            Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]),
            items,
        )
        .await
        .expect("reconcile");
    assert_eq!(out.have, vec![x], "have = our extra id");
    assert_eq!(out.need, vec![relay_items[2].1], "need = relay's c");
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn protected_publish_needs_auth() {
    let tag = unique_tag();
    let k = Arc::new(keys());
    let ev = protected_event(&tag, &k);
    // Without a signer — refused, and AUTH is issued for a later retry.
    let anon = relay(|_| {});
    let refused = anon.publish(&ev).await.expect("publish");
    assert!(!refused.accepted);
    assert!(refused.message.starts_with("auth-required:"), "{refused:?}");
    // With the event's author as signer — accepted.
    let k2: Arc<dyn NostrSigner> = k;
    let authed = relay(move |o| {
        o.signer = Some(Arc::clone(&k2));
    });
    publish_ok(&authed, &ev).await;
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn restricted_read_needs_auth() {
    let tag = unique_tag();
    let author = keys();
    let reader = keys();
    // Kind 4 DM to the reader — restricted-read kind.
    let unsigned = EventBuilder::new(Kind::new(4), "dm")
        .tags([
            Tag::new(["t", tag.as_str()]).expect("tag"),
            Tag::public_key(reader.public_key(), None, None),
        ])
        .build_at(author.public_key(), Timestamp::now());
    let dm = author
        .sign_event(unsigned, &mut UnwrapErr(SysRng))
        .expect("sign");
    publish_ok(&relay(|_| {}), &dm).await;
    let filter = Filter::new()
        .kinds([Kind::new(4)])
        .authors([author.public_key()])
        .tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]);
    // Unauthenticated reader — the whole filter group is restricted.
    let anon = relay(|_| {});
    let refused = anon
        .fetch(vec![filter.clone()], Duration::from_secs(10))
        .await
        .expect("fetch");
    match refused.end {
        FetchEnd::Closed(reason) => {
            assert!(reason.starts_with("auth-required:"), "{reason}");
        }
        other => panic!("expected Closed(auth-required:), got {other:?}"),
    }
    // Authenticated as the reader — the event comes back.
    let signer: Arc<dyn NostrSigner> = Arc::new(reader);
    let authed = relay(move |o| {
        o.signer = Some(Arc::clone(&signer));
    });
    let out = authed
        .fetch(vec![filter], Duration::from_secs(10))
        .await
        .expect("authed fetch");
    assert!(matches!(out.end, FetchEnd::Eose));
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].id(), dm.id());
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn pool_isolates_dead_relay() {
    let tag = unique_tag();
    let ev = event(&tag, "pool", 1, &keys());
    publish_ok(&relay(|_| {}), &ev).await;
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        RelayUrl::parse(&format!("ws://{addr}")).expect("url")
    };
    let pool = RelayPool::new({
        let mut o = RelayOptions::default();
        o.reconnect = false;
        o
    });
    let out = pool
        .fetch(
            &[url(), dead.clone()],
            vec![Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()])],
            Duration::from_secs(10),
        )
        .await
        .expect("pool fetch");
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].id(), ev.id());
    assert!(matches!(out.relays[&url()], Ok(FetchEnd::Eose)));
    assert!(out.relays[&dead].is_err());
}

#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn gossip_routes_to_outbox() {
    let tag = unique_tag();
    let author = keys();
    // Author's 10002 lists this relay — ingest it, then the route must
    // be per-relay-only with no remainder.
    let list = EventBuilder::new(Kind::new(10002), "")
        .tags([Tag::custom("r", [url().as_str()])])
        .build_at(author.public_key(), Timestamp::now());
    let list = author
        .sign_event(list, &mut UnwrapErr(SysRng))
        .expect("sign list");
    let note = event(&tag, "outbox", 1, &author);
    relay(|_| {}).publish(&note).await.expect("publish");
    let mut g = nk::gossip::Gossip::new({
        let mut o = nk::gossip::GossipOptions::default();
        o.allow_insecure = true;
        o
    });
    assert!(g.ingest(&list));
    let routing = g.route(&[Filter::new()
        .authors([author.public_key()])
        .tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()])]);
    assert!(routing.remainder.is_empty(), "author routes to the outbox");
    assert_eq!(routing.per_relay.len(), 1);
    assert!(routing.per_relay.contains_key(&url()));
    let pool = RelayPool::new(RelayOptions::default());
    let out = pool
        .fetch_routed(routing.per_relay, Duration::from_secs(10))
        .await;
    assert_eq!(out.events.len(), 1);
    assert_eq!(out.events[0].id(), note.id());
}

/// End-to-end `Client`: sign + publish → hydrate + routes on a fresh
/// client → routed fetch → local query → live subscribe.
#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn client_end_to_end() {
    let tag = unique_tag();
    let author = Keys::generate().expect("keys");
    let mut writer_opts = nk::client::ClientOptions::default();
    writer_opts.relays = vec![url()];
    writer_opts.gossip.allow_insecure = true;
    writer_opts.signer = Some(Arc::new(author.clone()));
    let writer = nk::client::Client::new(writer_opts);

    // 1. Sign + publish a 10002 listing nosfry as write, plus a note.
    let list = writer
        .sign(EventBuilder::from(nk_core::nips::nip65::RelayList::new(
            vec![nk_core::nips::nip65::RelayListItem {
                url: url(),
                marker: nk_core::nips::nip65::RelayMarker::Write,
            }],
        )))
        .await
        .expect("sign list");
    writer.publish(&list).await.expect("publish list");
    let note = writer
        .sign(
            EventBuilder::new(Kind::new(1), "client note").tags([Tag::custom("t", [tag.as_str()])]),
        )
        .await
        .expect("sign note");
    let out = writer.publish(&note).await.expect("publish note");
    assert!(
        out.values().all(|r| matches!(r, Ok(o) if o.accepted)),
        "{out:?}"
    );

    // 2. A second client (fresh store) hydrates the routes.
    let mut reader_opts = nk::client::ClientOptions::default();
    reader_opts.relays = vec![url()];
    reader_opts.gossip.allow_insecure = true;
    let reader = nk::client::Client::new(reader_opts);
    reader
        .hydrate(&[author.public_key()], Duration::from_secs(10))
        .await
        .expect("hydrate");
    assert_eq!(
        reader.routes(&author.public_key()).expect("routes").write(),
        &[url()]
    );

    // 3. Routed fetch returns the note.
    let fetched = reader
        .fetch(
            vec![
                Filter::new()
                    .authors([author.public_key()])
                    .tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]),
            ],
            Duration::from_secs(10),
        )
        .await
        .expect("fetch");
    assert!(fetched.events.iter().any(|e| e.id() == note.id()));

    // 4. flush, then query finds it locally.
    reader.flush().await.expect("flush");
    let stored = reader.query(vec![Filter::new()]).await.expect("query");
    assert!(stored.iter().any(|e| e.id() == note.id()));

    // 5. subscribe(#t) on the reader; the writer publishes another note
    // → the reader's stream yields it.
    let mut sub = reader
        .subscribe(vec![
            Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]),
        ])
        .await
        .expect("subscribe");
    let note2 = writer
        .sign(
            EventBuilder::new(Kind::new(1), "client note 2")
                .tags([Tag::custom("t", [tag.as_str()])]),
        )
        .await
        .expect("sign note 2");
    writer.publish(&note2).await.expect("publish note 2");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, sub.next()).await {
            Ok(Some(nk::pool::PoolEvent::Event { event, .. })) if event.id() == note2.id() => break,
            Ok(Some(_)) => {}
            _ => panic!("stream ended without note 2"),
        }
    }
    writer.close().await;
    reader.close().await;
}

/// `sync_with` both ways against nosfry: remote-only comes down,
/// local-only goes up.
#[tokio::test]
#[ignore = "needs NK_E2E_RELAY"]
async fn client_sync_both_ways() {
    let tag = unique_tag();
    let k = keys();
    let remote = k
        .sign_event(
            EventBuilder::new(Kind::new(1), "sync remote")
                .tags([Tag::custom("t", [tag.as_str()])])
                .build_at(k.public_key(), Timestamp::now()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign remote");
    let local = k
        .sign_event(
            EventBuilder::new(Kind::new(1), "sync local")
                .tags([Tag::custom("t", [tag.as_str()])])
                .build_at(k.public_key(), Timestamp::now()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign local");
    Relay::new(&url(), RelayOptions::default())
        .publish(&remote)
        .await
        .expect("seed remote");

    let mut options = nk::client::ClientOptions::default();
    options.relays = vec![url()];
    options.gossip.allow_insecure = true;
    let client = nk::client::Client::new(options);
    client.store().put(&local).expect("put");

    let mut sync_options = nk::client::SyncOptions::default();
    sync_options.direction = nk::client::SyncDirection::Both;
    let report = client
        .sync_with(
            &url(),
            Filter::new().tag(SingleLetterTag::new('t').expect("letter"), [tag.as_str()]),
            sync_options,
        )
        .await
        .expect("sync");
    assert!(report.received.contains(&remote.id()), "{report:?}");
    assert!(report.sent.contains(&local.id()), "{report:?}");
    // The remote picked up the upload.
    let out = Relay::new(&url(), RelayOptions::default())
        .fetch(
            vec![Filter::new().ids([local.id()])],
            Duration::from_secs(10),
        )
        .await
        .expect("fetch");
    assert!(out.events.iter().any(|e| e.id() == local.id()));
    client.close().await;
}
