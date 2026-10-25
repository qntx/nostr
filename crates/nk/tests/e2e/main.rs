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
    let pool = RelayPool::new(RelayOptions {
        reconnect: false,
        ..RelayOptions::default()
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
