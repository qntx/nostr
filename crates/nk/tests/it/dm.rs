//! `Client` NIP-17 private-message tests — mocks via `testing::MockRelay`.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use nk::client::{Client, ClientOptions, DmOptions, Error as ClientError, PrivateMessageEvent};
use nk::store::EventStore;
use nk::testing::MockRelay;
use nk_core::nips::nip17::{DmRelayList, Recipient};
use nk_core::{
    Event, EventBuilder, Filter, Keys, Kind, RelayUrl, SecretKey, SysRng, Tag, Timestamp,
    rand_core::UnwrapErr,
};

const T: Timestamp = Timestamp::from_secs(1_700_000_000);

fn keys(n: u8) -> Keys {
    Keys::new(SecretKey::from_bytes([n; 32]).expect("key"))
}

fn dm_client(k: &Keys, defaults: Vec<RelayUrl>) -> Client {
    let mut options = ClientOptions::default();
    options.relays = defaults;
    options.signer = Some(Arc::new(k.clone()));
    options.gossip.allow_insecure = true;
    Client::new(options)
}

/// A signed kind-10050 pointing `k`'s DMs at `url`.
fn dm_list(k: &Keys, url: &RelayUrl) -> Event {
    let list = DmRelayList::from_urls([url.as_str()]).expect("list");
    k.sign_event(
        EventBuilder::from(list).build_at(k.public_key(), T),
        &mut UnwrapErr(SysRng),
    )
    .expect("sign")
}

const fn recipient(k: &Keys) -> Recipient {
    Recipient {
        pubkey: k.public_key(),
        relay_hint: None,
    }
}

#[tokio::test]
async fn set_dm_relays_publishes_and_routes() {
    let mut mock_a = MockRelay::start().await.expect("a");
    let alice = keys(41);
    let client = dm_client(&alice, vec![mock_a.url()]);
    let out = client
        .set_dm_relays([mock_a.url()])
        .await
        .expect("set_dm_relays");
    assert!(
        out.values().all(|r| matches!(r, Ok(o) if o.accepted)),
        "{out:?}"
    );
    assert_eq!(
        client.routes(&alice.public_key()).expect("routes").dm(),
        [mock_a.url()]
    );
    let frame = mock_a
        .wait_for_frame("EVENT", Duration::from_secs(5))
        .await
        .expect("EVENT");
    assert!(frame.contains("\"kind\":10050"), "{frame}");
}

#[tokio::test]
async fn send_and_fetch_round_trip() {
    let mock_a = MockRelay::start().await.expect("a");
    let mock_b = MockRelay::start().await.expect("b");
    let (alice, bob) = (keys(42), keys(43));
    let alice_client = dm_client(&alice, vec![]);
    let bob_client = dm_client(&bob, vec![]);
    let (alice_list, bob_list) = (dm_list(&alice, &mock_a.url()), dm_list(&bob, &mock_b.url()));
    alice_client.observe(&alice_list).await.expect("alice list");
    alice_client.observe(&bob_list).await.expect("bob list");
    bob_client.observe(&bob_list).await.expect("bob list");

    let sent = alice_client
        .send_private_message(&[recipient(&bob)], "hi bob", DmOptions::default())
        .await
        .expect("send");
    assert_eq!(sent.wraps.len(), 2, "sender copy + recipient copy");
    assert_eq!(
        mock_a.store().count(&[Filter::new()]).expect("a"),
        1,
        "alice copy at A"
    );
    assert_eq!(
        mock_b.store().count(&[Filter::new()]).expect("b"),
        1,
        "bob copy at B"
    );

    let inbox = bob_client
        .fetch_private_messages(None, None, Duration::from_secs(5))
        .await
        .expect("fetch bob");
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].rumor.unsigned().content(), "hi bob");
    assert_eq!(inbox[0].rumor.unsigned().pubkey(), alice.public_key());

    let own = alice_client
        .fetch_private_messages(None, None, Duration::from_secs(5))
        .await
        .expect("fetch alice");
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].rumor.unsigned().content(), "hi bob");
}

#[tokio::test]
async fn send_fails_without_dm_relays() {
    let mock_a = MockRelay::start().await.expect("a");
    let mut mock_b = MockRelay::start().await.expect("b");
    let (alice, bob) = (keys(44), keys(45));
    let client = dm_client(&alice, vec![]);
    client
        .observe(&dm_list(&alice, &mock_a.url()))
        .await
        .expect("alice list");
    let err = client
        .send_private_message(&[recipient(&bob)], "hi", DmOptions::default())
        .await
        .expect_err("no bob routes");
    assert!(
        matches!(err, ClientError::NoDmRelays(pk) if pk == bob.public_key()),
        "{err:?}"
    );
    assert!(
        mock_b
            .wait_for_frame("EVENT", Duration::from_millis(200))
            .await
            .is_none(),
        "no EVENT sent to bob's relay"
    );
}

#[tokio::test]
async fn subscribe_receives_live_message() {
    let mock_a = MockRelay::start().await.expect("a");
    let mock_b = MockRelay::start().await.expect("b");
    let (alice, bob) = (keys(46), keys(47));
    let alice_client = dm_client(&alice, vec![]);
    let bob_client = dm_client(&bob, vec![]);
    alice_client
        .observe(&dm_list(&alice, &mock_a.url()))
        .await
        .expect("alice list");
    alice_client
        .observe(&dm_list(&bob, &mock_b.url()))
        .await
        .expect("bob list");
    bob_client
        .observe(&dm_list(&bob, &mock_b.url()))
        .await
        .expect("bob list");
    let mut sub = bob_client
        .subscribe_private_messages(None)
        .await
        .expect("subscribe");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), sub.next()).await,
        Ok(Some(PrivateMessageEvent::Eose))
    ));
    // The mock forwards live events only to the connection that
    // published them, so a fresh wrap (never stored on B — a
    // republish would be a `Duplicate` and not fan out) goes through
    // bob's own pool conn, the same conn his subscription rides. The
    // E2E covers real cross-conn delivery through nosfry.
    let rumor = nk_core::nips::nip17::ChatMessage::new([recipient(&bob)], "live dm")
        .into_rumor(alice.public_key(), Timestamp::from_secs(1_800_000_000))
        .expect("rumor");
    let signer: Arc<dyn nk_core::NostrSigner> = Arc::new(alice.clone());
    let options =
        nk_core::nips::nip59::WrapOptions::new(nk_core::nips::nip59::Timestamps::Random {
            now: Timestamp::from_secs(1_800_000_000),
            scope: nk_core::nips::nip59::RandomScope::SealAndWrap,
        });
    let (_, wrap) = nk_core::nips::nip17::wrap_direct_message_with_signer(
        signer.as_ref(),
        &[recipient(&bob)],
        &rumor,
        &options,
        &mut SysRng,
    )
    .await
    .expect("wrap")
    .pop()
    .expect("one wrap");
    bob_client.pool().publish(&[mock_b.url()], &wrap).await;
    match tokio::time::timeout(Duration::from_secs(5), sub.next()).await {
        Ok(Some(PrivateMessageEvent::Message(m))) => {
            assert_eq!(m.rumor.unsigned().content(), "live dm");
            assert_eq!(m.rumor.unsigned().pubkey(), alice.public_key());
        }
        other => panic!("expected message, got {other:?}"),
    }
}

#[tokio::test]
async fn junk_gift_wrap_is_skipped_and_not_stored() {
    let mock_b = MockRelay::start().await.expect("b");
    let bob = keys(48);
    let bob_client = dm_client(&bob, vec![]);
    bob_client
        .observe(&dm_list(&bob, &mock_b.url()))
        .await
        .expect("bob list");
    // A validly-signed kind 1059 with undecryptable content, p-tagging bob.
    let junk = keys(50)
        .sign_event(
            EventBuilder::new(Kind::GIFT_WRAP, "not-nip44")
                .tags([Tag::public_key(bob.public_key(), None, None)])
                .build_at(keys(50).public_key(), T),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign junk");
    mock_b.store().put(&junk).expect("seed junk");
    let inbox = bob_client
        .fetch_private_messages(None, None, Duration::from_secs(5))
        .await
        .expect("fetch");
    assert!(inbox.is_empty());
    bob_client.flush().await.expect("flush");
    let stored = bob_client.query(vec![Filter::new()]).await.expect("query");
    assert!(
        stored.iter().all(|e| e.id() != junk.id()),
        "junk not stored"
    );
}

#[tokio::test]
async fn dm_requires_signer() {
    let mut options = ClientOptions::default();
    options.gossip.allow_insecure = true;
    let client = Client::new(options);
    assert!(matches!(
        client
            .send_private_message(&[recipient(&keys(51))], "x", DmOptions::default())
            .await,
        Err(ClientError::NoSigner)
    ));
    assert!(matches!(
        client
            .fetch_private_messages(None, None, Duration::from_secs(1))
            .await,
        Err(ClientError::NoSigner)
    ));
    assert!(matches!(
        client.subscribe_private_messages(None).await,
        Err(ClientError::NoSigner)
    ));
}
