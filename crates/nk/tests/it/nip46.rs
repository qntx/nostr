//! `nip46::RemoteSigner` tests against `testing::MockRelay` with an
//! in-process mock bunker.

use super::*;

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering as AOrd};

use nk::client::{Client, ClientOptions, DmOptions};
use nk::nip46::{Error as Nip46Error, RemoteSigner, RemoteSignerOptions};
use nk::pool::{PoolEvent, RelayPool};
use nk_core::nips::nip17::{DmRelayList, Recipient};
use nk_core::nips::nip44::ConversationKey;
use nk_core::nips::nip46::{BunkerUri, Method, NostrConnectUri, Request, Response};
use nk_core::{
    EventBuilder, NostrSigner, PublicKey, RelayUrl, SingleLetterTag, SysRng, Tag, UnsignedEvent,
    rand_core::UnwrapErr,
};

const T: Timestamp = Timestamp::from_secs(1_700_000_000);

fn keys_n(n: u8) -> Keys {
    Keys::new(SecretKey::from_bytes([n; 32]).expect("key"))
}

const fn p_tag() -> SingleLetterTag {
    SingleLetterTag::new('p').expect("p")
}

/// How the mock bunker bends `sign_event`.
#[derive(Clone, Copy, Default, PartialEq)]
enum Tamper {
    /// Signs the template faithfully.
    #[default]
    Valid,
    /// Signs valid but different content.
    Mismatch,
    /// Returns a structurally valid event whose signature is wrong.
    BadSig,
}

/// The mock bunker's behaviour knobs.
#[derive(Default)]
struct BunkerCfg {
    /// Overrides the `connect` reply (default `"ack"`).
    connect_result: Option<String>,
    /// Answers `auth_url` once for this method, then delays the real
    /// reply by `auth_delay`.
    auth_url_for: Option<Method>,
    /// Delay between `auth_url` and the real reply.
    auth_delay: Duration,
    /// Raw `switch_relays` result (default `"null"`).
    switch_result: Option<String>,
    /// This method is answered with `error: "denied"`.
    deny: Option<Method>,
    /// This method is never answered.
    silent: Option<Method>,
    tamper: Tamper,
    /// Counts `auth_url` replies sent (for assertions).
    auth_sent: Arc<AtomicUsize>,
}

/// An in-process bunker: remote-signer keys + the user keys it holds.
struct MockBunker {
    remote: Keys,
    user: Keys,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockBunker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The bunker's answer payload for one request.
fn bunker_answer(cfg: &BunkerCfg, req: &Request, user: &Keys) -> (Option<String>, Option<String>) {
    let result = match req.method {
        Method::Connect => cfg
            .connect_result
            .clone()
            .unwrap_or_else(|| String::from("ack")),
        Method::GetPublicKey => user.public_key().to_hex(),
        Method::Ping => String::from("pong"),
        Method::Logout => String::from("ack"),
        Method::SwitchRelays => cfg
            .switch_result
            .clone()
            .unwrap_or_else(|| String::from("null")),
        Method::SignEvent => {
            let Some(template) = req.params.first() else {
                return (None, Some(String::from("no template")));
            };
            // The template carries no pubkey — inject the user's.
            let wrapped = template.replacen(
                '{',
                &format!("{{\"pubkey\":\"{}\",", user.public_key().to_hex()),
                1,
            );
            let Ok(unsigned) = UnsignedEvent::from_json(&wrapped) else {
                return (None, Some(String::from("bad template")));
            };
            let unsigned = match cfg.tamper {
                Tamper::Mismatch => UnsignedEvent::new(
                    user.public_key(),
                    unsigned.created_at(),
                    unsigned.kind(),
                    unsigned.tags().clone(),
                    String::from("tampered"),
                ),
                _ => unsigned,
            };
            let signed = user
                .sign_event(unsigned, &mut UnwrapErr(SysRng))
                .expect("bunker sign");
            let event = match cfg.tamper {
                Tamper::BadSig => Event::new(
                    signed.id(),
                    signed.pubkey(),
                    signed.created_at(),
                    signed.kind(),
                    signed.tags().clone(),
                    String::from("tampered"),
                    signed.sig(),
                ),
                _ => signed,
            };
            event.to_json()
        }
        Method::Nip44Encrypt | Method::Nip44Decrypt => {
            let [peer, text] = req.params.as_slice() else {
                return (None, Some(String::from("bad params")));
            };
            let Ok(peer) = PublicKey::from_hex(peer) else {
                return (None, Some(String::from("bad peer")));
            };
            let Ok(ck) = ConversationKey::derive(user.secret_key(), &peer) else {
                return (None, Some(String::from("bad key")));
            };
            match req.method {
                Method::Nip44Encrypt => ck
                    .encrypt(text, &mut UnwrapErr(SysRng))
                    .expect("bunker encrypt"),
                _ => ck.decrypt(text).expect("bunker decrypt"),
            }
        }
        _ => String::from("unsupported"),
    };
    (Some(result), None)
}

/// Sends one encrypted kind-24133 response from the bunker.
async fn bunker_reply(
    pool: &RelayPool,
    remote: &Keys,
    relay: &RelayUrl,
    client: PublicKey,
    conversation: &ConversationKey,
    response: Response,
) {
    let content = conversation
        .encrypt(&response.to_json(), &mut UnwrapErr(SysRng))
        .expect("encrypt");
    let event = remote
        .sign_event(
            EventBuilder::new(Kind::NOSTR_CONNECT, content)
                .tags([Tag::public_key(client, None, None)])
                .build(remote.public_key()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign response");
    drop(pool.publish(std::slice::from_ref(relay), &event).await);
}

/// The bunker loop: subscribe for requests on every relay, answer each.
async fn bunker_loop(relays: Vec<RelayUrl>, remote: Keys, user: Keys, cfg: BunkerCfg) {
    let pool = RelayPool::new(RelayOptions::default());
    let filter = Filter::new()
        .kinds([Kind::NOSTR_CONNECT])
        .expect("filter")
        .tag(p_tag(), [remote.public_key().to_hex()])
        .expect("filter")
        .limit(0);
    let plan = relays
        .iter()
        .map(|u| (u.clone(), vec![filter.clone()]))
        .collect();
    let mut sub = pool.subscribe_routed(plan).await;
    let mut auth_used = std::collections::HashSet::new();
    while let Some(item) = sub.next().await {
        let PoolEvent::Event { relay, event } = item else {
            continue;
        };
        let Ok(conversation) = ConversationKey::derive(remote.secret_key(), &event.pubkey()) else {
            continue;
        };
        let Ok(payload) = conversation.decrypt(event.content()) else {
            continue;
        };
        let Ok(req) = Request::from_json(&payload) else {
            continue;
        };
        if cfg.silent.as_ref() == Some(&req.method) {
            continue;
        }
        if cfg.deny.as_ref() == Some(&req.method) {
            bunker_reply(
                &pool,
                &remote,
                &relay,
                event.pubkey(),
                &conversation,
                Response {
                    id: req.id,
                    result: None,
                    error: Some(String::from("denied")),
                },
            )
            .await;
            continue;
        }
        if cfg.auth_url_for.as_ref() == Some(&req.method) && auth_used.insert(req.id.clone()) {
            cfg.auth_sent.fetch_add(1, AOrd::Relaxed);
            bunker_reply(
                &pool,
                &remote,
                &relay,
                event.pubkey(),
                &conversation,
                Response {
                    id: req.id.clone(),
                    result: Some(String::from("auth_url")),
                    error: Some(String::from("https://auth.example/go")),
                },
            )
            .await;
            tokio::time::sleep(cfg.auth_delay).await;
        }
        let (result, error) = bunker_answer(&cfg, &req, &user);
        bunker_reply(
            &pool,
            &remote,
            &relay,
            event.pubkey(),
            &conversation,
            Response {
                id: req.id,
                result,
                error,
            },
        )
        .await;
    }
}

/// Starts a bunker on `mocks` (listens on each), returning its keys.
/// Awaits the bunker's REQ (keyed by its unique remote pubkey) on every
/// mock so no request event is missed.
async fn bunker(mocks: &mut [&mut MockRelay], cfg: BunkerCfg) -> MockBunker {
    let remote = Keys::generate().expect("remote keys");
    let user = Keys::generate().expect("user keys");
    let relays: Vec<RelayUrl> = mocks.iter().map(|m| m.url()).collect();
    let task = tokio::spawn(bunker_loop(relays, remote.clone(), user.clone(), cfg));
    let needle = remote.public_key().to_hex();
    for mock in mocks.iter_mut() {
        mock.wait_for_frame(&needle, Duration::from_secs(5))
            .await
            .expect("bunker REQ");
    }
    MockBunker { remote, user, task }
}

fn opts(f: impl FnOnce(&mut RemoteSignerOptions)) -> RemoteSignerOptions {
    let mut o = RemoteSignerOptions::default();
    f(&mut o);
    o
}

fn uri_for(b: &MockBunker, mocks: &[&mut MockRelay], secret: &str) -> BunkerUri {
    BunkerUri {
        remote_signer: b.remote.public_key(),
        relays: mocks.iter().map(|m| m.url().to_string()).collect(),
        secret: if secret.is_empty() {
            None
        } else {
            Some(secret.to_owned())
        },
    }
}

#[tokio::test]
async fn bunker_connect_and_rpc_round_trips() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(&mut [&mut mock], BunkerCfg::default()).await;
    let signer = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock], "s3cr3t"),
        keys_n(0xC1),
        RemoteSignerOptions::default(),
    )
    .await
    .expect("connect");
    assert_eq!(signer.public_key().await.expect("pk"), b.user.public_key());
    signer.ping().await.expect("ping");
    let unsigned = EventBuilder::new(Kind::new(1), "hi bunker").build(b.user.public_key());
    let signed = signer.sign_event(unsigned.clone()).await.expect("sign");
    signed.verify().expect("verify");
    assert!(signed.matches_unsigned(&unsigned));
    // Remote nip44: the bunker encrypts under user↔peer; decrypt locally.
    let peer = keys_n(0xC2);
    let ciphertext = signer
        .nip44_encrypt(&peer.public_key(), "secret dm")
        .await
        .expect("nip44 encrypt");
    let plain = ConversationKey::derive(peer.secret_key(), &b.user.public_key())
        .expect("ck")
        .decrypt(&ciphertext)
        .expect("decrypt");
    assert_eq!(plain, "secret dm");
    let uri = signer.bunker_uri();
    assert_eq!(uri.remote_signer, b.remote.public_key());
    assert_eq!(uri.relays, [mock.url().to_string()]);
    assert_eq!(uri.secret.as_deref(), Some("s3cr3t"));
    signer.close().await;
}

#[tokio::test]
async fn connect_unexpected_result_hides_the_secret() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(
        &mut [&mut mock],
        BunkerCfg {
            connect_result: Some(String::from("bogus-result")),
            ..BunkerCfg::default()
        },
    )
    .await;
    let err = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock], "top-secret-token"),
        keys_n(0xC3),
        RemoteSignerOptions::default(),
    )
    .await
    .expect_err("bad connect result");
    assert!(
        matches!(err, Nip46Error::UnexpectedResult(Method::Connect)),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(!text.contains("top-secret-token"), "{text}");
    assert!(!text.contains("bogus-result"), "{text}");
}

#[tokio::test]
async fn remote_error_surfaces() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(
        &mut [&mut mock],
        BunkerCfg {
            deny: Some(Method::Ping),
            ..BunkerCfg::default()
        },
    )
    .await;
    let signer = RemoteSigner::attach(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xC4),
        RemoteSignerOptions::default(),
    )
    .await
    .expect("attach");
    match signer.ping().await {
        Err(Nip46Error::Remote(e)) => assert_eq!(e, "denied"),
        other => panic!("expected Remote(denied), got {other:?}"),
    }
}

#[tokio::test]
async fn auth_url_extends_the_deadline() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(
        &mut [&mut mock],
        BunkerCfg {
            auth_url_for: Some(Method::SignEvent),
            auth_delay: Duration::from_millis(600),
            ..BunkerCfg::default()
        },
    )
    .await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    let signer = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xC5),
        opts(|o| {
            o.request_timeout = Duration::from_millis(300);
            o.auth_timeout = Duration::from_secs(3);
            o.on_auth_url = Some(Arc::new(move |u| {
                seen2.lock().expect("lock").push(u.to_owned());
            }));
        }),
    )
    .await
    .expect("connect");
    let unsigned = EventBuilder::new(Kind::new(1), "auth me").build(b.user.public_key());
    signer
        .sign_event(unsigned)
        .await
        .expect("sign after auth_url");
    let urls = seen.lock().expect("lock");
    assert_eq!(urls.as_slice(), ["https://auth.example/go"]);
}

#[tokio::test]
async fn silent_method_times_out() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(
        &mut [&mut mock],
        BunkerCfg {
            silent: Some(Method::Ping),
            ..BunkerCfg::default()
        },
    )
    .await;
    let signer = RemoteSigner::attach(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xC6),
        opts(|o| o.request_timeout = Duration::from_millis(300)),
    )
    .await
    .expect("attach");
    match signer.ping().await {
        Err(Nip46Error::Timeout) => {}
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn tampered_and_bad_signature_events() {
    let mut mock = MockRelay::start().await.expect("mock");
    for (tamper, expect_mismatch) in [(Tamper::Mismatch, true), (Tamper::BadSig, false)] {
        let b = bunker(
            &mut [&mut mock],
            BunkerCfg {
                tamper,
                ..BunkerCfg::default()
            },
        )
        .await;
        let signer = RemoteSigner::connect(
            &uri_for(&b, &[&mut mock], ""),
            keys_n(0xC7),
            opts(|o| {
                o.request_timeout = Duration::from_secs(3);
            }),
        )
        .await
        .expect("connect");
        let unsigned = EventBuilder::new(Kind::new(1), "x").build(b.user.public_key());
        match signer.sign_event(unsigned).await {
            Err(Nip46Error::EventMismatch) if expect_mismatch => {}
            Err(Nip46Error::InvalidEvent) if !expect_mismatch => {}
            other => panic!("wrong error: {other:?}"),
        }
        signer.close().await;
    }
}

#[tokio::test]
async fn foreign_pubkey_is_mismatch_without_rpc() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(&mut [&mut mock], BunkerCfg::default()).await;
    let signer = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xC8),
        RemoteSignerOptions::default(),
    )
    .await
    .expect("connect");
    let unsigned = EventBuilder::new(Kind::new(1), "not mine").build(keys_n(0xC9).public_key());
    match signer.sign_event(unsigned).await {
        Err(Nip46Error::PublicKeyMismatch) => {}
        other => panic!("expected PublicKeyMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn switch_relays_moves_the_listener() {
    let mut mock_a = MockRelay::start().await.expect("a");
    let mut mock_b = MockRelay::start().await.expect("b");
    let b_url = mock_b.url();
    let b = bunker(
        &mut [&mut mock_a, &mut mock_b],
        BunkerCfg {
            switch_result: Some(format!(r#"["{b_url}"]"#)),
            ..BunkerCfg::default()
        },
    )
    .await;
    let signer = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock_a], ""),
        keys_n(0xCA),
        RemoteSignerOptions::default(),
    )
    .await
    .expect("connect");
    assert_eq!(signer.bunker_uri().relays, [mock_b.url().to_string()]);
    signer.ping().await.expect("ping after switch");
    assert!(
        mock_b
            .wait_for_frame("24133", Duration::from_secs(3))
            .await
            .is_some(),
        "no RPC frame on mock B"
    );
}

#[tokio::test]
async fn nostrconnect_handshake() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(&mut [&mut mock], BunkerCfg::default()).await;
    let client = keys_n(0xCB);
    let client_pub = client.public_key();
    let uri = NostrConnectUri::new(
        client_pub,
        vec![mock.url().to_string()],
        String::from("handshake-secret"),
    )
    .expect("uri");
    let connecting = tokio::spawn({
        let uri = uri.clone();
        async move { RemoteSigner::nostr_connect(&uri, client, RemoteSignerOptions::default()).await }
    });
    // Wait for the handshake REQ, then inject a spoof (wrong secret,
    // wrong author) — it must be ignored.
    let req = mock
        .wait_for_frame("REQ", Duration::from_secs(3))
        .await
        .expect("handshake REQ");
    let sub_id = req_id(&req).to_owned();
    let spoof = keys_n(0xCC);
    let payload = ConversationKey::derive(spoof.secret_key(), &client_pub)
        .expect("ck")
        .encrypt(
            &Response {
                id: String::from("spoof"),
                result: Some(String::from("wrong-secret")),
                error: None,
            }
            .to_json(),
            &mut UnwrapErr(SysRng),
        )
        .expect("encrypt");
    let spoof_ev = spoof
        .sign_event(
            EventBuilder::new(Kind::NOSTR_CONNECT, payload)
                .tags([Tag::public_key(client_pub, None, None)])
                .build(spoof.public_key()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign spoof");
    mock.send_raw(&format!(r#"["EVENT","{}",{}]"#, sub_id, spoof_ev.to_json()));
    // The real bunker answer: result equals the URI secret.
    let real = ConversationKey::derive(b.remote.secret_key(), &client_pub)
        .expect("ck")
        .encrypt(
            &Response {
                id: String::from("real"),
                result: Some(uri.secret().to_owned()),
                error: None,
            }
            .to_json(),
            &mut UnwrapErr(SysRng),
        )
        .expect("encrypt");
    let real_ev = b
        .remote
        .sign_event(
            EventBuilder::new(Kind::NOSTR_CONNECT, real)
                .tags([Tag::public_key(client_pub, None, None)])
                .build(b.remote.public_key()),
            &mut UnwrapErr(SysRng),
        )
        .expect("sign real");
    mock.send_raw(&format!(r#"["EVENT","{}",{}]"#, sub_id, real_ev.to_json()));
    let signer = connecting.await.expect("join").expect("nostr_connect");
    assert_eq!(signer.public_key().await.expect("pk"), b.user.public_key());
    assert_eq!(signer.bunker_uri().remote_signer, b.remote.public_key());
}

#[tokio::test]
async fn nostrconnect_client_mismatch() {
    let mock = MockRelay::start().await.expect("mock");
    let uri = NostrConnectUri::new(
        keys_n(0xCD).public_key(),
        vec![mock.url().to_string()],
        String::from("s"),
    )
    .expect("uri");
    match RemoteSigner::nostr_connect(&uri, keys_n(0xCE), RemoteSignerOptions::default()).await {
        Err(Nip46Error::ClientMismatch) => {}
        other => panic!("expected ClientMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn close_resolves_pending_with_closed() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(
        &mut [&mut mock],
        BunkerCfg {
            silent: Some(Method::Ping),
            ..BunkerCfg::default()
        },
    )
    .await;
    let signer = RemoteSigner::attach(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xCF),
        opts(|o| o.request_timeout = Duration::from_secs(10)),
    )
    .await
    .expect("attach");
    let pending = tokio::spawn({
        let signer = signer.clone();
        async move { signer.ping().await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    signer.close().await;
    match pending.await.expect("join") {
        Err(Nip46Error::Closed) => {}
        other => panic!("expected Closed, got {other:?}"),
    }
    match signer.ping().await {
        Err(Nip46Error::Closed) => {}
        other => panic!("expected Closed after close, got {other:?}"),
    }
}

#[tokio::test]
async fn logout_acks_then_closes() {
    let mut mock = MockRelay::start().await.expect("mock");
    let b = bunker(&mut [&mut mock], BunkerCfg::default()).await;
    let signer = RemoteSigner::attach(
        &uri_for(&b, &[&mut mock], ""),
        keys_n(0xD0),
        RemoteSignerOptions::default(),
    )
    .await
    .expect("attach");
    signer.logout().await.expect("logout");
    match signer.ping().await {
        Err(Nip46Error::Closed) => {}
        other => panic!("expected Closed after logout, got {other:?}"),
    }
}

#[tokio::test]
async fn client_sends_dm_through_remote_signer() {
    let mut mock_a = MockRelay::start().await.expect("a");
    let mut mock_b = MockRelay::start().await.expect("b");
    let b = bunker(&mut [&mut mock_a, &mut mock_b], BunkerCfg::default()).await;
    let signer = RemoteSigner::connect(
        &uri_for(&b, &[&mut mock_a, &mut mock_b], ""),
        keys_n(0xD1),
        opts(|o| o.request_timeout = Duration::from_secs(15)),
    )
    .await
    .expect("connect");
    let alice_client = {
        let mut o = ClientOptions::default();
        o.relays = vec![mock_a.url(), mock_b.url()];
        let arc: Arc<dyn NostrSigner> = Arc::new(signer.clone());
        o.signer = Some(arc);
        o.gossip.allow_insecure = true;
        Client::new(o)
    };
    let bob = keys_n(0xD2);
    let bob_client = {
        let mut o = ClientOptions::default();
        o.signer = Some(Arc::new(bob.clone()));
        o.gossip.allow_insecure = true;
        Client::new(o)
    };
    // Route alice's and bob's DMs through the two mocks.
    let t = T;
    for (k, url) in [(&b.user, &mock_a.url()), (&bob, &mock_b.url())] {
        let list = k
            .sign_event(
                EventBuilder::from(DmRelayList::from_urls([url.as_str()]).expect("list"))
                    .build_at(k.public_key(), t),
                &mut UnwrapErr(SysRng),
            )
            .expect("sign list");
        alice_client.observe(&list).await.expect("alice observe");
        bob_client.observe(&list).await.expect("bob observe");
    }
    alice_client
        .send_private_message(
            &[Recipient {
                pubkey: bob.public_key(),
                relay_hint: None,
            }],
            "hi bob via bunker",
            DmOptions::default(),
        )
        .await
        .expect("send");
    let inbox = bob_client
        .fetch_private_messages(None, None, Duration::from_secs(15))
        .await
        .expect("bob fetch");
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].rumor.unsigned().content(), "hi bob via bunker");
    assert_eq!(inbox[0].rumor.unsigned().pubkey(), b.user.public_key());
    // Alice's own copy is fetched back through the remote signer's
    // nip44_decrypt.
    let own = alice_client
        .fetch_private_messages(None, None, Duration::from_secs(15))
        .await
        .expect("alice fetch");
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].rumor.unsigned().content(), "hi bob via bunker");
}
