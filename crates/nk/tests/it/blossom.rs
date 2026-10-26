//! Blossom: `HttpClient` against `MockHttp` — wire assertions on
//! method/path/headers/body plus the hash-verification paths.

use base64ct::Encoding as _;
use std::str::FromStr;
use std::sync::Arc;

use nk::client::{Client, ClientOptions};
use nk::http::{Error, HttpClient, HttpOptions};
use nk::testing::{MockHttp, MockResponse};
use nk_core::nips::blossom::{AuthVerb, Authorization, BlobDescriptor, BlobHash, Server};
use nk_core::rand_core::UnwrapErr;
use nk_core::{Event, EventBuilder, Keys, SysRng, Timestamp};

const DATA: &[u8] = b"hello blossom";

fn client() -> HttpClient {
    HttpClient::new(HttpOptions::default()).unwrap()
}

fn server(http: &MockHttp) -> Server {
    Server::from_str(&http.url()).unwrap()
}

fn auth(hash: Option<BlobHash>) -> Event {
    let keys = Keys::generate().unwrap();
    let mut builder = Authorization::new(AuthVerb::Upload, Timestamp::from_secs(1_700_000_000));
    if let Some(h) = hash {
        builder = builder.blob(h);
    }
    keys.sign_event(
        EventBuilder::from(builder).build(keys.public_key()),
        &mut UnwrapErr(SysRng),
    )
    .unwrap()
}

fn descriptor(hash: &BlobHash, url: &str) -> String {
    format!(
        r#"{{"url":"{url}","sha256":"{hash}","size":{size},"type":"text/plain"}}"#,
        size = DATA.len(),
    )
}

/// A request header's value.
fn header<'a>(request: &'a nk::testing::MockRequest, name: &str) -> &'a str {
    request
        .headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .unwrap()
}

/// Decodes the `Nostr <base64url>` value and re-parses the event.
fn decoded_auth(request: &nk::testing::MockRequest) -> Event {
    let value = header(request, "authorization")
        .strip_prefix("Nostr ")
        .unwrap();
    let bytes = base64ct::Base64UrlUnpadded::decode_vec(value).unwrap();
    let event = Event::from_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
    event.verify().unwrap();
    event
}

#[tokio::test]
async fn upload_round_trip() {
    let mut http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let hash = BlobHash::of(DATA);
    http.route(
        "PUT",
        "/upload",
        MockResponse::new(201).body(descriptor(&hash, &format!("{}/{}", http.url(), hash))),
    );
    let auth = auth(Some(hash));
    let desc = client()
        .upload(&server, DATA.to_vec(), Some("text/plain"), &auth)
        .await
        .unwrap();
    assert_eq!(desc.sha256, hash);
    assert_eq!(desc.mime_type.as_deref(), Some("text/plain"));

    let request = http.next_request().await.unwrap();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.path, "/upload");
    assert_eq!(header(&request, "x-sha-256"), hash.to_string());
    assert_eq!(header(&request, "content-type"), "text/plain");
    assert_eq!(request.body, DATA);
    let signed = decoded_auth(&request);
    assert_eq!(signed.to_json(), auth.to_json());
}

#[tokio::test]
async fn upload_descriptor_hash_mismatch() {
    let http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let wrong = BlobHash::of(b"other");
    http.route(
        "PUT",
        "/upload",
        MockResponse::new(200).body(descriptor(&wrong, "https://x/")),
    );
    let err = client()
        .upload(&server, DATA.to_vec(), None, &auth(None))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::HashMismatch), "{err:?}");
}

#[tokio::test]
async fn check_upload_sends_preflight_headers() {
    let mut http = MockHttp::start().await.unwrap();
    let server = server(&http);
    http.route("HEAD", "/upload", MockResponse::new(200));
    client()
        .check_upload(&server, DATA, Some("image/png"), &auth(None))
        .await
        .unwrap();
    let request = http.next_request().await.unwrap();
    assert_eq!(request.method, "HEAD");
    assert_eq!(
        header(&request, "x-sha-256"),
        BlobHash::of(DATA).to_string()
    );
    assert_eq!(header(&request, "x-content-length"), DATA.len().to_string());
    assert_eq!(header(&request, "x-content-type"), "image/png");
}

#[tokio::test]
async fn list_and_delete() {
    let mut http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let hash = BlobHash::of(DATA);
    let pubkey = Keys::generate().unwrap().public_key();
    http.route(
        "GET",
        &format!("/list/{pubkey}"),
        MockResponse::new(200).body(format!("[{}]", descriptor(&hash, "https://x/"))),
    );
    http.route("DELETE", &format!("/{hash}"), MockResponse::new(204));

    let auth = auth(None);
    let items = client().list(&server, &pubkey, Some(&auth)).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].sha256, hash);
    let listed = http.next_request().await.unwrap();
    assert_eq!(listed.path, format!("/list/{pubkey}"));
    decoded_auth(&listed);

    client().delete(&server, &hash, &auth).await.unwrap();
    let deleted = http.next_request().await.unwrap();
    assert_eq!(deleted.method, "DELETE");
    assert_eq!(deleted.path, format!("/{hash}"));
    decoded_auth(&deleted);
}

#[tokio::test]
async fn mirror_sends_json_and_headers() {
    let mut http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let hash = BlobHash::of(DATA);
    let source = format!("{http_url}/{hash}.bin", http_url = http.url());
    http.route(
        "PUT",
        "/mirror",
        MockResponse::new(200).body(descriptor(
            &hash,
            &format!("{}/mirror/{}", http.url(), hash),
        )),
    );
    let desc = BlobDescriptor::from_json(&descriptor(&hash, &source)).unwrap();
    let mirrored = client().mirror(&server, &desc, &auth(None)).await.unwrap();
    assert_eq!(mirrored.sha256, hash);
    let request = http.next_request().await.unwrap();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.path, "/mirror");
    assert_eq!(
        request.body,
        format!(r#"{{"url":"{source}"}}"#).into_bytes()
    );
    assert_eq!(header(&request, "x-content-type"), "text/plain");
    assert_eq!(header(&request, "x-content-length"), DATA.len().to_string());
}

#[tokio::test]
async fn x_reason_surfaces_on_4xx() {
    let http = MockHttp::start().await.unwrap();
    let server = server(&http);
    http.route(
        "PUT",
        "/upload",
        MockResponse::new(403).header("x-reason", "blocked:file too large"),
    );
    let err = client()
        .upload(&server, DATA.to_vec(), None, &auth(None))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            Error::Status { status: 403, reason: Some(r) } if r == "blocked:file too large"
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn blob_exists_answers_status() {
    let http = MockHttp::start().await.unwrap();
    let alive = server(&http);
    let hash = BlobHash::of(DATA);
    http.route("HEAD", &format!("/{hash}"), MockResponse::new(200));
    assert!(client().blob_exists(&alive, &hash).await.unwrap());

    let http2 = MockHttp::start().await.unwrap();
    let dead = server(&http2);
    http2.route("HEAD", &format!("/{hash}"), MockResponse::new(404));
    assert!(!client().blob_exists(&dead, &hash).await.unwrap());

    http2.route("HEAD", &format!("/{hash}"), MockResponse::new(500));
    let err = client().blob_exists(&dead, &hash).await.unwrap_err();
    assert!(matches!(err, Error::Status { status: 500, .. }), "{err:?}");
}

#[tokio::test]
async fn get_blob_verifies_the_hash() {
    let http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let hash = BlobHash::of(DATA);
    http.route(
        "GET",
        &format!("/{hash}"),
        MockResponse::new(200).body(DATA),
    );
    assert_eq!(client().get_blob(&server, &hash).await.unwrap(), DATA);

    http.route(
        "GET",
        &format!("/{hash}"),
        MockResponse::new(200).body(b"tampered"),
    );
    let err = client().get_blob(&server, &hash).await.unwrap_err();
    assert!(matches!(err, Error::HashMismatch), "{err:?}");
}

#[tokio::test]
async fn heal_blob_url_prefers_original_then_servers() {
    let hash = BlobHash::of(DATA);
    let original = MockHttp::start().await.unwrap();
    let fallback = MockHttp::start().await.unwrap();
    let url = format!("{}/{hash}.png", original.url());

    // Original alive → original.
    original.route("HEAD", &format!("/{hash}.png"), MockResponse::new(200));
    let healed = client().heal_blob_url(&url, &[server(&fallback)]).await;
    assert_eq!(healed, url);

    // Original dead → the first alive server, extension kept.
    original.route("HEAD", &format!("/{hash}.png"), MockResponse::new(404));
    fallback.route("HEAD", &format!("/{hash}.png"), MockResponse::new(200));
    let moved = client().heal_blob_url(&url, &[server(&fallback)]).await;
    assert_eq!(moved, format!("{}/{hash}.png", fallback.url()));

    // Nothing alive → the original URL back.
    fallback.route("HEAD", &format!("/{hash}.png"), MockResponse::new(404));
    let gone = client().heal_blob_url(&url, &[server(&fallback)]).await;
    assert_eq!(gone, url);

    // The extension's original case survives the heal.
    let upper = format!("{}/{hash}.PNG", original.url());
    fallback.route("HEAD", &format!("/{hash}.PNG"), MockResponse::new(200));
    let cased = client().heal_blob_url(&upper, &[server(&fallback)]).await;
    assert_eq!(cased, format!("{}/{hash}.PNG", fallback.url()));

    // No hash in the URL → original, no requests.
    let no_hash = client()
        .heal_blob_url(&format!("{}/view", original.url()), &[server(&fallback)])
        .await;
    assert_eq!(no_hash, format!("{}/view", original.url()));
}

#[tokio::test]
async fn upload_to_servers_falls_back() {
    let a = MockHttp::start().await.unwrap();
    let b = MockHttp::start().await.unwrap();
    let hash = BlobHash::of(DATA);
    a.route("PUT", "/upload", MockResponse::new(500));
    b.route(
        "PUT",
        "/upload",
        MockResponse::new(200).body(descriptor(&hash, "https://b/")),
    );
    let auth = auth(None);
    let desc = client()
        .upload_to_servers(&[server(&a), server(&b)], DATA.to_vec(), None, &auth)
        .await
        .unwrap();
    assert_eq!(desc.sha256, hash);

    let err = client()
        .upload_to_servers(&[], DATA.to_vec(), None, &auth)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoServers), "{err:?}");
}

#[tokio::test]
async fn client_signed_auth_round_trips_the_header() {
    // `Client::sign` on `EventBuilder::from(Authorization)` produces a
    // verifiable kind 24242 event the header round-trips.
    let mut http = MockHttp::start().await.unwrap();
    let server = server(&http);
    let hash = BlobHash::of(DATA);
    http.route(
        "PUT",
        "/upload",
        MockResponse::new(200).body(descriptor(&hash, "https://x/")),
    );
    let mut options = ClientOptions::default();
    options.signer = Some(Arc::new(Keys::generate().unwrap()));
    let client = Client::new(options);
    let builder = EventBuilder::from(
        Authorization::new(AuthVerb::Upload, Timestamp::from_secs(1_700_000_000))
            .blob(hash)
            .message("upload it")
            .unwrap(),
    );
    let event = client.sign(builder).await.unwrap();
    event.verify().unwrap();
    let http_client = HttpClient::new(HttpOptions::default()).unwrap();
    http_client
        .upload(&server, DATA.to_vec(), None, &event)
        .await
        .unwrap();
    let request = http.next_request().await.unwrap();
    let decoded = decoded_auth(&request);
    assert_eq!(decoded.to_json(), event.to_json());
}
