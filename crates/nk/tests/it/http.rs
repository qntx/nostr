//! `http`-feature coverage: `HttpClient` against `MockRelay` and
//! `MockHttp`.

use std::time::Duration;

use nk::http::{Error, HttpClient, HttpOptions};
use nk::testing::{MockHttp, MockRelay, MockResponse};
use nk_core::RelayUrl;

const INFO: &str = r#"{"name":"mock","supported_nips":[1,11]}"#;

fn client() -> HttpClient {
    HttpClient::new(HttpOptions::default()).unwrap()
}

#[tokio::test]
async fn relay_information_round_trip() {
    let relay = MockRelay::start().await.unwrap();
    relay.set_information(INFO);
    let info = client().relay_information(&relay.url()).await.unwrap();
    assert_eq!(info.name.as_deref(), Some("mock"));
    assert_eq!(info.supported_nips, Some(vec![1, 11]));
}

#[tokio::test]
async fn relay_information_unset_is_status_404() {
    let relay = MockRelay::start().await.unwrap();
    let err = client().relay_information(&relay.url()).await.unwrap_err();
    assert!(matches!(err, Error::Status { status: 404, .. }), "{err:?}");
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let http = MockHttp::start().await.unwrap();
    http.route(
        "GET",
        "/",
        MockResponse::new(301).header("location", "https://evil.example/"),
    );
    let url = format!("ws://{}/", http.url().strip_prefix("http://").unwrap());
    let err = client()
        .relay_information(&RelayUrl::parse(&url).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Status { status: 301, .. }), "{err:?}");
}

#[tokio::test]
async fn x_reason_lands_in_status() {
    let http = MockHttp::start().await.unwrap();
    http.route(
        "GET",
        "/",
        MockResponse::new(500).header("x-reason", "too many requests"),
    );
    let url = format!("ws://{}/", http.url().strip_prefix("http://").unwrap());
    let err = client()
        .relay_information(&RelayUrl::parse(&url).unwrap())
        .await
        .unwrap_err();
    match err {
        Error::Status { status, reason } => {
            assert_eq!(status, 500);
            assert_eq!(reason.as_deref(), Some("too many requests"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let http = MockHttp::start().await.unwrap();
    http.route("GET", "/", MockResponse::new(200).body(vec![b'x'; 1024]));
    let mut options = HttpOptions::default();
    options.max_response_size = 100;
    let client = HttpClient::new(options).unwrap();
    let url = format!("ws://{}/", http.url().strip_prefix("http://").unwrap());
    let err = client
        .relay_information(&RelayUrl::parse(&url).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge), "{err:?}");
}

#[tokio::test]
async fn delayed_response_times_out() {
    let http = MockHttp::start().await.unwrap();
    http.route(
        "GET",
        "/",
        MockResponse::new(200)
            .body(INFO)
            .delay(Duration::from_secs(5)),
    );
    let mut options = HttpOptions::default();
    options.timeout = Duration::from_millis(200);
    let client = HttpClient::new(options).unwrap();
    let url = format!("ws://{}/", http.url().strip_prefix("http://").unwrap());
    let err = client
        .relay_information(&RelayUrl::parse(&url).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
}

#[tokio::test]
async fn malformed_document_is_nip11_error() {
    let relay = MockRelay::start().await.unwrap();
    relay.set_information("not json");
    let err = client().relay_information(&relay.url()).await.unwrap_err();
    assert!(matches!(err, Error::Nip11(_)), "{err:?}");
}

#[tokio::test]
async fn accept_header_reaches_the_mock() {
    let mut http = MockHttp::start().await.unwrap();
    http.route("GET", "/", MockResponse::new(200).body(INFO));
    let url = format!("ws://{}/", http.url().strip_prefix("http://").unwrap());
    client()
        .relay_information(&RelayUrl::parse(&url).unwrap())
        .await
        .unwrap();
    let request = http.next_request().await.unwrap();
    let accept = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept"));
    assert_eq!(
        accept.map(|(_, v)| v.as_str()),
        Some("application/nostr+json")
    );
}
