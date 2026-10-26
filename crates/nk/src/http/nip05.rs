//! NIP-05: `/.well-known/nostr.json` lookup over HTTPS.

use nk_core::PublicKey;
use nk_core::nips::nip05::{Nip05Address, Nip05Document};
use nk_core::nips::nip19::ProfilePointer;

use super::{Error, HttpClient, Response, Result, utf8};

impl HttpClient {
    /// Fetches `address`'s `nostr.json`. NIP-05 requires an exact 200 —
    /// redirects and other statuses are never trusted.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] on any non-200 status (with `X-Reason` when
    /// sent); [`Error::Nip05`] on a document failing the wire checks;
    /// the transport errors of `HttpClient::send`.
    pub async fn nip05_document(&self, address: &Nip05Address) -> Result<Nip05Document> {
        self.nip05_document_at(&address.well_known_url()).await
    }

    /// The URL-level fetch — the crate-private seam tests drive
    /// against `http://` mock servers (public API stays `https://`).
    pub(crate) async fn nip05_document_at(&self, url: &str) -> Result<Nip05Document> {
        let Response {
            status,
            reason,
            body,
        } = self.send(hyper::Method::GET, url, &[], None).await?;
        if status != 200 {
            return Err(Error::Status { status, reason });
        }
        Nip05Document::from_json(utf8(&body)?).map_err(Error::Nip05)
    }

    /// Resolves `address` to its profile pointer; `Ok(None)` only for
    /// a well-formed document without a match.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::nip05_document`].
    pub async fn nip05_profile(&self, address: &Nip05Address) -> Result<Option<ProfilePointer>> {
        Ok(self.nip05_document(address).await?.profile(address))
    }

    /// True when `address` resolves to `pubkey`. `Ok(false)` only for
    /// a well-formed document without that match.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::nip05_document`].
    pub async fn verify_nip05(&self, address: &Nip05Address, pubkey: &PublicKey) -> Result<bool> {
        Ok(self
            .nip05_profile(address)
            .await?
            .is_some_and(|p| p.pubkey == *pubkey))
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::tests_outside_test_module,
        reason = "tests fail by panicking; the lint misses cfg(all(test, ..))"
    )]

    use std::str::FromStr;

    use super::*;
    use crate::http::HttpOptions;
    use crate::testing::{MockHttp, MockResponse};

    const PK: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const PK2: &str = "2c7cc62a697ea3a7826521f3fd34f0cb273693cbe5e9310f35449f43622a5cdc";

    fn client() -> HttpClient {
        HttpClient::new(HttpOptions::default()).unwrap()
    }

    #[tokio::test]
    async fn document_with_relays() {
        let http = MockHttp::start().await.unwrap();
        http.route(
            "GET",
            "/.well-known/nostr.json?name=alice",
            MockResponse::new(200).body(format!(
                r#"{{"names":{{"alice":"{PK}"}},"relays":{{"{PK}":["wss://a.example"]}}}}"#
            )),
        );
        let address = Nip05Address::from_str("alice@example.com").unwrap();
        let doc = client()
            .nip05_document_at(&format!("{}/.well-known/nostr.json?name=alice", http.url()))
            .await
            .unwrap();
        let profile = doc.profile(&address).unwrap();
        assert_eq!(profile.relays, ["wss://a.example"]);
        assert!(
            doc.profile(&address)
                .is_some_and(|p| p.pubkey == PublicKey::from_hex(PK).unwrap())
        );
        assert!(
            doc.profile(&address)
                .is_none_or(|p| p.pubkey != PublicKey::from_hex(PK2).unwrap())
        );
    }

    #[tokio::test]
    async fn document_without_relays() {
        let http = MockHttp::start().await.unwrap();
        http.route(
            "GET",
            "/.well-known/nostr.json?name=_",
            MockResponse::new(200).body(format!(r#"{{"names":{{"_":"{PK}"}}}}"#)),
        );
        let doc = client()
            .nip05_document_at(&format!("{}/.well-known/nostr.json?name=_", http.url()))
            .await
            .unwrap();
        let root = Nip05Address::from_str("example.com").unwrap();
        let profile = doc.profile(&root).unwrap();
        assert_eq!(profile.relays, Vec::<String>::new());
    }

    async fn status_error(http: &MockHttp, status: u16) {
        let path = format!("/.well-known/nostr.json?name={status}");
        http.route("GET", &path, MockResponse::new(status));
        let err = client()
            .nip05_document_at(&format!("{}{path}", http.url()))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Status { status: s, .. } if s == status),
            "{status}: {err:?}"
        );
    }

    #[tokio::test]
    async fn non_200_statuses_error() {
        let http = MockHttp::start().await.unwrap();
        status_error(&http, 301).await;
        status_error(&http, 404).await;
        status_error(&http, 204).await;
    }

    #[tokio::test]
    async fn invalid_document_is_nip05_error() {
        let http = MockHttp::start().await.unwrap();
        http.route("GET", "/", MockResponse::new(200).body(r#"{"names":[]}"#));
        let err = client()
            .nip05_document_at(&format!("{}/", http.url()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Nip05(_)), "{err:?}");
    }
}
