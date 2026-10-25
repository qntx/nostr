//! Plain-HTTP APIs behind the `http` feature: NIP-11 relay
//! information and NIP-05 lookup over a hyper-util/rustls client.
//!
//! Redirects are never followed — hyper does not follow them, and
//! NIP-05, NIP-11 and Blossom all forbid trusting them, so this stays
//! manual forever.
//!
//! No `hyper`/`rustls` types appear in the public API.

mod nip05;
mod nip11;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Bytes;

/// The result type for this module.
pub type Result<T, E = Error> = core::result::Result<T, E>;

erased_error!(
    TlsError,
    "A type-erased TLS configuration failure.",
    "Wraps any rustls error."
);
erased_error!(
    RequestError,
    "A type-erased HTTP transport failure.",
    "Wraps any connector or body error."
);

/// A plain-HTTP call failed.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Building the TLS configuration failed.
    #[error("tls failure")]
    Tls(#[source] TlsError),
    /// The URL does not parse.
    #[error("invalid url")]
    InvalidUrl,
    /// The whole exchange exceeded `HttpOptions::timeout`.
    #[error("the request timed out")]
    Timeout,
    /// The request or the body read failed.
    #[error("request failure")]
    Request(#[source] RequestError),
    /// The server answered outside the expected status. `reason`
    /// carries the `X-Reason` response header when present.
    #[error("unexpected http status {status}")]
    Status {
        /// The numeric status.
        status: u16,
        /// The `X-Reason` header, when the server sent one.
        reason: Option<String>,
    },
    /// The body exceeded `HttpOptions::max_response_size` while
    /// reading.
    #[error("response body too large")]
    BodyTooLarge,
    /// The body is not valid UTF-8.
    #[error("response body is not utf-8")]
    InvalidBody,
    /// The `nostr.json` document failed the NIP-05 wire checks.
    #[error("invalid nip-05 document")]
    Nip05(#[source] nk_core::nips::nip05::Error),
    /// The relay information document failed the NIP-11 wire checks.
    #[error("invalid nip-11 document")]
    Nip11(#[source] nk_core::nips::nip11::Error),
}

/// [`HttpClient`] tuning. `#[non_exhaustive]` — construct via
/// `Default::default()` and mutate the fields:
///
/// ```
/// let mut opts = nk::http::HttpOptions::default();
/// opts.timeout = std::time::Duration::from_secs(5);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct HttpOptions {
    /// Deadline for the whole exchange — request plus body read.
    pub timeout: Duration,
    /// Cap on the response body, enforced while reading.
    pub max_response_size: usize,
    /// The `User-Agent` request header.
    pub user_agent: String,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_response_size: 16 * 1024 * 1024,
            user_agent: String::from(concat!("nk/", env!("CARGO_PKG_VERSION"))),
        }
    }
}

type InnerClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Empty<Bytes>,
>;

/// A plain-HTTP client for NIP-05/NIP-11 (and later Blossom). `Clone`
/// is cheap — clones share the connection pool. Never follows
/// redirects.
#[derive(Clone)]
pub struct HttpClient {
    client: InnerClient,
    options: Arc<HttpOptions>,
}

impl HttpClient {
    /// Builds the client: ring crypto provider, system-default TLS
    /// versions, `webpki-roots` — the same trust model as `wss://`.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when the TLS configuration cannot be built.
    pub fn new(options: HttpOptions) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(TlsError::new(e)))?
            .with_root_certificates(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);
        Ok(Self {
            client,
            options: Arc::new(options),
        })
    }

    /// One GET exchange: `Uri` parse, request, status read and a
    /// size-capped body read, all under `timeout`. Status interpretation
    /// is the caller's.
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<(u16, Option<String>, Bytes)> {
        let uri: hyper::Uri = url.parse().map_err(|_| Error::InvalidUrl)?;
        let mut builder = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header(hyper::header::USER_AGENT, self.options.user_agent.clone());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| Error::Request(RequestError::new(e)))?;
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| Error::Request(RequestError::new(e)))?;
            let status = response.status().as_u16();
            let reason = response
                .headers()
                .get("x-reason")
                .and_then(|v| v.to_str().ok().map(str::to_owned));
            let limited =
                http_body_util::Limited::new(response.into_body(), self.options.max_response_size);
            let body = match limited.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => return Err(body_error(e)),
            };
            Ok((status, reason, body))
        };
        tokio::time::timeout(self.options.timeout, exchange)
            .await
            .map_err(|_| Error::Timeout)?
    }
}

/// Maps a body-read failure: the size cap is [`Error::BodyTooLarge`],
/// everything else [`Error::Request`].
fn body_error(e: Box<dyn std::error::Error + Send + Sync>) -> Error {
    if e.downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
    {
        Error::BodyTooLarge
    } else {
        Error::Request(RequestError::new(std::io::Error::other(e)))
    }
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// UTF-8 decodes a body for the JSON codecs.
fn utf8(bytes: &Bytes) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidBody)
}
