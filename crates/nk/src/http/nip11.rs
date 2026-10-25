//! NIP-11: fetching a relay's information document over HTTP.

use nk_core::RelayUrl;
use nk_core::nips::nip11::RelayInformation;

use super::{Error, HttpClient, Response, Result, utf8};

impl HttpClient {
    /// `GET`s the relay's NIP-11 document (`Accept:
    /// application/nostr+json`) and parses it leniently. Any 2xx
    /// status is accepted; redirects are never followed.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with the `X-Reason` header when
    /// sent); [`Error::Nip11`] on a document failing the wire checks;
    /// the transport errors of `HttpClient::send`.
    pub async fn relay_information(&self, relay: &RelayUrl) -> Result<RelayInformation> {
        let url = RelayInformation::url(relay);
        let Response {
            status,
            reason,
            body,
        } = self
            .send(
                hyper::Method::GET,
                &url,
                &[("Accept", "application/nostr+json")],
                None,
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(Error::Status { status, reason });
        }
        RelayInformation::from_json(utf8(&body)?).map_err(Error::Nip11)
    }
}
