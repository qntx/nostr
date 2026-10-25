//! Blossom BUD-01/02/04/06 helpers on [`HttpClient`]: upload,
//! preflight check, list, delete, mirror, existence probe, fetch and
//! NIP-B7 URL healing.

use hyper::body::Bytes;
use nk_core::PublicKey;
use nk_core::event::Event;
use nk_core::nips::blossom::{BlobDescriptor, BlobHash, Server, authorization_header};

use super::{Error, HttpClient, Response, Result, utf8};

impl HttpClient {
    /// `PUT {server}/upload`. The descriptor's hash must equal the
    /// SHA-256 of `data` — a server lying about the stored blob is a
    /// [`Error::HashMismatch`].
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent);
    /// [`Error::Blossom`] on a descriptor failing the wire checks;
    /// [`Error::HashMismatch`]; the transport errors of `send`.
    pub async fn upload(
        &self,
        server: &Server,
        data: Vec<u8>,
        content_type: Option<&str>,
        auth: &Event,
    ) -> Result<BlobDescriptor> {
        let hash = BlobHash::of(&data);
        self.upload_bytes(server, Bytes::from(data), &hash, content_type, auth)
            .await
    }

    /// The `Bytes` form shared by [`Self::upload`] and
    /// [`Self::upload_to_servers`] — one hash, one copy.
    async fn upload_bytes(
        &self,
        server: &Server,
        data: Bytes,
        hash: &BlobHash,
        content_type: Option<&str>,
        auth: &Event,
    ) -> Result<BlobDescriptor> {
        let mut headers = vec![
            ("Authorization", authorization_header(auth)),
            ("X-SHA-256", hash.to_string()),
        ];
        if let Some(ct) = content_type.filter(|ct| !ct.is_empty()) {
            headers.push(("Content-Type", String::from(ct)));
        }
        let body = self
            .exchange(
                hyper::Method::PUT,
                &server.endpoint("/upload"),
                &headers,
                Some(data),
            )
            .await?;
        let desc = BlobDescriptor::from_json(utf8(&body)?).map_err(Error::Blossom)?;
        if desc.sha256 != *hash {
            return Err(Error::HashMismatch);
        }
        Ok(desc)
    }

    /// BUD-06 preflight: `HEAD {server}/upload` carrying the blob's
    /// hash and size — no body is sent.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent);
    /// the transport errors of `send`.
    pub async fn check_upload(
        &self,
        server: &Server,
        data: &[u8],
        content_type: Option<&str>,
        auth: &Event,
    ) -> Result<()> {
        let mut headers = vec![
            ("Authorization", authorization_header(auth)),
            ("X-SHA-256", BlobHash::of(data).to_string()),
            ("X-Content-Length", data.len().to_string()),
        ];
        if let Some(ct) = content_type.filter(|ct| !ct.is_empty()) {
            headers.push(("X-Content-Type", String::from(ct)));
        }
        self.exchange(
            hyper::Method::HEAD,
            &server.endpoint("/upload"),
            &headers,
            None,
        )
        .await?;
        Ok(())
    }

    /// `GET {server}/list/{pubkey}` — every item must parse (TS
    /// `listBlobs`).
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent);
    /// [`Error::Blossom`] on a non-array body or an invalid descriptor;
    /// the transport errors of `send`.
    pub async fn list(
        &self,
        server: &Server,
        pubkey: &PublicKey,
        auth: Option<&Event>,
    ) -> Result<Vec<BlobDescriptor>> {
        let url = server.endpoint(&format!("/list/{pubkey}"));
        let headers: Vec<(&str, String)> = auth.map_or_else(Vec::new, |auth| {
            vec![("Authorization", authorization_header(auth))]
        });
        let body = self
            .exchange(hyper::Method::GET, &url, &headers, None)
            .await?;
        BlobDescriptor::list_from_json(utf8(&body)?).map_err(Error::Blossom)
    }

    /// `DELETE {server}/{hash}`.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent); the
    /// transport errors of `send`.
    pub async fn delete(&self, server: &Server, hash: &BlobHash, auth: &Event) -> Result<()> {
        let url = server.endpoint(&format!("/{hash}"));
        self.exchange(
            hyper::Method::DELETE,
            &url,
            &[("Authorization", authorization_header(auth))],
            None,
        )
        .await?;
        Ok(())
    }

    /// BUD-04: `PUT {server}/mirror` — asks the server to fetch
    /// `descriptor.url`. The returned descriptor's hash must equal
    /// `descriptor.sha256`.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent);
    /// [`Error::Blossom`] on an invalid descriptor;
    /// [`Error::HashMismatch`]; the transport errors of `send`.
    pub async fn mirror(
        &self,
        server: &Server,
        descriptor: &BlobDescriptor,
        auth: &Event,
    ) -> Result<BlobDescriptor> {
        let mut headers = vec![
            ("Authorization", authorization_header(auth)),
            ("Content-Type", String::from("application/json")),
            ("X-SHA-256", descriptor.sha256.to_string()),
            ("X-Content-Length", descriptor.size.to_string()),
        ];
        if let Some(ct) = descriptor.mime_type.as_ref().filter(|ct| !ct.is_empty()) {
            headers.push(("X-Content-Type", ct.clone()));
        }
        let body = self
            .exchange(
                hyper::Method::PUT,
                &server.endpoint("/mirror"),
                &headers,
                Some(Bytes::from(descriptor.mirror_body())),
            )
            .await?;
        let desc = BlobDescriptor::from_json(utf8(&body)?).map_err(Error::Blossom)?;
        if desc.sha256 != descriptor.sha256 {
            return Err(Error::HashMismatch);
        }
        Ok(desc)
    }

    /// `HEAD {server}/{hash}`: 2xx → `true`, 404 → `false`, every
    /// other status → [`Error::Status`] (a strict probe — NIP-B7).
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx/404 (with `X-Reason` when sent);
    /// the transport errors of `send`.
    pub async fn blob_exists(&self, server: &Server, hash: &BlobHash) -> Result<bool> {
        let url = server.endpoint(&format!("/{hash}"));
        let Response { status, reason, .. } =
            self.send(hyper::Method::HEAD, &url, &[], None).await?;
        match status {
            404 => Ok(false),
            _ if (200..300).contains(&status) => Ok(true),
            _ => Err(Error::Status { status, reason }),
        }
    }

    /// `GET {server}/{hash}` and verify the bytes against `hash`.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] outside 2xx (with `X-Reason` when sent);
    /// [`Error::HashMismatch`]; the transport errors of `send`.
    pub async fn get_blob(&self, server: &Server, hash: &BlobHash) -> Result<Vec<u8>> {
        let url = server.endpoint(&format!("/{hash}"));
        let body = self.exchange(hyper::Method::GET, &url, &[], None).await?;
        if BlobHash::of(&body) != *hash {
            return Err(Error::HashMismatch);
        }
        Ok(Vec::from(body))
    }

    /// NIP-B7 healing: when `url` is unavailable, probe `servers` for
    /// `hash + extension`. Network errors and non-2xx/3xx statuses
    /// count as unavailable — this never errors.
    pub async fn heal_blob_url(&self, url: &str, servers: &[Server]) -> String {
        let Some(hash) = BlobHash::from_url(url) else {
            return String::from(url);
        };
        let ext = url_extension(url, &hash);
        // 2xx/3xx — the original still serves it.
        if let Ok(Response { status, .. }) = self.send(hyper::Method::HEAD, url, &[], None).await
            && (200..400).contains(&status)
        {
            return String::from(url);
        }
        for server in servers {
            let candidate = server.blob_url(&hash, &ext);
            if let Ok(Response { status, .. }) =
                self.send(hyper::Method::HEAD, &candidate, &[], None).await
                && (200..300).contains(&status)
            {
                return candidate;
            }
        }
        String::from(url)
    }

    /// `PUT /upload` to each server in order until one succeeds — the
    /// last error when all fail. `data` is hashed and copied once.
    ///
    /// # Errors
    ///
    /// [`Error::NoServers`] on an empty list; the last
    /// [`Self::upload`] error when every server fails.
    pub async fn upload_to_servers(
        &self,
        servers: &[Server],
        data: Vec<u8>,
        content_type: Option<&str>,
        auth: &Event,
    ) -> Result<BlobDescriptor> {
        if servers.is_empty() {
            return Err(Error::NoServers);
        }
        let hash = BlobHash::of(&data);
        let data = Bytes::from(data);
        let mut last = None;
        for server in servers {
            match self
                .upload_bytes(server, data.clone(), &hash, content_type, auth)
                .await
            {
                Ok(desc) => return Ok(desc),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(Error::NoServers))
    }

    /// One exchange whose only accepted statuses are 2xx — anything
    /// else is [`Error::Status`]. `blob_exists`/`heal_blob_url`
    /// interpret raw statuses and call `send` directly.
    async fn exchange(
        &self,
        method: hyper::Method,
        url: &str,
        headers: &[(&str, String)],
        body: Option<Bytes>,
    ) -> Result<Bytes> {
        let refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let Response {
            status,
            reason,
            body: bytes,
        } = self.send(method, url, &refs, body).await?;
        if !(200..300).contains(&status) {
            return Err(Error::Status { status, reason });
        }
        Ok(bytes)
    }
}

/// The path suffix after the last 64-hex run — TS
/// `extensionFromHashUrl` (`HASH.png` → `.png`). The hash is found
/// case-insensitively, but the extension keeps the original case.
fn url_extension(url: &str, hash: &BlobHash) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return String::new();
    };
    let path = parsed.path();
    // A serialized URL path is ASCII — byte offsets match the
    // lowercased copy's.
    let Some(i) = path.to_ascii_lowercase().rfind(&hash.to_string()) else {
        return String::new();
    };
    let Some(suffix) = path.get(i + 64..) else {
        return String::new();
    };
    // `/^\.[^/]+/` — a dot plus at least one non-slash character.
    let Some(rest) = suffix.strip_prefix('.') else {
        return String::new();
    };
    let end = rest.find('/').unwrap_or(rest.len());
    if end == 0 {
        return String::new();
    }
    format!(".{}", &rest[..end])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests fail by panicking")]

    use std::str::FromStr;

    use super::*;

    const HASH: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    fn extension(url: &str) -> String {
        url_extension(url, &BlobHash::from_str(HASH).unwrap())
    }

    #[test]
    fn url_extension_cases() {
        assert_eq!(
            extension(&format!("https://cdn.example/{HASH}.png")),
            ".png"
        );
        assert_eq!(
            extension(&format!("https://cdn.example/{HASH}.PNG")),
            ".PNG"
        );
        assert_eq!(extension(&format!("https://cdn.example/{HASH}")), "");
        assert_eq!(extension(&format!("https://cdn.example/{HASH}./x")), "");
        assert_eq!(
            extension(&format!("https://cdn.example/{HASH}.tar.gz/x")),
            ".tar.gz"
        );
        assert_eq!(
            extension(&format!("https://cdn.example/{}.png", HASH.to_uppercase())),
            ".png"
        );
        assert_eq!(extension("not a url"), "");
    }
}
