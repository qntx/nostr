//! The WebSocket transport: the only module that knows yawc and `url`.
//! Everything outside sees crate-owned types and [`Error`].

use futures_util::SinkExt;
use yawc::{Frame, WebSocket};

use super::{Error, Result, TransportError};

/// A parsed `ws://`/`wss://` endpoint; parsing happens once per driver.
#[derive(Clone, Debug)]
pub(crate) struct Endpoint(url::Url);

impl Endpoint {
    /// Parses `raw` into an endpoint.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] when `raw` is not a valid URL.
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        raw.parse::<url::Url>()
            .map(Self)
            .map_err(|_| Error::InvalidUrl)
    }
}

/// One inbound wire item.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A text frame carrying a JSON relay message.
    Text(String),
    /// A pong — liveness evidence.
    Pong,
    /// Any other inbound frame.
    Other,
}

/// One live WebSocket connection.
pub(crate) struct Transport {
    ws: yawc::TcpWebSocket,
}

impl Transport {
    /// Handshakes with `endpoint` inside `timeout`, enforcing
    /// `max_message_size` on inbound frames.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] when the deadline expires;
    /// [`Error::Transport`] when the handshake fails.
    pub(crate) async fn connect(
        endpoint: &Endpoint,
        timeout: std::time::Duration,
        max_message_size: usize,
    ) -> Result<Self> {
        let builder = WebSocket::connect(endpoint.0.clone()).with_options(
            yawc::Options::default().with_limits(max_message_size, 2 * max_message_size),
        );
        let ws = tokio::time::timeout(timeout, builder)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Transport(TransportError::new(e)))?;
        Ok(Self { ws })
    }

    /// Sends one client message as a text frame.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the write fails.
    pub(crate) async fn send(&mut self, msg: &nk_core::ClientMessage<'_>) -> Result<()> {
        self.ws
            .send(Frame::text(msg.to_json()))
            .await
            .map_err(|e| Error::Transport(TransportError::new(e)))
    }

    /// The next inbound item; `None` on a clean close.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the read fails.
    pub(crate) async fn next(&mut self) -> Result<Option<Inbound>> {
        let frame = self
            .ws
            .next_frame()
            .await
            .map_err(|e| Error::Transport(TransportError::new(e)))?;
        let inbound = match frame.opcode() {
            yawc::OpCode::Text => std::str::from_utf8(frame.payload())
                .ok()
                .map(|t| Inbound::Text(t.to_owned())),
            yawc::OpCode::Pong => Some(Inbound::Pong),
            yawc::OpCode::Close => None,
            _ => Some(Inbound::Other),
        };
        Ok(inbound)
    }

    /// Sends a WebSocket ping.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when the write fails.
    pub(crate) async fn ping(&mut self) -> Result<()> {
        self.ws
            .send(Frame::ping(&[][..]))
            .await
            .map_err(|e| Error::Transport(TransportError::new(e)))
    }

    /// Best-effort close frame; the socket drops either way.
    pub(crate) async fn close(&mut self) {
        drop(
            self.ws
                .send(Frame::close(yawc::close::CloseCode::Normal, &[][..]))
                .await,
        );
    }
}
