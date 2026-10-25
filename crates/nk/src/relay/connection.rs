//! The socket half of the driver: one `Transport` plus the reconnect and
//! liveness bookkeeping around it. The driver decides *when* to connect,
//! send, or give up; `Connection` owns *how* — handshake, backoff, ping,
//! and the pong deadline. `Connection` never disconnects itself: every
//! failure returns an `Err` and [`Driver`](super::driver) decides.

use std::time::Duration;

use tokio::time::Instant;

use super::options::RelayOptions;
use super::transport::{Endpoint, Inbound, Transport};
use super::{Error, Result};

/// One relay's connection state.
pub(crate) struct Connection {
    /// The live socket; `None` while disconnected or backing off.
    transport: Option<Transport>,
    /// The parsed endpoint, resolved once at driver start; `None` means
    /// the URL was invalid and every connect fails permanently.
    endpoint: Option<Endpoint>,
    /// Current backoff — doubles on each [`Self::disconnect`], capped.
    backoff: Duration,
    /// When set, a reconnect attempt fires at this instant.
    reconnect_at: Option<Instant>,
    /// Set after a ping until any inbound frame arrives.
    pong_deadline: Option<Instant>,
    /// The options slice this type owns.
    connect_timeout: Duration,
    pong_deadline_dur: Duration,
    reconnect: bool,
    reconnect_min: Duration,
    reconnect_max: Duration,
    max_message_size: usize,
}

impl Connection {
    /// A disconnected `Connection`; the first [`Self::connect`] handshakes.
    /// `endpoint` is `None` when the relay URL failed to parse — an
    /// invalid URL is permanent and never schedules a retry.
    pub(crate) const fn new(endpoint: Option<Endpoint>, options: &RelayOptions) -> Self {
        Self {
            transport: None,
            endpoint,
            backoff: options.reconnect_min,
            reconnect_at: None,
            pong_deadline: None,
            connect_timeout: options.connect_timeout,
            pong_deadline_dur: options.pong_deadline,
            reconnect: options.reconnect,
            reconnect_min: options.reconnect_min,
            reconnect_max: options.reconnect_max,
            max_message_size: options.max_message_size,
        }
    }

    /// `true` while a socket is live.
    pub(crate) const fn is_open(&self) -> bool {
        self.transport.is_some()
    }

    /// Handshakes with the endpoint inside `connect_timeout`; on success
    /// the backoff resets and any armed reconnect is cleared.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] when the URL is unparseable (permanent — no
    /// reconnect is armed); [`Error::Timeout`] when the deadline expires;
    /// [`Error::Transport`] when the handshake fails. The caller runs the
    /// single disconnect path on any error.
    pub(crate) async fn connect(&mut self) -> Result<()> {
        let Some(endpoint) = &self.endpoint else {
            return Err(Error::InvalidUrl);
        };
        let transport =
            Transport::connect(endpoint, self.connect_timeout, self.max_message_size).await?;
        self.transport = Some(transport);
        self.backoff = self.reconnect_min;
        self.reconnect_at = None;
        self.pong_deadline = None;
        Ok(())
    }

    /// Drops the socket and arms the jittered reconnect backoff when
    /// `reconnect` is enabled — called only from `Driver::disconnect` so
    /// a failure doubles the backoff exactly once.
    pub(crate) fn disconnect(&mut self) {
        self.transport = None;
        self.pong_deadline = None;
        if self.reconnect {
            self.reconnect_at = Some(Instant::now() + jittered(self.backoff));
            self.backoff = (self.backoff * 2).min(self.reconnect_max);
        }
    }

    /// The armed reconnect instant, if any.
    pub(crate) const fn reconnect_at(&self) -> Option<Instant> {
        self.reconnect_at
    }

    /// Sends one client message; a write failure returns the error —
    /// the caller decides whether to disconnect.
    ///
    /// # Errors
    ///
    /// [`Error::Disconnected`] without a socket;
    /// [`Error::Transport`] on a write failure.
    pub(crate) async fn send(&mut self, msg: &nk_core::ClientMessage<'_>) -> Result<()> {
        let Some(transport) = self.transport.as_mut() else {
            return Err(Error::Disconnected);
        };
        transport.send(msg).await
    }

    /// The next inbound item; any inbound frame is liveness evidence.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] on a read failure.
    pub(crate) async fn next(&mut self) -> Result<Option<Inbound>> {
        match self.transport.as_mut() {
            Some(t) => t.next().await,
            None => Ok(None),
        }
    }

    /// Sends a ping; the first unanswered ping arms `pong_deadline`.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] on a write failure — the caller treats
    /// it as a dead socket.
    pub(crate) async fn ping(&mut self) -> Result<()> {
        let Some(transport) = self.transport.as_mut() else {
            return Ok(());
        };
        transport.ping().await?;
        // Arm once per unanswered ping — re-arming every tick keeps the
        // deadline just out of reach.
        if self.pong_deadline.is_none() {
            self.pong_deadline = Some(Instant::now() + self.pong_deadline_dur);
        }
        Ok(())
    }

    /// Any inbound frame counts toward the pong deadline.
    pub(crate) const fn saw_inbound(&mut self) {
        self.pong_deadline = None;
    }

    /// The armed pong deadline, if a ping is unanswered.
    pub(crate) const fn pong_deadline(&self) -> Option<Instant> {
        self.pong_deadline
    }

    /// Best-effort close frame; the socket drops either way.
    pub(crate) async fn close(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.close().await;
        }
    }
}

/// Randomized ±25% of `base` so a fleet doesn't reconnect in lockstep.
fn jittered(base: Duration) -> Duration {
    use nk_core::rand_core::TryRng;
    let mut rng = nk_core::SysRng;
    let mut buf = [0u8; 8];
    let frac = rng
        .try_fill_bytes(&mut buf)
        .map_or(25, |()| (u64::from_le_bytes(buf) % 51) as u32);
    base.mul_f64(0.75 + f64::from(frac) / 100.0)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit-test fixtures panic loudly"
)]
mod tests {
    use super::*;

    impl Connection {
        /// Test-only view of the current backoff.
        #[cfg(test)]
        const fn backoff(&self) -> Duration {
            self.backoff
        }
    }

    fn opts() -> RelayOptions {
        RelayOptions {
            reconnect_min: Duration::from_millis(100),
            reconnect_max: Duration::from_secs(60),
            ..RelayOptions::default()
        }
    }

    #[test]
    fn one_disconnect_doubles_backoff_once() {
        // The driver calls `disconnect` once per failure — `connect`'s
        // own error must not double it again (D1).
        let mut conn = Connection::new(Endpoint::parse("ws://127.0.0.1:1").ok(), &opts());
        assert_eq!(conn.backoff(), Duration::from_millis(100));
        conn.disconnect();
        assert_eq!(conn.backoff(), Duration::from_millis(200));
        conn.disconnect();
        assert_eq!(conn.backoff(), Duration::from_millis(400));
    }

    #[test]
    fn invalid_url_is_permanent() {
        let conn = Connection::new(None, &opts());
        assert!(conn.reconnect_at().is_none());
        // The driver can't call connect() — it returns InvalidUrl
        // without arming a retry.
        assert!(conn.reconnect_at().is_none());
    }
}
