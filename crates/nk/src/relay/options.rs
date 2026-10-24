//! `Relay` tuning. Public fields — the struct is a plain options bag like
//! `std`'s `OpenOptions`: every knob is inspectable, and
//! `RelayOptions::default()` is the sensible profile.

use std::time::Duration;

/// Relay driver configuration.
#[derive(Clone, Copy, Debug)]
pub struct RelayOptions {
    /// Deadline for the WebSocket handshake.
    pub connect_timeout: Duration,
    /// Deadline for a publish's `OK`.
    pub publish_timeout: Duration,
    /// Idle interval between WebSocket pings.
    pub ping_interval: Duration,
    /// Maximum time to wait for a pong before reconnecting.
    pub pong_deadline: Duration,
    /// Reconnect with exponential backoff (jittered) after a drop.
    pub reconnect: bool,
    /// Initial reconnect delay.
    pub reconnect_min: Duration,
    /// Reconnect delay cap.
    pub reconnect_max: Duration,
    /// Maximum inbound message size.
    pub max_message_size: usize,
    /// Per-subscription channel capacity — a fuller consumer is lagged.
    pub subscription_capacity: usize,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            publish_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(30),
            pong_deadline: Duration::from_secs(10),
            reconnect: true,
            reconnect_min: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            max_message_size: 1024 * 1024,
            subscription_capacity: 1024,
        }
    }
}
