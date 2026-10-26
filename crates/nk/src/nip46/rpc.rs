//! The NIP-46 RPC plumbing: the pending-request table, the response
//! listener task, and the reply type they share.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::StreamExt;
use nk_core::nips::nip44::ConversationKey;
use nk_core::nips::nip46::Response;
use tokio::sync::mpsc;
use tracing::debug;

use crate::pool::{PoolEvent, PoolSubscription};

/// What a decrypted response means to a waiting call.
pub(crate) enum Reply {
    /// `result == "auth_url"` — the real reply follows under
    /// `auth_timeout`; `error` carries the URL.
    AuthUrl(String),
    /// The terminal reply for the request id.
    Response {
        /// The `result` payload, when present.
        result: Option<String>,
        /// The `error` payload, when present.
        error: Option<String>,
    },
}

/// The in-flight RPC reply channels, keyed by request id.
#[derive(Default)]
pub(crate) struct Pending(Mutex<HashMap<String, mpsc::Sender<Reply>>>);

/// A pending entry's deregistration guard — removes the id on drop.
pub(crate) struct Registration {
    pending: Arc<Pending>,
    id: String,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.pending
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl Pending {
    /// Registers `id`; the returned guard deregisters on drop.
    pub(crate) fn register(self: &Arc<Self>, id: String) -> (Registration, mpsc::Receiver<Reply>) {
        let (tx, rx) = mpsc::channel(4);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), tx);
        (
            Registration {
                pending: Arc::clone(self),
                id,
            },
            rx,
        )
    }

    /// Routes one decoded response: `auth_url` notifies the waiter
    /// without resolving it; anything else ends the call. Unknown ids
    /// are ignored.
    pub(crate) fn route(&self, response: Response) {
        let Response { id, result, error } = response;
        let mut pending = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if result.as_deref() == Some("auth_url") {
            if let Some(tx) = pending.get(&id) {
                drop(tx.try_send(Reply::AuthUrl(error.unwrap_or_default())));
            }
            return;
        }
        if let Some(tx) = pending.remove(&id) {
            drop(tx.try_send(Reply::Response { result, error }));
        }
    }

    /// Drops every channel — waiting callers see a closed receiver.
    pub(crate) fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// The response-listener task: decrypt every kind-24133 event on the
/// subscription and route it by request id. Failures are logged and
/// skipped — a bad event must not kill the listener.
pub(crate) async fn listen(
    mut sub: PoolSubscription,
    conversation: ConversationKey,
    pending: Arc<Pending>,
) {
    while let Some(item) = sub.next().await {
        let PoolEvent::Event { event, .. } = item else {
            continue;
        };
        let payload = match conversation.decrypt(event.content()) {
            Ok(payload) => payload,
            Err(e) => {
                debug!("undecryptable nip46 event {}: {e}", event.id().to_hex());
                continue;
            }
        };
        match Response::from_json(&payload) {
            Ok(response) => pending.route(response),
            Err(e) => debug!("malformed nip46 response: {e}"),
        }
    }
}
