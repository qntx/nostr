//! High-level NIP-77 sync — `sync_with` reconciles the local store
//! against one relay, then uploads/downloads the diff; `sync` fans out
//! to every default relay.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::StreamExt;
use nk_core::{Event, EventId, Filter, RelayUrl};
use nk_store::PutOutcome;

use super::{Client, Error, Result};
use crate::relay::PublishOutcome;

/// Which way `sync_with` moves events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncDirection {
    /// Local-only events go to the relay.
    Up,
    /// Remote-only events come to the store (default, as in TS).
    #[default]
    Down,
    /// Both directions.
    Both,
}

/// `sync_with`/`sync` options. `#[non_exhaustive]` — construct via
/// `Default::default()` and mutate the fields:
///
/// ```
/// let mut opts = nk::client::SyncOptions::default();
/// opts.dry_run = true;
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SyncOptions {
    /// Which direction(s) to transfer.
    pub direction: SyncDirection,
    /// Report the diff without transferring anything.
    pub dry_run: bool,
}

/// The result of one `sync_with`: `have`/`need` are the reconciliation
/// sets (local-only / remote-only), `sent`/`received` what moved, and
/// `send_failures` every refused or failed upload by event id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncReport {
    /// Ids the local store has and the relay lacks.
    pub have: Vec<EventId>,
    /// Ids the relay has and the local store lacks.
    pub need: Vec<EventId>,
    /// Events the relay accepted.
    pub sent: Vec<EventId>,
    /// Events written to (or reported for) the local store.
    pub received: Vec<EventId>,
    /// Uploads that failed — `OK(false)` messages or transport errors.
    pub send_failures: BTreeMap<EventId, String>,
}

impl Client {
    /// Reconciles the local store against one relay for `filter`, then
    /// transfers the diff per `options`.
    ///
    /// Uploads run with bounded concurrency (8) and never abort on a
    /// per-event failure — each lands in `send_failures`. Downloads are
    /// batched 100 ids at a time and written with an awaited `put_many`
    /// (not through the persister, so a failure is reported).
    ///
    /// Events still queued in the persister are not yet in the store's
    /// negentropy set — [`Client::flush`] first if that matters.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] — reading items/events or the download write
    /// failed.
    /// [`Error::Relay`] — the `NEG` exchange or a download fetch failed.
    /// [`Error::Closed`] — the client is closed, or the runtime shut
    /// down mid-call.
    pub async fn sync_with(
        &self,
        url: &RelayUrl,
        filter: Filter,
        options: SyncOptions,
    ) -> Result<SyncReport> {
        self.check_open()?;
        let store = Arc::clone(self.store());
        let neg_filter = filter.clone();
        let items = tokio::task::spawn_blocking(move || store.negentropy_items(&neg_filter))
            .await
            .map_err(|_| Error::Closed)?
            .map_err(Error::Store)?
            .into_iter()
            .map(|i| (i.created_at, i.id))
            .collect();
        let relay = self.pool().relay(url);
        let rec = relay.reconcile(filter, items).await.map_err(Error::Relay)?;
        let mut report = SyncReport {
            have: rec.have,
            need: rec.need,
            ..SyncReport::default()
        };
        if options.dry_run {
            return Ok(report);
        }
        if matches!(options.direction, SyncDirection::Up | SyncDirection::Both)
            && !report.have.is_empty()
        {
            self.upload(&relay, &mut report).await?;
        }
        if matches!(options.direction, SyncDirection::Down | SyncDirection::Both)
            && !report.need.is_empty()
        {
            self.download(&relay, &mut report).await?;
        }
        Ok(report)
    }

    /// `sync_with` on every default relay, concurrently.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelays`] — no default relays configured.
    /// [`Error::Closed`] — the client is closed.
    pub async fn sync(
        &self,
        filter: Filter,
        options: SyncOptions,
    ) -> Result<BTreeMap<RelayUrl, Result<SyncReport>>> {
        self.check_open()?;
        if self.relays().is_empty() {
            return Err(Error::NoRelays);
        }
        let out = futures_util::future::join_all(self.relays().iter().map(|u| {
            let filter = filter.clone();
            async move { (u.clone(), self.sync_with(u, filter, options).await) }
        }))
        .await;
        Ok(out.into_iter().collect())
    }

    /// Upload `report.have`: look the events up locally (a missing id
    /// is a recorded failure), then publish with `buffer_unordered(8)`.
    async fn upload(&self, relay: &crate::relay::Relay, report: &mut SyncReport) -> Result<()> {
        let store = Arc::clone(self.store());
        let ids = report.have.clone();
        let events = tokio::task::spawn_blocking(move || store.query(&[Filter::new().ids(ids)]))
            .await
            .map_err(|_| Error::Closed)?
            .map_err(Error::Store)?;
        let by_id: BTreeMap<EventId, Event> = events.into_iter().map(|e| (e.id(), e)).collect();
        for id in &report.have {
            if !by_id.contains_key(id) {
                report
                    .send_failures
                    .insert(*id, "event not in local store".into());
            }
        }
        let mut sent = futures_util::stream::iter(by_id)
            .map(|(id, event)| {
                let relay = relay.clone();
                async move { (id, relay.publish(&event).await) }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        sent.sort_by_key(|(id, _)| *id);
        for (id, res) in sent {
            match res {
                Ok(PublishOutcome { accepted: true, .. }) => report.sent.push(id),
                Ok(o) => drop(report.send_failures.insert(id, o.message)),
                Err(e) => drop(report.send_failures.insert(id, e.to_string())),
            }
        }
        Ok(())
    }

    /// Download `report.need` in serial 100-id chunks; gossip ingests,
    /// then (when persist is on) an awaited `put_many` — `Rejected`
    /// outcomes don't count as received.
    async fn download(&self, relay: &crate::relay::Relay, report: &mut SyncReport) -> Result<()> {
        for chunk in report.need.chunks(100) {
            let out = relay
                .fetch(
                    vec![Filter::new().ids(chunk.iter().copied())],
                    self.request_timeout(),
                )
                .await
                .map_err(Error::Relay)?;
            self.ingest_gossip(&out.events);
            if !self.persist_on() {
                report.received.extend(out.events.iter().map(Event::id));
                continue;
            }
            let store = Arc::clone(self.store());
            let events = out.events;
            // The batch moves into the blocking task and comes back with
            // its outcomes — no copy of the events.
            let (events, outcomes) = tokio::task::spawn_blocking(move || {
                store.put_many(&events).map(|outcomes| (events, outcomes))
            })
            .await
            .map_err(|_| Error::Closed)?
            .map_err(Error::Store)?;
            report.received.extend(
                events
                    .iter()
                    .zip(outcomes)
                    .filter(|(_, o)| *o != PutOutcome::Rejected)
                    .map(|(e, _)| e.id()),
            );
        }
        Ok(())
    }
}
