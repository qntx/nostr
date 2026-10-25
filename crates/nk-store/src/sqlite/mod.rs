//! `SqliteStore` — a persistent [`EventStore`] over one `Mutex<Connection>`.
//!
//! The schema, tombstone encoding, IN-list chunking, and filter compilation
//! are the reference backend's, so a database file is interchangeable
//! between languages. Every write batch runs in one transaction; WAL and
//! `synchronous = NORMAL` apply to file databases only.

mod schema;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use nk_core::{Coordinate, Event, EventId, Filter, PublicKey, Signature, Tags, Timestamp};
use rusqlite::types::Value;
use rusqlite::{Connection, Transaction, params_from_iter};

use crate::policy::{self, DeletionPlan, DeletionState};
use crate::{BackendError, Error, EventStore, NegentropyItem, PutOutcome, Result};
use schema::{DROP_SQL, SCHEMA_SQL, SCHEMA_VERSION};

/// `IN` list chunk size — the reference `IN_CHUNK`.
const IN_CHUNK: usize = 500;

/// `Timestamp` → the SQLite INTEGER bound value; the column is `i64`.
fn ts_to_i64(ts: Timestamp) -> i64 {
    i64::try_from(ts.as_secs()).unwrap_or(i64::MAX)
}

/// A stored INTEGER → `Timestamp`; negative rows are corrupt but clamped
/// rather than panicking.
fn ts_from_i64(value: i64) -> Timestamp {
    Timestamp::from_secs(u64::try_from(value).unwrap_or_default())
}

/// For a kind-5 event: `e` values join `id_list`, well-formed `a` values join
/// `address_list` — the same keys `plan_deletion` inspects.
fn collect_deletion_refs(event: &Event, id_list: &mut Vec<String>, address_list: &mut Vec<String>) {
    for tag in event.tags() {
        let Some(value) = tag.value() else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if tag.name() == "e" {
            id_list.push(value.to_lowercase());
        } else if tag.name() == "a"
            && value.splitn(3, ':').count() == 3
            && !address_list.iter().any(|a| a == value)
        {
            // The plan validates the `a` coordinate's shape; the lookup only
            // needs the literal key.
            address_list.push(value.to_owned());
        }
    }
}

/// Decodes a stored event row — `id`/`pubkey`/`sig` hex, `kind`/`created_at`
/// integer ranges, `tags` compact JSON — into a shape-valid `Event`. A
/// failing column is `Error::Corrupt("<column>")`.
fn decode_event_row(
    id: &str,
    pubkey: &str,
    kind: i64,
    created_at: i64,
    content: &str,
    tags: &str,
    sig: &str,
) -> Result<Event> {
    let id = EventId::from_hex(id).map_err(|_| Error::Corrupt("events.id"))?;
    let pubkey = PublicKey::from_hex(pubkey).map_err(|_| Error::Corrupt("events.pubkey"))?;
    let kind = u16::try_from(kind).map_err(|_| Error::Corrupt("events.kind"))?;
    let sig = Signature::from_hex(sig).map_err(|_| Error::Corrupt("events.sig"))?;
    let tags: Tags = serde_json::from_str(tags).map_err(|_| Error::Corrupt("events.tags"))?;
    Ok(Event::new(
        id,
        pubkey,
        ts_from_i64(created_at),
        nk_core::Kind::new(kind),
        tags,
        content.to_owned(),
        sig,
    ))
}

/// The `id, pubkey, kind, created_at, content, tags, sig` column order of a
/// stored event row.
type Cols = (String, String, i64, i64, String, String, String);

fn backend(error: rusqlite::Error) -> Error {
    Error::Backend(BackendError::new(error))
}

/// Splits `values` into `IN_CHUNK`-sized chunks.
fn chunk<T>(values: &[T]) -> Vec<&[T]> {
    values.chunks(IN_CHUNK).collect()
}

/// The `#x` filter parameter — `e`/`p` values lowercase filter-side like
/// `matches`; other letters match verbatim.
fn tag_param(name: &str, value: &str) -> String {
    if matches!(name, "e" | "p") {
        value.to_lowercase()
    } else {
        value.to_owned()
    }
}

/// `column IN (?, …)` for `count` placeholders.
fn in_clause(column: &str, count: usize) -> String {
    format!("{column} IN ({})", vec!["?"; count].join(","))
}

/// One `(wheres, params)` arm of a compiled filter — a plan is the cartesian
/// product of one arm per constrained field.
#[derive(Debug)]
struct Plan {
    wheres: Vec<String>,
    params: Vec<Value>,
}

/// Compiles `filter` like the reference `compileFilter`: the cartesian
/// product of each field's IN-chunk arms. List fields are never empty —
/// `Filter` rejects them at construction and on the wire.
fn compile_filter(filter: &Filter) -> Vec<Plan> {
    let mut variants: Vec<Vec<Plan>> = Vec::new();
    let mut push_in = |clause: &str, values: Vec<Value>| {
        variants.push(
            chunk(&values)
                .into_iter()
                .map(|c| Plan {
                    wheres: vec![in_clause(clause, c.len())],
                    params: c.to_vec(),
                })
                .collect(),
        );
    };
    if let Some(ids) = filter.get_ids() {
        push_in(
            "id",
            ids.iter().map(|id| Value::from(id.to_hex())).collect(),
        );
    }
    if let Some(authors) = filter.get_authors() {
        push_in(
            "pubkey",
            authors.iter().map(|pk| Value::from(pk.to_hex())).collect(),
        );
    }
    if let Some(kinds) = filter.get_kinds() {
        push_in(
            "kind",
            kinds
                .iter()
                .map(|k| Value::from(i64::from(k.as_u16())))
                .collect(),
        );
    }
    if let Some(since) = filter.get_since() {
        variants.push(vec![Plan {
            wheres: vec!["created_at >= ?".to_owned()],
            params: vec![Value::from(ts_to_i64(since))],
        }]);
    }
    if let Some(until) = filter.get_until() {
        variants.push(vec![Plan {
            wheres: vec!["created_at <= ?".to_owned()],
            params: vec![Value::from(ts_to_i64(until))],
        }]);
    }
    for letter in filter.tag_letters() {
        let Some(values) = filter.tag_values(letter) else {
            continue;
        };
        let name = letter.as_char().to_string();
        variants.push(
            chunk(values)
                .into_iter()
                .map(|c| {
                    let mut params = vec![Value::from(name.clone())];
                    params.extend(c.iter().map(|v| Value::from(tag_param(&name, v))));
                    Plan {
                        wheres: vec![format!(
                            "EXISTS (SELECT 1 FROM tags t WHERE t.event_id = events.id \
                             AND t.name = ? AND {})",
                            in_clause("t.value", c.len())
                        )],
                        params,
                    }
                })
                .collect(),
        );
    }
    let mut plans = vec![Plan {
        wheres: vec![],
        params: vec![],
    }];
    for field in variants {
        let mut next = Vec::with_capacity(plans.len() * field.len());
        for plan in &plans {
            for variant in &field {
                let mut wheres = plan.wheres.clone();
                wheres.extend(variant.wheres.iter().cloned());
                let mut params = plan.params.clone();
                params.extend(variant.params.iter().cloned());
                next.push(Plan { wheres, params });
            }
        }
        plans = next;
    }
    plans
}

/// The put-decision lookup over transaction state.
struct SqlLookup {
    deletion: DeletionState,
    by_id: HashMap<EventId, Event>,
    by_address: HashMap<String, Event>,
}

impl policy::Lookup for SqlLookup {
    fn deletion(&self) -> &DeletionState {
        &self.deletion
    }
    fn stored(&self, id: &EventId) -> Option<policy::Stored> {
        self.by_id.get(id).map(policy::Stored::of)
    }
    fn replaceable(&self, coordinate: &Coordinate) -> Option<(Timestamp, EventId)> {
        self.by_address
            .get(&coordinate.to_string())
            .map(|e| (e.created_at(), e.id()))
    }
}

/// A persistent [`EventStore`]. One `Mutex<Connection>`; `put_many` is a
/// single transaction — a failing batch leaves nothing.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Opens (or creates) a file database at `path` with WAL and
    /// `synchronous = NORMAL`, migrating the schema.
    ///
    /// # Errors
    /// [`Error::Backend`] when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref()).map_err(backend)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .map_err(backend)?;
        Self::new(conn)
    }

    /// Opens an in-memory database, migrating the schema.
    ///
    /// # Errors
    /// [`Error::Backend`] when the database cannot be opened or migrated.
    pub fn open_in_memory() -> Result<Self> {
        Self::new(Connection::open_in_memory().map_err(backend)?)
    }

    /// Runs the migration and wraps the connection.
    fn new(conn: Connection) -> Result<Self> {
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(backend)?;
        if version != SCHEMA_VERSION {
            if version != 0 {
                conn.execute_batch(DROP_SQL).map_err(backend)?;
            }
            conn.execute_batch(SCHEMA_SQL).map_err(backend)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(backend)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// # Errors
    ///
    /// [`Error::Backend`] on a driver failure.
    /// Fetches the events the lookup needs: `ids` (the event's own id plus,
    /// for a deletion, its `e` targets) and `addresses` (its own coordinate
    /// plus `a` targets).
    fn build_lookup(tx: &Transaction<'_>, event: &Event) -> Result<SqlLookup> {
        let mut id_list = vec![event.id().to_hex()];
        let mut address_list = Vec::new();
        if let Some(own) = policy::coordinate_of(event) {
            address_list.push(own.to_string());
        }
        if event.kind().as_u16() == 5 {
            collect_deletion_refs(event, &mut id_list, &mut address_list);
        }
        let mut by_id = HashMap::new();
        let ids: Vec<Value> = id_list.iter().map(|i| Value::from(i.clone())).collect();
        for c in chunk(&ids) {
            let mut stmt = tx
                .prepare_cached(&format!(
                    "SELECT id, pubkey, kind, created_at, content, tags, sig FROM events \
                     WHERE {}",
                    in_clause("id", c.len())
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(params_from_iter(c.iter().cloned()), Self::row_to_cols)
                .map_err(backend)?;
            for row in rows {
                let (id, pk, kind, ca, content, tags, sig) = row.map_err(backend)?;
                let stored = decode_event_row(&id, &pk, kind, ca, &content, &tags, &sig)?;
                by_id.insert(stored.id(), stored);
            }
        }
        let mut by_address = HashMap::new();
        let addresses: Vec<Value> = address_list
            .iter()
            .map(|a| Value::from(a.clone()))
            .collect();
        for c in chunk(&addresses) {
            let mut stmt = tx
                .prepare_cached(&format!(
                    "SELECT id, pubkey, kind, created_at, content, tags, sig FROM events \
                     WHERE {}",
                    in_clause("address", c.len())
                ))
                .map_err(backend)?;
            let rows = stmt
                .query_map(params_from_iter(c.iter().cloned()), Self::row_to_cols)
                .map_err(backend)?;
            for row in rows {
                let (id, pk, kind, ca, content, tags, sig) = row.map_err(backend)?;
                let stored = decode_event_row(&id, &pk, kind, ca, &content, &tags, &sig)?;
                by_address.extend(
                    policy::coordinate_of(&stored).map(|coord| (coord.to_string(), stored)),
                );
            }
        }
        let mut deletion = DeletionState::default();
        let own_address = policy::coordinate_of(event);
        let (sql, params): (String, Vec<Value>) = own_address.map_or_else(
            || {
                (
                    "SELECT kind, key, pubkey, until FROM tombstones \
                     WHERE kind IN ('id', 'pending') AND key = ?"
                        .to_owned(),
                    vec![Value::from(event.id().to_hex())],
                )
            },
            |address| {
                (
                    "SELECT kind, key, pubkey, until FROM tombstones \
                     WHERE (kind IN ('id', 'pending') AND key = ?) \
                        OR (kind = 'coord' AND key = ?)"
                        .to_owned(),
                    vec![
                        Value::from(event.id().to_hex()),
                        Value::from(address.to_string()),
                    ],
                )
            },
        );
        let mut stmt = tx.prepare_cached(&sql).map_err(backend)?;
        let rows = stmt
            .query_map(params_from_iter(params), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(backend)?;
        for row in rows {
            let (kind, key, pubkey, until) = row.map_err(backend)?;
            match kind.as_str() {
                "id" if let Ok(id) = EventId::from_hex(&key) => {
                    deletion.ids.insert(id);
                }
                "pending"
                    if let (Some(pk), Ok(id)) = (pubkey, EventId::from_hex(&key))
                        && let Ok(pk) = PublicKey::from_hex(&pk) =>
                {
                    deletion.pending.insert(id, pk);
                }
                "coord" if let (Some(until), Ok(coord)) = (until, key.parse::<Coordinate>()) => {
                    deletion.coordinates.insert(coord, ts_from_i64(until));
                }
                _ => return Err(Error::Corrupt("tombstone.kind")),
            }
        }
        Ok(SqlLookup {
            deletion,
            by_id,
            by_address,
        })
    }

    /// Reads the raw column tuple of a stored event — decoding happens
    /// outside `query_map` so corrupt rows surface as [`Error::Corrupt`].
    fn row_to_cols(row: &rusqlite::Row<'_>) -> std::result::Result<Cols, rusqlite::Error> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    }

    /// The outcome a decided put reports (the decision's `result` field).
    const fn outcome_of(decision: &policy::PutDecision) -> PutOutcome {
        match decision {
            policy::PutDecision::Skip(outcome) | policy::PutDecision::Tombstone(outcome) => {
                *outcome
            }
            policy::PutDecision::Delete { .. } => PutOutcome::Deleted,
            policy::PutDecision::Insert { outcome, .. } => *outcome,
        }
    }

    /// Applies one put decision inside `tx`.
    fn apply(tx: &Transaction<'_>, event: &Event, decision: policy::PutDecision) -> Result<()> {
        match decision {
            policy::PutDecision::Skip(_) => Ok(()),
            policy::PutDecision::Tombstone(_) => {
                Self::put_tombstone(tx, "id", &event.id().to_hex())?;
                Self::delete_tombstone(tx, "pending", &event.id().to_hex())
            }
            policy::PutDecision::Delete { plan } => {
                let mut coords = HashMap::new();
                for (key, _until) in &plan.coordinates {
                    coords.extend(
                        Self::by_address(tx, &key.to_string())?.map(|cur| (key.clone(), cur)),
                    );
                }
                let coord_ids = policy::coordinate_removals(&plan.coordinates, &|key| {
                    coords.get(key).map(|e| (e.created_at(), e.id()))
                });
                Self::persist_plan(tx, &event.id().to_hex(), &plan, &coord_ids)?;
                for id in plan.remove_ids.iter().chain(coord_ids.iter()) {
                    Self::delete_event(tx, &id.to_hex())?;
                }
                Self::insert_event(tx, event)
            }
            policy::PutDecision::Insert { replace_id, .. } => {
                if let Some(id) = replace_id {
                    Self::delete_event(tx, &id.to_hex())?;
                }
                Self::insert_event(tx, event)
            }
        }
    }

    /// The stored event at `coordinate`, if any.
    fn by_address(tx: &Transaction<'_>, coordinate: &str) -> Result<Option<Event>> {
        let mut stmt = tx
            .prepare_cached(
                "SELECT id, pubkey, kind, created_at, content, tags, sig FROM events \
                 WHERE address = ?",
            )
            .map_err(backend)?;
        let mut rows = stmt
            .query_map([coordinate], Self::row_to_cols)
            .map_err(backend)?;
        rows.next().map_or_else(
            || Ok(None),
            |row| {
                let (id, pk, kind, ca, content, tags, sig) = row.map_err(backend)?;
                decode_event_row(&id, &pk, kind, ca, &content, &tags, &sig).map(Some)
            },
        )
    }

    /// Persists a deletion plan's tombstones, mirroring `DeletionState.absorb`.
    fn persist_plan(
        tx: &Transaction<'_>,
        deletion_id: &str,
        plan: &DeletionPlan,
        coord_ids: &[EventId],
    ) -> Result<()> {
        Self::delete_tombstone(tx, "pending", deletion_id)?;
        for id in plan.remove_ids.iter().chain(coord_ids.iter()) {
            Self::put_tombstone(tx, "id", &id.to_hex())?;
            Self::delete_tombstone(tx, "pending", &id.to_hex())?;
        }
        for (id, pubkey) in &plan.pending_ids {
            let covered: bool = tx
                .prepare_cached("SELECT 1 AS found FROM tombstones WHERE kind = 'id' AND key = ?")
                .map_err(backend)?
                .exists([id.to_hex()])
                .map_err(backend)?;
            if !covered {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO tombstones (kind, key, pubkey) \
                     VALUES ('pending', ?, ?)",
                )
                .map_err(backend)?
                .execute(params_from_iter([
                    Value::from(id.to_hex()),
                    Value::from(pubkey.to_hex()),
                ]))
                .map_err(backend)?;
            }
        }
        for (key, until) in &plan.coordinates {
            tx.prepare_cached(
                "INSERT INTO tombstones (kind, key, until) VALUES ('coord', ?, ?) \
                 ON CONFLICT(kind, key) \
                 DO UPDATE SET until = MAX(tombstones.until, excluded.until)",
            )
            .map_err(backend)?
            .execute(params_from_iter([
                Value::from(key.to_string()),
                Value::from(ts_to_i64(*until)),
            ]))
            .map_err(backend)?;
        }
        Ok(())
    }

    fn put_tombstone(tx: &Transaction<'_>, kind: &str, key: &str) -> Result<()> {
        tx.prepare_cached("INSERT OR REPLACE INTO tombstones (kind, key) VALUES (?, ?)")
            .map_err(backend)?
            .execute(rusqlite::params![kind, key])
            .map_err(backend)?;
        Ok(())
    }

    fn delete_tombstone(tx: &Transaction<'_>, kind: &str, key: &str) -> Result<()> {
        tx.prepare_cached("DELETE FROM tombstones WHERE kind = ? AND key = ?")
            .map_err(backend)?
            .execute(rusqlite::params![kind, key])
            .map_err(backend)?;
        Ok(())
    }

    /// Inserts one event row plus one `tags` row per single-letter tag —
    /// the `tags` column is the compact JSON form of the tag array.
    fn insert_event(tx: &Transaction<'_>, event: &Event) -> Result<()> {
        let tags_json = serde_json::to_string(event.tags())
            .map_err(|_| Error::Corrupt("event.tags serialize"))?;
        tx.prepare_cached(
            "INSERT INTO events (id, pubkey, kind, created_at, content, tags, sig, address) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .map_err(backend)?
        .execute(params_from_iter([
            Value::from(event.id().to_hex()),
            Value::from(event.pubkey().to_hex()),
            Value::from(i64::from(event.kind().as_u16())),
            Value::from(ts_to_i64(event.created_at())),
            Value::from(event.content().to_owned()),
            Value::from(tags_json),
            Value::from(event.sig().to_hex()),
            policy::coordinate_of(event).map_or(Value::Null, |c| Value::from(c.to_string())),
        ]))
        .map_err(backend)?;
        for tag in event.tags() {
            let name = tag.name();
            if name.len() != 1 {
                continue;
            }
            let Some(value) = tag.value() else {
                continue;
            };
            tx.prepare_cached(
                "INSERT INTO tags (event_id, name, value, created_at) VALUES (?, ?, ?, ?)",
            )
            .map_err(backend)?
            .execute(params_from_iter([
                Value::from(event.id().to_hex()),
                Value::from(name.to_owned()),
                Value::from(value.to_owned()),
                Value::from(ts_to_i64(event.created_at())),
            ]))
            .map_err(backend)?;
        }
        Ok(())
    }

    /// Deletes the event plus its tag rows — explicit, since a transaction
    /// may run where `ON DELETE CASCADE` never fires.
    fn delete_event(tx: &Transaction<'_>, id: &str) -> Result<usize> {
        tx.prepare_cached("DELETE FROM tags WHERE event_id = ?")
            .map_err(backend)?
            .execute([id])
            .map_err(backend)?;
        tx.prepare_cached("DELETE FROM events WHERE id = ?")
            .map_err(backend)?
            .execute([id])
            .map_err(backend)
    }

    /// One filter's rows: compiled plans, each run newest-first with
    /// `LIMIT`, merged deduped newest-first, truncated to `limit`.
    fn filter_rows(conn: &Connection, filter: &Filter) -> Result<Vec<Event>> {
        if filter.get_limit() == Some(0) {
            return Ok(Vec::new());
        }
        let plans = compile_filter(filter);
        let limit = filter.get_limit();
        let tail = " ORDER BY created_at DESC, id ASC";
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut merged: Vec<Event> = Vec::new();
        for plan in &plans {
            let where_clause = if plan.wheres.is_empty() {
                String::new()
            } else {
                format!(" WHERE {}", plan.wheres.join(" AND "))
            };
            let sql = if limit.is_some() {
                format!("SELECT * FROM events{where_clause}{tail} LIMIT ?")
            } else {
                format!("SELECT * FROM events{where_clause}{tail}")
            };
            let mut stmt = conn.prepare_cached(&sql).map_err(backend)?;
            let params: Vec<Value> = limit.map_or_else(
                || plan.params.clone(),
                |l| {
                    let mut p = plan.params.clone();
                    p.push(Value::from(i64::try_from(l).unwrap_or(i64::MAX)));
                    p
                },
            );
            let rows = stmt
                .query_map(params_from_iter(params), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .map_err(backend)?;
            for row in rows {
                let (id, pubkey, created_at, kind, tags, content, sig) = row.map_err(backend)?;
                let event =
                    decode_event_row(&id, &pubkey, kind, created_at, &content, &tags, &sig)?;
                merged.extend(seen.insert(event.id()).then_some(event));
            }
        }
        merged.sort_by(Event::cmp_newest_first);
        if let Some(limit) = limit {
            merged.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        Ok(merged)
    }

    /// `(created_at, id)` items — same selection as `filter_rows` without
    /// decoding the events.
    fn negentropy_rows(conn: &Connection, filter: &Filter) -> Result<Vec<NegentropyItem>> {
        if filter.get_limit() == Some(0) {
            return Ok(Vec::new());
        }
        let plans = compile_filter(filter);
        let limit = filter.get_limit();
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut items: Vec<NegentropyItem> = Vec::new();
        for plan in &plans {
            let where_clause = if plan.wheres.is_empty() {
                String::new()
            } else {
                format!(" WHERE {}", plan.wheres.join(" AND "))
            };
            let sql = if limit.is_some() {
                format!(
                    "SELECT id, created_at FROM events{where_clause} ORDER BY created_at DESC, id ASC LIMIT ?"
                )
            } else {
                format!(
                    "SELECT id, created_at FROM events{where_clause} ORDER BY created_at DESC, id ASC"
                )
            };
            let mut stmt = conn.prepare_cached(&sql).map_err(backend)?;
            let params: Vec<Value> = limit.map_or_else(
                || plan.params.clone(),
                |l| {
                    let mut p = plan.params.clone();
                    p.push(Value::from(i64::try_from(l).unwrap_or(i64::MAX)));
                    p
                },
            );
            let rows = stmt
                .query_map(params_from_iter(params), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(backend)?;
            for row in rows {
                let (id_hex, created_at) = row.map_err(backend)?;
                let id = EventId::from_hex(&id_hex).map_err(|_| Error::Corrupt("events.id"))?;
                items.extend(seen.insert(id).then_some(NegentropyItem {
                    created_at: ts_from_i64(created_at),
                    id,
                }));
            }
        }
        if let Some(limit) = limit {
            items.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        items.sort();
        Ok(items)
    }
}

#[expect(
    clippy::significant_drop_tightening,
    reason = "the lock guard must outlive the transaction or statements borrowed from it"
)]
impl EventStore for SqliteStore {
    fn put(&self, event: &Event) -> Result<PutOutcome> {
        let mut conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = conn.transaction().map_err(backend)?;
        let lookup = Self::build_lookup(&tx, event)?;
        let decision = policy::decide_put(event, &lookup);
        let outcome = Self::outcome_of(&decision);
        Self::apply(&tx, event, decision)?;
        tx.commit().map_err(backend)?;
        Ok(outcome)
    }

    fn put_many(&self, events: &[Event]) -> Result<Vec<PutOutcome>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = conn.transaction().map_err(backend)?;
        let mut results = Vec::with_capacity(events.len());
        for event in events {
            let lookup = Self::build_lookup(&tx, event)?;
            let decision = policy::decide_put(event, &lookup);
            results.push(Self::outcome_of(&decision));
            Self::apply(&tx, event, decision)?;
        }
        tx.commit().map_err(backend)?;
        Ok(results)
    }

    fn get(&self, id: &EventId) -> Result<Option<Event>> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, pubkey, kind, created_at, content, tags, sig FROM events \
                 WHERE id = ?",
            )
            .map_err(backend)?;
        let mut rows = stmt
            .query_map([id.to_hex()], Self::row_to_cols)
            .map_err(backend)?;
        rows.next().map_or_else(
            || Ok(None),
            |row| {
                let (eid, pk, kind, ca, content, tags, sig) = row.map_err(backend)?;
                decode_event_row(&eid, &pk, kind, ca, &content, &tags, &sig).map(Some)
            },
        )
    }

    fn query(&self, filters: &[Filter]) -> Result<Vec<Event>> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen: HashSet<EventId> = HashSet::new();
        let mut out: Vec<Event> = Vec::new();
        for filter in filters {
            out.extend(
                Self::filter_rows(&conn, filter)?
                    .into_iter()
                    .filter(|event| seen.insert(event.id())),
            );
        }
        out.sort_by(Event::cmp_newest_first);
        Ok(out)
    }

    fn count(&self, filters: &[Filter]) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen: HashSet<EventId> = HashSet::new();
        for filter in filters {
            seen.extend(
                Self::filter_rows(&conn, filter)?
                    .into_iter()
                    .map(|e| e.id()),
            );
        }
        Ok(seen.len())
    }

    fn negentropy_items(&self, filter: &Filter) -> Result<Vec<NegentropyItem>> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::negentropy_rows(&conn, filter)
    }

    fn remove(&self, ids: &[EventId]) -> Result<usize> {
        let mut conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = conn.transaction().map_err(backend)?;
        let mut removed = 0usize;
        for id in ids {
            removed += Self::delete_event(&tx, &id.to_hex())?;
            Self::put_tombstone(&tx, "id", &id.to_hex())?;
            Self::delete_tombstone(&tx, "pending", &id.to_hex())?;
        }
        tx.commit().map_err(backend)?;
        Ok(removed)
    }

    fn clear(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        conn.execute_batch(
            "DELETE FROM tags; DELETE FROM events; DELETE FROM tombstones; \
             DELETE FROM outbox_bounds;",
        )
        .map_err(backend)
    }
}
