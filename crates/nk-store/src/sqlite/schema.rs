//! Schema constants — byte-identical to `storage/sqlite.ts` (asserted by a
//! test that extracts the template literals from the TS source).

/// Bump on any schema change: a database whose `user_version` does not match
/// is dropped and recreated, not migrated (the store caches relay data).
pub(crate) const SCHEMA_VERSION: i64 = 2;

pub(crate) const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  kind INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  sig TEXT NOT NULL,
  address TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS events_address
  ON events(address) WHERE address IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_kind_created ON events(kind, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_pubkey_kind_created
  ON events(pubkey, kind, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_pubkey_created ON events(pubkey, created_at DESC, id);
CREATE INDEX IF NOT EXISTS events_created ON events(created_at DESC, id);
CREATE TABLE IF NOT EXISTS tags (
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tags_name_value_created
  ON tags(name, value, created_at DESC);
CREATE INDEX IF NOT EXISTS tags_event_id ON tags(event_id);
CREATE TABLE IF NOT EXISTS tombstones (
  kind TEXT NOT NULL CHECK(kind IN ('id', 'pending', 'coord')),
  key TEXT NOT NULL,
  pubkey TEXT,
  until INTEGER,
  PRIMARY KEY(kind, key)
);
CREATE TABLE IF NOT EXISTS outbox_bounds (
  pubkey TEXT NOT NULL,
  kind INTEGER NOT NULL,
  oldest INTEGER NOT NULL,
  newest INTEGER NOT NULL,
  PRIMARY KEY(pubkey, kind)
);
";

/// Dropping a table also drops its indexes. Child tables go before `events`
/// so the drop is safe under `PRAGMA foreign_keys`.
pub(crate) const DROP_SQL: &str = "
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS tombstones;
DROP TABLE IF EXISTS outbox_bounds;
DROP TABLE IF EXISTS events;
";

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "a missing template constant must fail the test loudly"
)]
mod tests {
    use super::*;

    /// The DDL, DROP and version constants must stay byte-identical with the
    /// reference backend so a database file is interchangeable between
    /// languages.
    #[test]
    fn schema_matches_ts() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packages/nostr/src/storage/sqlite.ts"
        ));
        let template = |name: &str| -> String {
            let marker = format!("const {name} = `");
            let start = source.find(&marker).map_or_else(
                || panic!("{name} not found in sqlite.ts"),
                |i| i + marker.len(),
            );
            let end = source[start..]
                .find('`')
                .map_or_else(|| panic!("unterminated {name} in sqlite.ts"), |i| start + i);
            source[start..end].to_owned()
        };
        assert_eq!(SCHEMA_SQL, template("SCHEMA_SQL"));
        assert_eq!(DROP_SQL, template("DROP_SQL"));
        let version_marker = "const SCHEMA_VERSION = ";
        let start = source.find(version_marker).map_or_else(
            || panic!("SCHEMA_VERSION not found in sqlite.ts"),
            |i| i + version_marker.len(),
        );
        let end = source[start..].find(';').map_or_else(
            || panic!("unterminated SCHEMA_VERSION in sqlite.ts"),
            |i| start + i,
        );
        assert_eq!(SCHEMA_VERSION.to_string(), source[start..end].trim());
    }
}
