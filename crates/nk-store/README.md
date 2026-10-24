# nk-store

The event-storage crate of the `nk-*` workspace: a synchronous,
object-safe [`EventStore`] trait plus two backends that share one
insertion/deletion policy so put semantics cannot drift.

- [`MemoryStore`] — `RwLock` + `Arc`-shared events in ordered buckets
  (all / pubkey / kind / kind+pubkey / single-letter tag `name:value`),
  with a per-filter planner choosing the smallest usable index.
- [`SqliteStore`] (feature `sqlite`) — a `Mutex<Connection>` backend
  whose schema is byte-identical to `@qntx/nostr`'s SQLite store: the
  files are interchangeable across languages, `put_many` is one
  transaction, and deletion tombstones persist.

Both implement the same NIP-09 deletion semantics (author-scoped `e` and
`a` targets, pending tombstones for unknown ids, coordinate coverage up
to the deletion's `created_at`) through the shared `policy` module.

```
use nk_core::Event;
use nk_store::{EventStore, MemoryStore, PutOutcome};

// A signed NIP-01 text note (kind 1), as received on the wire.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event = Event::from_json(
        r#"{"id":"791e76a4715f1514309947f51c1d20a6f80698833ecc97b7b3a9c56cc3063113","pubkey":"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","created_at":1700000000,"kind":1,"tags":[["t","hi"]],"content":"gm","sig":"35931bdb21989c9049272418de0df733b0ebede3bcb45c54161511d8633cab516d6b25cd808ddb8cbba7600940678e3ba3fe655a830abbe631e640e9fc460ff1"}"#,
    )?;
    let store = MemoryStore::new();
    assert_eq!(store.put(&event)?, PutOutcome::Accepted);
    assert_eq!(store.put(&event)?, PutOutcome::Duplicate);
    Ok(())
}
```

## Features

| feature  | default | effect                                         |
| -------- | ------- | ---------------------------------------------- |
| `sqlite` | no      | `SqliteStore` over `rusqlite` (bundled SQLite) |
