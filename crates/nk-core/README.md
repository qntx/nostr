# nk-core

The leaf crate of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `core` layer.

NK1-01 scope: the opaque `Error`/`ErrorKind`, protocol limits, `Timestamp`, and `RelayUrl` (WHATWG relay-URL normalization, byte-identical to the TS `normalizeURL`). Keys, events, filters, tags, and messages land in later milestones.

## Features

| feature | default | effect                          |
| ------- | ------- | ------------------------------- |
| `std`   | yes     | OS facilities; base for `clock` |
| `clock` | yes     | `Timestamp::now` (wall clock)   |

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
