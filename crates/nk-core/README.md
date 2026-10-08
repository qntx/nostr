# nk-core

The leaf crate of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `core` layer.

NK1-02 scope: the opaque `Error`/`ErrorKind`, protocol limits, `Timestamp`, `RelayUrl` (WHATWG relay-URL normalization, byte-identical to the TS `normalizeURL`), `Kind`/`KindClass`, `PublicKey`, `Tag`/`Tags`/`EventAddress`, and the `UnsignedEvent`/`Event` model with canonical NIP-01 serialization and SHA-256 event ids. Secret keys, signing, and verification land in NK1-03.

## Features

| feature | default | effect                          |
| ------- | ------- | ------------------------------- |
| `std`   | yes     | OS facilities; base for `clock` |
| `clock` | yes     | `Timestamp::now` (wall clock)   |

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
