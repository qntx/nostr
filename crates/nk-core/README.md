# nk-core

The leaf crate of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `core` layer.

NK1-06 scope: the opaque `Error`/`ErrorKind`, protocol limits, `Timestamp`, `RelayUrl` (WHATWG relay-URL normalization, byte-identical to the TS `normalizeURL`), `Kind`/`KindClass`, `PublicKey`, `Tag`/`Tags`/`EventAddress`, the `UnsignedEvent`/`Event` model with canonical NIP-01 serialization and SHA-256 event ids, `SecretKey`/`Keys` (BIP-340 Schnorr signing over `secp256k1`), `Signature::verify`/`Event::verify`, `SingleLetterTag`/`Filter`/`fingerprint` (NIP-01 filter matching, limits, and canonical serialization), and `EventBuilder` with `ProfileMetadata`/`DeletionTarget` (NIP-09 deletion, NIP-18 reposts, NIP-25 reactions — tag shapes byte-identical to the TS `EventBuilder`).

## Features

| feature  | default | effect                                                                   |
| -------- | ------- | ------------------------------------------------------------------------ |
| `std`    | yes     | OS facilities; global secp256k1 context; base for `clock`/`os-rng`       |
| `clock`  | yes     | `Timestamp::now` (wall clock)                                            |
| `os-rng` | yes     | `SecretKey::generate`, `Keys::generate`, `Keys::sign_event` (OS entropy) |

Without `os-rng` the caller supplies randomness (`generate_with_rng`, `sign_event_with_rng`, `sign_id_with_aux`); without `std` secp256k1 uses a per-call self-contained context. Secret material is zeroized on drop.

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
