# nk-nips

The NIP implementations of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `nips` layer.

Current scope: the opaque `Error`/`ErrorKind` shared by every NIP module; `nip19` — the bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) with byte-identical semantics to the TS implementation: descending TLV order, first-value-wins for duplicated single-valued TLVs, lossy UTF-8 for identifiers and relays, the 5000-character limit, and scalar validation on decoded `nsec`; `nip21` — the `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`), which rejects `nsec` and reports NIP-19 decode failures with `ErrorKind::Nip21`; and `nip44` — NIP-44 v2 authenticated payload encryption (`ConversationKey`, `MessageKeys`, `encrypt`/`decrypt`, `calc_padded_len`), with constant-time MAC verification before decryption, the extended u32 length prefix, and zeroized key material.

```rust,ignore
use nk_nips::nip19;
use nk_core::SecretKey;

let nsec = nip19::encode_nsec(&SecretKey::generate())?; // os-rng feature on nk-core
let entity = nip19::decode(&nsec)?;
```

## Features

| feature  | default | effect                                                                 |
| -------- | ------- | ---------------------------------------------------------------------- |
| `std`    | yes     | OS facilities; base for `clock`/`os-rng`                               |
| `clock`  | yes     | wall-clock helpers where a NIP needs them                              |
| `os-rng` | yes     | OS entropy where a NIP needs it                                        |
| `nip19`  | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) |
| `nip21`  | no      | `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`); needs `nip19`        |
| `nip44`  | no      | NIP-44 v2 payload encryption (`ConversationKey`, `encrypt`/`decrypt`)  |

Each NIP is a separate default-off feature and compiles independently. `nsec` secrets move through `SecretKey::with_secret_bytes` and decoded scratch buffers are zeroized before the key is returned.

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
