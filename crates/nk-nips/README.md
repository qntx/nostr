# nk-nips

The NIP implementations of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `nips` layer.

Current scope: the opaque `Error`/`ErrorKind` shared by every NIP module; `nip19` — the bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) with byte-identical semantics to the TS implementation: descending TLV order, first-value-wins for duplicated single-valued TLVs, lossy UTF-8 for identifiers and relays, the 5000-character limit, and scalar validation on decoded `nsec`; `nip21` — the `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`), which rejects `nsec` and reports NIP-19 decode failures with `ErrorKind::Nip21`; `nip04` — the legacy AES-256-CBC encrypted-DM payload (`SharedSecret`, `encrypt`/`decrypt`) reporting only the missing-iv and generic-payload errors of the TS implementation; and `nip44` — NIP-44 v2 authenticated payload encryption (`ConversationKey`, `MessageKeys`, `encrypt`/`decrypt`, `calc_padded_len`), with constant-time MAC verification before decryption, the extended u32 length prefix, and zeroized key material; and `nip49` — NIP-49 `ncryptsec` secret-key encryption (`KeySecurity`, `EncryptOptions`, `encrypt_with`/`encrypt`/`decrypt`) with scrypt over the NFKC-normalized password, XChaCha20-Poly1305 with the key-security byte as AAD, a `max_log_n` ceiling checked before the KDF, and zeroized intermediates.

```rust,ignore
use nk_nips::nip19;
use nk_core::SecretKey;

let nsec = nip19::encode_nsec(&SecretKey::generate())?; // os-rng feature on nk-core
let entity = nip19::decode(&nsec)?;
```

## Features

| feature  | default | effect                                                                                |
| -------- | ------- | ------------------------------------------------------------------------------------- |
| `std`    | yes     | OS facilities; base for `clock`/`os-rng`                                              |
| `clock`  | yes     | wall-clock helpers where a NIP needs them                                             |
| `os-rng` | yes     | OS entropy where a NIP needs it                                                       |
| `nip04`  | no      | legacy encrypted DMs (`SharedSecret`, `encrypt`/`decrypt`)                            |
| `nip13`  | no      | proof of work (`pow`, `PowMiner`)                                                     |
| `nip19`  | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`)                |
| `nip21`  | no      | `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`); needs `nip19`                       |
| `nip42`  | no      | relay authentication (`auth_event`, `is_auth_required`)                               |
| `nip44`  | no      | NIP-44 v2 payload encryption (`ConversationKey`, `encrypt`/`decrypt`)                 |
| `nip49`  | no      | `ncryptsec` secret-key encryption (`encrypt_with`/`encrypt`/`decrypt`); needs `nip19` |
| `nip59`  | no      | gift wrap (`Rumor`, `wrap`/`unwrap`, `seal`/`gift_wrap`); needs `nip44`               |
| `nip98`  | no      | HTTP auth (`auth_event`, `token`, `unpack_token`, `validate_auth_event`)              |

Each NIP is a separate default-off feature and compiles independently. `nsec` secrets move through `SecretKey::with_secret_bytes` and decoded scratch buffers are zeroized before the key is returned.

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
