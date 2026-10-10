# nk

The protocol crate of the `nk-*` workspace: the platform-neutral (`no_std` + `alloc`, sans-IO) Rust counterpart of `@qntx/nostr`'s `core` and `nips` layers. It supersedes `nk-core` and `nk-nips`, which are no longer published — `nk_core::X` is now `nk::X` and `nk_nips::nipXX` is now `nk::nips::nipXX`.

> `nk` 0.13.0+ is a from-scratch implementation and is unrelated to the `nk` 0.3.0 previously published on crates.io under the same name.

## Core

The crate root carries the core model: the opaque `Error`/`ErrorKind`, protocol limits, `Timestamp`, `RelayUrl` (WHATWG relay-URL normalization, byte-identical to the TS `normalizeURL`), `Kind`/`KindClass`, `PublicKey`, `Tag`/`Tags`/`EventAddress`, the `UnsignedEvent`/`Event` model with canonical NIP-01 serialization and SHA-256 event ids, `SecretKey`/`Keys` (BIP-340 Schnorr signing over `secp256k1`), `Signature::verify`/`Event::verify`, `SingleLetterTag`/`Filter`/`fingerprint` (NIP-01 filter matching, limits, and canonical serialization), `EventBuilder` with `ProfileMetadata`/`DeletionTarget` (NIP-09 deletion, NIP-18 reposts, NIP-25 reactions — tag shapes byte-identical to the TS `EventBuilder`), and `SubscriptionId`/`CountHll`/`CountResult`/`ClientMessage`/`RelayMessage` (NIP-01/NIP-42/NIP-45/NIP-77 wire messages, byte-identical encoding and strict parsing).

```rust,ignore
use nk::{EventBuilder, Keys, SecretKey};

let keys = Keys::new(SecretKey::generate()); // os-rng feature
let event = keys.sign_event(EventBuilder::text_note("hello nostr").build_at(
    keys.public_key(),
    1_700_000_000.into(),
))?;
event.verify()?;
```

## NIPs

`nk::nips` hosts the feature-gated NIP implementations, sharing an opaque `Error`/`ErrorKind` that is separate from the core one (a unified error lands later): `nip19` — the bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) byte-identical to the TS implementation; `nip21` — the `nostr:` URI scheme; `nip04` — the legacy AES-256-CBC encrypted-DM payload; `nip44` — NIP-44 v2 authenticated payload encryption with constant-time MAC verification; `nip49` — `ncryptsec` secret-key encryption; and the remaining NIPs listed in the feature table below.

```rust,ignore
use nk::nips::nip19;
use nk::SecretKey;

let nsec = nip19::encode_nsec(&SecretKey::generate())?; // os-rng feature
let entity = nip19::decode(&nsec)?;
```

## Features

| feature  | default | effect                                                                                                  | external dependencies                                 |
| -------- | ------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `std`    | yes     | OS facilities; global secp256k1 context; base for `clock`/`os-rng`                                      | —                                                     |
| `clock`  | yes     | `Timestamp::now` and wall-clock helpers where a NIP needs them                                          | —                                                     |
| `os-rng` | yes     | `SecretKey::generate`, `Keys::generate`, `Keys::sign_event` and OS-entropy NIP helpers                  | `getrandom`                                           |
| `nip04`  | no      | legacy encrypted DMs (`SharedSecret`, `encrypt`/`decrypt`)                                              | `aes`, `base64ct`, `cbc`                              |
| `nip10`  | no      | thread references (`parse_thread_tags`, `reply_tags`/`reply_to`); needs `nip19`                         | —                                                     |
| `nip13`  | no      | proof of work (`pow`, `PowMiner`)                                                                       | —                                                     |
| `nip17`  | no      | private DMs (`chat_message_rumor`, `wrap_direct_message`, kind-10050 lists); needs `nip59`              | —                                                     |
| `nip19`  | no      | bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`)                                  | `bech32`                                              |
| `nip21`  | no      | `nostr:` URI scheme (`NostrUri`, `is_nostr_uri`); needs `nip19`                                         | —                                                     |
| `nip27`  | no      | content tokenizer (`parse_content`, `ContentBlock`); needs `nip19`                                      | `unicode-properties`                                  |
| `nip42`  | no      | relay authentication (`auth_event`, `is_auth_required`)                                                 | —                                                     |
| `nip44`  | no      | NIP-44 v2 payload encryption (`ConversationKey`, `encrypt`/`decrypt`)                                   | `base64ct`, `chacha20`, `hkdf`, `hmac`                |
| `nip46`  | no      | Nostr Connect URI + RPC codecs (`BunkerUri`, `NostrConnectUri`, `Request`/`Response`)                   | —                                                     |
| `nip49`  | no      | `ncryptsec` secret-key encryption (`encrypt_with`/`encrypt`/`decrypt`); needs `nip19`                   | `chacha20poly1305`, `scrypt`, `unicode-normalization` |
| `nip51`  | no      | lists (`parse_mute_list`, `mute_list`, `pin_list`, `bookmark_list`, NIP-44 private tags); needs `nip44` | —                                                     |
| `nip57`  | no      | Lightning zaps (`ZapTarget`, `zap_request`, `parse_bolt11`, `validate_zap_receipt`)                     | `bech32`                                              |
| `nip59`  | no      | gift wrap (`Rumor`, `wrap`/`unwrap`, `seal`/`gift_wrap`); needs `nip44`                                 | —                                                     |
| `nip65`  | no      | relay lists (`parse_relay_list`, `relay_list`, `read_relays`/`write_relays`)                            | —                                                     |
| `nip98`  | no      | HTTP auth (`auth_event`, `token`, `unpack_token`, `validate_auth_event`)                                | `base64ct`                                            |

Each NIP is a separate default-off feature and compiles independently. `base16ct`, `rand_core`, `secp256k1`, `serde`, `serde_json`, `sha2`, `url`, and `zeroize` are unconditional core dependencies — the external-dependencies column lists only what a feature adds on top.

Without `os-rng` the caller supplies randomness (`generate_with_rng`, `sign_event_with_rng`, `sign_id_with_aux`); without `std` secp256k1 uses a per-call self-contained context. Secret material is zeroized on drop, raw secret bytes only leave the crate through the scoped `SecretKey::with_secret_bytes` accessor, and `nsec` payloads wipe their decoded scratch buffers before the key is returned.

All public types are `Send + Sync`; no third-party types appear in the public API.

License: MIT OR Apache-2.0.
