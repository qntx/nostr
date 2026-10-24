# nk-core

The owned Rust implementation of the nostr wire protocol — the protocol
crate of the `nk-*` workspace, platform-neutral (`no_std` + `alloc`,
sans-IO) and byte-compatible with `@qntx/nostr`: both run the shared
vectors in `vectors/` and the differential stream suite with zero
divergence (Rust's only intentional difference is rejecting non-canonical
JSON that `JSON.parse` accepts).

## Core

The crate root carries the model: per-module error enums (`key::Error`,
`event::Error`, `tag::Error`, `url::Error`, `filter::Error`,
`message::Error`), `Timestamp`, `RelayUrl` (WHATWG relay-URL
normalization), `Kind`/`KindClass`, `PublicKey`, `Tag`/`Tags`/`Coordinate`,
the `UnsignedEvent`/`Event` model with canonical NIP-01 serialization and
SHA-256 event ids, `SecretKey`/`Keys` (BIP-340 Schnorr signing over
`secp256k1`), `Signature::verify`/`Event::verify`,
`SingleLetterTag`/`Filter`/`fingerprint` (NIP-01 filter matching, limits,
canonical serialization), `EventBuilder` with `Metadata`/`DeletionTarget`
(NIP-09 deletion, NIP-18 reposts, NIP-25 reactions), and
`SubscriptionId`/`CountResult`/`ClientMessage`/`RelayMessage`
(NIP-01/NIP-42/NIP-45/NIP-77 wire messages with `from_json`/`to_json`).

```
use nk_core::{EventBuilder, Keys, Timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = Keys::generate()?; // os-rng feature
    let unsigned = EventBuilder::text_note("hello nostr")
        .build_at(keys.public_key(), Timestamp::from_secs(1_700_000_000));
    let event = keys.sign_event(unsigned, &mut nk_core::SysRng)?;
    event.verify()?;
    Ok(())
}
```

## NIPs

`nips` hosts the NIP implementations — every module is always compiled
except `nip04`, `nip44`, and `nip49`, which carry extra dependencies. Each
module owns its own `Error` enum: `nip19` — the bech32 entity codec
(`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`); `nip21` — the `nostr:`
URI scheme; `nip04` — the legacy AES-256-CBC encrypted-DM payload;
`nip44` — NIP-44 v2 authenticated payload encryption with constant-time
MAC verification; `nip49` — `ncryptsec` secret-key encryption; plus the
always-on NIP modules listed in the feature table below.

```
use nk_core::nips::nip19::Entity;
use nk_core::SecretKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nsec = SecretKey::from_bytes([7; 32])?.to_bech32();
    let entity = Entity::from_bech32(&nsec)?;
    assert!(matches!(entity, Entity::Secret(_)));
    Ok(())
}
```

## Features

| feature  | default | effect                                                                                                  |
| -------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `std`    | yes     | OS facilities; global secp256k1 context; base for `clock`/`os-rng`                                      |
| `clock`  | yes     | `Timestamp::now` and wall-clock helpers where a NIP needs them                                          |
| `os-rng` | yes     | `SecretKey::generate`, `Keys::generate`, `SubscriptionId::generate`, `SysRng`                           |
| `nip04`  | no      | legacy encrypted DMs (aes, cbc)                                                                         |
| `nip44`  | no      | v2 payload encryption (chacha20, hkdf, hmac); also enables `nips::nip17`, `nips::nip59`, nip51 privates |
| `nip49`  | no      | `ncryptsec` secret-key encryption (scrypt, chacha20poly1305)                                            |
