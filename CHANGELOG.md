# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A `vX.Y.Z` tag runs `publish-npm.yml` (publishing `packages/nostr` and `packages/nostr-wasm` via npm trusted publishing / OIDC) and `publish-crates.yml` (publishing `nk-core` and `nk-nips` to crates.io).

## [Unreleased]

### Added

- `DelegatedSigner`: a `NostrSigner` backed by a `NostrKeyOperations` key holder (`getPublicKey`, `signEventId`, optional `sharedSecret`) for wallets, NFC cards, and secure stores that never expose the secret. Signatures are BIP-340-verified before returning; NIP-44 conversation keys are derived via the new `nip44.getConversationKeyFromSharedSecret` and cached per peer; NIP-04 uses the new `nip04.encryptWithSharedSecret`/`nip04.decryptWithSharedSecret` with no cache; shared secrets are wiped after each use, and `dispose()` zero-fills the cache and makes later calls reject with `SignerDisposedError` (#223).
- `KeysSigner.dispose()`: zeroizes the wrapped secret key and every cached NIP-44 conversation key; all later signer calls reject with the new `SignerDisposedError`. `KeysSigner` also now wipes the per-call secret-key copies used by NIP-04 and conversation-key derivation (#211).
- `nk-nips` `nip21` feature: `NostrUri` (`parse`/`as_str`/`entity`/`into_entity`, `Display`, `FromStr`) and `is_nostr_uri` — the NIP-21 `nostr:` URI scheme over the NIP-19 codec, verified against the new `vectors/nip21/uri.json` cases by both languages. NIP-19 also gains a seeded differential stream (`nip19.codec` in `scripts/parity/diff.ts` and `nk-vectors`' diff replay) covering random pointers, corrupted bech32, and mutated inputs.
- `nk-nips` `nip04` feature: NIP-04 legacy encrypted direct messages — `SharedSecret` (`derive`, `from_bytes` for external key holders) plus `encrypt_with_iv`/`encrypt_with_rng`/`encrypt` (the last under `os-rng`) and `decrypt` over AES-256-CBC with the unhashed ECDH x coordinate, PKCS#7, and lossy UTF-8. Decryption reports only two errors — missing `?iv=` split and a generic invalid-payload — matching TS. Verified by both languages against the generated `vectors/nip04/codec.json` cases (fixed-IV byte-exact encryption, failure shapes, non-liftable peer keys).
- `nk-nips` `nip49` feature: NIP-49 `ncryptsec` secret-key encryption — `KeySecurity`, `EncryptOptions` (builder for `log_n`/`key_security`), `encrypt_with`/`encrypt_with_rng`/`encrypt` (the last under `os-rng`), and `decrypt` returning `Decrypted { secret_key, key_security }`. scrypt (`r=8`, `p=1`, `dkLen=32`) over the NFKC-normalized password derives the XChaCha20-Poly1305 key with the key-security byte as AAD; `decrypt` rejects `log_n > max_log_n` before scrypt runs, and every intermediate — the normalized password, the scrypt output, the decoded payload — is zeroized. Verified by both languages against `vectors/nip49/official.json` (the spec examples), the generated `vectors/nip49/codec.json` (NFKC-equivalent passwords, every key-security byte, deterministic `encrypt_with` equality, and all failure shapes), and `vectors/nip49/max-logn.json`.
- `nk-core`: `Tag::custom(name, values)` — an infallible constructor that is non-empty by construction because the name element is required (used by `nk-nips`' NIP-13 nonce and NIP-42 auth tags).
- `nk-nips` `nip13` feature: NIP-13 proof of work — `pow` (leading zero bits of an `EventId`) and `PowMiner`, the sans-IO counterpart of `minePow` that takes the current time and a per-call attempt budget, pauses the SHA-256 state before the nonce digits, and clones it per attempt. Verified against `vectors/nip13/codec.json` (leading-zero-bit boundaries plus fixed-`now` mining cases reproduced nonce-for-nonce by both languages).
- `nk-nips` `nip42` feature: NIP-42 relay authentication — `auth_event(&RelayUrl, challenge)` building the kind-22242 template with normalized relay tag, and `is_auth_required` for `auth-required:` CLOSED reasons. Verified against `vectors/nip42/codec.json`.
- `nk-nips` `nip98` feature: NIP-98 HTTP auth — `auth_event` (kind-27235 template with `u`/`method`/`payload` tags), `token` and `authorization_header` (standard base64 of the wire-order event JSON), `unpack_token` (optional `Nostr` scheme, missing `=` padding accepted, TS error messages mirrored), and `validate_auth_event` with `DEFAULT_MAX_SKEW_SECS`. Verified against `vectors/nip98/codec.json` (deterministically signed events via a fixed BIP-340 aux).
- `nk-nips` `nip59` feature: NIP-59 gift wrap — `Rumor` (`createRumor`/`rumorToJson`/`parseRumor` counterparts), `Timestamps`/`RandomScope`/`WrapOptions`, the local-key flow `seal_with_rng`/`gift_wrap_with_rng`/`wrap_with_rng`/`unwrap` (OS-entropy `seal`/`gift_wrap`/`wrap` under `os-rng`), and the pure steps `seal_template`/`check_gift_wrap`/`parse_seal`/`open_rumor` for remote-signer composition. Random offsets use the same big-endian-u32 rejection sampling as TS, unwrap mirrors the TS check order and `Nip59Error` messages, and every draw (timestamp offset, ephemeral key, NIP-44 nonce, BIP-340 aux) comes from the caller's `CryptoRng` in the documented order.
- `nk-nips` `nip17` feature: NIP-17 private direct messages — `Recipient`/`ReplyTo`/`ChatMessageOptions`, `chat_message_rumor` (kind-14 rumor with `p` tags, unmarked reply `e` tag, `subject`), `wrap_direct_message_with_rng`/`wrap_direct_message` (sender copy first, recipients deduplicated by public key, NIP-59 errors propagated per copy), `normalize_recipients`, and the kind-10050 DM relay list (`parse_dm_relay_list`, `dm_relay_list_tags`, `dm_relay_list`). Verified against `vectors/nip17/codec.json` replayed byte-for-byte under the recorded entropy stream.
- `nk-nips` `nip44` feature: NIP-44 v2 payload encryption — `ConversationKey` (`derive`, `from_shared_secret`, `from_bytes`, `to_bytes`), `MessageKeys`, `calc_padded_len`, `encrypt_with_nonce`/`encrypt_with_rng`/`encrypt` (the last under `os-rng`), and `decrypt`/`decrypt_with_max_len` under `DEFAULT_MAX_PAYLOAD_CHARS`. The MAC is verified in constant time before decryption, the extended u32 length prefix is used at ≥65536 bytes, and all key material and scratch buffers are zeroized. Verified by both languages against `vectors/nip44/official.json` (every section), the new `vectors/nip44/extended.json` spec-text boundary cases, and generated `shared-secret.json` cases proving `from_shared_secret(ecdh_x) == conversation_key`; a `nip44.v2` differential stream covers random plaintexts, keys, nonces, and corrupted payloads.
- `nk-nips` is now published to crates.io with the `nip04`, `nip13`, `nip17`, `nip19`, `nip21`, `nip42`, `nip44`, `nip49`, `nip59`, and `nip98` features (all default-off, each compiling independently).
- `finalizeEvent` and `signEvent` accept an optional 32-byte `auxRand` BIP-340 auxiliary randomness (default: a fresh `randomBytes(32)` draw) — the counterpart of nk-core `Keys::sign_event_with_aux`, for reproducible signatures in vectors and tests. Never reuse aux randomness in production.

### Changed

- **BREAKING:** `nip49.decrypt` now requires `opts.maxLogN` — an integer in `1..=22`. A payload whose `logn` exceeds the ceiling throws `Nip49Error` before scrypt runs, bounding memory use at `128 * r * 2^logn` bytes (#211).
- `nip49.decrypt` rejects key-security bytes other than `0x00`, `0x01`, or `0x02` and zero-fills the scrypt-derived key after use (NIP-49).
- `nip49.decrypt` rejects a decrypted secret that is not a valid secp256k1 scalar with `Nip49Error` (NIP-49 ruling N3 — a key that decrypts to `0` or `≥ n` can never sign or derive a conversation key).
- `nip98.getToken` encodes the signed event in canonical NIP-01 field order (`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`) and drops non-event properties from the signer's return value, so tokens are deterministic and byte-identical to nk-nips.
- **BREAKING:** `nip59` `WrapOptions.randomInt` is replaced by `randomBytes` — a single entropy stream feeding the ephemeral secret key, timestamp offsets (big-endian `u32` rejection sampling), the NIP-44 nonce, and the BIP-340 auxiliary randomness, in that order. Gift wraps are reproducible under an injected stream, matching the draw order of `nk-nips`' `*_with_rng` functions.
- `nip59.createGiftWrap` signs through `signEvent`'s `auxRand` parameter instead of an injected signing backend.

### Security

- `nip59.createGiftWrap` wipes the ephemeral secret key, its ephemeral-key candidate draws, and the NIP-44 conversation key after use; `signEvent`, `finalizeEvent`, and the `Keys` constructor wipe the secret-key copies handed to the `SigningBackend` after each call — reducing the lifetime of key material in memory.

### Fixed

- The version bump refreshes `Cargo.lock` again: bumpp runs `execute` without a shell, so the `&&`-chained `cargo update --workspace` never ran and the lockfile kept the pre-bump version. `sync-versions` now spawns the update itself and `check-version` fails lint when a workspace member's lockfile entry drifts.

## [0.11.0] - 2026-10-09

### Added

- `nk-core` is published to crates.io from this release on. The crate is a from-scratch implementation inside this repository and is unrelated to the old `nk` 0.3.x crates on crates.io.
- `nk-core` crate foundation: `no_std` + `alloc` error type, limits, internal hex codec, `Timestamp`, and `RelayUrl` — the Rust counterpart of `normalizeURL`/`normalizeRelayUrls`, verified byte-for-byte against the shared `vectors/core/url-normalize.json` cases by the new `nk-vectors` runner. The Hermes smoke test now runs the same vectors through the `whatwg-url` polyfill.
- `nk-core` event model: `Kind`/`KindClass` (every named `Kind` constant), `PublicKey`, `EventId`, `Signature`, `Tag`/`Tags`/`EventAddress`, `UnsignedEvent`/`Event`, canonical NIP-01 serialization and SHA-256 event ids, `cmp_newest_first`/`cmp_oldest_first`, and `ErrorKind::EventValidation` — parity-verified by the shared kind/tag/event/hex vectors in `nk-vectors`.
- `nk-core` keys, signing, and verification: `SecretKey` (zeroized on drop, `CryptoRng`-injected generation, `os-rng` convenience methods) and `Keys` with BIP-340 Schnorr signing (`sign_id_with_aux`, `sign_event_with_aux`/`_with_rng`/`sign_event`), `Signature::verify`, `Event::verify`, and `ErrorKind::Crypto` — parity-verified against `vectors/core/event-sign.json` and the official `vectors/bip340/official.csv` rows.
- `nk-core` filters: `SingleLetterTag`, `Filter` (chainable builders, set semantics, `matches`/`matches_any`, `limit_bound`, canonical serialization), and `fingerprint` — parity-verified by the shared filter vectors in `nk-vectors`.
- `nk-core` event builder: `ProfileMetadata`, `DeletionTarget`, and `EventBuilder` (`text_note`, `metadata`, `contacts`, `deletion`, `reaction`, `repost`, `generic_repost`, `tag`/`tags`, `build_at`/`build`) matching `EventBuilder` in `core/builder.ts` — parity-verified byte-for-byte against `vectors/core/builder.json`, including the NIP-18 repost content serialization.
- `nk-core` wire messages: `SubscriptionId` (1..=64 Unicode scalar values, RNG-injected generation), `CountHll`/`CountResult` (NIP-45), `ClientMessage`/`RelayMessage` with byte-identical `encode`, strict `parse`, and `ErrorKind::Message` — parity-verified by the shared message/count-hll vectors in `nk-vectors`.
- `nk-nips` crate: the `nips`-layer crate with the shared `Error`/`ErrorKind` and the `nip19` feature — the NIP-19 bech32 entity codec (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`) with `decode`, `encode_*`, and pointer `to_bech32` — parity-verified by the shared `vectors/nip19` cases in `nk-vectors`.

### Changed

- `nk-core`: `SecretKey::to_secret_bytes` is replaced by the scoped accessor `SecretKey::with_secret_bytes`, which hands a zeroized-on-drop copy to a closure so no unwiped secret bytes escape the crate — a pre-release API change ahead of the first crates.io tag (#209).
- `nip19Decode` and the `nevent`/`naddr` encoders now require the kind TLV to be a NIP-01 kind (`0..=65535`); values above 65535 throw `Nip19Error` on both encode and decode (NIP-01/NIP-19).
- `nip19Decode` validates that an `nsec` payload is a valid secp256k1 scalar and throws `Nip19Error` otherwise (NIP-19).
- `assertSubscriptionId` counts Unicode scalar values (`[...id].length`), so astral characters count once per NIP-01's "chars" wording.
- `parseClientMessage` and `parseRelayMessage` now validate subscription ids (1..=64 scalar values) in both directions for every message type carrying one (NIP-01).
- `parseRelayMessage` requires the `OK` event id to be 64-char lowercase hex (NIP-01).
- `validateEvent`/`validateSignedEvent` reject `kind`/`created_at` that are not non-negative safe integers (`Number.isSafeInteger`) and `content` or tag values containing lone UTF-16 surrogates — both of which `JSON.parse` accepts but the Rust side cannot express (NIP-01).
- `parseClientMessage` wire filters require safe integers for `since`/`until`/`limit`/`kinds`, matching the `2^53-1` bound enforced by `nk-core` (NIP-01).

- `matchFilter` and the local event stores (memory, SQLite, IndexedDB) ignore multi-letter `#` keys, matching NIP-01's single-letter tag conditions; the SQLite fallback path for them is removed (NIP-01).
- `canonicalizeFilter` drops unknown non-`#` keys and multi-letter `#` keys, keeping only the NIP-01 known fields plus single-letter tag conditions (NIP-01).
- `canonicalizeFilter` now deduplicates every list so semantically equal filters share one `filterFingerprint` (NIP-01).
- `getFilterLimit` counts unique ids/authors/kinds/`#d` values after deduplication (NIP-01).
- `encodeClientMessage` canonicalizes the filters of `REQ`, `COUNT`, and `NEG-OPEN` before encoding; `parseClientMessage` validates wire filters per NIP-01 (64-hex `ids`/`authors` normalized lowercase, `kinds` in 0..=65535, non-negative `since`/`until`/`limit`, string `search` and `#<letter>` value arrays), lowercases `ids`/`authors`/`#e`/`#p`, and drops multi-letter `#` keys — malformed filters raise `MessageError` (NIP-01).
- `EventBuilder.metadata` emits `ProfileMetadata` keys in declaration order (name, display_name, about, picture, banner, website, nip05, lud06, lud16) regardless of the input object's key order, matching `nk-core`'s `ProfileMetadata` serialization (NIP-01).
- Rust toolchain and workspace MSRV (`rust-version`) moved to 1.99.
- `@qntx/nostr-wasm` now ships `nk_wasm.wasm` built on `nk-core` with its own versioned byte ABI (`nk_*` exports, zero imports, single scratch buffer); `wasm-bindgen` and its CLI are gone. The public API (`loadNostrWasm`, `NostrWasm`, `WasmPoisonedError`, sync call model, browser export) is unchanged.

### Fixed

- `Tag.e`/`Tag.p` now keep NIP-10/NIP-02 positional semantics: a present later slot (marker, pubkey, petname) pads earlier absent slots with `""` instead of shifting into them (e.g. `Tag.e(id, undefined, "root")` now emits `["e", id, "", "root"]`, not `["e", id, "root"]`). Emitted tags change only for callers that skipped an earlier optional position.

## [0.10.1] - 2026-10-08

### Fixed

- `@qntx/nostr-wasm` is published by CI through npm trusted publishing; the 0.10.0 publish job checked the wrong export and the version was published by hand (#199).

## [0.10.0] - 2026-10-08

### Added

- `@qntx/nostr-wasm`: the WebAssembly cryptography backend, published as its own package next to `@qntx/nostr` (#194).
- `FakeRelay.matchingLiveSubscribers(event)` in `@qntx/nostr/testing`: the number of subscriptions whose initial dump ended with EOSE and whose filters match the event (#184).

### Changed

- **Breaking:** the WASM acceleration layer moved out of `@qntx/nostr` into a dedicated `@qntx/nostr-wasm` package — replace `import { loadNostrWasm } from "@qntx/nostr/wasm"` with `import { loadNostrWasm } from "@qntx/nostr-wasm"`. `@qntx/nostr` no longer ships a `.wasm` file and no longer needs a Rust toolchain to build or publish. `WasmPoisonedError` stays exported from `@qntx/nostr/core` (#194).
- The TypeScript side is now a `packages/*` monorepo: `@qntx/nostr` at `packages/nostr`, `@qntx/nostr-wasm` at `packages/nostr-wasm`; versioning stays lockstep across both packages and the Cargo workspace (#194).
- Licensed under MIT OR Apache-2.0 (previously MIT); the repository moved to `github.com/qntx/nostr` (#184).
- `@qntx/nostr` declares `sideEffects: false` now that it ships no `.wasm` asset (#194).

## [0.9.0] - 2026-10-03

### Removed

- **Breaking:** `mergeFilters` — it narrowed rather than unioned when inputs constrained different fields and had no internal callers (#174).
- **Breaking:** `markVerified` and `markUnverified` are no longer exported from `@qntx/nostr/core`; marking externally could bypass signature verification (#179).

### Changed

- **Breaking:** `classifyKind` no longer returns `"unknown"`: NIP-01 leaves kinds 45–999 and 40000+ undefined and relays store them like regular events, so they classify `"regular"` (#177).
- **Breaking:** `ManualFetch`'s init type now declares `redirect: "manual"` — custom fetch adapters must forward it (NIP-05/NIP-11/Blossom must never follow redirects) (#173).
- **Breaking:** `Client.observe` and `Client.observeAll` throw `EventValidationError` for events that fail signature verification, instead of writing them into the index, gossip routes, and storage. `observeAll` is all-or-nothing.
- Runtime dependencies (`@noble/*`, `@scure/base`) use caret ranges so consumers can deduplicate them (#180).
- README no longer points at the intentionally untracked `docs/`; layering invariants and the dependency policy are recorded in `AGENTS.md` (#178).

### Fixed

- `fanIn` fires the aggregate `onclose` when a relay's subscription ends before another relay's connect fails; a subscription's last close reason is reported instead of the misleading "all relays failed", and any attach failure retires the URL instead of escaping as an unhandled rejection (#170).
- NIP-77: the initiator fails fast with `Nip77Error` on a protocol version mismatch instead of re-sending the version byte until `MAX_NEG_ROUNDS` (#171).
- A live subscription's reconnect `since` watermark clamps to the current wall clock, so one far-future `created_at` can no longer blank the feed after reconnect; the worst case is re-delivery, never loss (#172). `OutboxFeed.sync` applies the same clamp to its bound-derived `since`.
- Relays can no longer inject events into a subscription: an EVENT that does not match the subscription's filters is dropped before signature verification (silently — it does not count toward `invalidEventPolicy`).
- `SqliteEventStore` deletes tag rows explicitly instead of relying on `ON DELETE CASCADE`: expo-sqlite's `withExclusiveTransactionAsync` runs on a new connection where `PRAGMA foreign_keys` is off, so tag rows of replaced and deleted events leaked. A `tags(event_id)` index is added on open.
- `Nip46Signer.fromNostrConnectURI` rejects immediately on a pre-aborted signal (it previously never settled), ignores duplicate handshake responses, and closes the signer when the post-handshake `get_public_key` fails.
- `parseEventAddress` accepts only decimal kinds (`1e4`, `0x10`, `+1` were parsed as numbers).
- `parseRelayMessage` rejects COUNT replies whose `count` is not a non-negative safe integer.
- A stale relay's delayed `close` no longer evicts a newer relay for the same URL from the `Pool`.
- `Client.fetchEvents` and `Client.fetchEach` put each event into the reactive index once; additional relay deliveries record `seenOn` via `markSeen` instead of re-running the full put path (#175).
- Verify, sign, and storage `decidePut` paths no longer repeat structural event validation: an internal `serializeValidatedEvent` is used post-validation, and `decidePut` trusts the verified-event cache (#176).
- JSDoc drift: `GossipOptions.maxRelaysPerPubkey` documents first-N list order, and the facade header lists all published subpaths (#178).
- `tests/fan-in.test.ts` covers `fanIn`/`fetchRouted` completion interleavings directly (#181).

## [0.8.0] - 2026-10-03

### Changed

- **Breaking:** one event model for long-lived objects: `Pool` and `ReactiveEventStore` gain `on(type, listener)` like `Relay` and `Client`. `PoolOptions.onIdleRelaysClosed` / `onRelaySuspended` become `pool.on("idle", urls)` / `pool.on("suspend", { url, until })` (typed by `PoolEventMap`), and `ReactiveEventStore.onInsert` / `onRemove` become `store.on("insert" | "remove", listener)` (typed by `ReactiveEventStoreEventMap`). Per-operation callbacks (`subscribe`'s `onevent` / `oneose` / `onclose`, `fetch`'s `onevent`) are unchanged.
- **Breaking:** failure results carry the thrown `Error` instead of its message: `PoolPublishResult` / `PoolCountResult` `failed` variants have `error: Error`, `PoolFetchResult.end` `failed` is `{ type: "failed", error }`, `SyncSummary.persistFailures` maps ids to `Error`.
- **Breaking:** exported data and result types (NIP pointers and documents, relay/pool results, client, loader, gossip and storage results) are `readonly` with `ReadonlyArray` fields and `?: T | undefined` optionals. `BunkerPointer.secret` is optional.
- **Breaking:** `Pool.close(urls)` is split into `Pool.close()` (everything) and `Pool.closeRelays(urls)`.
- **Breaking:** a hashtag longer than 42 code points is now plain text instead of a hashtag block holding its first 42 code points.
- `Relay` is decomposed into cohesive internal units (subscription registry, OK/COUNT trackers, NIP-42 auth state); public behaviour is unchanged.
- `ReactiveEventStore` indexes query watches by kind, so an insert or removal only re-matches the watches that can contain its kind instead of every query watch.
- Async iteration over a subscription dequeues in O(1).

### Added

- NIP-17/59 disappearing messages: `WrapOptions.expiration` (and `SendPrivateMessageOptions.expiration`) adds an `expiration` tag to both the seal and the gift wrap, as NIP-17 recommends.
- NIP-59 ephemeral gift wraps: `WrapOptions.ephemeral` (and `SendPrivateMessageOptions.ephemeral`) produces `kind:21059`.

### Fixed

- A one-shot subscription with `closeOnEose` and `eoseTimeoutMs` now closes when the timeout synthesizes EOSE instead of hanging until a real EOSE.
- NIP-27 recognizes custom emoji shortcodes containing hyphens (`:my-emoji:`), which NIP-30 allows.

## [0.7.0] - 2026-10-03

### Removed

- **Breaking:** `ClientBuilder` and `Client.builder()`. Pass a `ClientOptions` object to `new Client(...)`.
- **Breaking:** NIP-96 (`@qntx/nostr/nips/nip96`). The spec is `unrecommended` in favor of NIP-B7 Blossom, which `@qntx/nostr/nips/blossom` implements.
- **Breaking:** `createOutboxFeed` (use `new OutboxFeed(...)`), `decodeNostrURI` (use `parseNostrURI` / `isNostrURI` from NIP-21), `markerOf`, `BUNKER_REGEX`, the `MutedEntity` type (mute lists use NIP-51 `MuteItem`), and the unreferenced `src/nips/index.ts` barrel.
- **Breaking:** the `Subscription` class is no longer exported; `Relay.subscribe` returns the `RelaySubscription` type. `ReactiveEventStore` no longer exposes `_version`, `_register`, or `_unregister`.

### Changed

- **Breaking:** `Relay` lifecycle callbacks `onnotice`, `onclose`, `onauth`, `onreconnect`, and `oninvalidevent` are replaced by `relay.on(type, listener)`, which returns an unsubscribe function and is typed by `RelayEventMap`. `Pool` registers its own bookkeeping through the same API, so user listeners can no longer overwrite it. `Client` replaces the `onstorageerror` option and property with `client.on("storageerror", listener)`.
- **Breaking:** `PoolPublishResult` and `PoolCountResult` are discriminated by `status` (`"ok" | "rejected" | "failed"`, and `"ok" | "failed"` for COUNT). `Pool.publishAny` resolves to the `"ok"` variant.
- **Breaking:** `PoolOptions` is derived from `RelayOptions` and `ClientOptions` from `PoolOptions`, so every relay option is accepted, and forwarded, at every layer. Exported option bags accept `undefined` for every optional property, and public methods take `ReadonlyArray` inputs.
- **Breaking:** NIP-65 `RelayListItem` is `{ url, marker }` with `RelayMarker = "read" | "write" | "both"`, so an item can no longer be neither read nor write.
- **Breaking:** NIP-57 `validateZapReceipt` returns a discriminated `ZapReceiptValidation` (`{ valid: true, request, amountMsats }` or `{ valid: false, reason }`), and `makeZapRequest` rejects an `amount` that is not a positive safe integer.
- **Breaking:** `WasmVerifyPoisonedError` is renamed `WasmPoisonedError`; it is also raised by `sign` and `publicKey` on an aborted instance.
- **Breaking:** `Pool.publish`, `publishAny`, `fetchEach`, and `count` de-duplicate relay URLs after normalization and report the normalized URL.
- `signEvent` throws `EventValidationError` (not `CryptoError`) for a structurally invalid unsigned event. NIP-04 decoding failures throw `CryptoError`, NIP-19 `decode` wraps bech32 failures in `Nip19Error`, and NIP-21 `parseNostrURI` throws `Nip21Error`.
- Blossom `createAuthTemplate` / `createUploadAuth` accept `servers` to add BUD-11 `server` scoping tags, and `upload` / `checkUpload` accept a precomputed `sha256` so the blob is not hashed twice.
- `Relay` connection state is a single status plus a manual-stop flag instead of four overlapping booleans.
- `ReactiveEventStore` tracks the ids pinned by subscribed watches incrementally instead of rebuilding the set on every over-capacity insert.
- `OutboxFeed` persists live outbox bounds in one trailing write per second instead of one write per event.
- NIP-13 `minePow` serializes the event once per second and writes only the nonce digits per hash.
- The NIP-77 decoder reads through a cursor instead of allocating a view per byte.

### Fixed

- Two concurrent `Relay.publish` calls for the same event no longer reject the first with a timeout after the relay answered OK; the second call joins the in-flight publish.
- `Relay.fetch`, `Pool.fetch`, `Pool.subscribe`, `subscriptionToAsyncIterable`, `Relay.count`, NIP-77 sessions, and `subscribePrivateMessages` no longer leave an `abort` listener on a long-lived `AbortSignal` after they finish.
- NIP-77 varints are decoded and encoded arithmetically, so timestamps after 2038 and values above 2^32 round-trip.
- NIP-46 `parseBunkerURL` parses with `URL`, so secrets containing `+`, spaces, or other reserved characters round-trip through `toBunkerURL`.
- `Relay` no longer references `WebAssembly`, which threw a `ReferenceError` on Hermes when a custom verifier threw.
- Profile metadata parsing keeps only string-valued `ProfileMetadata` fields instead of passing arbitrary JSON through.
- NIP-59 timestamp randomization uses unbiased rejection sampling.
- `vp pack` without `WASM_PACK` no longer deletes the `./wasm.browser` export from `package.json`.

## [0.6.0] - 2026-10-02

### Added

- `ReactiveEventStore.onRemove(listener)`: synchronous listener for every physical index removal (NIP-09 tombstones, superseded replaceables, eviction), called after watch invalidation. Symmetric with `onInsert`; a throwing listener is isolated via `reportError`.
- `./wasm` gains a `browser` export condition: a fetch-only loader with no `node:` specifiers, so bundlers no longer externalize `node:fs/promises` / `node:url` for the browser. Node keeps the file-reading entry.

### Changed

- `watchEvent(id)` and `watchReplaceable(kind, pubkey, d)` are interned by key (lowercased id, `formatEventAddress`) like `watchQuery`: repeated calls return the same watch until it is unsubscribed and unregistered.
- The crypto WASM is built with `secp256k1`'s `lowmemory` tables and `wasm-opt -Oz`: 1,288,146 → 230,427 bytes raw, 1,152,812 → 99,814 bytes gzip (`verifyEvent` throughput about 1.3× lower). `build:wasm` enforces a 100 KiB gzip budget and requires `wasm-opt` (binaryen devDependency).

### Fixed

- A kind-5 deletion now invalidates the watches of the ids (`e`) and addresses (`a`) it targets, so a watch on an event absent from the index sees `isDeleted` change.

## [0.5.0] - 2026-10-01

### Changed

- **Breaking:** `Relay.fetch` resolves to a `RelayFetchResult` (`{ events, end }`) instead of a bare `Event[]`; `end` reports `eose`, `closed` (with the relay's reason), or `timeout`, and events received before a CLOSED or the deadline are kept. `Pool.fetch` keeps its `Event[]` shape and still merges whatever each relay delivered.
- `fanIn` (`Pool.subscribe`, `Client.subscribe`): a relay's CLOSED or connect failure now removes it from the pending-EOSE set without counting as an EOSE. The aggregate `oneose` fires only once every remaining relay ended and at least one actually EOSE'd; when every relay closed or failed before any EOSE, only `onclose` fires (with the last reason).
- `Relay.subscribe` no longer merges a new live subscription into a coalesced wire that already EOSE'd — the late subscriber gets its own REQ and a full replay instead of an empty synthesized EOSE.

### Added

- `Pool.fetchEach` and `Client.fetchEach`: one-shot fetch returning one `PoolFetchResult` per relay (`{ url, events, end }`, with `failed` when the connect or REQ itself errored). `Client.fetchEach` ingests events into the index with their relay URL in `seenOn` and persists them like `fetchEvents`.

## [0.4.1] - 2026-09-29

### Added

- `nip57`: `parseBolt11` decodes the `d` description (UTF-8; omitted on invalid input), the invoice `timestamp` (unix seconds), and `x` expiry (default 3600) into `Bolt11Fields`.

### Fixed

- `nip27`: invoices with an amount-bearing HRP (`lnbc10u1…`) were left as text because the tokenizer expected the `1` separator right after the currency code; the amount and multiplier are now part of the recognized prefix.

## [0.4.0] - 2026-09-29

### Changed

- **Breaking:** `nip27` `parseContent` is a rewritten single-scan tokenizer that returns a `ContentBlock[]` array instead of a generator, and `parseContentBlocks` is removed. `ContentBlock` references now carry `bare`, URLs keep the original substring (no normalization), media classification honors NIP-92 `imeta` MIME hints before path extensions, and new block types cover Lightning invoices (`invoice`) and opt-in bare bech32 references (`ParseContentOptions.legacyBech32`). Hashtags and URL boundaries now understand Unicode letters, CJK punctuation, and full-width forms.

## [0.3.1] - 2026-09-29

### Fixed

- `IndexedDbEventStore` no longer hangs when another tab holds an older-schema connection: an `onblocked` open now rejects with `StorageError("IndexedDB open blocked by another connection")` instead of never settling, and an opened store closes its connection on `versionchange` so a newer-version open elsewhere is never blocked by it. Operations on a connection that yielded this way reject with `StorageError("IndexedDB connection closed by a newer version")` instead of a raw `InvalidStateError`.

## [0.3.0] - 2026-09-28

### Added

- `SigningBackend` (`@qntx/nostr/core`, also re-exported from the package root): a `{ publicKey, sign }` BIP-340 backend bound to `Keys` via `Keys.generate(backend)` and `Keys.fromSecretKey(secretKey, backend)`. `finalizeEvent`, `signEvent`, `KeysSigner`, and `EventBuilder.signWithKeys` route through `keys.backend`, so a WASM module or a React Native native signer (for example libsecp256k1 over Nitro) can replace noble signing. `NostrWasm` is now a `SigningBackend`, so `Keys.fromSecretKey(sk, wasm)` works directly.

### Changed

- **Breaking:** `nip49.encrypt` and `nip49.decrypt` are now async and take an options object in place of positional `logn`/`ksb`: `encrypt(secretKey, password, { logn, ksb, scrypt })` and `decrypt(ncryptsec, password, { scrypt })`. The `scrypt` option (`Scrypt` type) receives the NFKC-normalized UTF-8 password bytes, the payload salt, and `{ N, r, p, dkLen }`, letting runtimes delegate the KDF off the JS thread (for example OpenSSL scrypt via a native module); the default remains noble `scryptAsync` with the same parameters (logn 16, ksb 0x02). A throwing/rejecting scrypt surfaces as `Nip49Error("scrypt failed")` and a wrong-length result as `Nip49Error("scrypt returned N bytes, expected 32")`, both distinguishable from the `Nip49Error("failed to decrypt")` raised by a wrong password.

## [0.2.2] - 2026-09-28

### Added

- `createEventVerifier` and `SerializedEventVerifier` (`@qntx/nostr/core`, also re-exported from the package root): build an event verifier with `verifyEvent`'s exact semantics — shared verified/failed WeakSet caches, `validateSignedEvent`, canonical serialization — over a pluggable backend that receives the serialized UTF-8 bytes plus the raw `id`/`pubkey`/`sig` and answers whether `sha256(serialized)` equals `id` and `sig` is a valid BIP-340 signature. Backend exceptions propagate without marking the event, so backends can implement sticky-failure semantics (as the WASM adapter does with `WasmVerifyPoisonedError`). Intended for native verifiers such as libsecp256k1 Nitro modules on React Native.

### Changed

- The WASM event verifier is now built on `createEventVerifier` instead of the internal `makeVerifyEvent` adapter (removed, along with `WasmSerializedVerify`); no behaviour change. `verifyEvent` is itself `createEventVerifier` over the noble `sha256` + `schnorr.verify` backend — same semantics, single code path.

## [0.2.1] - 2026-09-28

### Added

- Per-relay invalid-event policy: `PoolOptions.invalidEventPolicy` (`{ limit, windowMs, cooldownMs }`) and `PoolOptions.onRelaySuspended(url, until)`, also exposed on `ClientOptions`/`ClientBuilder`. A relay whose `limit`-plus-one delivered EVENT fails id/signature verification inside a `windowMs` sliding window is disconnected and suspended for `cooldownMs`. During suspension `ensureRelay` rejects with the new `RelaySuspendedError` (`url`, `until`), so fetch/publish/subscribe treat it as that relay failing without affecting others; pinned relays are suspended too. Once the cooldown lifts, live subscriptions resume through the normal reconnect path. Supporting API: `Relay.oninvalidevent` (fired when a delivered EVENT fails verification) and `Relay.disconnect()` (sever the socket while keeping subscriptions for a later `connect()`).
- `FakeRelay.deliver`: push an event to matching subscriptions without storing it, so forged events used in verification-failure tests are never re-served on resubscribe.

### Fixed

- The `SqlDriver` TSDoc `expo-sqlite` example now runs transaction statements on the `txn` connection passed to `withExclusiveTransactionAsync` — which resolves `void` — and captures the callback result out-of-band, matching the actual API.
- Every package export gains a `default` condition pointing at `dist/*.mjs`, so `require`-based resolvers (e.g. jest-expo in React Native apps) resolve `@qntx/nostr/*` subpaths without a manual `moduleNameMapper`.

## [0.2.0] - 2026-09-27

### Breaking changes

- Event `id`/`pubkey`/`sig` must be canonical lowercase hex: `isHex32`/`isHex64` are strict lowercase predicates, `validateEvent`/`validateSignedEvent` and wire parsing (`parseRelayMessage`/`parseClientMessage`) reject uppercase fields, and `serializeEvent`/`verifyEvent` no longer lowercase them. Caller input stays case-insensitive via `assertHex32` and lowercased lookups (#129).
- `PutResult` gains `"invalid"`: `EventStore.put`/`MemoryIndex.put`/`ReactiveEventStore.add` return it for events failing `validateSignedEvent` instead of silently lowercasing and storing them; handle the new variant. The fake relay answers `OK false "invalid: malformed event"` (#129).
- `normalizeURL` throws `UrlError` for non-websocket schemes (`ftp:`, …); pass `ws:`/`wss:` (or `http(s):`/bare hosts, which are rewritten) (#129).
- Every abort-aware API rejects with `signal.reason` (falling back to an `AbortError`-named `Error`) instead of a synthesized `RelayConnectionError`/`Nip13Error`/`ClientError`; `fetchRouted`/`Pool.fetch`/`Pool.count`/`Client.fetchEvents` and outbox `sync` reject on abort instead of resolving partial results. Catch `signal.reason`/`AbortError`; subscription `onclose("aborted")` reason strings are unchanged (#131).
- `Nip46Transport.publish` must return `Promise<readonly { result?: { ok: boolean; message: string }; error?: string }[]>` (satisfied by `Pool.publish`); when no relay accepts the request event, `Nip46Signer` fails fast with `Nip46Error` instead of waiting for the timeout (#131).
- `RelayError` takes `options?: ErrorOptions` (so `cause` works), and every relay timeout — connect, publish, auth, COUNT, NIP-77 session — rejects with the new `RelayTimeoutError` subclass (#131).
- `ClientOptions.automaticAuth` defaults to `true` regardless of signer presence; the AUTH sign function reads the current signer at challenge time (a challenge with no signer is ignored). Pass `automaticAuth: false` to restore the 0.1.0 opt-in behavior (#123).
- `PoolOptions.allowInsecure` defaults to `false`; `ws://` relays are rejected unless listed in `trustedInsecureUrls` or `setAllowInsecure(true)` is called (#123).
- `Relay.connect` no longer lets a caller's `AbortSignal` own the shared connect attempt: every caller races its own signal and rejects with `signal.reason`, while the attempt keeps running and only `close()` cancels it (#135).
- `subscriptionToAsyncIterable` distinguishes local vs remote closes by state, not reason strings: an `onclose` without a preceding local close throws `RelayClosedError(reason)` from the iterator after draining queued events; locally initiated closes complete normally (#135).
- `createLoaders` requires `index: ReactiveEventStore` and drops the `cache` option — pass `client.index` (or your own store); fetched events flow through the new optional `ingest` callback (default `index.add`). `Loaders` drops `context` and gains `addRelay`/`removeRelay`/`replaceable(kind)`; `Client` wires `index` and `ingest` itself (#137).
- `EventBuilder.deletion` takes `targets, reason` where each target is an event-id string, `{ id, kind? }`, or `{ address }`; deduped `k` tags are emitted automatically (NIP-09 SHOULD) and the `kinds`/`addresses` options are gone (#133).
- `Nip96UploadResult` is a discriminated union — `{ status: "success"; url; tags }` or `{ status: "processing"; processingUrl; tags }`; check `status` before reading `url` (#133).
- `CountResult.hll` is a 512-char lowercase hex HyperLogLog sketch, not opaque base64.
- Validation that returned corrupt output in 0.1.0 now throws: NIP-19 encoders reject bad hex/kinds/>255-byte TLV values (`Nip19Error`), `getPow` rejects non-hex input (`Nip13Error`), `relayListToTags` rejects `{ read: false, write: false }` (`EventValidationError`), `dmRelayListEventBuilder`/`blossomServerListEventBuilder` throw when no valid tag would be emitted, and `createAuthTemplate` throws `BlossomError` for an explicitly empty `message` (#131, #133).
- Optional/absent values are `undefined` instead of `null` across the API — `Relay` callbacks (`onnotice`/`onclose`/`onauth`/`onreconnect`), `PoolOptions.automaticallyAuth`, `ReplaceableLoadResult.event`, `ListResult.event`, `NostrUser.event`, the NIP-46 `secret`, NIP-05/NIP-11/Blossom lookup results, `Nip46Signer.switchRelays()`, `parseBunkerURL()`, `NegentropyResult.nextMessage`, and the NIP-19 `{ type: "invalid" }` sentinel's `data`. Compare against `undefined` (`== null` still works; `=== null` and `toBeNull()` do not).
- `parseClientMessage` validates REQ/COUNT filter positions: a non-object filter (string, array, null, …) now throws `MessageError` instead of flowing through as a malformed `Filter`.
- Every `NostrError` subclass sets a fixed `name` field instead of deriving `new.target.name` at construction. A consumer subclassing a library error class no longer gets its own class name automatically — set `override name` in the subclass.
- Exported interfaces are now `type` aliases, so declaration merging and `interface extends` no longer apply to them.

### Added

- `SqliteEventStore`: a production `EventStore` over a minimal async SQLite driver (`SqlDriver`: `exec`/`run`/`all`/exclusive `transaction`), for React Native (`expo-sqlite`, `op-sqlite`) and desktop runtimes — no dependency on Expo. Same semantics as `MemoryEventStore`/`IndexedDbEventStore`: shared `decidePut` insertion policy, NIP-09 tombstones, single winner row per address, per-filter SQL query plans with 500-value `IN` chunking, outbox-bound persistence and derivation, `negentropyItems`, and `count`. One driver transaction per `putMany`; a mid-batch failure rolls back atomically. Covered by the shared `eventStoreConformanceCases` suite (#139).
- `@qntx/nostr/store`: `ReactiveEventStore`, a synchronous in-memory event store with `useSyncExternalStore`-style watches (`watchEvent`, `watchReplaceable`, `watchQuery`), per-relay `seenOn` tracking, insertion listeners, and bounded LRU eviction that never evicts a subscribed watch's snapshot; evicted replaceable/addressable winners leave a bounded watermark so a stale version stays rejected while a newer one is re-accepted (#121, #137). `Client` owns one by default (`client.index`, `ClientBuilder.index`) and writes every inbound and published event into it before invoking caller callbacks.
- `@qntx/nostr/testing`: transport-agnostic fake relay shared by an in-process `createFakeRelayNetwork` (`websocketImplementation` for `Client`/`Pool`/`Relay`) and `serveFakeRelay` (real `ws` server, `port: 0`). NIP-01 EVENT/REQ/CLOSE/EOSE/OK/NOTICE/CLOSED, NIP-42 AUTH gating, NIP-45 COUNT, NIP-50 `search`, NIP-77 `NEG-*`; faults (`latencyMs`, `rateLimited`, `inject`, `disconnect`, …). Also `eventStoreConformanceCases` (shared `EventStore` suite) and `createFakeNip46Signer` (#119).
- Source relay URL on callbacks: `onevent(event, relayUrl)` fires on first receipt, `receivedEvent(id, relayUrl)` fires for every receipt including deduped duplicates; `fetchRouted`/`Pool.fetch`/`fetchGossip`/`Client.fetchEvents` `onevent` fires per event per relay. `relayUrl` is the `normalizeURL` result; `ReceivedPrivateMessage.relayUrl` is populated (#117).
- `RelayTimeoutError` (`RelayError` subclass) for every relay timeout, and `Nip46SignerOptions.authTimeoutMs` (default 300s) applied while waiting for the real response after a bunker `auth_url` answer (#131).
- `Relay.resetAuth` / `Pool.resetAuth`: clear a cached AUTH rejection and re-fire `onauth` so automatic auth can retry; `Client.setSigner` calls it so a new signer applies to already-connected relays (#125).
- `OutboxFeedOptions.observe` receives the relay URL and new `OutboxFeedOptions.seen` fires for every event receipt from every relay (#125).
- `NoSignerError` (`NostrError` subclass): thrown by a lazy AUTH sign function when no signer is configured at challenge time; `Relay` ignores the challenge — no AUTH frame, connection stays open (#123).
- `PoolOptions.pinnedUrls` + `Pool.setPinnedUrls`: relays never closed by idle cleanup or `maxRelays` eviction (#123).
- `Relay.inFlightCount`: one-shot requests still awaiting a reply; idle detection uses it alongside `subscriptionCount` (#123).
- `ClientOptions`/`ClientBuilder` forward `allowInsecure`, `trustedInsecureUrls`, `idleTimeoutMs`, `maxRelays`, and `pinnedUrls` to the pool. `Client.setSigner` accepts `undefined` to remove the signer (#123).
- `GossipOptions.maxPubkeys` (default 10_000): routing state is LRU — route lookups refresh recency and inserts beyond the cap drop the oldest pubkey (#137).
- `nip44.getMessageKeys` export covering the spec's `get_message_keys` vectors (#133).
- `MemoryIndex` and `MemoryIndexOptions` are exported from `./storage` (the synchronous index behind `MemoryEventStore`/`ReactiveEventStore`), with `maxTombstones` bounding all three deletion-state collections (#135).
- Runtime requirements are now documented: the host must provide `crypto.getRandomValues`, `TextEncoder`, a UTF-8 `TextDecoder`, WHATWG `URL`/`URLSearchParams`, `queueMicrotask`, `setTimeout`, and `AbortController`, plus `fetch`/`WebSocket` for network features (Node, browsers, and Expo/React Native all satisfy them; the library ships no polyfills). Verified by a bundled smoke test run on the Hermes V1 engine React Native 0.86 ships (`bun run smoke:hermes`), exercised in CI on every pull request (#140).

### Changed

- `MemoryEventStore` internals moved into the synchronous `MemoryIndex`; `MemoryEventStore` is a thin async facade with unchanged `EventStore` semantics.
- User-facing throws use `NostrError` subclasses (`Nip19Error`, `OutboxError`, `RelayPublishError`, `RelayClosedError`, `CryptoError`, `StorageError`, `ClientError` for Client lifecycle, …); `WasmVerifyPoisonedError` keeps `name` for relay duck-typing.
- `subscribePrivateMessages` live REQ includes kind 21059 in addition to 1059; `fetchPrivateMessages` still REQs 1059 only. Kind 21059 wraps are not stored.
- `KeysSigner` caches NIP-44 conversation keys per peer pubkey; gift-wrap `encryptToPubkey` still derives per call.
- `Relay.subscribe` coalesces identical live REQs (`filterFingerprint`): the first subscribe sends REQ, later identical attaches reuse the wire id, and the last `close()` sends CLOSE; verify/watermark run once per EVENT then fan out; a late attach after EOSE fires that listener's `oneose` on a microtask; non-identical filters are not merged.
- Pool/Client `oneose` waits for the slowest relay unless `eoseTimeoutMs` is set; `eoseTimeoutMs` synthesizes `oneose` once and no longer closes the live REQ. `Relay.fetch` remains the one-shot closer.
- `Client.sync` runs per-relay sessions in parallel (`Promise.allSettled`) and merges fulfilled summaries, throwing only when every relay rejects. NIP-77 upload queries `ids: have` once, then publishes in chunks of 8.
- Gossip `publish` includes up to five normalized `e`/`a` tag relay hints; mixed-author feeds REQ unrouted keys on the Client default relays, and `onclose` fires once after every inner sub closes.
- `groupAuthorsByOutboxRelay`/`OutboxFeed` prefer already-connected candidate URLs; `OutboxFeed` rehydrates/persists via `EventStore.getOutboxBound`/`setOutboxBound` and splits mixed bounded/unbounded groups.
- `SyncOptions.observe: false` skips `putMany` and ingest meta; received ids are still listed.
- `Client.fetchEvents` merges storage, index, and network results through NIP-01 semantics — replaceable/addressable winners, kind-5 deletions, id dedupe, per-filter `limit` — instead of a plain id-keyed map (#125).
- Client inbound events share one ingest path — index add (with relay URL) -> gossip/loader meta -> persistence queue (#135).
- `Kind` catalog is 28 production names; dual-key DM kinds 10044/4454/4455 dropped.
- NIP spec alignments (#133): NIP-10 unknown `e` markers go to `mentions` only and `buildReplyTags` omits an unknown root pubkey hint; NIP-59 seals carry empty tags and `unwrap` accepts expiration-only seal tags (NIP-17); `isNip05`/`parseNip05` share one validator (`[a-z0-9._-]`, case-insensitive); `nip44.decodePayload` checks the `#` version marker then `DEFAULT_MAX_PAYLOAD_CHARS` before base64; NIP-77 `Negentropy.reconcile` answers a single `0x61` to foreign 0x60-0x6f queries; `fetchNip96Info` follows `delegated_to_url` exactly one hop.
- `bytesToHex`/`hexToBytes` delegate to `@noble/hashes` (`hexToBytes` still throws `HexError`); event ordering drops `localeCompare` for `created_at`-then-id over canonical ids; custom REQ/COUNT ids are validated to 1..64 characters (#129).
- `signEvent`/`finalizeEvent` accept a `Keys` instance and reuse its cached public key; `Nip07Signer.getPublicKey` validates with `assertHex32`; NIP-46 request ids are 128-bit random (#131).
- `MemoryIndexOptions.maxTombstones` bounds tombstoned ids, pending e-tag ids, and coordinate tombstones, each FIFO; `ReactiveEventStore` keeps a 100_000 default, `MemoryEventStore` stays unbounded (#135).
- IndexedDB `scanFilter` opens at most 64 merge cursors per filter, then falls back to one cursor per kind or a single `created_at` scan plus `matchFilter`; results and per-filter limits are unchanged (#135).
- TypeScript strictness: `tsconfig` enables `erasableSyntaxOnly`, `noUncheckedIndexedAccess`, `noImplicitOverride`, and `isolatedDeclarations`; every root export carries a TSDoc summary; `check:pkg` (`WASM_PACK=1 vp pack && publint && attw --pack . --profile esm-only`) validates the published package at the end of `build:wasm` (#138).

### Removed

- `isMarkedVerified`, `utf8Encoder`, and `utf8Decoder` are no longer exported from the root entry or `./core`; `cloneFilter` is deleted (it had no callers). Internal users import from `core/util.ts`/`core/event.ts` directly (#138).
- Loader internals are no longer exported from `./loaders` or the root entry: `DataLoader`, `LoaderError`, `LoaderContext`, `LoaderContextOptions`, `ReplaceableCache`, `createReplaceableLoader`, `createListLoaders`, `createProfileLoader`, `createEventLoader`; `Loaders.context` is gone — use `createLoaders` and `Loaders.replaceable(kind)` (#137).

### Fixed

- `decodeNip46Response` (and so `Nip46Signer`) treats explicit JSON `null` in `result`/`error` as absent — some remote signers emit `{"result": null, "error": "…"}`, which 0.1.0 rejected as an invalid response.
- A throwing `onevent` no longer drops the rest of a relay fetch batch; user-callback errors are isolated via `reportError` across `fetchRouted`/`fanIn`, REQ dispatch, `Subscription.close`, and store watch/`onInsert` listeners (#125).
- Equivalent relay URL spellings no longer duplicate fan-in attachments or `Client` relay entries: job URLs are normalized and deduped, and `Client` stores normalized `relays` (#125).
- Event stores canonicalize address coordinates (lowercase pubkey) in `isDeleted`/`getByAddress`, and a replacement newer than the tombstone's `until` clears the deletion (#125).
- `IndexedDbEventStore.setOutboxBound` serializes through the write queue so it cannot overlap `putMany` or `clear`.
- `Nip46Signer`: an `auth_url` reply re-arms the request under `authTimeoutMs` instead of consuming it, `close()` clears pending auth waits, and `onAuthUrl` (plus `Relay.onnotice`/`onclose`/`onauth`/`onreconnect`, `PoolOptions.onIdleRelaysClosed`, `Client.onstorageerror`, `OutboxFeed` `onEvent`/`observe`/`seen`) throwing is isolated via `reportError` (#131).
- `Relay.fetch` aborted mid-flight rejects with `signal.reason` instead of resolving a partial batch (#131).
- EVENT `auth-required:` rearms the publish timeout after AUTH.
- An extra live REQ while disconnected no longer resets reconnect backoff.
- `subscribePrivateMessages` close/abort skips later persist and `onevent`; junk wraps are not stored.

[Unreleased]: https://github.com/qntx/nostr.js/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/qntx/nostr.js/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/qntx/nostr.js/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/qntx/nostr.js/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/qntx/nostr.js/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/qntx/nostr.js/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/qntx/nostr.js/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/qntx/nostr.js/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/qntx/nostr.js/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/qntx/nostr.js/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/qntx/nostr.js/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/qntx/nostr.js/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/qntx/nostr.js/compare/v0.1.0...v0.2.0
