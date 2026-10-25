# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- One-directional layering inside `packages/nostr/src`: `core` is the leaf; `nips/*` and `storage` may only import `core`; `signer` adds `nips`; `store` adds `storage`; `relay` adds `nips`/`signer`; `gossip` adds `nips`; `loaders` and `testing` consume the mid layers; `client` composes everything. `nips/*` must never import `relay`, `signer`, `storage`, or `client`. The acceleration backends are the separate `packages/nostr-wasm` and `packages/nostr-native` packages, which may only import `@qntx/nostr/core`; `packages/nostr-native` is React Native–only by design and may additionally import `react-native-nitro-modules`, an explicit exception to the platform-neutral rule. `packages/nostr-native/cpp` is the single C core (vendored libsecp256k1 + `nostr_core.c`) shared by `@qntx/nostr-native` (React Native, Nitro) and `@qntx/nostr-wasm` (wasm32 build in `packages/nostr-wasm/c`); only the wasm build forces 64-bit wide multiplication (`USE_FORCE_WIDEMUL_INT64`): wasm32 has no 64×64→128 multiply, and the int128 field code is 3–4× slower there. The TypeScript layer graph is enforced by lint (`LAYERS` in `vite.config.ts`).
- All I/O is injected (WebSocket, fetch, storage drivers); `packages/*/src/` holds no ambient singletons.
- `packages/*/src/` is platform-neutral: no Node-only or browser-only globals and no `node:*` imports outside the declared lint exceptions (`packages/nostr/src/testing/serve.ts`, `packages/nostr-wasm/src/load.ts`).

## Dependency policy

Runtime dependencies (`@noble/*`, `@scure/base`) use caret ranges so consumers can deduplicate them against the rest of their dependency tree; devDependencies stay exact-pinned for reproducible builds. Review upstream changelogs on every bump.

## Rust

- The repository owns the Rust implementation; rust-nostr is a design reference only (no dependency, no copied code). `crates/nk-core` is the leaf protocol crate — `no_std + alloc`, platform-neutral, and sans-IO — covering the core types and every NIP codec of the TS surface; higher-level crates land per milestone (`nk-store`, then `nk`). Crates are split only at hard boundaries (platform/runtime guarantee, dependency closure, artifact type, unhideable public dependency); everything else is a module. CI enforces the boundaries: no `std` without the `std` feature, no `getrandom`/`tokio` in `no_std` builds (`forbid-deps` on the cross targets).
- Features gate dependencies or platform capabilities only (`std`, `clock`, `os-rng`, `nip04`, `nip44`, `nip49`); NIPs without extra dependencies are always compiled. No third-party types in public APIs except `rand_core` RNG traits and `serde` impls. One `#[non_exhaustive]` error enum per module; one RNG-taking function per operation — no `_with_rng` twins, no OS-rng convenience wrappers.
- Follow the Rust API Guidelines. No panics and no `unwrap`/`expect` outside tests.
- `crates/nk` is the SDK crate: a sans-IO relay session (one request table for REQ/fetch/COUNT/NEG, pending publishes, NIP-42 state, REQ replay) behind a tokio/yawc driver task that owns only I/O, waiters, one `DelayQueue` of deadlines and a `JoinSet` for off-loop signing (it holds no sender to its own command channel, so dropping the last `Relay` stops it); only live subscriptions survive a disconnect, one-shots (publish, fetch, count, reconcile) fail fast with `Disconnected` and each has a deadline (`request_timeout`); `Subscription` is a `Stream` whose drop sends `CLOSE`, bounded per-subscription channels end a lagged consumer with `Closed(Lagged)`, `NostrSigner` is an object-safe async trait in `nk-core` (`BoxFuture`-shaped, `Keys` implements it under `os-rng`); `RelayOptions.signer` enables NIP-42 — an `auth-required:` refusal triggers one off-loop kind-22242 `AUTH` and a one-shot retry of the refused `REQ`/`EVENT`/`COUNT`, `Relay::count` covers NIP-45, and `Relay::reconcile` runs NIP-77 negentropy sync (`negentropy` crate, NEG-OPEN/-MSG/-ERR/-CLOSED, 60 000-byte frame limit, `Reconciliation{have,need}`). `RelayPool` shares one `Relay` per normalized URL, fans out operations concurrently (`join_all`) into per-relay `BTreeMap` results, and `PoolSubscription` merges streams with first-receipt dedupe and one aggregate EOSE; `gossip::Gossip` is a sans-IO NIP-65/10050 LRU routing table — `route` yields per-relay filters plus a `remainder`, and `RelayPool::fetch_routed`/`subscribe_routed` execute the plan. `Client` composes `RelayPool` + `Gossip` + `Arc<dyn EventStore>` behind one handle — one ingest path (gossip sync, a batched persister on `spawn_blocking`, `flush`), gossip-routed `fetch`/`subscribe`/`publish` with default-relay fallback, and third-party `ws://` gossip URLs dropped unless `allow_insecure`; `Client::sync_with`/`sync` run NIP-77 reconciles with per-relay reports — bounded-concurrency uploads, batched downloads with awaited store writes. The `test-util` feature provides `MockRelay` (hyper + yawc upgrade over `MemoryStore`) for integration tests.
- Shared test vectors live in `vectors/` (see `vectors/README.md`) and `parity.json` lists each capability, its TS tests, and the nk-core test files that run the same vectors — zero divergence, no skip or expected-failure lists. The only permitted platform difference is the `nonCanonicalJson` class: Rust rejects non-canonical JSON forms (duplicate keys, non-integral number spellings, `-0`) that `JSON.parse` accepts; vector cases and diff-stream records carry the flag.
- npm packages and crates are versioned lockstep: `[workspace.package].version` equals every package.json version, members inherit `version.workspace = true`, internal path deps pin `=<version>`, and `scripts/check-version.ts` + `scripts/sync-versions.ts` keep Cargo.toml/Cargo.lock/bun.lock in sync on bump. Crates are published from release tags (`publish-crates.yml`).
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt`, and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version and
                                                    # parity checks
bun run test:parity                                 # generates the diff
                                                    # streams and replays
                                                    # them through nk-core
cargo fmt --all --check
for p in nk-core nk-store nk; do                       # per package, like CI:
  for f in --all-features --no-default-features; do # workspace runs unify
    cargo clippy -p "$p" --all-targets "$f" -- -D warnings # features and
    cargo test -p "$p" "$f"                         # hide gaps
  done
  cargo hack check -p "$p" --each-feature --no-dev-deps
done
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
    cargo check -p nk-core --target wasm32-unknown-unknown --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
crates/nk/tests/e2e/run.sh      # nk E2E against a pinned nosfry
                                # release; NOSFRY_BIN overrides
                                # the binary under test
cd packages/nostr-wasm
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" bun run build:wasm
bun run test:wasm
```

Fuzz one target locally (needs a nightly toolchain and cargo-fuzz):

```bash
cargo +nightly fuzz run <target> -- -max_total_time=60   # run from fuzz/
```
