# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- One-directional layering inside `packages/nostr/src`: `core` is the leaf; `nips/*` and `storage` may only import `core`; `signer` adds `nips`; `store` adds `storage`; `relay` adds `nips`/`signer`; `gossip` adds `nips`; `loaders` and `testing` consume the mid layers; `client` composes everything. `nips/*` must never import `relay`, `signer`, `storage`, or `client`. The wasm layer is the separate `packages/nostr-wasm` package, which may only import `@qntx/nostr/core`.
- All I/O is injected (WebSocket, fetch, storage drivers); `packages/*/src/` holds no ambient singletons.
- `packages/*/src/` is platform-neutral: no Node-only or browser-only globals and no `node:*` imports outside the declared lint exceptions (`packages/nostr/src/testing/serve.ts`, `packages/nostr-wasm/src/load.ts`).

## Dependency policy

Runtime dependencies (`@noble/*`, `@scure/base`) use caret ranges so consumers can deduplicate them against the rest of their dependency tree; devDependencies stay exact-pinned for reproducible builds. Review upstream changelogs on every bump.

## Rust crates

- One `nk-*` crate per TypeScript layer (`nk-core` is the leaf; crates are added per milestone). Dependency direction mirrors the TS layering and is enforced by `scripts/check-layers.ts`.
- `nk-core`, `nk-nips`, `nk-signer`, and `nk-gossip` are `no_std` + `alloc` and sans-IO; `nk-storage` is portable but uses `std` (its `sqlite` feature only needs to build for iOS/Android); `nk-wasm` is the wasm binding crate. All of these P-level crates must build for `wasm32-unknown-unknown` with `--no-default-features` and for the iOS/Android toolchain targets. `std` (default), `clock`, and `os-rng` are additive features; OS entropy and wall clock live behind them.
- Follow the Rust API Guidelines. No third-party types in public APIs. No panics and no `unwrap`/`expect` in library code. `unsafe` only inside `nk-wasm`'s ABI module.
- Shared test vectors live in `vectors/` (see `vectors/README.md`) and every capability is tracked in `parity.json`; both languages run the same files.
- npm and crates versions are lockstep: `bump.config.ts` bumps `packages/*/package.json` + `Cargo.toml` together, `scripts/check-version.ts` guards drift (including the `@qntx/nostr-wasm` peer/dev ranges on `@qntx/nostr`).
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt`, and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version, layer and
                                                    # parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cd packages/nostr-wasm
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" bun run build:wasm
bun run test:wasm
```
