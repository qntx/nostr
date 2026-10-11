# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- One-directional layering inside `packages/nostr/src`: `core` is the leaf; `nips/*` and `storage` may only import `core`; `signer` adds `nips`; `store` adds `storage`; `relay` adds `nips`/`signer`; `gossip` adds `nips`; `loaders` and `testing` consume the mid layers; `client` composes everything. `nips/*` must never import `relay`, `signer`, `storage`, or `client`. The acceleration backends are the separate `packages/nostr-wasm` and `packages/nostr-native` packages, which may only import `@qntx/nostr/core`; `packages/nostr-native` is React Native–only by design and may additionally import `react-native-nitro-modules`, an explicit exception to the platform-neutral rule. The TypeScript layer graph is enforced by lint (`LAYERS` in `vite.config.ts`).
- All I/O is injected (WebSocket, fetch, storage drivers); `packages/*/src/` holds no ambient singletons.
- `packages/*/src/` is platform-neutral: no Node-only or browser-only globals and no `node:*` imports outside the declared lint exceptions (`packages/nostr/src/testing/serve.ts`, `packages/nostr-wasm/src/load.ts`).

## Dependency policy

Runtime dependencies (`@noble/*`, `@scure/base`) use caret ranges so consumers can deduplicate them against the rest of their dependency tree; devDependencies stay exact-pinned for reproducible builds. Review upstream changelogs on every bump.

## Rust

- The Rust side does not implement the protocol. Rust consumers use rust-nostr (`nostr`, `nostr-sdk`, ...) from crates.io; this repository does not fork or copy it, and upstream defects go upstream as issues or pull requests.
- `crates/wasm` (`qntx-nostr-wasm`) is the WebAssembly ABI behind `@qntx/nostr-wasm`. It depends only on `secp256k1` and `sha2`, builds for `wasm32-unknown-unknown`, and is the only place `unsafe` is allowed (ABI module, with safety comments).
- `crates/interop` (`qntx-nostr-interop`) runs the shared vectors in `vectors/` and the TS differential streams against rust-nostr. Only protocol behavior is compared. Known divergences are listed in `crates/interop/divergences.json`; unlisted divergences and stale entries fail the tests.
- Rust crates are not published and are not versioned with the npm packages.
- Follow the Rust API Guidelines. No panics and no `unwrap`/`expect` outside tests.
- Shared test vectors live in `vectors/` (see `vectors/README.md`) and every capability is tracked in `parity.json`.
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt`, and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version and
                                                    # parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cd packages/nostr-wasm
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" bun run build:wasm
bun run test:wasm
```
