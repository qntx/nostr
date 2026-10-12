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

- The Rust side does not implement the protocol. Rust consumers use rust-nostr (`nostr`, `nostr-sdk`, ...) from crates.io; this repository does not fork or copy it, and upstream defects go upstream as issues or pull requests.
- `crates/interop` (`qntx-nostr-interop`) runs the shared vectors in `vectors/` and the TS differential streams against rust-nostr. Only protocol behavior is compared. Known divergences are listed in `crates/interop/divergences.json`; unlisted divergences and stale entries fail the tests.
- `crates/interop` is a standalone Cargo project (test targets only, no library): its `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, and `deny.toml` all live inside it. The repository root has no Cargo files.
- Rust crates are not published and are not versioned with the npm packages.
- Follow the Rust API Guidelines. No panics and no `unwrap`/`expect` outside tests.
- Shared test vectors live in `vectors/` (see `vectors/README.md`); `parity.json` lists each protocol capability that has shared vectors, its TS tests, and its rust-nostr counterpart.
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt`, and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version and
                                                    # parity checks
cd crates/interop
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cd ../..
cd packages/nostr-wasm
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" bun run build:wasm
bun run test:wasm
```
