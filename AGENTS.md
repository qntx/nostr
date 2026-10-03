# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- One-directional layering: `core` is the leaf; `nips/*`, `signer`, `storage`, `wasm` may only import `core`; `store` adds `storage`; `relay` adds `nips`/`signer`; `gossip` adds `nips`; `loaders` and `testing` consume the mid layers; `client` composes everything. `nips/*` must never import `relay`, `signer`, `storage`, or `client`.
- All I/O is injected (WebSocket, fetch, storage drivers); `src/` holds no ambient singletons.
- `src/` is platform-neutral: no Node-only or browser-only globals and no `node:*` imports outside the declared lint exceptions (`src/testing/serve.ts`, `src/wasm/load.ts`).

## Dependency policy

Runtime dependencies (`@noble/*`, `@scure/base`) use caret ranges so consumers can deduplicate them against the rest of their dependency tree; devDependencies stay exact-pinned for reproducible builds. Review upstream changelogs on every bump.
