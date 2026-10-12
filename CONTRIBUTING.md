# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust** — via `crates/interop/rust-toolchain.toml` (interop crate only).
- **LLVM clang** for `wasm32-unknown-unknown` — `@qntx/nostr-wasm` compiles the
  shared C core with a wasm-capable clang; Apple clang will not work.

  ```bash
  brew install llvm
  export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
  ```

- `cargo-deny` for the supply-chain check (`cargo install cargo-deny`).

## Repository layout

```text
packages/nostr/       @qntx/nostr — pure-TypeScript library (core, nips,
                      signer, relay, storage, store, loaders, gossip, client,
                      testing); builds with vp pack, no Rust toolchain needed
packages/nostr-wasm/  @qntx/nostr-wasm — wasm32 build of the shared C core
                      (packages/nostr-wasm/c) plus JS bindings
packages/nostr-native/ @qntx/nostr-native — React Native Nitro C++ backend
                      over vendored libsecp256k1 (iOS/Android); its
                      cpp/nostr_core.c is the shared C core
crates/interop/       qntx-nostr-interop — runs vectors/ and the TS
                      differential streams against rust-nostr
vectors/              shared cross-language test vectors (see vectors/README.md)
parity.json           ledger of shared-vector capabilities consumed by
                      scripts/parity/check.ts
scripts/              repo tooling (check-version, sync-versions, parity/);
                      script tests run under the root vp test
```

## Local gate

Run before opening a pull request:

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

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is local-only and must never be committed, except the `docs/index.mdx`
and `docs/meta.json` stubs.

## Versioning and release

Only the npm packages carry a release version; the crates under `crates/` are
unpublished (`version = "0.0.0"`) and are not versioned with them.
`bump.config.ts` bumps the `packages/*/package.json` files and runs
`bun scripts/sync-versions.ts`, which syncs internal `@qntx/*` ranges and
refreshes `bun.lock` via `bun install --lockfile-only`; `release` runs
`bumpp`, which pushes a
`release/vX.Y.Z` branch and opens the release pull request via `gh`.
After the release PR merges, tag the merge commit and push the tag:

```sh
git tag -a vX.Y.Z <merge-sha> -m vX.Y.Z && git push origin vX.Y.Z
```

`scripts/check-version.ts` fails the lint gate when the internal `@qntx/*`
ranges or bun.lock workspace entries drift from the manifests.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
