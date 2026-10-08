# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust 1.99** — via `rust-toolchain.toml` (kept in sync with
  `[workspace.package].rust-version`; includes the `wasm32-unknown-unknown`
  target).
- **LLVM clang** for `wasm32-unknown-unknown` — `secp256k1-sys` needs a
  wasm-capable clang; Apple clang will not work.

  ```bash
  brew install llvm
  export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
  ```

- **Optional**, for local portable builds: Xcode, the Android NDK, and the iOS
  and Android rustup targets. CI runs these builds.

  ```bash
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android
  ```

- `cargo-deny` for the supply-chain check (`cargo install cargo-deny`).

## Repository layout

```text
packages/nostr/       @qntx/nostr — pure-TypeScript library (core, nips,
                      signer, relay, storage, store, loaders, gossip, client,
                      testing); builds with vp pack, no Rust toolchain needed
packages/nostr-wasm/  @qntx/nostr-wasm — JS bindings of crates/nk-wasm
crates/               nk-* Rust crates (one crate per TypeScript layer)
vectors/              shared cross-language test vectors (see vectors/README.md)
parity.json           capability ledger consumed by scripts/parity/check.ts
scripts/              repo tooling (check-version, check-layers, sync-versions,
                      parity/); script tests run under the root vp test
```

## Local gate

Run before opening a pull request:

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

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is local-only and must never be committed, except the `docs/index.mdx`
and `docs/meta.json` stubs.

## Versioning and release

npm and crates versions are lockstep. `bump.config.ts` bumps both
`packages/*/package.json` files and `Cargo.toml` together and runs
`bun scripts/sync-versions.ts` (internal `@qntx/*` ranges) and
`cargo update --workspace`; `release` runs `bumpp`, which pushes a
`release/vX.Y.Z` branch and opens the release pull request via `gh`.
After the release PR merges, tag the merge commit and push the tag:

```sh
git tag -a vX.Y.Z <merge-sha> -m vX.Y.Z && git push origin vX.Y.Z
```

`scripts/check-version.ts` fails the lint gate when they drift.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
