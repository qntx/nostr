# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust 1.94** — via `rust-toolchain.toml` (kept in sync with
  `[workspace.package].rust-version`; includes the `wasm32-unknown-unknown`
  target).
- **LLVM clang** for `wasm32-unknown-unknown` — `secp256k1-sys` needs a
  wasm-capable clang; Apple clang will not work.

  ```bash
  brew install llvm
  export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
  ```

- **wasm-bindgen CLI** matching the `wasm-bindgen` version in `Cargo.lock`
  (`cargo install wasm-bindgen-cli --version 0.2.122`). `scripts/build-wasm.sh`
  verifies the match. This pin stays until the wasm-bindgen ABI is replaced.
- **Optional**, for local portable builds: the iOS and Android rustup targets
  (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim
aarch64-linux-android x86_64-linux-android`), Xcode, and the Android NDK. CI
  runs these builds.
- `cargo-deny` for the supply-chain check (`cargo install cargo-deny`).

## Repository layout

```
src/            @qntx/nostr — TypeScript library (core, nips, signer, relay,
                storage, store, loaders, gossip, client, wasm, testing)
crates/         nk-* Rust crates (one crate per TypeScript layer)
vectors/        shared cross-language test vectors (see vectors/README.md)
parity.json     capability ledger consumed by scripts/parity/check.ts
tests/          vitest/bun tests; tests/vectors runs the shared vectors
wasm-tests/     tests that exercise the compiled wasm module
scripts/        repo tooling (build-wasm, check-version, check-layers, parity/)
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
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" bun run build:wasm
bun run test:wasm
```

`bun test` must also pass (it runs the same test files under Bun's runner).

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is local-only and must never be committed, except the `docs/index.mdx`
and `docs/meta.json` stubs.

## Versioning and release

npm and crates versions are lockstep. `bump.config.ts` bumps `package.json` and
`Cargo.toml` together and runs `cargo update --workspace`; `release` runs
`bumpp` (commit + tag + push). `scripts/check-version.ts` fails the lint gate
when they drift.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
