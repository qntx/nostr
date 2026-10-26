# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust** — via the root `rust-toolchain.toml` (`crates/nk-core` is the
  protocol crate; `fuzz/` builds with the nightly toolchain).
- **LLVM clang** for `wasm32-unknown-unknown` — `@qntx/nostr-wasm` compiles the
  shared C core with a wasm-capable clang, and nk-core's wasm32 no-default-features
  check uses the same toolchain; Apple clang will not work.

  ```bash
  brew install llvm
  export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"
  ```

- `cargo-deny` for the supply-chain check and `cargo-hack` for the
  each-feature matrix (`cargo install cargo-deny cargo-hack`).
- `cargo-fuzz` + a nightly toolchain only for fuzzing (`cargo install cargo-fuzz`).

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
crates/nk-core/       nk-core — the owned Rust protocol crate (no_std +
                      alloc, sans-IO); runs vectors/ and the TS differential
                      streams in tests/it/ plus in-crate vector tests
crates/nk-store/      nk-store — synchronous EventStore trait with memory
                      and sqlite (feature-gated) backends sharing one put
                      policy
crates/nk/            nk — the SDK crate: tokio/yawc single-relay client
                      with a sans-IO session and a `test-util` MockRelay
fuzz/                 standalone cargo-fuzz workspace over nk-core
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
bun run test:parity
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

## Commits

English Conventional Commits: `type(scope): subject` (`feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`), subject
in imperative mood, no period, ≤ 50 chars; `BREAKING CHANGE:` footer for
breaking changes.

## Documentation policy

`docs/` is local-only and must never be committed, except the `docs/index.mdx`
and `docs/meta.json` stubs.

## Versioning and release

npm packages and Cargo workspace crates are versioned lockstep:
`[workspace.package].version` equals every package.json version.
`bump.config.ts` bumps the `packages/*/package.json` files and `Cargo.toml`
(`[workspace.package].version` plus the `nk-core = "=x.y.z"` pin) and runs
`bun scripts/sync-versions.ts`, which syncs internal `@qntx/*` ranges,
refreshes `Cargo.lock` via `cargo update --workspace`, and refreshes
`bun.lock` via `bun install --lockfile-only`; `release` runs
`bumpp`, which pushes a
`release/vX.Y.Z` branch and opens the release pull request via `gh`.
After the release PR merges, tag the merge commit and push the tag:

```sh
git tag -a vX.Y.Z <merge-sha> -m vX.Y.Z && git push origin vX.Y.Z
```

`scripts/check-version.ts` fails the lint gate when the internal `@qntx/*`
ranges, the Cargo workspace version, member `version.workspace = true`
inheritance, internal `=<version>` pins, Cargo.lock workspace-member entries,
or bun.lock workspace entries drift from the manifests. The pushed tag also
triggers `publish-crates.yml`, which publishes `nk-core` to crates.io.

## License

Contributions are dual-licensed under MIT OR Apache-2.0.
