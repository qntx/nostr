<!-- markdownlint-disable MD033 MD041 -->

# nostr

Nostr protocol implementation and SDK. One repo, two languages:

- `@qntx/nostr` — layered TypeScript library: events, keys, filters, signers, relays, storage, gossip, and a `Client` facade in one ESM package.
- `nk-*` — Rust crates mirroring the TypeScript layers (`crates/`), starting with `nk-core`.

Changes are tracked in [CHANGELOG.md](CHANGELOG.md); layering rules and invariants for contributors live in [AGENTS.md](AGENTS.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
