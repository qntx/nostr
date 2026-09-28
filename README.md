<!-- markdownlint-disable MD033 MD041 -->

# nostr.js

Layered TypeScript Nostr library: events, keys, filters, signers, relays, storage, gossip, and a `Client` facade in one ESM package.

See [docs/](docs/).

## Per-relay invalid-event policy

`Pool`/`Client` can suspend a relay that keeps delivering events failing id/signature
verification: when more than `limit` delivered EVENTs fail inside a `windowMs` sliding window,
the connection is closed and `ensureRelay` rejects with `RelaySuspendedError` until `cooldownMs`
elapses. `onRelaySuspended(url, until)` fires once per suspension, and live subscriptions resume
automatically once the cooldown lifts.

```ts
const client = new Client({
  relays: ["wss://relay.example"],
  invalidEventPolicy: { limit: 20, windowMs: 60_000, cooldownMs: 5 * 60_000 },
  onRelaySuspended: (url, until) => console.warn(`${url} suspended until ${new Date(until)}`),
});
```

## License

Licensed under the MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
