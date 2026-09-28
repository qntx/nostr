<!-- markdownlint-disable MD033 MD041 -->

# nostr.js

Layered TypeScript Nostr library: events, keys, filters, signers, relays, storage, gossip, and a `Client` facade in one ESM package.

See [docs/](docs/).

## Custom verification backends

`verifyEvent` validates an event's id hash and BIP-340 signature in pure JS (noble). Runtimes with a faster verifier — the bundled WASM module, or a React Native native module such as libsecp256k1 over Nitro — can plug in via `createEventVerifier` (`@qntx/nostr/core`), which keeps `verifyEvent`'s exact semantics (shared verified/failed caches, structural validation, canonical serialization) and delegates the hash + signature check to raw bytes:

```ts
import { createEventVerifier } from "@qntx/nostr/core";

// Backend contract: sha256(serializedUtf8) === id && BIP-340(sig, id, pubkey).
// Inputs are raw bytes (id/pubkey 32, sig 64); thrown errors propagate.
const verifyEventNative = createEventVerifier((serializedUtf8, id, pubkey, sig) =>
  myNativeSecp256k1.verifyEvent(serializedUtf8, id, pubkey, sig),
);
```

The WASM backend in `@qntx/nostr/wasm` is built on the same API.

## License

Licensed under the MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
