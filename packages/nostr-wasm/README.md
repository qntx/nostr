# @qntx/nostr-wasm

WebAssembly-accelerated cryptography for [`@qntx/nostr`](https://www.npmjs.com/package/@qntx/nostr) (BIP-340 signing and event verification), built from the `nk-wasm` Rust crate.

```bash
npm install @qntx/nostr-wasm @qntx/nostr
```

```ts
import { Keys } from "@qntx/nostr";
import { loadNostrWasm } from "@qntx/nostr-wasm";
import { Relay } from "@qntx/nostr/relay";

const wasm = await loadNostrWasm();

// Signing backend: `keys` signs with the wasm module.
const keys = Keys.fromSecretKey(secretKey, wasm);

// Verifier injection: relays verify incoming events with wasm.
const relay = await Relay.connect("wss://relay.example", {
  verifyEvent: wasm.verifyEvent,
});
```

The default (Node) entry reads the bundled `.wasm` file from disk; bundlers and browsers should resolve the `browser` export condition (or import `@qntx/nostr-wasm/browser`), which fetches the asset served next to the module. Both accept explicit bytes via `loadNostrWasm({ module })`.

## License

MIT OR Apache-2.0
