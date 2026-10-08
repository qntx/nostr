# @qntx/nostr

Nostr protocol implementation and SDK in TypeScript: events, keys, filters, signers, relays, storage, gossip, and a `Client` facade in one ESM package.

```bash
npm install @qntx/nostr
```

Subpath entry points mirror the layering: `/core`, `/signer`, `/relay`, `/client`, `/storage`, `/store`, `/loaders`, `/gossip`, `/nips/*`, `/testing`.

For WebAssembly-accelerated signing and verification, install [`@qntx/nostr-wasm`](https://www.npmjs.com/package/@qntx/nostr-wasm) and inject its `SigningBackend`/`EventVerifier` (see that package's README).

## License

MIT OR Apache-2.0
