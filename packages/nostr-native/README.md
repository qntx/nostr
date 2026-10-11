# @qntx/nostr-native

Native libsecp256k1 verification and signing for [`@qntx/nostr`](https://www.npmjs.com/package/@qntx/nostr) on React Native (iOS/Android), via a Nitro C++ HybridObject over vendored libsecp256k1.

```bash
npm install @qntx/nostr-native @qntx/nostr react-native-nitro-modules
```

```ts
import { Keys, createEventVerifier } from "@qntx/nostr";
import { signing, verifySerialized } from "@qntx/nostr-native";
import { Relay } from "@qntx/nostr/relay";

// Verifier injection: relays verify incoming events natively.
const verifyEvent = createEventVerifier(verifySerialized);
const relay = await Relay.connect("wss://relay.example", { verifyEvent });

// Signing backend: `keys` signs on the same randomized native context.
const keys = Keys.fromSecretKey(secretKey, signing);
```

## Requirements

- React Native with the New Architecture (Nitro Modules 0.37.x), iOS and Android only.
- Expo projects need a dev client / prebuild — the module compiles from source and cannot run in Expo Go.
- libsecp256k1 v0.8.0 is vendored under `vendor/secp256k1` (MIT, see `vendor/secp256k1/COPYING`).

## License

MIT OR Apache-2.0
