import { CryptoError } from "../core/error.ts";
import type { SigningBackend } from "../core/key.ts";
import type { EventVerifier } from "../core/verifier.ts";
import {
  instantiateCryptoWasm,
  wasmPublicKey,
  wasmSign,
  wasmVerify,
  wasmVerifySerialized,
} from "./abi.ts";
import type { CryptoWasmExports } from "./abi.ts";
import { createWasmEventVerifier, runPoisoned } from "./adapter.ts";

export type LoadNostrWasmOptions = {
  /** Bytes, or a URL whose bytes will be read by the platform loader. */
  module?: ArrayBuffer | ArrayBufferView | URL | undefined;
};

export type NostrWasm = SigningBackend & {
  verify: (id: Uint8Array, pubkey: Uint8Array, sig: Uint8Array) => boolean;
  verifySerialized: (
    serializedUtf8: Uint8Array,
    id: Uint8Array,
    pubkey: Uint8Array,
    sig: Uint8Array,
  ) => boolean;
  verifyEvent: EventVerifier;
};

export function isWasmBytes(value: unknown): value is ArrayBuffer | ArrayBufferView {
  return value instanceof ArrayBuffer || ArrayBuffer.isView(value);
}

export async function fetchWasmUrl(url: URL): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new CryptoError(`failed to fetch wasm: ${res.status} ${url.href}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

function requireByteLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new CryptoError(`invalid ${label} length: expected ${expected}, got ${bytes.length}`);
  }
}

function bindExports(exports: CryptoWasmExports): NostrWasm {
  const poison: { error?: Error } = {};
  const rawSerialized = (
    serializedUtf8: Uint8Array,
    id: Uint8Array,
    pubkey: Uint8Array,
    sig: Uint8Array,
  ): boolean => wasmVerifySerialized(exports, serializedUtf8, id, pubkey, sig);
  return {
    verify: (id, pubkey, sig) => runPoisoned(poison, () => wasmVerify(exports, id, pubkey, sig)),
    verifySerialized: (serializedUtf8, id, pubkey, sig) =>
      runPoisoned(poison, () => rawSerialized(serializedUtf8, id, pubkey, sig)),
    verifyEvent: createWasmEventVerifier(rawSerialized, poison),
    sign: (id, seckey, aux) =>
      runPoisoned(poison, () => {
        requireByteLength(id, 32, "id");
        requireByteLength(seckey, 32, "secret key");
        requireByteLength(aux, 32, "aux");
        const sig = wasmSign(exports, id, seckey, aux);
        if (sig.length !== 64) {
          throw new CryptoError("wasm sign failed");
        }
        return sig;
      }),
    publicKey: (seckey) =>
      runPoisoned(poison, () => {
        requireByteLength(seckey, 32, "secret key");
        const pk = wasmPublicKey(exports, seckey);
        if (pk.length !== 32) {
          throw new CryptoError("wasm publicKey failed");
        }
        return pk;
      }),
  };
}

/** Builds a loader that interns a single instance per module slot. */
export function createNostrWasmLoader(
  wasmBytes: (opts?: LoadNostrWasmOptions) => Promise<ArrayBuffer | ArrayBufferView>,
): {
  loadNostrWasm: (opts?: LoadNostrWasmOptions) => Promise<NostrWasm>;
  resetNostrWasm: () => void;
} {
  let interned: Promise<NostrWasm> | undefined;

  async function instantiate(opts?: LoadNostrWasmOptions): Promise<NostrWasm> {
    const bytes = await wasmBytes(opts);
    const exports = await instantiateCryptoWasm(bytes);
    return bindExports(exports);
  }

  /** Instantiate once. Repeats reuse the same module. Failure throws; no noble fallback. */
  async function loadNostrWasm(opts?: LoadNostrWasmOptions): Promise<NostrWasm> {
    if (interned) {
      return interned;
    }
    const pending = instantiate(opts);
    interned = pending;
    try {
      return await pending;
    } catch (error) {
      if (interned === pending) {
        interned = undefined;
      }
      throw error;
    }
  }

  function resetNostrWasm(): void {
    interned = undefined;
  }

  return { loadNostrWasm, resetNostrWasm };
}
