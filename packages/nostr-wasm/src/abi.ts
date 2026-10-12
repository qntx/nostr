import { CryptoError, randomBytes } from "@qntx/nostr/core";

/**
 * Byte-ABI version 3 surface exported by `nostr_wasm.wasm` (`packages/nostr-wasm/c/nostr_wasm.c`
 * over the shared `nostr_core.c` in `packages/nostr-native/cpp`). All inputs are caller-written
 * regions of a single scratch buffer; status codes are 0 ok/verified, 1 verification failed, 2
 * invalid input. `nostr_init` must succeed once with a 32-byte seed before the crypto ops run.
 */
export type CryptoWasmExports = {
  memory: WebAssembly.Memory;
  nostr_abi_version: () => number;
  nostr_init: (seed: number) => number;
  nostr_buffer: (len: number) => number;
  nostr_verify: (id: number, pubkey: number, sig: number) => number;
  nostr_verify_serialized: (
    ser: number,
    serLen: number,
    id: number,
    pubkey: number,
    sig: number,
  ) => number;
  nostr_sign: (id: number, seckey: number, aux: number, outSig: number) => number;
  nostr_public_key: (seckey: number, outPubkey: number) => number;
};

export const NOSTR_ABI_VERSION = 3;

const SEED_LEN = 32;

const ID_LEN = 32;
const PUBKEY_LEN = 32;
const SIG_LEN = 64;
const SECKEY_LEN = 32;
const AUX_LEN = 32;

function requireMemory(value: WebAssembly.ExportValue | undefined): WebAssembly.Memory {
  if (!(value instanceof WebAssembly.Memory)) {
    throw new TypeError("wasm missing memory export");
  }
  return value;
}

// oxlint-disable-next-line no-unnecessary-type-parameters -- T binds the declared ABI signature at each call site
function requireFn<T extends (...args: number[]) => unknown>(
  value: WebAssembly.ExportValue | undefined,
  name: string,
): T {
  if (typeof value !== "function") {
    throw new TypeError(`wasm missing ${name} export`);
  }
  // oxlint-disable-next-line no-unsafe-type-assertion -- wasm exports are opaque; each name is bound to the signature the ABI contract requires
  return value as T;
}

function asExports(raw: WebAssembly.Exports): CryptoWasmExports {
  return {
    memory: requireMemory(raw["memory"]),
    nostr_abi_version: requireFn(raw["nostr_abi_version"], "nostr_abi_version"),
    nostr_init: requireFn(raw["nostr_init"], "nostr_init"),
    nostr_buffer: requireFn(raw["nostr_buffer"], "nostr_buffer"),
    nostr_verify: requireFn(raw["nostr_verify"], "nostr_verify"),
    nostr_verify_serialized: requireFn(raw["nostr_verify_serialized"], "nostr_verify_serialized"),
    nostr_sign: requireFn(raw["nostr_sign"], "nostr_sign"),
    nostr_public_key: requireFn(raw["nostr_public_key"], "nostr_public_key"),
  };
}

/**
 * Reserve `total` bytes in the wasm scratch region and return a fresh view. `nostr_buffer` returns
 * NULL when `memory.grow` fails; `__heap_base` is never 0, so 0 is unambiguously an allocation
 * failure — throw instead of writing at address 0. The view is taken after `nostr_buffer` ran, so a
 * growth inside it cannot leave a detached view in the caller's hands.
 */
function scratch(exports: CryptoWasmExports, total: number): { ptr: number; view: Uint8Array } {
  const ptr = exports.nostr_buffer(total) >>> 0;
  if (ptr === 0) {
    throw new CryptoError("wasm scratch allocation failed");
  }
  return { ptr, view: new Uint8Array(exports.memory.buffer, ptr, total) };
}

/** Copies `len` scratch bytes out; the view is re-acquired after the call. */
function takeOut(exports: CryptoWasmExports, ptr: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  out.set(new Uint8Array(exports.memory.buffer, ptr, len));
  return out;
}

export function wasmVerify(
  exports: CryptoWasmExports,
  id: Uint8Array,
  pubkey: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (id.length !== ID_LEN || pubkey.length !== PUBKEY_LEN || sig.length !== SIG_LEN) {
    return false; // fixed-size ABI: a wrong-length input simply cannot verify
  }
  const { ptr, view } = scratch(exports, ID_LEN + PUBKEY_LEN + SIG_LEN);
  view.set(id, 0);
  view.set(pubkey, ID_LEN);
  view.set(sig, ID_LEN + PUBKEY_LEN);
  return exports.nostr_verify(ptr, ptr + ID_LEN, ptr + ID_LEN + PUBKEY_LEN) === 0;
}

export function wasmVerifySerialized(
  exports: CryptoWasmExports,
  serialized: Uint8Array,
  id: Uint8Array,
  pubkey: Uint8Array,
  sig: Uint8Array,
): boolean {
  if (id.length !== ID_LEN || pubkey.length !== PUBKEY_LEN || sig.length !== SIG_LEN) {
    return false;
  }
  const serLen = serialized.length;
  const { ptr, view } = scratch(exports, serLen + ID_LEN + PUBKEY_LEN + SIG_LEN);
  view.set(serialized, 0);
  view.set(id, serLen);
  view.set(pubkey, serLen + ID_LEN);
  view.set(sig, serLen + ID_LEN + PUBKEY_LEN);
  return (
    exports.nostr_verify_serialized(
      ptr,
      serLen,
      ptr + serLen,
      ptr + serLen + ID_LEN,
      ptr + serLen + ID_LEN + PUBKEY_LEN,
    ) === 0
  );
}

/**
 * Returns the 64-byte signature, or an empty array on failure (invalid input). The wasm module
 * zeroes the scratch copy of `seckey` before returning.
 */
export function wasmSign(
  exports: CryptoWasmExports,
  id: Uint8Array,
  seckey: Uint8Array,
  aux: Uint8Array,
): Uint8Array {
  const outOffset = ID_LEN + SECKEY_LEN + AUX_LEN;
  const { ptr, view } = scratch(exports, outOffset + SIG_LEN);
  view.set(id, 0);
  view.set(seckey, ID_LEN);
  view.set(aux, ID_LEN + SECKEY_LEN);
  const status = exports.nostr_sign(ptr, ptr + ID_LEN, ptr + ID_LEN + SECKEY_LEN, ptr + outOffset);
  if (status !== 0) {
    return new Uint8Array(0);
  }
  return takeOut(exports, ptr + outOffset, SIG_LEN);
}

/**
 * Returns the 32-byte x-only public key, or an empty array on failure. The wasm module zeroes the
 * scratch copy of `seckey` before returning.
 */
export function wasmPublicKey(exports: CryptoWasmExports, seckey: Uint8Array): Uint8Array {
  const { ptr, view } = scratch(exports, SECKEY_LEN + PUBKEY_LEN);
  view.set(seckey, 0);
  const status = exports.nostr_public_key(ptr, ptr + SECKEY_LEN);
  if (status !== 0) {
    return new Uint8Array(0);
  }
  return takeOut(exports, ptr + SECKEY_LEN, PUBKEY_LEN);
}

/**
 * Compile and instantiate `nostr_wasm.wasm`. The module must declare no imports and must implement
 * ABI version {@link NOSTR_ABI_VERSION} — a mismatch means the artifact predates or postdates this
 * loader and instantiation fails.
 */
export async function instantiateCryptoWasm(
  bytes: ArrayBuffer | ArrayBufferView,
): Promise<CryptoWasmExports> {
  const module = await WebAssembly.compile(bytes);
  const imports = WebAssembly.Module.imports(module);
  if (imports.length > 0) {
    throw new TypeError(
      `nostr_wasm module must not import anything, got ${imports.length} imports`,
    );
  }
  const instance = await WebAssembly.instantiate(module, {});
  const version = requireFn(instance.exports["nostr_abi_version"], "nostr_abi_version")();
  if (version !== NOSTR_ABI_VERSION) {
    throw new CryptoError(
      `unsupported nostr_wasm ABI version ${String(version)}, expected ${NOSTR_ABI_VERSION}`,
    );
  }
  const exports = asExports(instance.exports);
  // Seed the context: 32 bytes of fresh randomness into the scratch buffer; the C side
  // randomizes the context and wipes the seed region on every path.
  const { ptr, view } = scratch(exports, SEED_LEN);
  view.set(randomBytes(SEED_LEN), 0);
  if (exports.nostr_init(ptr) !== 0) {
    throw new CryptoError("nostr_init failed to randomize the wasm context");
  }
  return exports;
}
