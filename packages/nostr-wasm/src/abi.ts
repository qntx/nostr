import { CryptoError } from "@qntx/nostr/core";

/**
 * Byte-ABI version 1 surface exported by `nk_wasm.wasm` (`crates/nk-wasm/src/abi.rs`). All inputs
 * are caller-written regions of a single scratch buffer; status codes are 0 ok/verified, 1
 * verification failed, 2 invalid input.
 */
export type CryptoWasmExports = {
  memory: WebAssembly.Memory;
  nk_abi_version: () => number;
  nk_buffer: (len: number) => number;
  nk_verify: (id: number, pubkey: number, sig: number) => number;
  nk_verify_serialized: (
    ser: number,
    serLen: number,
    id: number,
    pubkey: number,
    sig: number,
  ) => number;
  nk_sign: (id: number, seckey: number, aux: number, outSig: number) => number;
  nk_public_key: (seckey: number, outPubkey: number) => number;
};

export const NK_ABI_VERSION = 1;

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
    nk_abi_version: requireFn(raw["nk_abi_version"], "nk_abi_version"),
    nk_buffer: requireFn(raw["nk_buffer"], "nk_buffer"),
    nk_verify: requireFn(raw["nk_verify"], "nk_verify"),
    nk_verify_serialized: requireFn(raw["nk_verify_serialized"], "nk_verify_serialized"),
    nk_sign: requireFn(raw["nk_sign"], "nk_sign"),
    nk_public_key: requireFn(raw["nk_public_key"], "nk_public_key"),
  };
}

/**
 * Reserve `total` bytes in the wasm scratch region and return a fresh view. The view is taken after
 * `nk_buffer` ran, so a growth inside it cannot leave a detached view in the caller's hands.
 */
function scratch(exports: CryptoWasmExports, total: number): { ptr: number; view: Uint8Array } {
  const ptr = exports.nk_buffer(total) >>> 0;
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
  return exports.nk_verify(ptr, ptr + ID_LEN, ptr + ID_LEN + PUBKEY_LEN) === 0;
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
    exports.nk_verify_serialized(
      ptr,
      serLen,
      ptr + serLen,
      ptr + serLen + ID_LEN,
      ptr + serLen + ID_LEN + PUBKEY_LEN,
    ) === 0
  );
}

/**
 * Returns the 64-byte signature, or an empty array on failure (invalid input). The Rust side zeroes
 * the scratch copy of `seckey` before returning.
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
  const status = exports.nk_sign(ptr, ptr + ID_LEN, ptr + ID_LEN + SECKEY_LEN, ptr + outOffset);
  if (status !== 0) {
    return new Uint8Array(0);
  }
  return takeOut(exports, ptr + outOffset, SIG_LEN);
}

/**
 * Returns the 32-byte x-only public key, or an empty array on failure. The Rust side zeroes the
 * scratch copy of `seckey` before returning.
 */
export function wasmPublicKey(exports: CryptoWasmExports, seckey: Uint8Array): Uint8Array {
  const { ptr, view } = scratch(exports, SECKEY_LEN + PUBKEY_LEN);
  view.set(seckey, 0);
  const status = exports.nk_public_key(ptr, ptr + SECKEY_LEN);
  if (status !== 0) {
    return new Uint8Array(0);
  }
  return takeOut(exports, ptr + SECKEY_LEN, PUBKEY_LEN);
}

/**
 * Compile and instantiate `nk_wasm.wasm`. The module must declare no imports and must implement ABI
 * version {@link NK_ABI_VERSION} — a mismatch means the artifact predates or postdates this loader
 * and instantiation fails.
 */
export async function instantiateCryptoWasm(
  bytes: ArrayBuffer | ArrayBufferView,
): Promise<CryptoWasmExports> {
  const module = await WebAssembly.compile(bytes);
  const imports = WebAssembly.Module.imports(module);
  if (imports.length > 0) {
    throw new TypeError(`nk_wasm module must not import anything, got ${imports.length} imports`);
  }
  const instance = await WebAssembly.instantiate(module, {});
  const version = requireFn(instance.exports["nk_abi_version"], "nk_abi_version")();
  if (version !== NK_ABI_VERSION) {
    throw new CryptoError(
      `unsupported nk_wasm ABI version ${String(version)}, expected ${NK_ABI_VERSION}`,
    );
  }
  return asExports(instance.exports);
}
