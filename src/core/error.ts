/** Base error for all @qntx/nostr failures. */
export class NostrError extends Error {
  override name = "NostrError";
}

/** `error.message` for Error instances, `String(error)` otherwise. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Invalid hex encoding or length. */
export class HexError extends NostrError {
  override name = "HexError";
}

/** Invalid URL / relay URL. */
export class UrlError extends NostrError {
  override name = "UrlError";
}

/** Event shape / wire validation failure. */
export class EventValidationError extends NostrError {
  override name = "EventValidationError";
}

/** Cryptographic operation failure (keys, signatures). */
export class CryptoError extends NostrError {
  override name = "CryptoError";
}

/** Message parse / encode failure. */
export class MessageError extends NostrError {
  override name = "MessageError";
}

/** Wasm instance aborted; later calls on that instance fail. */
export class WasmPoisonedError extends NostrError {
  override name = "WasmPoisonedError";
}
