import { NostrError } from "../core/error.ts";

/** Base class for relay errors; carries the relay URL when known. */
export class RelayError extends NostrError {
  override name = "RelayError";
  readonly url: string | undefined;

  constructor(message: string, url?: string, options?: ErrorOptions) {
    super(url !== undefined && url !== "" ? `${message} (${url})` : message, options);
    this.url = url;
  }
}

/** A relay connection attempt or socket failed. */
export class RelayConnectionError extends RelayError {
  override name = "RelayConnectionError";
}
/** A relay answered an EVENT with `ok: false`. */
export class RelayPublishError extends RelayError {
  override name = "RelayPublishError";
  /**
   * The NIP-01 `<params>` of the OK frame; its meaning depends on the message prefix
   * (`rate-limited:` → retry-after ms as a decimal string). Undefined when the relay sent none.
   */
  readonly params: string | undefined;

  constructor(
    message: string,
    url?: string,
    options?: ErrorOptions & { readonly params?: string | undefined },
  ) {
    super(message, url, options);
    this.params = options?.params;
  }
}
/** A subscription was closed by the relay (`CLOSED`) or the socket dropped. */
export class RelayClosedError extends RelayError {
  override name = "RelayClosedError";
  /**
   * The NIP-01 `<params>` of the CLOSED frame; its meaning depends on the message prefix
   * (`rate-limited:` → retry-after ms as a decimal string). Undefined when the relay sent none.
   */
  readonly params: string | undefined;

  constructor(
    message: string,
    url?: string,
    options?: ErrorOptions & { readonly params?: string | undefined },
  ) {
    super(message, url, options);
    this.params = options?.params;
  }
}
/** A relay operation exceeded its deadline. */
export class RelayTimeoutError extends RelayError {
  override name = "RelayTimeoutError";
}
/**
 * A relay was suspended for delivering more events that fail id/signature verification than its
 * {@link PoolOptions.invalidEventPolicy} allows. Carries `until`, the epoch-ms time when the relay
 * may connect again.
 */
export class RelaySuspendedError extends RelayError {
  override name = "RelaySuspendedError";
  /** Epoch milliseconds when the suspension lifts. */
  readonly until: number;

  constructor(url: string, until: number) {
    super("relay suspended for delivering invalid events", url);
    this.until = until;
  }
}
