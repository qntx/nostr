import { invokeSafely } from "./report.ts";

/**
 * Typed multi-listener dispatch for long-lived objects: `M` maps each event name to its payload
 * type. Listeners fire synchronously in registration order off a snapshot, so unsubscribing or
 * registering during dispatch neither skips nor double-fires the in-flight pass; a throwing
 * listener is reported and does not starve the rest.
 */
export class Emitter<M extends Record<string, unknown>> {
  readonly #listeners: { [K in keyof M]?: Set<(payload: M[K]) => void> } = {};

  /** Register `listener` for `type`; returns an unsubscribe function. */
  on<K extends keyof M>(type: K, listener: (payload: M[K]) => void): () => void {
    let set = this.#listeners[type];
    if (set === undefined) {
      set = new Set<(payload: M[K]) => void>();
      this.#listeners[type] = set;
    }
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }

  emit<K extends keyof M>(type: K, payload: M[K]): void {
    const set = this.#listeners[type];
    if (set === undefined) {
      return;
    }
    // snapshot: listeners may unsubscribe or register during dispatch
    for (const listener of new Set(set)) {
      invokeSafely(() => listener(payload));
    }
  }
}
