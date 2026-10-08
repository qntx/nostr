export function abortReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) {
    return signal.reason;
  }
  const error = new Error("This operation was aborted");
  error.name = "AbortError";
  return error;
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw abortReason(signal);
  }
}

/** Listen for `abort` once; the returned disposer removes the listener. No-op without a signal. */
export function onAbort(signal: AbortSignal | undefined, listener: () => void): () => void {
  if (!signal) {
    return () => {
      // no signal — nothing to remove
    };
  }
  signal.addEventListener("abort", listener, { once: true });
  return () => {
    signal.removeEventListener("abort", listener);
  };
}

/**
 * Race `promise` against the caller's `signal` without cancelling the shared work: on abort the
 * returned promise rejects with `signal.reason` (or an `AbortError`-named Error) while `promise`
 * itself keeps running. With no signal the original promise is returned.
 */
export async function raceSignal<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  if (!signal) {
    return promise;
  }
  if (signal.aborted) {
    throw abortReason(signal);
  }
  return new Promise<T>((resolve, reject) => {
    const dispose = onAbort(signal, () => {
      // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- the rejection is the caller's signal.reason verbatim
      reject(abortReason(signal));
    });
    void (async (): Promise<void> => {
      try {
        resolve(await promise);
      } catch (error) {
        // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards the raced promise's own rejection
        reject(error);
      } finally {
        dispose();
      }
    })();
  });
}
