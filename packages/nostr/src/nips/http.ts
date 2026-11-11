/**
 * Shared nips HTTP primitive. Not a pack entry (core has zero network). Callers never pass
 * `redirect`; sendManual always sets `"manual"`.
 */

export type ManualFetchInit = {
  method?: string;
  headers?: Record<string, string>;
  // oxlint-disable-next-line typescript/no-restricted-types -- mirrors RequestInit.body, which is nullable
  body?: Blob | FormData | string | null;
  signal?: AbortSignal | undefined;
  /**
   * Request-body upload progress as `(sent, total)` byte counts. Adapters that can observe it call
   * it; the global `fetch` cannot and ignores it.
   */
  onUploadProgress?: ((sent: number, total: number) => void) | undefined;
  /**
   * Always `"manual"`: NIP-05, NIP-11 and Blossom responses must never be followed through
   * redirects. Adapters must forward this to their underlying fetch implementation.
   */
  redirect: "manual";
};

export type ManualFetch = (
  url: string,
  init?: ManualFetchInit,
) => Promise<{
  ok: boolean;
  status: number;
  // oxlint-disable-next-line typescript/no-restricted-types -- mirrors Headers.get, which returns null
  headers: { get: (name: string) => string | null };
  json: () => Promise<unknown>;
  arrayBuffer: () => Promise<ArrayBuffer>;
}>;

type ManualInit = Omit<ManualFetchInit, "redirect">;

export function requireGlobalFetch(missing: () => Error): ManualFetch {
  if (typeof globalThis.fetch !== "function") {
    throw missing();
  }
  const fetchImpl = globalThis.fetch.bind(globalThis);
  // RequestInit.signal is AbortSignal | null and rejects explicit undefined under
  // exactOptionalPropertyTypes; normalize it for the real fetch. The real fetch
  // cannot observe request-body progress, so onUploadProgress is stripped.
  return async (url, init) => {
    if (init === undefined) {
      return fetchImpl(url, init);
    }
    const { onUploadProgress: _progress, ...rest } = init;
    return fetchImpl(url, { ...rest, signal: init.signal ?? null });
  };
}

/** Always sets redirect:manual. Shared by fetchManual and headStatus. */
export async function sendManual(
  fetchImpl: ManualFetch,
  url: string,
  init: ManualInit,
): Promise<Awaited<ReturnType<ManualFetch>>> {
  return fetchImpl(url, { ...init, redirect: "manual" });
}

export async function fetchManual(
  fetchImpl: ManualFetch,
  url: string,
  init: ManualInit,
  wrapNetwork: (err: unknown) => Error,
): Promise<Awaited<ReturnType<ManualFetch>>> {
  try {
    return await sendManual(fetchImpl, url, init);
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw error;
    }
    throw wrapNetwork(error);
  }
}
