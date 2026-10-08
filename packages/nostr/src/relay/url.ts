import { normalizeURL } from "../core/util.ts";

/**
 * {@link normalizeURL}, or the raw string when it is not a valid relay URL (ensureRelay then fails
 * it like a dead relay).
 */
export function relayUrlKey(url: string): string {
  try {
    return normalizeURL(url);
  } catch {
    return url;
  }
}

/** Unique relay keys in first-seen order. */
export function uniqueRelayUrls(urls: Iterable<string>): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const url of urls) {
    const key = relayUrlKey(url);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(key);
  }
  return unique;
}

/**
 * True for `ws:` / `http:` URLs that are not `.onion`. Local-network `ws://` is still insecure;
 * allow those via a trusted set.
 */
export function isInsecureRelayUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.hostname.endsWith(".onion")) {
      return false;
    }
    return parsed.protocol === "ws:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}
