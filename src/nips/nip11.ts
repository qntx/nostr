/**
 * NIP-11: Relay Information Document
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/11.md
 */
import { NostrError } from "../core/error.ts";
import type { Mutable } from "../core/util.ts";
import { isRecord } from "../core/util.ts";
import { fetchManual, requireGlobalFetch } from "./http.ts";
import type { ManualFetch } from "./http.ts";

const ACCEPT = "application/nostr+json";

const STRING_FIELDS = [
  "name",
  "description",
  "banner",
  "icon",
  "pubkey",
  "self",
  "contact",
  "software",
  "version",
  "payments_url",
  "terms_of_service",
] as const;

const LIMITATION_NUMBERS = [
  "max_message_length",
  "max_subscriptions",
  "max_limit",
  "max_subid_length",
  "max_event_tags",
  "max_content_length",
  "min_pow_difficulty",
  "created_at_lower_limit",
  "created_at_upper_limit",
  "default_limit",
] as const;

const LIMITATION_BOOLEANS = ["auth_required", "payment_required", "restricted_writes"] as const;

export type Nip11Fetch = ManualFetch;

export type RelayInformation = {
  readonly name?: string | undefined;
  readonly description?: string | undefined;
  readonly banner?: string | undefined;
  readonly icon?: string | undefined;
  readonly pubkey?: string | undefined;
  readonly self?: string | undefined;
  readonly contact?: string | undefined;
  readonly supported_nips?: ReadonlyArray<number> | undefined;
  readonly software?: string | undefined;
  readonly version?: string | undefined;
  readonly limitation?:
    | {
        readonly max_message_length?: number | undefined;
        readonly max_subscriptions?: number | undefined;
        readonly max_limit?: number | undefined;
        readonly max_subid_length?: number | undefined;
        readonly max_event_tags?: number | undefined;
        readonly max_content_length?: number | undefined;
        readonly default_limit?: number | undefined;
        readonly auth_required?: boolean | undefined;
        readonly payment_required?: boolean | undefined;
        readonly restricted_writes?: boolean | undefined;
        readonly min_pow_difficulty?: number | undefined;
        readonly created_at_lower_limit?: number | undefined;
        readonly created_at_upper_limit?: number | undefined;
      }
    | undefined;
  readonly payments_url?: string | undefined;
  readonly terms_of_service?: string | undefined;
};

export class Nip11Error extends NostrError {
  override name = "Nip11Error";
}

/** Convert a relay websocket URL to the HTTP URL that serves the NIP-11 document. */
export function relayInfoHttpUrl(wsUrl: string): string {
  let url: URL;
  try {
    url = new URL(wsUrl);
  } catch (error) {
    throw new Nip11Error(`invalid relay URL: ${wsUrl}`, {
      cause: error,
    });
  }

  if (url.protocol === "wss:") {
    url.protocol = "https:";
  } else if (url.protocol === "ws:") {
    url.protocol = "http:";
  } else if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Nip11Error(`unsupported relay URL scheme: ${url.protocol}`);
  }

  return url.toString();
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function parseRelayInformation(json: unknown): RelayInformation {
  if (!isRecord(json)) {
    throw new Nip11Error("relay information document must be a JSON object");
  }
  const raw = json;
  const info: Mutable<RelayInformation> = {};

  for (const key of STRING_FIELDS) {
    const value = raw[key];
    if (typeof value === "string") {
      info[key] = value;
    }
  }

  if (Array.isArray(raw["supported_nips"])) {
    info.supported_nips = raw["supported_nips"].filter(isNonNegativeInteger);
  }

  const rawLim = raw["limitation"];
  if (isRecord(rawLim)) {
    const limitation: Mutable<NonNullable<RelayInformation["limitation"]>> = {};
    for (const key of LIMITATION_NUMBERS) {
      const value = rawLim[key];
      if (isNonNegativeInteger(value)) {
        limitation[key] = value;
      }
    }
    for (const key of LIMITATION_BOOLEANS) {
      const value = rawLim[key];
      if (typeof value === "boolean") {
        limitation[key] = value;
      }
    }
    if (Object.keys(limitation).length > 0) {
      info.limitation = limitation;
    }
  }

  return info;
}

export async function fetchRelayInformation(
  wsUrl: string,
  opts?: { fetch?: Nip11Fetch; signal?: AbortSignal },
): Promise<RelayInformation> {
  const httpUrl = relayInfoHttpUrl(wsUrl);
  const fetchImpl =
    opts?.fetch ??
    requireGlobalFetch(() => new Nip11Error("no fetch implementation available; pass opts.fetch"));

  const res = await fetchManual(
    fetchImpl,
    httpUrl,
    { headers: { Accept: ACCEPT }, signal: opts?.signal },
    (cause) =>
      new Nip11Error(`relay information request failed: ${httpUrl}`, {
        cause,
      }),
  );

  if (!res.ok) {
    throw new Nip11Error(`relay information request failed: HTTP ${res.status}`);
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch (error) {
    throw new Nip11Error("relay information document is not valid JSON", {
      cause: error,
    });
  }

  return parseRelayInformation(json);
}
