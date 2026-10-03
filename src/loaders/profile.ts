import type { ProfileMetadata } from "../core/builder.ts";
import type { Event } from "../core/event.ts";
import { Kind } from "../core/kind.ts";
import { isRecord } from "../core/util.ts";
import { npubEncode } from "../nips/nip19.ts";
import type { LoadStyle, ReplaceableLoader } from "./replaceable.ts";

/** A profile-card view of a pubkey: identity fields plus the kind:0 event. */
export type NostrUser = {
  readonly pubkey: string;
  readonly npub: string;
  readonly shortName: string;
  readonly image?: string | undefined;
  readonly metadata: ProfileMetadata;
  readonly lastUpdated: number;
  readonly event: Event | undefined;
  readonly fresh: boolean;
};

/** A {@link NostrUser} with no metadata — used when no kind:0 event exists. */
export function bareNostrUser(pubkey: string): NostrUser {
  const pk = pubkey.toLowerCase();
  let npub: string;
  try {
    npub = npubEncode(pk);
  } catch {
    npub = pk;
  }
  return {
    pubkey: pk,
    npub,
    shortName: npub.startsWith("npub1") ? `${npub.slice(0, 8)}…${npub.slice(-4)}` : pk.slice(0, 8),
    metadata: {},
    lastUpdated: 0,
    event: undefined,
    fresh: false,
  };
}

function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

const PROFILE_METADATA_KEYS: ReadonlyArray<keyof ProfileMetadata> = [
  "name",
  "display_name",
  "about",
  "picture",
  "banner",
  "website",
  "nip05",
  "lud06",
  "lud16",
];

function parseMetadata(content: string): ProfileMetadata {
  try {
    const obj: unknown = JSON.parse(content);
    if (!isRecord(obj)) {
      return {};
    }
    const out: Record<string, string> = {};
    for (const key of PROFILE_METADATA_KEYS) {
      const value = obj[key];
      if (typeof value === "string") {
        out[key] = value;
      }
    }
    return out;
  } catch {
    return {};
  }
}

export type ProfileLoader = {
  load: (
    pubkey: string,
    opts?: { hints?: string[] | undefined; style?: LoadStyle | undefined },
  ) => Promise<NostrUser>;
};

export function createProfileLoader(
  replaceable: (kind: number) => ReplaceableLoader,
): ProfileLoader {
  const loader = replaceable(Kind.Metadata);

  return {
    async load(
      pubkey: string,
      opts?: { hints?: string[] | undefined; style?: LoadStyle | undefined },
    ): Promise<NostrUser> {
      const base = bareNostrUser(pubkey);
      const { event, fresh } = await loader(pubkey, opts);
      if (!event) {
        return { ...base, fresh };
      }

      const metadata = parseMetadata(event.content);
      const display = nonEmpty(metadata.display_name) ?? nonEmpty(metadata.name);
      return {
        ...base,
        shortName: display ?? base.shortName,
        ...(metadata.picture === undefined ? {} : { image: metadata.picture }),
        metadata,
        lastUpdated: event.created_at,
        event,
        fresh,
      };
    },
  };
}
