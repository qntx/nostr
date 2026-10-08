import type { Event } from "../core/event.ts";
import { Kind } from "../core/kind.ts";
import { isHex32 } from "../core/util.ts";
import { parseDmRelayList } from "../nips/nip17.ts";
import { parseMuteList } from "../nips/nip51.ts";
import type { MuteItem } from "../nips/nip51.ts";
import type { RelayListItem } from "../nips/nip65.ts";
import { parseRelayList } from "../nips/nip65.ts";
import type { LoadStyle, ReplaceableLoader } from "./replaceable.ts";

/** Result of a list loader: the source event, its decoded items, and freshness. */
export type ListResult<T> = {
  readonly event: Event | undefined;
  readonly items: ReadonlyArray<T>;
  readonly fresh: boolean;
};

function fromTags<T>(
  event: Event | undefined,
  map: (tag: ReadonlyArray<string>) => T | undefined,
): T[] {
  if (event === undefined) {
    return [];
  }
  const out: T[] = [];
  for (const tag of event.tags) {
    const item = map(tag);
    if (item !== undefined) {
      out.push(item);
    }
  }
  return out;
}

type ListLoaderOpts = { hints?: string[] | undefined; style?: LoadStyle | undefined };

export type ListLoaders = {
  follows: (pubkey: string, opts?: ListLoaderOpts) => Promise<ListResult<string>>;
  muteList: (pubkey: string, opts?: ListLoaderOpts) => Promise<ListResult<MuteItem>>;
  relayList: (pubkey: string, opts?: ListLoaderOpts) => Promise<ListResult<RelayListItem>>;
  dmRelayList: (pubkey: string, opts?: ListLoaderOpts) => Promise<ListResult<string>>;
};

export function createListLoaders(replaceable: (kind: number) => ReplaceableLoader): ListLoaders {
  const followsLoader = replaceable(Kind.Contacts);
  const muteLoader = replaceable(Kind.MuteList);
  const relayListLoader = replaceable(Kind.RelayList);
  const dmRelayListLoader = replaceable(Kind.DirectMessageRelaysList);

  return {
    async follows(pubkey: string, opts?: ListLoaderOpts): Promise<ListResult<string>> {
      const { event, fresh } = await followsLoader(pubkey, opts);
      return {
        event,
        fresh,
        items: fromTags(event, (tag) =>
          tag[0] === "p" && tag[1] !== undefined && isHex32(tag[1].toLowerCase())
            ? tag[1].toLowerCase()
            : undefined,
        ),
      };
    },

    async muteList(pubkey: string, opts?: ListLoaderOpts): Promise<ListResult<MuteItem>> {
      const { event, fresh } = await muteLoader(pubkey, opts);
      let items: MuteItem[] = [];
      if (event) {
        try {
          items = parseMuteList(event);
        } catch {
          items = [];
        }
      }
      return { event, fresh, items };
    },

    async relayList(pubkey: string, opts?: ListLoaderOpts): Promise<ListResult<RelayListItem>> {
      const { event, fresh } = await relayListLoader(pubkey, opts);
      let items: RelayListItem[] = [];
      if (event) {
        try {
          items = parseRelayList(event);
        } catch {
          items = [];
        }
      }
      return { event, fresh, items };
    },

    async dmRelayList(pubkey: string, opts?: ListLoaderOpts): Promise<ListResult<string>> {
      const { event, fresh } = await dmRelayListLoader(pubkey, opts);
      let items: string[] = [];
      if (event) {
        try {
          items = parseDmRelayList(event);
        } catch {
          items = [];
        }
      }
      return { event, fresh, items };
    },
  };
}
