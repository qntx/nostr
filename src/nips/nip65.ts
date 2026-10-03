import { EventBuilder } from "../core/builder.ts";
import { EventValidationError } from "../core/error.ts";
import type { Event } from "../core/event.ts";
import { Kind } from "../core/kind.ts";
import type { Tag } from "../core/tag.ts";
import { normalizeURL } from "../core/util.ts";

/** NIP-65 `r` tag marker: read-only, write-only, or unmarked (both). */
export type RelayMarker = "read" | "write" | "both";

/** One NIP-65 relay-list entry: normalized URL plus its marker. */
export type RelayListItem = {
  readonly url: string;
  readonly marker: RelayMarker;
};

/** Parse a kind:10002 NIP-65 event into relay list entries. */
export function parseRelayList(event: Event): RelayListItem[] {
  if (event.kind !== Kind.RelayList) {
    throw new EventValidationError(`expected kind ${Kind.RelayList}, got ${event.kind}`);
  }
  const out: RelayListItem[] = [];
  const seen = new Set<string>();

  for (const tag of event.tags) {
    const value = tag.at(1);
    if (tag[0] !== "r" || value === undefined || value === "") {
      continue;
    }
    let url: string;
    try {
      url = normalizeURL(value);
    } catch {
      continue;
    }
    if (seen.has(url)) {
      continue;
    }
    seen.add(url);

    const marker = tag.at(2);
    if (marker === "read" || marker === "write") {
      out.push({ url, marker });
    } else {
      out.push({ url, marker: "both" });
    }
  }
  return out;
}

/** Encode relay list items as NIP-65 `r` tags (`both` is unmarked). */
export function relayListToTags(items: ReadonlyArray<RelayListItem>): Tag[] {
  return items.map((item) =>
    item.marker === "both" ? ["r", item.url] : ["r", item.url, item.marker],
  );
}

/** Build an unsigned kind:10002 EventBuilder from relay list items. */
export function relayListEventBuilder(items: ReadonlyArray<RelayListItem>): EventBuilder {
  return new EventBuilder(Kind.RelayList, "").tags(relayListToTags(items));
}

/** URLs of the read-enabled items. */
export function readRelays(items: ReadonlyArray<RelayListItem>): string[] {
  return items.filter((i) => i.marker !== "write").map((i) => i.url);
}

/** URLs of the write-enabled items. */
export function writeRelays(items: ReadonlyArray<RelayListItem>): string[] {
  return items.filter((i) => i.marker !== "read").map((i) => i.url);
}
