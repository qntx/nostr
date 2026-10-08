import type { Event } from "../core/event.ts";
import { isMarkedVerified, isReplaceableWinner, validateSignedEvent } from "../core/event.ts";
import { isEphemeralKind, Kind } from "../core/kind.ts";
import { eventAddress } from "../core/tag.ts";
import { coordinateRemovals, planDeletion } from "./deletion.ts";
import type { DeletionPlan, DeletionState } from "./deletion.ts";
import type { PutResult } from "./types.ts";

export function outboxBoundKey(pubkey: string, kind: number): string {
  return `${pubkey.toLowerCase()}:${kind}`;
}

export type PutDecision =
  | {
      readonly action: "skip";
      readonly result: "duplicate" | "ephemeral" | "rejected" | "invalid";
      readonly event: Event;
    }
  | { readonly action: "tombstone"; readonly result: "duplicate"; readonly event: Event }
  | {
      readonly action: "delete";
      readonly result: "deleted";
      readonly event: Event;
      readonly plan: DeletionPlan;
      readonly coordIds: ReadonlyArray<string>;
    }
  | {
      readonly action: "insert";
      readonly result: "accepted" | "replaced";
      readonly event: Event;
      readonly address?: string | undefined;
      readonly replaceId?: string | undefined;
    };

export type PutLookup = {
  deletion: DeletionState;
  getById: (
    id: string,
  ) => Pick<Event, "id" | "pubkey" | "kind" | "created_at" | "tags"> | undefined;
  /**
   * Current replaceable winner for an address. `evicted: true` marks an eviction watermark: the
   * winning event body was dropped, but its id/created_at still reject older versions, and a re-put
   * of the watermarked id re-inserts it.
   */
  getReplaceable: (
    address: string,
  ) => (Pick<Event, "id" | "created_at"> & { evicted?: boolean }) | undefined;
};

export function decidePut(raw: Event, lookup: PutLookup): PutDecision {
  // Canonical-input precondition: non-canonical events are never indexed. An
  // already-verified event has necessarily passed validateSignedEvent.
  if (!isMarkedVerified(raw) && !validateSignedEvent(raw)) {
    return { action: "skip", result: "invalid", event: raw };
  }
  const event = raw;
  if (lookup.deletion.ids.has(event.id) || lookup.getById(event.id)) {
    return { action: "skip", result: "duplicate", event };
  }
  if (event.kind === Kind.EventDeletion) {
    const plan = planDeletion(event, lookup.getById);
    const coordIds = coordinateRemovals(plan.coordinates, lookup.getReplaceable);
    return { action: "delete", result: "deleted", event, plan, coordIds };
  }
  if (lookup.deletion.covers(event)) {
    return { action: "tombstone", result: "duplicate", event };
  }
  if (isEphemeralKind(event.kind)) {
    return { action: "skip", result: "ephemeral", event };
  }
  const address = eventAddress(event);
  if (address !== undefined) {
    const prev = lookup.getReplaceable(address);
    // A stored incumbent rejects stale versions; an eviction watermark does
    // the same, except a re-put of the watermarked id re-inserts it.
    if (prev && prev.id !== event.id && !isReplaceableWinner(event, prev)) {
      return { action: "skip", result: "rejected", event };
    }
    if (prev !== undefined && prev.evicted !== true) {
      return { action: "insert", result: "replaced", event, address, replaceId: prev.id };
    }
    return { action: "insert", result: "accepted", event, address };
  }
  return { action: "insert", result: "accepted", event };
}

export function applyPutMemory(
  s: {
    deletion: DeletionState;
    indexInsert: (event: Event) => void;
    indexRemove: (id: string) => boolean;
  },
  d: PutDecision,
): PutResult {
  if (d.action === "skip") {
    return d.result;
  }
  if (d.action === "tombstone") {
    s.deletion.ids.add(d.event.id);
    s.deletion.pending.delete(d.event.id);
    return "duplicate";
  }
  if (d.action === "delete") {
    s.deletion.pending.delete(d.event.id);
    s.deletion.absorb(d.plan);
    for (const id of d.plan.removeIds) {
      s.indexRemove(id);
    }
    for (const id of d.coordIds) {
      s.deletion.ids.add(id);
      s.indexRemove(id);
    }
    s.indexInsert(d.event);
    return "deleted";
  }
  if (d.replaceId !== undefined) {
    s.indexRemove(d.replaceId);
  }
  s.indexInsert(d.event);
  return d.result;
}
