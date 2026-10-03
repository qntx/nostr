/** REQ subscription runtime: exclusive one-shot, live coalescing, dispatch, reconnect replay. */
import { abortReason, onAbort, throwIfAborted } from "../core/abort.ts";
import type { Event } from "../core/event.ts";
import { filterFingerprint } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import type { ClientMessage, SubscriptionId } from "../core/message.ts";
import { invokeSafely } from "../core/report.ts";
import type { EventVerifier } from "../core/verifier.ts";
import { Subscription, subscriptionToAsyncIterable } from "./subscription.ts";
import type { Closer, RelaySubscription, SubscribeOptions } from "./subscription.ts";

export type LiveGroup = {
  fp: string;
  sub: Subscription;
  attachments: Set<Subscription>;
};

/** How a one-shot {@link Relay.fetch} REQ ended. */
export type RelayFetchEnd =
  | { readonly type: "eose" }
  | { readonly type: "closed"; readonly reason: string }
  | { readonly type: "timeout" };

/** `Relay.fetch` result: collected events plus the REQ's end reason. */
export type RelayFetchResult = {
  readonly events: Event[];
  readonly end: RelayFetchEnd;
};

export type LiveCtx = {
  liveByFp: Map<string, LiveGroup>;
  liveBySubId: Map<SubscriptionId, LiveGroup>;
  subs: Map<SubscriptionId, Subscription>;
  connected: () => boolean;
  enableReconnect: () => boolean;
  send: (message: ClientMessage) => void;
  scheduleReconnect: () => void;
  acceptEvent: EventVerifier;
  armEoseTimeout: (sub: Subscription, ms: number) => void;
};

export function openExclusive(
  ctx: LiveCtx,
  filters: Filter[],
  opts: SubscribeOptions,
): Subscription {
  const sub = new Subscription(filters, opts, (id) => {
    ctx.subs.delete(id);
    try {
      if (ctx.connected()) {
        ctx.send(["CLOSE", id]);
      }
    } catch {
      // ignore
    }
  });

  ctx.subs.set(sub.id, sub);
  if (ctx.connected()) {
    ctx.send(["REQ", sub.id, ...filters]);
  } else if (ctx.enableReconnect()) {
    ctx.scheduleReconnect();
  }

  if (opts.eoseTimeoutMs !== undefined) {
    ctx.armEoseTimeout(sub, opts.eoseTimeoutMs);
  }
  return sub;
}

export function subscribeLive(
  ctx: LiveCtx,
  filters: Filter[],
  opts: SubscribeOptions,
): Subscription {
  const fp = filterFingerprint(filters);
  // Coalesce only into a wire that has not EOSE'd yet: a late subscriber on an
  // EOSE'd wire would see an empty synthesized EOSE and no replay, so it gets a
  // fresh REQ of its own instead. `liveByFp` always points at the joinable wire.
  let group = ctx.liveByFp.get(fp);
  if (group?.sub.eosed === true) {
    group = undefined;
  }
  let created = false;
  if (!group) {
    created = true;
    const slot: { group: LiveGroup | undefined } = { group: undefined };
    const wire = new Subscription(filters, { id: opts.id }, () => {
      const g = slot.group;
      if (g) {
        endLiveGroup(ctx, g, { sendClose: true, reason: "closed by client" });
      }
    });
    group = { fp, sub: wire, attachments: new Set() };
    slot.group = group;
    ctx.liveByFp.set(fp, group);
    ctx.liveBySubId.set(wire.id, group);
    ctx.subs.set(wire.id, wire);
  }

  const slot: { handle: Subscription | undefined } = { handle: undefined };
  // The handle detaches from its own group, never looked up by fingerprint:
  // `liveByFp` may already point at a newer wire for the same fingerprint.
  const attached = group;
  const handle = new Subscription(filters, { ...opts, id: group.sub.id }, () => {
    // constructor may close on an already-aborted signal before `handle` is assigned
    const current = slot.handle;
    if (!current) {
      return;
    }
    detachLive(ctx, attached, current);
  });
  slot.handle = handle;

  if (handle.closed) {
    if (created && group.attachments.size === 0) {
      forgetLiveGroup(ctx, group);
    }
    return handle;
  }

  group.attachments.add(handle);

  if (created) {
    if (ctx.connected()) {
      ctx.send(["REQ", group.sub.id, ...filters]);
    } else if (ctx.enableReconnect()) {
      ctx.scheduleReconnect();
    }
  }

  if (opts.eoseTimeoutMs !== undefined) {
    ctx.armEoseTimeout(handle, opts.eoseTimeoutMs);
  }

  return handle;
}

export function forgetLiveGroup(ctx: LiveCtx, group: LiveGroup): void {
  // A newer wire may already own the fingerprint slot; only unlink this group.
  if (ctx.liveByFp.get(group.fp) === group) {
    ctx.liveByFp.delete(group.fp);
  }
  ctx.liveBySubId.delete(group.sub.id);
  ctx.subs.delete(group.sub.id);
  group.sub.closed = true;
  group.sub.dispose();
}

export function detachLive(ctx: LiveCtx, group: LiveGroup, handle: Subscription): void {
  if (!group.attachments.delete(handle)) {
    return;
  }
  if (group.attachments.size > 0) {
    return;
  }
  endLiveGroup(ctx, group, { sendClose: true, reason: "closed by client" });
}

export function endLiveGroup(
  ctx: LiveCtx,
  group: LiveGroup,
  opts: { sendClose: boolean; reason: string },
): void {
  const { id } = group.sub;
  const remaining = [...group.attachments];
  group.attachments.clear();
  forgetLiveGroup(ctx, group);
  if (opts.sendClose) {
    try {
      if (ctx.connected()) {
        ctx.send(["CLOSE", id]);
      }
    } catch {
      // ignore
    }
  }
  for (const att of remaining) {
    invokeSafely(() => {
      att.close(opts.reason);
    });
  }
}

export function deliverLiveEvent(ctx: LiveCtx, group: LiveGroup, event: Event): void {
  const { sub } = group;
  const attachments = [...group.attachments];
  for (const att of attachments) {
    invokeSafely(() => {
      att.handlers.receivedEvent?.(event.id);
    });
  }
  if (sub.idsAtWatermark.has(event.id)) {
    return;
  }

  const recipients: Subscription[] = [];
  for (const att of attachments) {
    if (att.closed) {
      continue;
    }
    let skip = false;
    invokeSafely(() => {
      skip = Boolean(att.handlers.alreadyHaveEvent?.(event.id));
    });
    if (!skip) {
      recipients.push(att);
    }
  }
  if (recipients.length === 0) {
    return;
  }
  if (!ctx.acceptEvent(event)) {
    return;
  }

  sub.noteVerified(event);
  for (const att of recipients) {
    att.noteVerified(event);
  }
  for (const att of recipients) {
    invokeSafely(() => {
      att.handlers.onevent?.(event);
    });
  }
}

export function deliverLiveEose(group: LiveGroup): void {
  const attachments = [...group.attachments];
  for (const att of attachments) {
    if (att.closed || att.eosed) {
      continue;
    }
    att.eosed = true;
    invokeSafely(() => {
      att.handlers.oneose?.();
    });
  }
}

export function closeAllSubscriptions(ctx: LiveCtx, reason: string): void {
  const groups = [...ctx.liveBySubId.values()];
  for (const group of groups) {
    invokeSafely(() => {
      endLiveGroup(ctx, group, { sendClose: false, reason });
    });
  }
  for (const sub of ctx.subs.values()) {
    if (!sub.closed) {
      sub.closed = true;
      sub.dispose();
      invokeSafely(() => {
        sub.handlers.onclose?.(reason);
      });
    }
  }
  ctx.subs.clear();
  ctx.liveByFp.clear();
  ctx.liveBySubId.clear();
}

export function dropSubscription(ctx: LiveCtx, sub: Subscription, reason: string): void {
  const group = ctx.liveBySubId.get(sub.id);
  if (group) {
    endLiveGroup(ctx, group, { sendClose: false, reason });
    return;
  }
  ctx.subs.delete(sub.id);
  sub.closed = true;
  sub.dispose();
  invokeSafely(() => {
    sub.handlers.onclose?.(reason);
  });
}

export function onSubEvent(ctx: LiveCtx, subId: string, event: Event): void {
  const sub = ctx.subs.get(subId);
  if (!sub || sub.closed) {
    return;
  }
  const group = ctx.liveBySubId.get(subId);
  if (group) {
    deliverLiveEvent(ctx, group, event);
    return;
  }
  invokeSafely(() => {
    sub.handlers.receivedEvent?.(event.id);
  });
  if (sub.idsAtWatermark.has(event.id)) {
    return;
  }
  let have = false;
  invokeSafely(() => {
    have = Boolean(sub.handlers.alreadyHaveEvent?.(event.id));
  });
  if (have) {
    return;
  }
  if (!ctx.acceptEvent(event)) {
    return;
  }
  sub.noteVerified(event);
  invokeSafely(() => {
    sub.handlers.onevent?.(event);
  });
}

export function onSubEose(ctx: LiveCtx, subId: string): void {
  const sub = ctx.subs.get(subId);
  if (!sub || sub.closed) {
    return;
  }
  if (sub.eosed) {
    return;
  }
  sub.eosed = true;
  const group = ctx.liveBySubId.get(subId);
  if (group) {
    deliverLiveEose(group);
  } else {
    invokeSafely(() => {
      sub.handlers.oneose?.();
    });
    if (sub.closeOnEose) {
      sub.close("eose");
    }
  }
}

export function resubscribeAll(ctx: LiveCtx): boolean {
  for (const sub of ctx.subs.values()) {
    if (sub.closed) {
      continue;
    }
    sub.eosed = false;
    sub.authRetried = false;
    const group = ctx.liveBySubId.get(sub.id);
    if (group) {
      for (const att of group.attachments) {
        att.eosed = false;
      }
    }
    try {
      ctx.send(["REQ", sub.id, ...sub.replayFilters()]);
    } catch {
      return false;
    }
  }
  return true;
}

export function streamFilters(
  subscribe: (filters: ReadonlyArray<Filter>, opts: SubscribeOptions) => RelaySubscription,
  filters: ReadonlyArray<Filter>,
  opts?: { signal?: AbortSignal | undefined; id?: string | undefined },
): AsyncIterable<Event> & Closer {
  return subscriptionToAsyncIterable(
    (handlers) => subscribe(filters, { ...handlers, id: opts?.id, signal: opts?.signal }),
    { signal: opts?.signal },
  );
}

export async function fetchFilters(
  subscribe: (filters: ReadonlyArray<Filter>, opts: SubscribeOptions) => RelaySubscription,
  filters: ReadonlyArray<Filter>,
  opts: {
    timeoutMs: number;
    signal?: AbortSignal | undefined;
    id?: string | undefined;
  },
): Promise<RelayFetchResult> {
  throwIfAborted(opts.signal);
  const events: Event[] = [];
  const seen = new Set<string>();
  let end: RelayFetchEnd = { type: "timeout" };

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const done = (err?: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      disposeAbort();
      clearTimeout(timer);
      let reason = "aborted";
      if (err instanceof Error) {
        reason = err.message;
      } else if (err === undefined) {
        reason = "fetch complete";
      }
      sub.close(reason);
      if (err === undefined) {
        resolve();
      } else {
        // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards abort/signal reasons verbatim
        reject(err);
      }
    };

    const disposeAbort = onAbort(opts.signal, () => {
      if (opts.signal !== undefined) {
        done(abortReason(opts.signal));
      }
    });

    const timer = setTimeout(() => {
      end = { type: "timeout" };
      done();
    }, opts.timeoutMs);

    const sub = subscribe(filters, {
      id: opts.id,
      signal: opts.signal,
      closeOnEose: true,
      onevent(event) {
        if (seen.has(event.id)) {
          return;
        }
        seen.add(event.id);
        events.push(event);
      },
      oneose() {
        end = { type: "eose" };
        done();
      },
      onclose(reason) {
        // The Subscription's own abort listener may close it before ours runs;
        // an aborted signal still rejects the fetch with the signal's reason.
        if (settled) {
          return;
        }
        if (opts.signal?.aborted === true) {
          done(abortReason(opts.signal));
          return;
        }
        // A remote CLOSED (or transport drop) still returns collected events.
        end = { type: "closed", reason };
        done();
      },
    });
  });

  return { events, end };
}

export function armEoseTimeout(sub: Subscription, eoseTimeoutMs: number): void {
  const timer = setTimeout(() => {
    if (sub.eosed || sub.closed) {
      return;
    }
    sub.eosed = true;
    invokeSafely(() => {
      sub.handlers.oneose?.();
    });
  }, eoseTimeoutMs);
  const prevClose = sub.handlers.onclose;
  // oxlint-disable-next-line unicorn/prefer-add-event-listener -- SubscriptionHandlers is a callback record, not an EventTarget
  sub.handlers.onclose = (reason) => {
    clearTimeout(timer);
    prevClose?.(reason);
  };
  const prevEose = sub.handlers.oneose;
  sub.handlers.oneose = () => {
    clearTimeout(timer);
    prevEose?.();
  };
}
