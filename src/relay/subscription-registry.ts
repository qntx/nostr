/** REQ subscription runtime: exclusive one-shot, live coalescing, dispatch, reconnect replay. */
import type { Event } from "../core/event.ts";
import { filterFingerprint } from "../core/filter.ts";
import type { Filter } from "../core/filter.ts";
import type { ClientMessage, SubscriptionId } from "../core/message.ts";
import { invokeSafely } from "../core/report.ts";
import type { EventVerifier } from "../core/verifier.ts";
import { Subscription } from "./subscription.ts";
import type { SubscribeOptions } from "./subscription.ts";

export type LiveGroup = {
  fp: string;
  sub: Subscription;
  attachments: Set<Subscription>;
};

type RegistryDeps = {
  isOpen: () => boolean;
  enableReconnect: boolean;
  send: (message: ClientMessage) => void;
  scheduleReconnect: () => void;
  acceptEvent: EventVerifier;
};

/**
 * Owns every open REQ of a relay: exclusive subscriptions keyed by id, and live coalescing groups
 * (one wire REQ plus per-subscriber handles) keyed by fingerprint and wire id.
 */
export class SubscriptionRegistry {
  readonly #subs = new Map<SubscriptionId, Subscription>();
  readonly #liveByFp = new Map<string, LiveGroup>();
  readonly #liveBySubId = new Map<SubscriptionId, LiveGroup>();
  readonly #isOpen: () => boolean;
  readonly #enableReconnect: boolean;
  readonly #send: (message: ClientMessage) => void;
  readonly #scheduleReconnect: () => void;
  readonly #acceptEvent: EventVerifier;

  constructor(deps: RegistryDeps) {
    this.#isOpen = deps.isOpen;
    this.#enableReconnect = deps.enableReconnect;
    this.#send = deps.send;
    this.#scheduleReconnect = deps.scheduleReconnect;
    this.#acceptEvent = deps.acceptEvent;
  }

  /** User subscriptions only; dummy ping REQs are not counted. */
  get size(): number {
    return this.#subs.size;
  }

  get(subId: SubscriptionId): Subscription | undefined {
    return this.#subs.get(subId);
  }

  /** Exclusive one-shot REQ when `closeOnEose`, live coalescing otherwise. */
  open(filters: ReadonlyArray<Filter>, opts: SubscribeOptions): Subscription {
    if (opts.closeOnEose === true) {
      return this.#openExclusive(filters, opts);
    }
    return this.#openLive(filters, opts);
  }

  handleEvent(subId: SubscriptionId, event: Event): void {
    const sub = this.#subs.get(subId);
    if (!sub || sub.closed) {
      return;
    }
    const group = this.#liveBySubId.get(subId);
    if (group) {
      this.#deliverLiveEvent(group, event);
      return;
    }
    sub.notifyReceived(event.id);
    if (sub.isAtWatermark(event.id)) {
      return;
    }
    if (sub.alreadyHas(event.id)) {
      return;
    }
    if (!this.#acceptEvent(event)) {
      return;
    }
    sub.deliver(event);
  }

  handleEose(subId: SubscriptionId): void {
    const sub = this.#subs.get(subId);
    if (!sub || sub.closed || sub.eosed) {
      return;
    }
    const group = this.#liveBySubId.get(subId);
    if (group) {
      sub.markEose();
      this.#deliverLiveEose(group);
      return;
    }
    sub.markEose();
  }

  /** Remote/transport termination of a REQ (CLOSED, auth-retry failure). */
  drop(sub: Subscription, reason: string): void {
    const group = this.#liveBySubId.get(sub.id);
    if (group) {
      this.#endLiveGroup(group, { sendClose: false, reason });
      return;
    }
    this.#subs.delete(sub.id);
    sub.end(reason);
  }

  /**
   * Re-REQ after the relay demanded AUTH: drop the subscription when auth fails or the
   * socket/subscription died during the AUTH window, replay the REQ on success.
   */
  async authRetry(
    sub: Subscription,
    reason: string,
    ensureAuthed: () => Promise<boolean>,
  ): Promise<void> {
    try {
      if (!(await ensureAuthed()) || sub.closed || !this.#isOpen()) {
        this.drop(sub, reason);
        return;
      }
      this.replay(sub);
    } catch {
      this.drop(sub, reason);
    }
  }

  /** Re-REQ after AUTH: rearm the wire and its handles, then send the replayed filters. */
  replay(sub: Subscription): void {
    sub.rearm();
    const group = this.#liveBySubId.get(sub.id);
    if (group) {
      for (const att of group.attachments) {
        att.rearm();
      }
    }
    this.#send(["REQ", sub.id, ...sub.replayFilters()]);
  }

  /** Reconnect path: rearm every open REQ and re-send; false on send failure. */
  replayAll(): boolean {
    for (const sub of this.#subs.values()) {
      if (sub.closed) {
        continue;
      }
      sub.rearm();
      sub.resetAuthRetry();
      const group = this.#liveBySubId.get(sub.id);
      if (group) {
        for (const att of group.attachments) {
          att.rearm();
          att.resetAuthRetry();
        }
      }
      try {
        this.#send(["REQ", sub.id, ...sub.replayFilters()]);
      } catch {
        return false;
      }
    }
    return true;
  }

  closeAll(reason: string): void {
    const groups = [...this.#liveBySubId.values()];
    for (const group of groups) {
      invokeSafely(() => {
        this.#endLiveGroup(group, { sendClose: false, reason });
      });
    }
    for (const sub of this.#subs.values()) {
      sub.end(reason);
    }
    this.#subs.clear();
    this.#liveByFp.clear();
    this.#liveBySubId.clear();
  }

  #openExclusive(filters: ReadonlyArray<Filter>, opts: SubscribeOptions): Subscription {
    const sub = new Subscription(filters, opts, (closed) => {
      this.#subs.delete(closed.id);
      try {
        if (this.#isOpen()) {
          this.#send(["CLOSE", closed.id]);
        }
      } catch {
        // ignore
      }
    });

    this.#subs.set(sub.id, sub);
    if (this.#isOpen()) {
      this.#send(["REQ", sub.id, ...filters]);
    } else if (this.#enableReconnect) {
      this.#scheduleReconnect();
    }
    return sub;
  }

  #openLive(filters: ReadonlyArray<Filter>, opts: SubscribeOptions): Subscription {
    const fp = filterFingerprint(filters);
    // Coalesce only into a wire that has not EOSE'd yet: a late subscriber on an
    // EOSE'd wire would see an empty synthesized EOSE and no replay, so it gets a
    // fresh REQ of its own instead. `liveByFp` always points at the joinable wire.
    let group = this.#liveByFp.get(fp);
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
          this.#endLiveGroup(g, { sendClose: true, reason: "closed by client" });
        }
      });
      group = { fp, sub: wire, attachments: new Set() };
      slot.group = group;
      this.#liveByFp.set(fp, group);
      this.#liveBySubId.set(wire.id, group);
      this.#subs.set(wire.id, wire);
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
      this.#detachLive(attached, current);
    });
    slot.handle = handle;

    if (handle.closed) {
      if (created && group.attachments.size === 0) {
        this.#forgetLiveGroup(group, "closed by client");
      }
      return handle;
    }

    group.attachments.add(handle);

    if (created) {
      if (this.#isOpen()) {
        this.#send(["REQ", group.sub.id, ...filters]);
      } else if (this.#enableReconnect) {
        this.#scheduleReconnect();
      }
    }

    return handle;
  }

  #forgetLiveGroup(group: LiveGroup, reason: string): void {
    // A newer wire may already own the fingerprint slot; only unlink this group.
    if (this.#liveByFp.get(group.fp) === group) {
      this.#liveByFp.delete(group.fp);
    }
    this.#liveBySubId.delete(group.sub.id);
    this.#subs.delete(group.sub.id);
    // The wire has no handlers, so `end` fires nothing.
    group.sub.end(reason);
  }

  #detachLive(group: LiveGroup, handle: Subscription): void {
    if (!group.attachments.delete(handle)) {
      return;
    }
    if (group.attachments.size > 0) {
      return;
    }
    this.#endLiveGroup(group, { sendClose: true, reason: "closed by client" });
  }

  #endLiveGroup(group: LiveGroup, opts: { sendClose: boolean; reason: string }): void {
    const { id } = group.sub;
    const remaining = [...group.attachments];
    group.attachments.clear();
    this.#forgetLiveGroup(group, opts.reason);
    if (opts.sendClose) {
      try {
        if (this.#isOpen()) {
          this.#send(["CLOSE", id]);
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

  #deliverLiveEvent(group: LiveGroup, event: Event): void {
    const { sub } = group;
    const attachments = [...group.attachments];
    for (const att of attachments) {
      att.notifyReceived(event.id);
    }
    if (sub.isAtWatermark(event.id)) {
      return;
    }

    const recipients: Subscription[] = [];
    for (const att of attachments) {
      if (att.closed) {
        continue;
      }
      if (!att.alreadyHas(event.id)) {
        recipients.push(att);
      }
    }
    if (recipients.length === 0) {
      return;
    }
    if (!this.#acceptEvent(event)) {
      return;
    }

    sub.noteVerified(event);
    for (const att of recipients) {
      att.deliver(event);
    }
  }

  #deliverLiveEose(group: LiveGroup): void {
    // snapshot: a oneose handler may close its handle and detach mid-pass
    const attachments = [...group.attachments];
    for (const att of attachments) {
      att.markEose();
    }
  }
}
