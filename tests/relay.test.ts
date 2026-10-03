import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import {
  EventBuilder,
  Keys,
  KeysSigner,
  MessageError,
  Pool,
  Relay,
  RelayClosedError,
  RelayConnectionError,
  RelayStatus,
  RelayTimeoutError,
  SUBSCRIPTION_ID_MAX_CHARS,
  WasmPoisonedError,
  isInsecureRelayUrl,
  useWebSocketImplementation,
  verifyEvent,
} from "../src/index.ts";
import type { Event, EventTemplate } from "../src/index.ts";
import { NegentropyStorageVector, Nip77Error } from "../src/nips/nip77.ts";
import { subscriptionToAsyncIterable } from "../src/relay/index.ts";
import type { SubscriptionHandlers } from "../src/relay/index.ts";
import type { Subscription } from "../src/relay/subscription.ts";
import type { WebSocketConstructor } from "../src/relay/websocket.ts";
import { createFakeRelayNetwork } from "../src/testing/index.ts";
import type { FakeRelayNetwork } from "../src/testing/index.ts";
import { MockWebSocket, MockWebSocketCtor } from "./helpers/mock-ws.ts";
import { stubReportError } from "./helpers/report-error.ts";

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function captureError(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => {
      throw new Error("expected reject");
    },
    (error: unknown) => error,
  );
}

function syncThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected throw");
}

async function waitUntil(pred: () => boolean, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling must alternate check and sleep sequentially
    await sleep(5);
  }
  throw new Error("timeout waiting for condition");
}

function sentMessages(ws: MockWebSocket): unknown[][] {
  return ws.sent.map((s) => JSON.parse(s) as unknown[]);
}

function authSignerFor(keys: Keys): (template: EventTemplate) => Promise<Event> {
  return async (template) => {
    await Promise.resolve();
    return EventBuilder.textNote("")
      .kind(template.kind)
      .tags(template.tags)
      .content(template.content)
      .createdAt(template.created_at)
      .signWithKeys(keys);
  };
}

function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`expected ${what}`);
  }
  return value;
}

function errText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function all(...preds: ReadonlyArray<() => boolean>): () => boolean {
  return () => preds.every((pred) => pred());
}

function hasSent(ws: MockWebSocket, type: string): boolean {
  return sentMessages(ws).some((m) => m[0] === type);
}

function instanceCountIs(n: number): () => boolean {
  return () => MockWebSocket.instances.length === n;
}

function everyInstanceSent(type: string): () => boolean {
  return () => MockWebSocket.instances.every((ws) => hasSent(ws, type));
}

function openInstance(exclude: MockWebSocket, urlPart: string): MockWebSocket | undefined {
  return MockWebSocket.instances.find(
    (ws) => ws !== exclude && ws.url.includes(urlPart) && ws.readyState === MockWebSocket.OPEN,
  );
}

function otherOpenInstanceSent(exclude: MockWebSocket, urlPart: string, type: string): boolean {
  const ws = openInstance(exclude, urlPart);
  return ws !== undefined && hasSent(ws, type);
}

function urlSent(urlPart: string, type: string): (ws: MockWebSocket) => boolean {
  return (ws) => ws.url.includes(urlPart) && hasSent(ws, type);
}

function sentCloseFor(ws: MockWebSocket, subId: unknown): boolean {
  return sentMessages(ws).some((m) => m[0] === "CLOSE" && m[1] === subId);
}

function isNegFrame(m: unknown[]): boolean {
  return m[0] === "NEG-OPEN" || m[0] === "NEG-MSG" || m[0] === "NEG-CLOSE";
}

function heldTimeout(
  targetDelay: number,
  held: Array<() => void>,
  realSetTimeout: typeof globalThis.setTimeout,
): typeof globalThis.setTimeout {
  return ((handler: unknown, delay?: number, ...args: unknown[]) => {
    if (delay === targetDelay && typeof handler === "function") {
      held.push(() => {
        (handler as (...a: unknown[]) => void)(...args);
      });
      return 0 as unknown as ReturnType<typeof setTimeout>;
    }
    return realSetTimeout(handler as Parameters<typeof setTimeout>[0], delay, ...args);
  }) as typeof setTimeout;
}

type AuthWireEvent = { id: string; tags: string[][] };

function sentAuthEvents(ws: MockWebSocket): AuthWireEvent[] {
  return sentMessages(ws)
    .filter((m) => m[0] === "AUTH")
    .map((m) => m[1] as AuthWireEvent);
}

function challengeTag(event: AuthWireEvent): string | undefined {
  return event.tags.find((t) => t[0] === "challenge")?.[1];
}

function dummyPingReqs(
  ws: MockWebSocket,
): Array<[string, string, { ids: string[]; limit: number }]> {
  return sentMessages(ws).filter(
    (m) => m[0] === "REQ" && String(m[1]).startsWith("__ping__"),
  ) as Array<[string, string, { ids: string[]; limit: number }]>;
}

class NativePingSocket extends MockWebSocket {
  pingCalls = 0;
  pongAddEventListenerCalls = 0;
  pongEnabled = true;
  readonly #once = new Map<string, Set<(...args: unknown[]) => void>>();

  override addEventListener(type: string, listener: (ev: unknown) => void): void {
    if (type === "pong") {
      this.pongAddEventListenerCalls += 1;
    }
    super.addEventListener(type, listener);
  }

  ping(): void {
    this.pingCalls += 1;
    if (!this.pongEnabled) {
      return;
    }
    queueMicrotask(() => {
      const set = this.#once.get("pong");
      if (!set) {
        return;
      }
      this.#once.delete("pong");
      for (const fn of set) {
        fn();
      }
    });
  }

  once(event: string, listener: (...args: unknown[]) => void): void {
    let set = this.#once.get(event);
    if (!set) {
      set = new Set();
      this.#once.set(event, set);
    }
    set.add(listener);
  }

  off(event: string, listener: (...args: unknown[]) => void): void {
    this.#once.get(event)?.delete(listener);
  }

  pongListenerCount(): number {
    return this.#once.get("pong")?.size ?? 0;
  }
}

class NodeWsPingSocket extends MockWebSocket {
  pingCalls = 0;
  pongEnabled = false;
  readonly #listeners = new Map<string, Set<(...args: unknown[]) => void>>();

  ping(): void {
    this.pingCalls += 1;
    if (!this.pongEnabled) {
      return;
    }
    queueMicrotask(() => {
      for (const fn of this.#listeners.get("pong") ?? []) {
        fn();
      }
    });
  }

  on(event: string, listener: (...args: unknown[]) => void): void {
    let set = this.#listeners.get(event);
    if (!set) {
      set = new Set();
      this.#listeners.set(event, set);
    }
    set.add(listener);
  }

  once(event: string, listener: (...args: unknown[]) => void): void {
    const wrap = (...args: unknown[]) => {
      this.off(event, wrap);
      listener(...args);
    };
    this.on(event, wrap);
  }

  off(event: string, listener: (...args: unknown[]) => void): void {
    this.#listeners.get(event)?.delete(listener);
  }

  pongListenerCount(): number {
    return this.#listeners.get("pong")?.size ?? 0;
  }
}

class NativeTimeoutSocket extends NativePingSocket {
  override pongEnabled = false;
}

const NativePingCtor = NativePingSocket as unknown as WebSocketConstructor;
const NativeTimeoutCtor = NativeTimeoutSocket as unknown as WebSocketConstructor;
const NodeWsPingCtor = NodeWsPingSocket as unknown as WebSocketConstructor;

class PingOnlySocket extends MockWebSocket {
  pingCalls = 0;
  ping(): void {
    this.pingCalls += 1;
  }
}

const PingOnlyCtor = PingOnlySocket as unknown as WebSocketConstructor;

/** RemoveEventListener is a no-op so stale open/close can still hit captured handlers. */
class StickyListenersSocket extends MockWebSocket {
  override removeEventListener(_type: string, _listener: (ev: unknown) => void): void {}
}

const StickyListenersCtor = StickyListenersSocket as unknown as WebSocketConstructor;

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

beforeEach(() => {
  MockWebSocket.reset();
  useWebSocketImplementation(MockWebSocketCtor);
});

afterEach(() => {
  MockWebSocket.reset();
});

describe("Relay", () => {
  test("connect, subscribe, receive events, eose", async () => {
    const relay = new Relay("wss://relay.example.com");
    const connectP = relay.connect();
    // allow microtask open
    await connectP;
    expect(relay.connected).toBe(true);

    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("hi").createdAt(1).signWithKeys(keys);

    const events: Array<typeof note> = [];
    let eosed = false;

    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e),
      oneose: () => {
        eosed = true;
      },
    });

    const ws = MockWebSocket.last();
    const req = ws.lastSent() as [string, string, ...unknown[]];
    expect(req[0]).toBe("REQ");
    expect(req[1]).toBe(sub.id);

    ws.receive(JSON.stringify(["EVENT", sub.id, note]));
    ws.receive(JSON.stringify(["EOSE", sub.id]));

    expect(events).toHaveLength(1);
    expect(events[0]!.id).toBe(note.id);
    expect(verifyEvent(events[0]!)).toBe(true);
    expect(eosed).toBe(true);

    sub.close();
    const closeMsg = ws.lastSent() as [string, string];
    expect(closeMsg[0]).toBe("CLOSE");
    relay.close();
  });

  test("publish waits for OK", async () => {
    const relay = await Relay.connect("wss://relay.example.com");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("pub").createdAt(2).signWithKeys(keys);

    const publishP = relay.publish(note);
    const ws = MockWebSocket.last();
    const sent = ws.lastSent() as [string, typeof note];
    expect(sent[0]).toBe("EVENT");
    expect(sent[1].id).toBe(note.id);

    ws.receive(JSON.stringify(["OK", note.id, true, ""]));
    const result = await publishP;
    expect(result.ok).toBe(true);
    relay.close();
  });

  test("timeout does not fire while AUTH is in flight", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-auth-timeout.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const note = EventBuilder.textNote("slow-auth").createdAt(2).signWithKeys(keys);
    const publishP = relay.publish(note, { timeoutMs: 40 });
    let settled = false;
    void publishP.then(
      () => {
        settled = true;
        return undefined;
      },
      () => {
        settled = true;
        return undefined;
      },
    );
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "slow-challenge"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    const authFrame = sentMessages(ws).find((m) => m[0] === "AUTH") as [string, { id: string }];
    expect(authFrame[0]).toBe("AUTH");
    await sleep(80);
    expect(settled).toBe(false);
    ws.receive(JSON.stringify(["OK", authFrame[1].id, true, ""]));
    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "EVENT").length >= 2);
    ws.receive(JSON.stringify(["OK", note.id, true, ""]));
    await expect(publishP).resolves.toStrictEqual({ ok: true, message: "" });
    relay.close();
  });

  test("publish times out after AUTH retry, not during AUTH", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-auth-post-timeout.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const note = EventBuilder.textNote("post-auth-timeout").createdAt(2).signWithKeys(keys);
    const publishP = relay.publish(note, { timeoutMs: 40 });
    let settled = false;
    void publishP.then(
      () => {
        settled = true;
        return undefined;
      },
      () => {
        settled = true;
        return undefined;
      },
    );
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "post-timeout-challenge"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    const authFrame = sentMessages(ws).find((m) => m[0] === "AUTH") as [string, { id: string }];
    expect(authFrame[0]).toBe("AUTH");
    await sleep(80);
    expect(settled).toBe(false);
    ws.receive(JSON.stringify(["OK", authFrame[1].id, true, ""]));
    const timeoutErr = await captureError(publishP);
    expect(timeoutErr).toBeInstanceOf(RelayTimeoutError);
    expect((timeoutErr as Error).message).toMatch(/publish timed out/);
    relay.close();
  });

  test("AUTH failure resolves publish as { ok: false }", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-auth-fail.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const note = EventBuilder.textNote("auth-fail").createdAt(2).signWithKeys(keys);
    const publishP = relay.publish(note, { timeoutMs: 40 });
    let settled = false;
    void publishP.then(
      () => {
        settled = true;
        return undefined;
      },
      () => {
        settled = true;
        return undefined;
      },
    );
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "fail-challenge"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    const authFrame = sentMessages(ws).find((m) => m[0] === "AUTH") as [string, { id: string }];
    expect(authFrame[0]).toBe("AUTH");
    await sleep(80);
    expect(settled).toBe(false);
    ws.receive(JSON.stringify(["OK", authFrame[1].id, false, "restricted: bad auth"]));
    await expect(publishP).resolves.toStrictEqual({ ok: false, message: "auth-required: login" });
    relay.close();
  });

  test("AUTH failure after a replacement publish of the same event does not settle the new waiter", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-auth-reuse.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const note = EventBuilder.textNote("auth-reuse").createdAt(2).signWithKeys(keys);
    const first = relay.publish(note, { timeoutMs: 2000 });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "reuse-challenge"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    const authFrame = sentMessages(ws).find((m) => m[0] === "AUTH") as [string, { id: string }];
    ws.receive(JSON.stringify(["OK", note.id, true, ""]));
    await expect(first).resolves.toStrictEqual({ ok: true, message: "" });

    const second = relay.publish(note, { timeoutMs: 2000 });
    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "EVENT").length >= 2);
    ws.receive(JSON.stringify(["OK", authFrame[1].id, false, "restricted: bad auth"]));
    await sleep(20);
    ws.receive(JSON.stringify(["OK", note.id, true, ""]));
    await expect(second).resolves.toStrictEqual({ ok: true, message: "" });
    relay.close();
  });

  test("authSigner throw resolves publish as { ok: false }", async () => {
    const boom = new Error("sign failed");
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-auth-throw.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: () => {
        throw boom;
      },
    });
    const note = EventBuilder.textNote("auth-throw").createdAt(2).signWithKeys(keys);
    const publishP = relay.publish(note, { timeoutMs: 200 });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "throw-challenge"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await expect(publishP).resolves.toStrictEqual({ ok: false, message: "auth-required: login" });
    relay.close();
  });

  test("authSigner throw drops the subscription", async () => {
    const relay = await Relay.connect("wss://sub-auth-throw.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: () => {
        throw new Error("sign failed");
      },
    });
    const reasons: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onclose: (reason) => {
        reasons.push(reason);
      },
    });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "throw-challenge"]));
    ws.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));
    await waitUntil(() => reasons.length === 1);
    expect(reasons).toStrictEqual(["auth-required: login"]);
    expect(sub.closed).toBe(true);
    relay.close();
  });

  test("AUTH rotation: OK-false stale challenge then ch2 REQ retry proceeds", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-rotate.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const events: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => {
        events.push(e.id);
      },
    });
    const ws = MockWebSocket.last();
    expect(sentMessages(ws).filter((m) => m[0] === "REQ")).toHaveLength(1);

    ws.receive(JSON.stringify(["AUTH", "ch1"]));
    ws.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));
    await waitUntil(() => sentAuthEvents(ws).length > 0);
    const stale = sentAuthEvents(ws)[0]!;
    expect(challengeTag(stale)).toBe("ch1");

    ws.receive(JSON.stringify(["AUTH", "ch2"]));
    ws.receive(JSON.stringify(["OK", stale.id, false, "restricted: stale challenge"]));
    await waitUntil(() => sentAuthEvents(ws).length >= 2);
    const fresh = sentAuthEvents(ws)[1]!;
    expect(challengeTag(fresh)).toBe("ch2");

    ws.receive(JSON.stringify(["OK", fresh.id, true, ""]));
    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "REQ").length >= 2);

    const note = EventBuilder.textNote("after rotation").createdAt(1).signWithKeys(keys);
    ws.receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(events).toStrictEqual([note.id]);
    expect(sub.closed).toBe(false);
    relay.close();
  });

  test("AUTH rotation: OK-false stale challenge then ch2 EVENT retry proceeds", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-rotate-pub.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const note = EventBuilder.textNote("rotate-pub").createdAt(2).signWithKeys(keys);
    const publishP = relay.publish(note);
    const ws = MockWebSocket.last();
    expect(sentMessages(ws).filter((m) => m[0] === "EVENT")).toHaveLength(1);

    ws.receive(JSON.stringify(["AUTH", "ch1"]));
    ws.receive(JSON.stringify(["OK", note.id, false, "auth-required: login"]));
    await waitUntil(() => sentAuthEvents(ws).length > 0);
    const stale = sentAuthEvents(ws)[0]!;
    expect(challengeTag(stale)).toBe("ch1");

    ws.receive(JSON.stringify(["AUTH", "ch2"]));
    ws.receive(JSON.stringify(["OK", stale.id, false, "restricted: stale challenge"]));
    await waitUntil(() => sentAuthEvents(ws).length >= 2);
    const fresh = sentAuthEvents(ws)[1]!;
    expect(challengeTag(fresh)).toBe("ch2");

    ws.receive(JSON.stringify(["OK", fresh.id, true, ""]));
    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "EVENT").length >= 2);
    ws.receive(JSON.stringify(["OK", note.id, true, ""]));
    await expect(publishP).resolves.toStrictEqual({ ok: true, message: "" });
    relay.close();
  });

  test("hostile AUTH rotation bound 3 terminates wrapper without livelock", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-hostile.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const reasons: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onclose: (reason) => {
        reasons.push(reason);
      },
    });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "ch1"]));
    ws.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));

    for (let i = 0; i < 3; i++) {
      // oxlint-disable-next-line no-await-in-loop -- challenge rounds must be answered in order
      await waitUntil(() => sentAuthEvents(ws).length >= i + 1);
      const event = sentAuthEvents(ws)[i]!;
      expect(challengeTag(event)).toBe(`ch${i + 1}`);
      ws.receive(JSON.stringify(["AUTH", `ch${i + 2}`]));
      ws.receive(JSON.stringify(["OK", event.id, false, "restricted: stale challenge"]));
    }

    await waitUntil(() => reasons.length === 1);
    expect(reasons).toStrictEqual(["auth-required: login"]);
    expect(sub.closed).toBe(true);
    expect(sentAuthEvents(ws)).toHaveLength(3);
    await sleep(30);
    expect(sentAuthEvents(ws)).toHaveLength(3);
    relay.close();
  });

  test("defense-in-depth: reconnect with reused AUTH challenge string sends a second AUTH event", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-reconnect-pin.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
      reconnectBackoffMs: [5],
      authSigner: authSignerFor(keys),
    });
    const sub = relay.subscribe([{ kinds: [1] }]);
    const first = MockWebSocket.last();
    first.receive(JSON.stringify(["AUTH", "ch1"]));
    first.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));
    await waitUntil(() => sentAuthEvents(first).length > 0);
    const authed = sentAuthEvents(first)[0]!;
    expect(challengeTag(authed)).toBe("ch1");
    first.receive(JSON.stringify(["OK", authed.id, true, ""]));
    await waitUntil(() => sentMessages(first).filter((m) => m[0] === "REQ").length >= 2);

    first.close();
    await waitUntil(
      all(
        () => relay.connected,
        () => MockWebSocket.instances.length >= 2,
      ),
    );
    const second = MockWebSocket.last();
    expect(second).not.toBe(first);
    await waitUntil(() => sentMessages(second).some((m) => m[0] === "REQ"));

    second.receive(JSON.stringify(["AUTH", "ch1"]));
    second.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));
    await waitUntil(() => sentAuthEvents(second).length > 0);
    expect(challengeTag(sentAuthEvents(second)[0]!)).toBe("ch1");
    relay.close();
  });

  test("auth() after challenge rotation does not await or clear the replacement in-flight AUTH", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-identity.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const sign = authSignerFor(keys);

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "ch1"]));
    const first = relay.auth(sign);
    let firstResult: { ok: boolean; message: string } | undefined;
    void first.then((r) => {
      firstResult = r;
      return undefined;
    });
    await waitUntil(() => sentAuthEvents(ws).length > 0);
    const stale = sentAuthEvents(ws)[0]!;
    expect(challengeTag(stale)).toBe("ch1");

    ws.receive(JSON.stringify(["AUTH", "ch2"]));
    const second = relay.auth(sign);
    let secondSettled = false;
    void second.then(
      () => {
        secondSettled = true;
        return undefined;
      },
      () => {
        secondSettled = true;
        return undefined;
      },
    );
    await waitUntil(() => sentAuthEvents(ws).length >= 2);
    const fresh = sentAuthEvents(ws)[1]!;
    expect(challengeTag(fresh)).toBe("ch2");

    ws.receive(JSON.stringify(["OK", stale.id, false, "restricted: stale challenge"]));
    await waitUntil(() => firstResult !== undefined);
    expect(firstResult).toStrictEqual({ ok: false, message: "restricted: stale challenge" });
    expect(secondSettled).toBe(false);

    const third = relay.auth(sign);
    await Promise.resolve();
    expect(sentAuthEvents(ws)).toHaveLength(2);

    ws.receive(JSON.stringify(["OK", fresh.id, true, ""]));
    await expect(second).resolves.toStrictEqual({ ok: true, message: "" });
    await expect(third).resolves.toStrictEqual({ ok: true, message: "" });
    expect(sentAuthEvents(ws)).toHaveLength(2);
    relay.close();
  });

  test("fetch collects until eose", async () => {
    const relay = await Relay.connect("wss://relay.example.com");
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);

    const fetchP = relay.fetch([{ kinds: [1] }], { timeoutMs: 2000 });
    // let REQ go out
    await Promise.resolve();
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], a]));
    ws.receive(JSON.stringify(["EVENT", req[1], b]));
    ws.receive(JSON.stringify(["EOSE", req[1]]));

    const result = await fetchP;
    expect(result.end).toStrictEqual({ type: "eose" });
    expect(result.events.map((e) => e.content).toSorted()).toStrictEqual(["a", "b"]);
    relay.close();
  });

  test("fetch returns partial events with a closed end on relay CLOSED", async () => {
    const relay = await Relay.connect("wss://fetch-closed.example");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("kept").createdAt(1).signWithKeys(keys);

    const fetchP = relay.fetch([{ kinds: [1] }], { timeoutMs: 2000 });
    await Promise.resolve();
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    ws.receive(JSON.stringify(["CLOSED", req[1], "rate-limited: slow down"]));

    const result = await fetchP;
    expect(result.end).toStrictEqual({ type: "closed", reason: "rate-limited: slow down" });
    expect(result.events.map((e) => e.id)).toStrictEqual([note.id]);
    relay.close();
  });

  test("fetch returns partial events with a timeout end at the deadline", async () => {
    const relay = await Relay.connect("wss://fetch-timeout.example");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("early").createdAt(1).signWithKeys(keys);

    const fetchP = relay.fetch([{ kinds: [1] }], { timeoutMs: 40 });
    await Promise.resolve();
    const ws = MockWebSocket.last();
    const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], note]));

    const result = await fetchP;
    expect(result.end).toStrictEqual({ type: "timeout" });
    expect(result.events.map((e) => e.id)).toStrictEqual([note.id]);
    relay.close();
  });

  test("WasmPoisonedError poisons verify and drops later EVENTs", async () => {
    let verifies = 0;
    const notices: string[] = [];
    const relay = await Relay.connect("wss://poison-instance.example", {
      verifyEvent: () => {
        verifies += 1;
        throw new WasmPoisonedError("wasm instance aborted");
      },
    });
    relay.on("notice", (msg) => notices.push(msg));
    const keys = Keys.fromSecretKey(SK);
    const first = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const second = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const events: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e.id),
    }) as Subscription;
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", sub.id, first]));
    expect(verifies).toBe(1);
    expect(events).toStrictEqual([]);
    expect(notices).toStrictEqual(["wasm-poisoned: instance aborted"]);
    expect(sub.lastCreatedAt).toBeUndefined();
    expect(sub.idsAtWatermark.size).toBe(0);

    ws.receive(JSON.stringify(["EVENT", sub.id, second]));
    expect(verifies).toBe(1);
    expect(events).toStrictEqual([]);
    expect(notices).toStrictEqual(["wasm-poisoned: instance aborted"]);
    expect(sub.idsAtWatermark.size).toBe(0);
    relay.close();
  });

  test("Error named WasmPoisonedError does not poison verify", async () => {
    let verifies = 0;
    const notices: string[] = [];
    const relay = await Relay.connect("wss://poison-name.example", {
      verifyEvent: () => {
        verifies += 1;
        const err = new Error("wasm verify aborted");
        err.name = "WasmPoisonedError";
        throw err;
      },
    });
    relay.on("notice", (msg) => notices.push(msg));
    const keys = Keys.fromSecretKey(SK);
    const first = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const second = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const events: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e.id),
    });
    const ws = MockWebSocket.last();
    const firstErr = syncThrow(() => {
      ws.receive(JSON.stringify(["EVENT", sub.id, first]));
    });
    expect(firstErr).toBeInstanceOf(Error);
    expect(firstErr).not.toBeInstanceOf(WasmPoisonedError);
    expect((firstErr as Error).name).toBe("WasmPoisonedError");
    expect(verifies).toBe(1);
    expect(events).toStrictEqual([]);
    expect(notices).toStrictEqual([]);

    const secondErr = syncThrow(() => {
      ws.receive(JSON.stringify(["EVENT", sub.id, second]));
    });
    expect(secondErr).toBeInstanceOf(Error);
    expect(secondErr).not.toBeInstanceOf(WasmPoisonedError);
    expect(verifies).toBe(2);
    expect(events).toStrictEqual([]);
    expect(notices).toStrictEqual([]);
    relay.close();
  });

  test("WasmPoisonedError from the wasm adapter poisons verify and does not map to false", async () => {
    let verifies = 0;
    const notices: string[] = [];
    const relay = await Relay.connect("wss://poison-runtime.example", {
      verifyEvent: () => {
        verifies += 1;
        // The wasm adapter converts WebAssembly.RuntimeError into
        // WasmPoisonedError before it reaches the relay.
        throw new WasmPoisonedError("unreachable");
      },
    });
    relay.on("notice", (msg) => notices.push(msg));
    const keys = Keys.fromSecretKey(SK);
    const first = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const second = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const events: string[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e.id),
    });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", sub.id, first]));
    expect(verifies).toBe(1);
    expect(events).toStrictEqual([]);
    expect(notices).toHaveLength(1);
    expect(notices[0]).toBe("wasm-poisoned: instance aborted");

    ws.receive(JSON.stringify(["EVENT", sub.id, second]));
    expect(verifies).toBe(1);
    expect(events).toStrictEqual([]);
    expect(notices).toHaveLength(1);
    relay.close();
  });

  test("rejects invalid signatures", async () => {
    const relay = await Relay.connect("wss://relay.example.com");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("x").createdAt(1).signWithKeys(keys);
    const bad = { ...note, content: "tampered" };

    const events: unknown[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e),
    });
    MockWebSocket.last().receive(JSON.stringify(["EVENT", sub.id, bad]));
    expect(events).toHaveLength(0);
    relay.close();
  });

  test("forged EVENT with huge created_at does not move watermark", async () => {
    let verifies = 0;
    const relay = await Relay.connect("wss://forged-wm.example", {
      verifyEvent: (event) => {
        verifies += 1;
        return verifyEvent(event);
      },
    });
    const keys = Keys.fromSecretKey(SK);
    const good = EventBuilder.textNote("ok").createdAt(10).signWithKeys(keys);
    const forgedId = "bb".repeat(32);
    const forged = { ...good, id: forgedId, created_at: 999_999 };
    const events: string[] = [];
    const sub = relay.subscribe([{ kinds: [1], since: 5 }], {
      onevent: (e) => events.push(e.id),
    }) as Subscription;

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", sub.id, good]));
    expect(events).toStrictEqual([good.id]);
    expect(verifies).toBe(1);
    expect(sub.lastCreatedAt).toBe(10);
    expect([...sub.idsAtWatermark]).toStrictEqual([good.id]);
    expect(sub.filters[0]!.since).toBe(5);
    expect(sub.replayFilters()[0]!.since).toBe(10);

    ws.receive(JSON.stringify(["EVENT", sub.id, forged]));
    expect(verifies).toBe(2);
    expect(events).toStrictEqual([good.id]);
    expect(sub.lastCreatedAt).toBe(10);
    expect(sub.idsAtWatermark.has(good.id)).toBe(true);
    expect(sub.idsAtWatermark.has(forgedId)).toBe(false);
    expect(sub.idsAtWatermark.size).toBe(1);
    relay.close();
  });

  test("subscribe rejects empty and oversize custom ids at the call", async () => {
    const relay = await Relay.connect("wss://sub-id.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    expect(() => relay.subscribe([{ kinds: [1] }], { id: "" })).toThrow(MessageError);
    expect(() => relay.subscribe([{ kinds: [1] }], { id: "a".repeat(65) })).toThrow(MessageError);
    expect(() => relay.subscribe([{ kinds: [1] }], { id: "", closeOnEose: true })).toThrow(
      MessageError,
    );
    expect(sentMessages(MockWebSocket.last()).filter((m) => m[0] === "REQ")).toHaveLength(0);
    relay.close();
  });

  test("subscribe empty filters throws MessageError before any socket send", async () => {
    const relay = await Relay.connect("wss://empty-req.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const err = syncThrow(() => relay.subscribe([]));
    expect(err).toBeInstanceOf(MessageError);
    expect(err).not.toBeInstanceOf(RelayClosedError);
    expect((err as Error).message).toBe("REQ requires at least one filter");
    expect(sentMessages(MockWebSocket.last()).filter((m) => m[0] === "REQ")).toHaveLength(0);
    relay.close();
  });

  test("disconnected subscribe empty filters is MessageError not RelayClosedError", () => {
    const relay = new Relay("wss://empty-disconnected.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const err = syncThrow(() => relay.subscribe([]));
    expect(err).toBeInstanceOf(MessageError);
    expect(err).not.toBeInstanceOf(RelayClosedError);
    expect((err as Error).message).toBe("REQ requires at least one filter");
    expect(MockWebSocket.instances).toHaveLength(0);
  });

  test("fetch empty filters throws MessageError before connect", async () => {
    const relay = new Relay("wss://empty-fetch.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    await expect(relay.fetch([])).rejects.toThrow(MessageError);
    await expect(relay.fetch([])).rejects.toThrow("REQ requires at least one filter");
    expect(MockWebSocket.instances).toHaveLength(0);
  });

  test("subscribe match-all and empty-ids filters are legal", async () => {
    const relay = await Relay.connect("wss://empty-ids.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const a = relay.subscribe([{}]);
    const b = relay.subscribe([{ ids: [] }]);
    const reqs = sentMessages(MockWebSocket.last()).filter((m) => m[0] === "REQ");
    expect(reqs).toHaveLength(2);
    a.close();
    b.close();
    relay.close();
  });

  test("subscribe uses a 64-char custom id on the REQ", async () => {
    const relay = await Relay.connect("wss://sub-id-ok.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const id = "a".repeat(64);
    const sub = relay.subscribe([{ kinds: [1] }], { id });
    expect(sub.id).toBe(id);
    const req = MockWebSocket.last().lastSent() as [string, string, ...unknown[]];
    expect(req[0]).toBe("REQ");
    expect(req[1]).toBe(id);
    sub.close();
    relay.close();
  });

  test("negReconcile rejects empty and oversize custom ids without sending NEG", async () => {
    const relay = await Relay.connect("wss://neg-id.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const storage = new NegentropyStorageVector();
    storage.seal();
    await expect(relay.negReconcile({ kinds: [1] }, storage, { id: "" })).rejects.toThrow(
      MessageError,
    );
    await expect(
      relay.negReconcile({ kinds: [1] }, storage, {
        id: "a".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1),
      }),
    ).rejects.toThrow(MessageError);
    expect(sentMessages(MockWebSocket.last()).filter(isNegFrame)).toHaveLength(0);
    relay.close();
  });

  test("negReconcile sends NEG-OPEN with a 64-char custom id", async () => {
    const relay = await Relay.connect("wss://neg-id-ok.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const storage = new NegentropyStorageVector();
    storage.seal();
    const id = "n".repeat(SUBSCRIPTION_ID_MAX_CHARS);
    const pending = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    await Promise.resolve();
    const open = sentMessages(MockWebSocket.last()).find((m) => m[0] === "NEG-OPEN") as
      | [string, string, ...unknown[]]
      | undefined;
    expect(open?.[0]).toBe("NEG-OPEN");
    expect(open?.[1]).toBe(id);
    MockWebSocket.last().receive(JSON.stringify(["NEG-MSG", id, "61"]));
    await expect(pending).resolves.toStrictEqual({ have: [], need: [] });
    relay.close();
  });

  test("negReconcile overlapping custom id fails previous; first finally does not NEG-CLOSE the second", async () => {
    const relay = await Relay.connect("wss://neg-id-reuse.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const storage = new NegentropyStorageVector();
    storage.seal();
    const id = "n".repeat(SUBSCRIPTION_ID_MAX_CHARS);
    const first = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    await waitUntil(() => sentMessages(MockWebSocket.last()).some((m) => m[0] === "NEG-OPEN"));
    const ws = MockWebSocket.last();

    const second = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    const firstErr = await captureError(first);
    expect(firstErr).toBeInstanceOf(Nip77Error);
    expect((firstErr as Nip77Error).message).toBe("closed: replaced by new NEG-OPEN");

    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "NEG-OPEN").length >= 2);
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(0);

    ws.receive(JSON.stringify(["NEG-MSG", id, "61"]));
    await expect(second).resolves.toStrictEqual({ have: [], need: [] });
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(1);
    relay.close();
  });

  test("negReconcile overlapping custom id: NEG-ERR after replace fails only the new session", async () => {
    const relay = await Relay.connect("wss://neg-id-reuse-err.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const storage = new NegentropyStorageVector();
    storage.seal();
    const id = "e".repeat(SUBSCRIPTION_ID_MAX_CHARS);
    const first = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    await waitUntil(() => sentMessages(MockWebSocket.last()).some((m) => m[0] === "NEG-OPEN"));
    const ws = MockWebSocket.last();

    const second = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    const firstErr = await captureError(first);
    expect(firstErr).toBeInstanceOf(Nip77Error);
    expect((firstErr as Nip77Error).message).toBe("closed: replaced by new NEG-OPEN");

    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "NEG-OPEN").length >= 2);
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(0);

    ws.receive(JSON.stringify(["NEG-ERR", id, "error: boom"]));
    const secondErr = await captureError(second);
    expect(secondErr).toBeInstanceOf(Nip77Error);
    expect((secondErr as Nip77Error).message).toBe("error: boom");
    expect(firstErr).not.toBe(secondErr);
    expect((firstErr as Nip77Error).message).toBe("closed: replaced by new NEG-OPEN");
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(1);
    relay.close();
  });

  test("negReconcile invalid custom id does not replace or NEG-CLOSE a live session", async () => {
    const relay = await Relay.connect("wss://neg-id-invalid-reuse.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const storage = new NegentropyStorageVector();
    storage.seal();
    const id = "v".repeat(SUBSCRIPTION_ID_MAX_CHARS);
    const first = relay.negReconcile({ kinds: [1] }, storage, { id, timeoutMs: 2000 });
    await waitUntil(() => sentMessages(MockWebSocket.last()).some((m) => m[0] === "NEG-OPEN"));
    const ws = MockWebSocket.last();

    await expect(relay.negReconcile({ kinds: [1] }, storage, { id: "" })).rejects.toThrow(
      MessageError,
    );
    await expect(
      relay.negReconcile({ kinds: [1] }, storage, {
        id: "a".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1),
      }),
    ).rejects.toThrow(MessageError);

    expect(sentMessages(ws).filter((m) => m[0] === "NEG-OPEN")).toHaveLength(1);
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(0);

    ws.receive(JSON.stringify(["NEG-MSG", id, "61"]));
    await expect(first).resolves.toStrictEqual({ have: [], need: [] });
    expect(sentMessages(ws).filter((m) => m[0] === "NEG-CLOSE")).toHaveLength(1);
    relay.close();
  });
});

describe("Pool", () => {
  test("fetch dedupes across relays", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("shared").createdAt(1).signWithKeys(keys);

    const fetchP = pool.fetch(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      timeoutMs: 2000,
    });

    // wait for both sockets
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(MockWebSocket.instances).toHaveLength(2);

    for (const ws of MockWebSocket.instances) {
      const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
      ws.receive(JSON.stringify(["EVENT", req[1], note]));
      ws.receive(JSON.stringify(["EOSE", req[1]]));
    }

    const events = await fetchP;
    expect(events).toHaveLength(1);
    expect(events[0]!.id).toBe(note.id);
    pool.close();
  });

  test("fetchEach reports per-relay eose, closed and failed ends", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("per-relay").createdAt(1).signWithKeys(keys);

    const fetchP = pool.fetchEach(
      ["wss://a.example", "wss://b.example", "not a url"],
      [{ kinds: [1] }],
      { timeoutMs: 2000 },
    );
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));

    const a = socketFor("a.example");
    a.receive(JSON.stringify(["EVENT", reqId(a), note]));
    a.receive(JSON.stringify(["EOSE", reqId(a)]));
    const b = socketFor("b.example");
    b.receive(JSON.stringify(["CLOSED", reqId(b), "rate-limited: slow down"]));

    const results = await fetchP;
    expect(results).toHaveLength(3);
    const aResult = must(
      results.find((r) => r.url.includes("a.example")),
      "a.example result",
    );
    expect(aResult.end).toStrictEqual({ type: "eose" });
    expect(aResult.events.map((e) => e.id)).toStrictEqual([note.id]);
    const bResult = must(
      results.find((r) => r.url.includes("b.example")),
      "b.example result",
    );
    expect(bResult.end).toStrictEqual({ type: "closed", reason: "rate-limited: slow down" });
    expect(bResult.events).toStrictEqual([]);
    const bad = must(
      results.find((r) => r.url === "not a url"),
      "invalid url result",
    );
    expect(bad.events).toStrictEqual([]);
    expect(bad.end.type).toBe("failed");
    pool.close();
  });

  test("fetchEach reports a timeout end with the partial events", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("partial").createdAt(1).signWithKeys(keys);

    const fetchP = pool.fetchEach(["wss://slow.example"], [{ kinds: [1] }], {
      timeoutMs: 60,
    });
    await waitUntil(all(instanceCountIs(1), everyInstanceSent("REQ")));
    const ws = socketFor("slow.example");
    ws.receive(JSON.stringify(["EVENT", reqId(ws), note]));

    const results = await fetchP;
    expect(results).toHaveLength(1);
    expect(results[0]!.end).toStrictEqual({ type: "timeout" });
    expect(results[0]!.events.map((e) => e.id)).toStrictEqual([note.id]);
    pool.close();
  });

  test("fetchEach rejects the whole call on abort", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const ac = new AbortController();
    const reason = new Error("user aborted");
    const fetchP = pool.fetchEach(["wss://pool-abort-each.example"], [{ kinds: [1] }], {
      timeoutMs: 2000,
      signal: ac.signal,
    });
    await waitUntil(() => MockWebSocket.instances.length === 1);
    ac.abort(reason);
    await expect(fetchP).rejects.toBe(reason);
    pool.close();
  });

  test("publish fans out", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("fan").createdAt(1).signWithKeys(keys);

    const publishP = pool.publish(["wss://a.example", "wss://b.example"], note);
    await new Promise((resolve) => setTimeout(resolve, 10));

    for (const ws of MockWebSocket.instances) {
      const eventMsg = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "EVENT") as [
        string,
        typeof note,
      ];
      ws.receive(JSON.stringify(["OK", eventMsg[1].id, true, ""]));
    }

    const results = await publishP;
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.status === "ok")).toBe(true);
    pool.close();
  });

  test("connectedUrls excludes disconnected pool entries that listRelays still has", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
    });
    try {
      await pool.ensureRelay("wss://up.example");
      MockWebSocket.failConnect = true;
      await expect(pool.ensureRelay("wss://down.example")).rejects.toThrow(RelayConnectionError);
      const listed = pool.listRelays();
      expect(listed.some((u) => u.includes("up.example"))).toBe(true);
      expect(listed.some((u) => u.includes("down.example"))).toBe(true);
      const connected = pool.connectedUrls();
      expect(connected).toHaveLength(1);
      expect(connected[0]).toContain("up.example");
    } finally {
      pool.close();
    }
  });

  test("subscribe rejects empty custom id before opening a socket", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
    });
    expect(() => pool.subscribe(["wss://x"], [{ kinds: [1] }], { id: "" })).toThrow(MessageError);
    expect(MockWebSocket.instances).toHaveLength(0);
    await Promise.resolve();
    expect(MockWebSocket.instances).toHaveLength(0);
    pool.close();
  });

  test("subscribe empty filters throws before opening a socket", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    expect(() => pool.subscribe(["wss://empty-pool-sub.example"], [])).toThrow(MessageError);
    expect(() => pool.subscribe(["wss://empty-pool-sub.example"], [])).toThrow(
      "REQ requires at least one filter",
    );
    expect(MockWebSocket.instances).toHaveLength(0);
    await Promise.resolve();
    expect(MockWebSocket.instances).toHaveLength(0);
    pool.close();
  });

  test("fetch empty filters throws and does not return []", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    await expect(pool.fetch(["wss://empty-pool-fetch.example"], [])).rejects.toThrow(MessageError);
    await expect(pool.fetch(["wss://empty-pool-fetch.example"], [])).rejects.toThrow(
      "REQ requires at least one filter",
    );
    expect(MockWebSocket.instances).toHaveLength(0);
    pool.close();
  });

  test("subscribe rejects oversize custom id before opening a socket", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
    });
    expect(() =>
      pool.subscribe(["wss://x"], [{ kinds: [1] }], {
        id: "a".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1),
      }),
    ).toThrow(MessageError);
    expect(MockWebSocket.instances).toHaveLength(0);
    await Promise.resolve();
    expect(MockWebSocket.instances).toHaveLength(0);
    pool.close();
  });

  test("subscribe uses caller id on REQ", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const closer = pool.subscribe(["wss://id.example"], [{ kinds: [1] }], { id: "my-sub" });
    await waitUntil(() =>
      MockWebSocket.instances.some((ws) => sentMessages(ws).some((m) => m[0] === "REQ")),
    );
    expect(reqId(socketFor("id.example"))).toBe("my-sub");
    closer.close();
    pool.close();
  });
});

describe("isInsecureRelayUrl", () => {
  test("ws/http without .onion are insecure; onion and wss are not", () => {
    expect(isInsecureRelayUrl("ws://x.com")).toBe(true);
    expect(isInsecureRelayUrl("http://x.com")).toBe(true);
    expect(isInsecureRelayUrl("wss://x.com")).toBe(false);
    expect(isInsecureRelayUrl("ws://foo.onion")).toBe(false);
    expect(isInsecureRelayUrl("ws://192.168.1.9")).toBe(true);
  });
});

describe("alreadyHaveEvent / receivedEvent", () => {
  test("alreadyHaveEvent true skips verify and onevent; receivedEvent still fires", async () => {
    let verifies = 0;
    const relay = await Relay.connect("wss://have.example", {
      websocketImplementation: MockWebSocketCtor,
      verifyEvent: (event) => {
        verifies += 1;
        return verifyEvent(event);
      },
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("dup").createdAt(1).signWithKeys(keys);
    const received: string[] = [];
    const events: unknown[] = [];

    const sub = relay.subscribe([{ kinds: [1] }], {
      alreadyHaveEvent: () => true,
      receivedEvent: (id) => received.push(id),
      onevent: (e) => events.push(e),
    }) as Subscription;

    MockWebSocket.last().receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(received).toStrictEqual([note.id]);
    expect(events).toHaveLength(0);
    expect(verifies).toBe(0);
    expect(sub.lastCreatedAt).toBeUndefined();
    expect(sub.idsAtWatermark.size).toBe(0);
    relay.close();
  });

  test("Pool.subscribe two relays verifies once and records receivedEvent", async () => {
    let verifies = 0;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      verifyEvent: (event) => {
        verifies += 1;
        return verifyEvent(event);
      },
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("shared-sub").createdAt(1).signWithKeys(keys);
    const events: string[] = [];
    const received: string[] = [];

    const closer = pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      receivedEvent: (id) => received.push(id),
      onevent: (e) => events.push(e.id),
    });

    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    for (const ws of MockWebSocket.instances) {
      const req = sentMessages(ws).find((m) => m[0] === "REQ") as [string, string];
      ws.receive(JSON.stringify(["EVENT", req[1], note]));
    }

    expect(verifies).toBe(1);
    expect(events).toStrictEqual([note.id]);
    expect(received).toStrictEqual([note.id, note.id]);
    closer.close();
    pool.close();
  });

  test("failed verify is not added to Pool seen; later valid copy surfaces", async () => {
    let verifies = 0;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      verifyEvent: (event) => {
        verifies += 1;
        return verifyEvent(event);
      },
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("ok").createdAt(1).signWithKeys(keys);
    const bad = { ...note, content: "tampered" };
    const events: string[] = [];

    const closer = pool.subscribe(["wss://seen.example"], [{ kinds: [1] }], {
      onevent: (e) => events.push(e.id),
    });
    await waitUntil(
      all(
        () => MockWebSocket.instances.length > 0,
        () => hasSent(MockWebSocket.last(), "REQ"),
      ),
    );
    const ws = MockWebSocket.last();
    const req = sentMessages(ws).find((m) => m[0] === "REQ") as [string, string];
    ws.receive(JSON.stringify(["EVENT", req[1], bad]));
    expect(events).toHaveLength(0);
    ws.receive(JSON.stringify(["EVENT", req[1], note]));
    expect(events).toStrictEqual([note.id]);
    expect(verifies).toBe(2);
    closer.close();
    pool.close();
  });
});

describe("insecure URL policy", () => {
  test("ws:// is rejected by default unless trusted", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    await expect(pool.ensureRelay("ws://evil.example")).rejects.toThrow(
      /insecure relay connection blocked/,
    );
    pool.setTrustedInsecureUrls(["ws://evil.example"]);
    const relay = await pool.ensureRelay("ws://evil.example");
    expect(relay.connected).toBe(true);
    pool.close();
  });

  test("allowInsecure true permits ws:// and setAllowInsecure toggles the check", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor, allowInsecure: true });
    const first = await pool.ensureRelay("ws://open.example");
    expect(first.connected).toBe(true);
    pool.close(["ws://open.example"]);
    pool.setAllowInsecure(false);
    await expect(pool.ensureRelay("ws://open.example")).rejects.toThrow(
      /insecure relay connection blocked/,
    );
    pool.close();
  });
});

describe("pool relay cap and pinning", () => {
  test("maxRelays closes the least-recently-used idle relay but keeps busy ones", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor, maxRelays: 2 });
    try {
      await pool.ensureRelay("wss://old.example");
      const busy = await pool.ensureRelay("wss://busy.example");
      busy.subscribe([{ kinds: [1] }]);
      expect(busy.subscriptionCount).toBe(1);

      await pool.ensureRelay("wss://new.example");
      expect(pool.listRelays()).not.toContain("wss://old.example/");
      expect(pool.listRelays()).toContain("wss://busy.example/");
      expect(pool.listRelays()).toContain("wss://new.example/");
    } finally {
      pool.close();
    }
  });

  test("cap is soft: with no idle relay the connect still succeeds", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor, maxRelays: 1 });
    try {
      const busy = await pool.ensureRelay("wss://busy.example");
      busy.subscribe([{ kinds: [1] }]);
      await pool.ensureRelay("wss://second.example");
      expect(pool.listRelays()).toHaveLength(2);
    } finally {
      pool.close();
    }
  });

  test("pinned relays survive the cap and idle cleanup", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      maxRelays: 1,
      idleTimeoutMs: 10,
      pinnedUrls: ["wss://pin.example"],
    });
    try {
      await pool.ensureRelay("wss://pin.example");
      await pool.ensureRelay("wss://a.example");
      await pool.ensureRelay("wss://b.example");
      expect(pool.listRelays()).toContain("wss://pin.example/");
      expect(pool.listRelays()).toContain("wss://b.example/");
      expect(pool.listRelays()).not.toContain("wss://a.example/");

      await sleep(20);
      pool.cleanIdleRelays();
      expect(pool.listRelays()).toContain("wss://pin.example/");
    } finally {
      pool.close();
    }
  });
});

describe("idle cleanup", () => {
  test("subscribe holds relay; after close + idleTimeout cleanIdleRelays drops it", async () => {
    const closed: string[] = [];
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      idleTimeoutMs: 30,
      onIdleRelaysClosed: (urls) => closed.push(...urls),
    });
    try {
      const relay = await pool.ensureRelay("wss://idle.example");
      const sub = relay.subscribe([{ kinds: [1] }]);
      expect(relay.subscriptionCount).toBe(1);
      await sleep(50);
      pool.cleanIdleRelays();
      expect(pool.listRelays()).toHaveLength(1);

      sub.close();
      expect(relay.subscriptionCount).toBe(0);
      await sleep(40);
      pool.cleanIdleRelays();
      expect(pool.listRelays()).toHaveLength(0);
      expect(closed.length).toBeGreaterThan(0);
    } finally {
      pool.close();
    }
  });

  test("cleanIdleRelays is a no-op when idleTimeoutMs is unset", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    try {
      await pool.ensureRelay("wss://keep.example");
      await sleep(20);
      pool.cleanIdleRelays();
      expect(pool.listRelays()).toHaveLength(1);
    } finally {
      pool.close();
    }
  });
});

describe("ping", () => {
  test("dummy REQ is outside #subs; EOSE sends CLOSE and leaves subscriptionCount 0", async () => {
    const relay = await Relay.connect("wss://ping-dummy.example", {
      websocketImplementation: MockWebSocketCtor,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
    });
    try {
      const ws = MockWebSocket.last();
      await waitUntil(() => dummyPingReqs(ws).length > 0);
      expect(relay.subscriptionCount).toBe(0);

      const ping = dummyPingReqs(ws)[0]!;
      expect(ping[2]).toStrictEqual({ ids: ["a".repeat(64)], limit: 0 });
      ws.receive(JSON.stringify(["EOSE", ping[1]]));
      expect(relay.subscriptionCount).toBe(0);
      expect(relay.connected).toBe(true);
      expect(sentCloseFor(ws, ping[1])).toBe(true);
    } finally {
      relay.close();
    }
  });

  test("dummy ping CLOSED is liveness; CLOSE is sent; subscriptionCount stays 0", async () => {
    const relay = await Relay.connect("wss://ping-closed.example", {
      websocketImplementation: MockWebSocketCtor,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
    });
    try {
      const ws = MockWebSocket.last();
      await waitUntil(() => dummyPingReqs(ws).length > 0);
      const ping = dummyPingReqs(ws)[0]!;
      ws.receive(JSON.stringify(["CLOSED", ping[1], "rate-limited"]));
      expect(relay.subscriptionCount).toBe(0);
      expect(relay.connected).toBe(true);
      expect(sentCloseFor(ws, ping[1])).toBe(true);
    } finally {
      relay.close();
    }
  });

  test("dummy ping does not block idle cleanup", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
      idleTimeoutMs: 40,
    });
    try {
      const relay = await pool.ensureRelay("wss://ping-idle.example");
      const ws = MockWebSocket.last();
      await waitUntil(() => dummyPingReqs(ws).length > 0);
      const ping = dummyPingReqs(ws)[0]!;
      ws.receive(JSON.stringify(["EOSE", ping[1]]));
      expect(relay.subscriptionCount).toBe(0);
      await sleep(50);
      pool.cleanIdleRelays();
      expect(pool.listRelays()).toHaveLength(0);
    } finally {
      pool.close();
    }
  });

  test("native ping uses once('pong'), not addEventListener('pong')", async () => {
    const relay = await Relay.connect("wss://ping-native.example", {
      websocketImplementation: NativePingCtor,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
    });
    try {
      const ws = MockWebSocket.last() as NativePingSocket;
      await waitUntil(() => ws.pingCalls > 0);
      expect(ws.pongAddEventListenerCalls).toBe(0);
      expect(dummyPingReqs(ws)).toHaveLength(0);
      expect(relay.connected).toBe(true);
      expect(relay.subscriptionCount).toBe(0);
    } finally {
      relay.close();
    }
  });

  test("native ping timeout without pong closes the socket", async () => {
    const relay = await Relay.connect("wss://ping-timeout.example", {
      websocketImplementation: NativeTimeoutCtor,
      enablePing: true,
      pingIntervalMs: 20,
      pingTimeoutMs: 40,
    });
    try {
      const ws = MockWebSocket.last() as NativeTimeoutSocket;
      await waitUntil(() => ws.pingCalls > 0);
      await waitUntil(() => !relay.connected);
      expect(relay.connected).toBe(false);
      expect(ws.pongListenerCount()).toBe(0);
    } finally {
      relay.close();
    }
  });

  test("native ping on node ws uses on/off and timeout drops the pong listener", async () => {
    const relay = await Relay.connect("wss://ping-ws.example", {
      websocketImplementation: NodeWsPingCtor,
      enablePing: true,
      pingIntervalMs: 20,
      pingTimeoutMs: 40,
    });
    try {
      const ws = MockWebSocket.last() as NodeWsPingSocket;
      await waitUntil(() => ws.pingCalls > 0);
      expect(dummyPingReqs(ws)).toHaveLength(0);
      await waitUntil(() => !relay.connected);
      expect(ws.pongListenerCount()).toBe(0);
    } finally {
      relay.close();
    }
  });

  test("ping without once/on falls back to dummy REQ", async () => {
    const relay = await Relay.connect("wss://ping-only.example", {
      websocketImplementation: PingOnlyCtor,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
    });
    try {
      const ws = MockWebSocket.last() as PingOnlySocket;
      await waitUntil(() => dummyPingReqs(ws).length > 0);
      expect(ws.pingCalls).toBe(0);
      expect(relay.subscriptionCount).toBe(0);
      const ping = dummyPingReqs(ws)[0]!;
      ws.receive(JSON.stringify(["EOSE", ping[1]]));
      expect(relay.connected).toBe(true);
    } finally {
      relay.close();
    }
  });
});

describe("Relay generation / close", () => {
  test("close() during in-flight connect() rejects; next connect() is a new handshake", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://gen-close.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const first = relay.connect();
    const coalesced = relay.connect();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(relay.status).toBe(RelayStatus.Connecting);
    const firstWs = MockWebSocket.last();
    const firstClosed = captureError(first);
    const coalescedClosed = captureError(coalesced);
    relay.close();
    await expect(firstClosed).resolves.toBeInstanceOf(RelayClosedError);
    await expect(coalescedClosed).resolves.toBeInstanceOf(RelayClosedError);
    expect(relay.status).toBe(RelayStatus.Closed);
    expect(relay.connected).toBe(false);

    MockWebSocket.autoConnect = true;
    const second = relay.connect();
    expect(second).not.toBe(first);
    await second;
    expect(relay.connected).toBe(true);
    expect(relay.status).toBe(RelayStatus.Connected);
    expect(MockWebSocket.instances).toHaveLength(2);
    expect(MockWebSocket.last()).not.toBe(firstWs);
    relay.close();
  });

  test("late open after close() does not set connected and does not send REQ", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://late-open.example", {
      websocketImplementation: StickyListenersCtor,
    });
    const connecting = relay.connect();
    const firstWs = MockWebSocket.last();
    const closed = captureError(connecting);
    relay.close();
    await expect(closed).resolves.toBeInstanceOf(RelayClosedError);

    MockWebSocket.autoConnect = true;
    await relay.connect();
    const secondWs = MockWebSocket.last();
    expect(secondWs).not.toBe(firstWs);
    expect(relay.connected).toBe(true);
    relay.subscribe([{ kinds: [1] }]);
    expect(sentMessages(secondWs).filter((m) => m[0] === "REQ")).toHaveLength(1);
    expect(sentMessages(firstWs).filter((m) => m[0] === "REQ")).toHaveLength(0);

    firstWs.open();
    expect(relay.connected).toBe(true);
    expect(relay.status).toBe(RelayStatus.Connected);
    expect(MockWebSocket.last()).toBe(secondWs);
    expect(sentMessages(secondWs).filter((m) => m[0] === "REQ")).toHaveLength(1);
    expect(sentMessages(firstWs).filter((m) => m[0] === "REQ")).toHaveLength(0);
    relay.close();
  });

  test("close() then connect() succeeds with a new generation", async () => {
    const relay = new Relay("wss://reopen.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    await relay.connect();
    const genAfterConnect = relay.generation;
    relay.close();
    expect(relay.status).toBe(RelayStatus.Closed);
    expect(relay.generation).toBeGreaterThan(genAfterConnect);
    await relay.connect();
    expect(relay.connected).toBe(true);
    expect(relay.status).toBe(RelayStatus.Connected);
    expect(relay.generation).toBeGreaterThan(genAfterConnect);
    relay.close();
  });

  test("stale connect timeout after close() does not kill the next socket", async () => {
    const realSetTimeout = globalThis.setTimeout;
    const held: Array<() => void> = [];
    globalThis.setTimeout = heldTimeout(80, held, realSetTimeout);

    try {
      MockWebSocket.autoConnect = false;
      const relay = new Relay("wss://stale-timeout.example", {
        websocketImplementation: MockWebSocketCtor,
        connectTimeoutMs: 10_000,
        enableReconnect: true,
        reconnectBackoffMs: [10],
      });
      const first = relay.connect({ timeoutMs: 80 });
      const firstClosed = captureError(first);
      relay.close();
      await expect(firstClosed).resolves.toBeInstanceOf(RelayClosedError);
      expect(held).toHaveLength(1);

      MockWebSocket.autoConnect = true;
      await relay.connect();
      expect(relay.connected).toBe(true);
      const secondWs = MockWebSocket.last();
      let secondCloseCalls = 0;
      const origClose = secondWs.close.bind(secondWs);
      secondWs.close = () => {
        secondCloseCalls += 1;
        origClose();
      };

      held[0]!();
      expect(relay.connected).toBe(true);
      expect(relay.status).toBe(RelayStatus.Connected);
      expect(secondWs.readyState).toBe(MockWebSocket.OPEN);
      expect(secondCloseCalls).toBe(0);

      relay.subscribe([{ kinds: [1] }], {});
      const before = MockWebSocket.instances.length;
      secondWs.close();
      await waitUntil(
        all(
          () => MockWebSocket.instances.length > before,
          () => relay.connected,
        ),
      );
      expect(relay.connected).toBe(true);
      relay.close();
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
  });

  test("WebSocket constructor throw leaves Closed status", async () => {
    class BoomSocket {
      static OPEN = 1;
      static CONNECTING = 0;
      static CLOSING = 2;
      static CLOSED = 3;
      constructor(_url: string) {
        throw new Error("no socket");
      }
    }
    const relay = new Relay("wss://boom.example", {
      websocketImplementation: BoomSocket as unknown as WebSocketConstructor,
    });
    await expect(relay.connect()).rejects.toThrow("no socket");
    expect(relay.status).toBe(RelayStatus.Closed);
    expect(relay.connected).toBe(false);
  });

  test("intentional close does not schedule reconnect", async () => {
    const relay = new Relay("wss://nogo-gen.example", {
      enableReconnect: true,
      reconnectBackoffMs: [10],
      websocketImplementation: MockWebSocketCtor,
    });
    await relay.connect();
    relay.subscribe([{ kinds: [1] }], {});
    const before = MockWebSocket.instances.length;
    relay.close();
    await sleep(30);
    expect(MockWebSocket.instances).toHaveLength(before);
    expect(relay.status).toBe(RelayStatus.Closed);
  });
});

function socketFor(substr: string): MockWebSocket {
  const ws = MockWebSocket.instances.find((s) => s.url.includes(substr));
  if (!ws) {
    throw new Error(`no socket matching ${substr}`);
  }
  return ws;
}

function reqId(ws: MockWebSocket): string {
  const req = sentMessages(ws).find((m) => m[0] === "REQ") as [string, string] | undefined;
  if (!req) {
    throw new Error(`no REQ on ${ws.url}`);
  }
  return req[1];
}

describe("Relay synthetic EOSE", () => {
  test("eoseTimeoutMs fires oneose without CLOSE; later EOSE is ignored; EVENT still delivered; reconnect allows a new oneose", async () => {
    const relay = await Relay.connect("wss://synth-eose.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
      reconnectBackoffMs: [10],
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("live").createdAt(1).signWithKeys(keys);
    const events: string[] = [];
    let eose = 0;
    const sub = relay.subscribe([{ kinds: [1] }], {
      eoseTimeoutMs: 40,
      onevent: (e) => events.push(e.id),
      oneose: () => {
        eose += 1;
      },
    });
    const first = MockWebSocket.last();
    await waitUntil(() => sentMessages(first).some((m) => m[0] === "REQ"));
    await waitUntil(() => eose === 1);
    expect(sentMessages(first).some((m) => m[0] === "CLOSE")).toBe(false);

    first.receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(events).toStrictEqual([note.id]);
    first.receive(JSON.stringify(["EOSE", sub.id]));
    expect(eose).toBe(1);

    first.close();
    await waitUntil(() => otherOpenInstanceSent(first, "synth-eose.example", "REQ"));
    const second = must(openInstance(first, "synth-eose.example"), "second socket");
    second.receive(JSON.stringify(["EOSE", sub.id]));
    expect(eose).toBe(2);
    relay.close();
  });

  test("AUTH retry after synthetic EOSE allows a new oneose", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://auth-synth-eose.example", {
      websocketImplementation: MockWebSocketCtor,
      authSigner: authSignerFor(keys),
    });
    const events: string[] = [];
    let eose = 0;
    const sub = relay.subscribe([{ kinds: [1] }], {
      eoseTimeoutMs: 30,
      onevent: (e) => events.push(e.id),
      oneose: () => {
        eose += 1;
      },
    });
    const ws = MockWebSocket.last();
    await waitUntil(() => eose === 1);

    ws.receive(JSON.stringify(["AUTH", "retry-challenge"]));
    ws.receive(JSON.stringify(["CLOSED", sub.id, "auth-required: login"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    const authFrame = sentMessages(ws).find((m) => m[0] === "AUTH") as [string, { id: string }];
    ws.receive(JSON.stringify(["OK", authFrame[1].id, true, ""]));
    await waitUntil(() => sentMessages(ws).filter((m) => m[0] === "REQ").length >= 2);

    const note = EventBuilder.textNote("after auth").createdAt(1).signWithKeys(keys);
    ws.receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(events).toStrictEqual([note.id]);
    ws.receive(JSON.stringify(["EOSE", sub.id]));
    expect(eose).toBe(2);
    relay.close();
  });
});

describe("Pool aggregated EOSE", () => {
  test("two relays both EOSE fire oneose once", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    const closer = pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
    });
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    for (const ws of MockWebSocket.instances) {
      ws.receive(JSON.stringify(["EOSE", reqId(ws)]));
    }
    expect(eose).toBe(1);
    closer.close();
    pool.close();
  });

  test("one silent relay plus eoseTimeoutMs fires oneose once and does not CLOSE the silent REQ", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    const closer = pool.subscribe(
      ["wss://loud.example", "wss://silent.example"],
      [{ kinds: [1] }],
      {
        eoseTimeoutMs: 50,
        oneose: () => {
          eose += 1;
        },
      },
    );
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    const loud = socketFor("loud.example");
    const silent = socketFor("silent.example");
    loud.receive(JSON.stringify(["EOSE", reqId(loud)]));
    expect(eose).toBe(0);
    await waitUntil(() => eose === 1);
    expect(eose).toBe(1);
    expect(sentMessages(silent).some((m) => m[0] === "CLOSE")).toBe(false);
    closer.close();
    pool.close();
  });

  test("enableReconnect first socket error does not fire oneose; REQ is on socket 2", async () => {
    MockWebSocket.failConnect = true;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
      reconnectBackoffMs: [80],
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("live after fail").createdAt(1).signWithKeys(keys);
    let eose = 0;
    let closed: string | undefined;
    const events: string[] = [];
    const closer = pool.subscribe(["wss://first-socket-fail.example"], [{ kinds: [1] }], {
      onevent: (e) => events.push(e.id),
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(
      all(instanceCountIs(1), () =>
        MockWebSocket.instances.every((ws) => ws.readyState === MockWebSocket.CLOSED),
      ),
    );
    expect(eose).toBe(0);
    expect(closed).toBeUndefined();
    expect(pool.listRelays().some((u) => u.includes("first-socket-fail.example"))).toBe(true);

    MockWebSocket.failConnect = false;
    await sleep(20);
    expect(eose).toBe(0);
    expect(closed).toBeUndefined();
    const firstSocket = must(MockWebSocket.instances[0], "first socket");
    await waitUntil(() => otherOpenInstanceSent(firstSocket, "", "REQ"));
    expect(eose).toBe(0);
    expect(closed).toBeUndefined();

    const first = must(MockWebSocket.instances[0], "first socket");
    const second = must(openInstance(first, ""), "second socket");
    const req = must(
      sentMessages(second).find((m) => m[0] === "REQ") as
        | [string, string, ...unknown[]]
        | undefined,
      "REQ on socket 2",
    );
    expect(req[0]).toBe("REQ");
    expect(req[1]).toBeTypeOf("string");
    expect(req[1].length).toBeGreaterThan(0);
    expect(sentMessages(first).some((m) => m[0] === "REQ")).toBe(false);

    second.receive(JSON.stringify(["EVENT", req[1], note]));
    expect(events).toStrictEqual([note.id]);
    expect(eose).toBe(0);
    second.receive(JSON.stringify(["EOSE", req[1]]));
    expect(eose).toBe(1);
    closer.close();
    pool.close();
  });

  test("connect failure plus EOSE fires oneose once", async () => {
    MockWebSocket.autoConnect = false;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      connectTimeoutMs: 40,
    });
    let eose = 0;
    const closer = pool.subscribe(["wss://ok.example", "wss://fail.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
    });
    await waitUntil(() => MockWebSocket.instances.length === 2);
    socketFor("ok.example").open();
    await waitUntil(() => sentMessages(socketFor("ok.example")).some((m) => m[0] === "REQ"));
    const ok = socketFor("ok.example");
    ok.receive(JSON.stringify(["EOSE", reqId(ok)]));
    await waitUntil(() => eose === 1);
    expect(eose).toBe(1);
    closer.close();
    pool.close();
  });

  test("caller close before EOSE fires onclose and not oneose", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    let closed: string | undefined;
    const closer = pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    closer.close("stop");
    expect(closed).toBe("stop");
    expect(eose).toBe(0);
    pool.close();
  });

  test("abort before EOSE fires onclose and not oneose", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const ac = new AbortController();
    let eose = 0;
    let closed: string | undefined;
    pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      signal: ac.signal,
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    ac.abort();
    expect(closed).toBe("aborted");
    expect(eose).toBe(0);
    pool.close();
  });

  test("empty relay list fires onclose(no relays) and not oneose", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    let closed: string | undefined;
    pool.subscribe([], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(() => closed !== undefined);
    expect(closed).toBe("no relays");
    expect(eose).toBe(0);
    pool.close();
  });

  test("all connect failures fire onclose(all relays failed)", async () => {
    MockWebSocket.failConnect = true;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    let eose = 0;
    let closed: string | undefined;
    pool.subscribe(["wss://fail-a.example", "wss://fail-b.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(() => closed !== undefined);
    expect(closed).toBe("all relays failed");
    expect(eose).toBe(0);
    expect(pool.listRelays()).toStrictEqual([]);
    pool.close();
  });

  test("a single refused relay fires only onclose, never oneose", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    let closed: string | undefined;
    pool.subscribe(["wss://refused.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(() => MockWebSocket.instances.some(urlSent("refused.example", "REQ")));
    const ws = socketFor("refused.example");
    ws.receive(JSON.stringify(["CLOSED", reqId(ws), "rate-limited: slow down"]));
    await waitUntil(() => closed !== undefined);
    expect(closed).toBe("rate-limited: slow down");
    expect(eose).toBe(0);
    pool.close();
  });

  test("one refused relay does not block the others' aggregate oneose", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    let closed: string | undefined;
    const closer = pool.subscribe(
      ["wss://ok-mixed.example", "wss://refused-mixed.example"],
      [{ kinds: [1] }],
      {
        oneose: () => {
          eose += 1;
        },
        onclose: (reason) => {
          closed = reason;
        },
      },
    );
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    const refused = socketFor("refused-mixed.example");
    refused.receive(JSON.stringify(["CLOSED", reqId(refused), "rate-limited: slow down"]));
    expect(eose).toBe(0);
    expect(closed).toBeUndefined();
    const ok = socketFor("ok-mixed.example");
    ok.receive(JSON.stringify(["EOSE", reqId(ok)]));
    expect(eose).toBe(1);
    expect(closed).toBeUndefined();
    closer.close();
    pool.close();
  });

  test("all refused relays fire only onclose with the last reason", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let eose = 0;
    let closed: string | undefined;
    pool.subscribe(["wss://refused-a.example", "wss://refused-b.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    for (const ws of MockWebSocket.instances) {
      ws.receive(JSON.stringify(["CLOSED", reqId(ws), "rate-limited: slow down"]));
    }
    await waitUntil(() => closed !== undefined);
    expect(closed).toBe("rate-limited: slow down");
    expect(eose).toBe(0);
    pool.close();
  });

  test("attach RelayClosedError after ensureRelay fires onclose(all relays failed)", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const origEnsure = pool.ensureRelay.bind(pool);
    pool.ensureRelay = async (url, opts) => {
      const relay = await origEnsure(url, opts);
      expect(relay.connected).toBe(true);
      MockWebSocket.last().close();
      expect(relay.connected).toBe(false);
      return relay;
    };

    const rejections: unknown[] = [];
    const onUnhandled = (reason: unknown) => {
      rejections.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    let closed: string | undefined;
    try {
      pool.subscribe(["wss://attach-closed.example"], [{ kinds: [1] }], {
        onclose: (reason) => {
          closed = reason;
        },
      });
      await waitUntil(() => closed !== undefined);
      await sleep(20);
      expect(closed).toBe("all relays failed");
      expect(rejections).toStrictEqual([]);
      expect(
        MockWebSocket.instances.every((ws) => !sentMessages(ws).some((m) => m[0] === "REQ")),
      ).toBe(true);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      pool.close();
    }
  });

  test("reconnect EOSE on one URL does not complete the set while the other is silent", async () => {
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
      reconnectBackoffMs: [10],
    });
    let eose = 0;
    const closer = pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      oneose: () => {
        eose += 1;
      },
    });
    await waitUntil(all(instanceCountIs(2), everyInstanceSent("REQ")));
    const firstA = socketFor("a.example");
    const b = socketFor("b.example");
    firstA.receive(JSON.stringify(["EOSE", reqId(firstA)]));
    expect(eose).toBe(0);

    firstA.close();
    await waitUntil(() => otherOpenInstanceSent(firstA, "a.example", "REQ"));
    const secondA = must(openInstance(firstA, "a.example"), "second socket");
    secondA.receive(JSON.stringify(["EOSE", reqId(secondA)]));
    await sleep(20);
    expect(eose).toBe(0);

    b.receive(JSON.stringify(["EOSE", reqId(b)]));
    expect(eose).toBe(1);
    closer.close();
    pool.close();
  });

  test("fetch, count, and publish do not arm reconnect on first connect failure", async () => {
    MockWebSocket.failConnect = true;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: true,
      reconnectBackoffMs: [10],
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("one-shot").createdAt(1).signWithKeys(keys);

    const events = await pool.fetch(["wss://fetch-fail.example"], [{ kinds: [1] }], {
      timeoutMs: 50,
    });
    expect(events).toStrictEqual([]);

    const counts = await pool.count(["wss://count-fail.example"], [{ kinds: [1] }], {
      timeoutMs: 50,
    });
    expect(counts).toHaveLength(1);
    expect(counts[0]).toMatchObject({ status: "failed", error: expect.stringMatching(/\S/) });

    const pubs = await pool.publish(["wss://pub-fail.example"], note);
    expect(pubs).toHaveLength(1);
    expect(pubs[0]).toMatchObject({ status: "failed", error: expect.stringMatching(/\S/) });

    expect(MockWebSocket.instances).toHaveLength(3);
    await sleep(40);
    expect(MockWebSocket.instances).toHaveLength(3);
    pool.close();
  });

  test("all connect failures fire onclose once even if the handler calls close", async () => {
    MockWebSocket.failConnect = true;
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    let n = 0;
    const closer = pool.subscribe(["wss://a.example", "wss://b.example"], [{ kinds: [1] }], {
      onclose: () => {
        n += 1;
        closer.close();
      },
    });
    await waitUntil(() => n >= 1);
    await sleep(20);
    expect(n).toBe(1);
    pool.close();
  });

  test("invalid URL after a valid one does not throw and caller close CLOSEs the valid REQ", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const closer = pool.subscribe(["wss://ok.example", "not a url"], [{ kinds: [1] }]);
    await waitUntil(() => MockWebSocket.instances.some(urlSent("ok.example", "REQ")));
    const ok = socketFor("ok.example");
    closer.close();
    expect(sentMessages(ok).some((m) => m[0] === "CLOSE")).toBe(true);
    pool.close();
  });

  test("automaticallyAuth is invoked once and the same signer answers AUTH", async () => {
    const keys = Keys.fromSecretKey(SK);
    let calls = 0;
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      automaticallyAuth: (url) => {
        calls += 1;
        expect(url).toContain("auth-once.example");
        return authSignerFor(keys);
      },
    });
    await pool.ensureRelay("wss://auth-once.example");
    expect(calls).toBe(1);
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "once-challenge"]));
    await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
    expect(calls).toBe(1);
    pool.close();
  });

  test("a repeated identical challenge does not send a second AUTH frame", async () => {
    const keys = Keys.fromSecretKey(SK);
    const pool = new Pool({
      websocketImplementation: MockWebSocketCtor,
      automaticallyAuth: () => authSignerFor(keys),
    });
    try {
      await pool.ensureRelay("wss://auth-dup.example");
      const ws = MockWebSocket.last();
      ws.receive(JSON.stringify(["AUTH", "same-challenge"]));
      await waitUntil(() => sentMessages(ws).some((m) => m[0] === "AUTH"));
      ws.receive(JSON.stringify(["AUTH", "same-challenge"]));
      await sleep(30);
      expect(sentMessages(ws).filter((m) => m[0] === "AUTH")).toHaveLength(1);
    } finally {
      pool.close();
    }
  });
});

function framesOf(ws: MockWebSocket, type: string): unknown[][] {
  return sentMessages(ws).filter((m) => m[0] === type);
}

describe("live REQ coalescing", () => {
  test("two identical live subscribe send one REQ and fan out EVENT", async () => {
    const relay = await Relay.connect("wss://coal.example");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("hi").createdAt(1).signWithKeys(keys);
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], { onevent: (e) => aEvents.push(e.id) });
    const b = relay.subscribe([{ kinds: [1] }], { onevent: (e) => bEvents.push(e.id) });
    expect(b.id).toBe(a.id);
    const ws = MockWebSocket.last();
    expect(framesOf(ws, "REQ")).toHaveLength(1);
    expect((framesOf(ws, "REQ")[0] as [string, string])[1]).toBe(a.id);
    ws.receive(JSON.stringify(["EVENT", a.id, note]));
    expect(aEvents).toStrictEqual([note.id]);
    expect(bEvents).toStrictEqual([note.id]);
    relay.close();
  });

  test("close first of two live attachments does not CLOSE; remaining gets later EVENT", async () => {
    const relay = await Relay.connect("wss://coal-close1.example");
    const keys = Keys.fromSecretKey(SK);
    const first = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const second = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], { onevent: (e) => aEvents.push(e.id) });
    const b = relay.subscribe([{ kinds: [1] }], { onevent: (e) => bEvents.push(e.id) });
    const ws = MockWebSocket.last();
    a.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(0);
    expect(a.closed).toBe(true);
    expect(b.closed).toBe(false);
    ws.receive(JSON.stringify(["EVENT", b.id, first]));
    expect(aEvents).toStrictEqual([]);
    expect(bEvents).toStrictEqual([first.id]);
    ws.receive(JSON.stringify(["EVENT", b.id, second]));
    expect(bEvents).toStrictEqual([first.id, second.id]);
    relay.close();
  });

  test("close last live attachment sends one CLOSE", async () => {
    const relay = await Relay.connect("wss://coal-close2.example");
    const a = relay.subscribe([{ kinds: [1] }]);
    const b = relay.subscribe([{ kinds: [1] }]);
    const ws = MockWebSocket.last();
    a.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(0);
    b.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(1);
    expect((framesOf(ws, "CLOSE")[0] as [string, string])[1]).toBe(a.id);
    expect(relay.subscriptionCount).toBe(0);
    const c = relay.subscribe([{ kinds: [1] }]);
    expect(c.closed).toBe(false);
    expect(framesOf(ws, "REQ")).toHaveLength(2);
    expect(relay.subscriptionCount).toBe(1);
    relay.close();
  });

  test("limit 10 vs 50 does not coalesce", async () => {
    const relay = await Relay.connect("wss://coal-limit.example");
    const a = relay.subscribe([{ kinds: [1], limit: 10 }]);
    const b = relay.subscribe([{ kinds: [1], limit: 50 }]);
    expect(a.id).not.toBe(b.id);
    const ws = MockWebSocket.last();
    expect(framesOf(ws, "REQ")).toHaveLength(2);
    relay.close();
  });

  test("fetch while live same filters uses a separate REQ then CLOSE; live stays", async () => {
    const relay = await Relay.connect("wss://coal-fetch.example");
    const keys = Keys.fromSecretKey(SK);
    const liveNote = EventBuilder.textNote("live").createdAt(2).signWithKeys(keys);
    const fetchNote = EventBuilder.textNote("fetch").createdAt(1).signWithKeys(keys);
    const liveEvents: string[] = [];
    const live = relay.subscribe([{ kinds: [1] }], { onevent: (e) => liveEvents.push(e.id) });
    const fetchP = relay.fetch([{ kinds: [1] }], { timeoutMs: 2000 });
    await Promise.resolve();
    const ws = MockWebSocket.last();
    const reqs = framesOf(ws, "REQ") as Array<[string, string]>;
    expect(reqs).toHaveLength(2);
    const [, firstReqId] = must(reqs[0], "first REQ");
    expect(firstReqId).toBe(live.id);
    const [, fetchId] = must(reqs[1], "second REQ");
    expect(fetchId).not.toBe(live.id);
    ws.receive(JSON.stringify(["EVENT", fetchId, fetchNote]));
    ws.receive(JSON.stringify(["EOSE", fetchId]));
    const fetched = await fetchP;
    expect(fetched.events.map((e) => e.id)).toStrictEqual([fetchNote.id]);
    expect(framesOf(ws, "CLOSE").some((m) => m[1] === fetchId)).toBe(true);
    expect(framesOf(ws, "CLOSE").some((m) => m[1] === live.id)).toBe(false);
    expect(live.closed).toBe(false);
    ws.receive(JSON.stringify(["EVENT", live.id, liveNote]));
    expect(liveEvents).toStrictEqual([liveNote.id]);
    live.close();
    expect(framesOf(ws, "CLOSE").some((m) => m[1] === live.id)).toBe(true);
    relay.close();
  });

  test("late attach after EOSE opens a fresh wire that replays stored events", async () => {
    const relay = await Relay.connect("wss://coal-late.example");
    const keys = Keys.fromSecretKey(SK);
    const old = EventBuilder.textNote("old").createdAt(1).signWithKeys(keys);
    let eoseA = 0;
    let eoseB = 0;
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => aEvents.push(e.id),
      oneose: () => {
        eoseA += 1;
      },
    });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", a.id, old]));
    ws.receive(JSON.stringify(["EOSE", a.id]));
    expect(eoseA).toBe(1);

    const b = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => bEvents.push(e.id),
      oneose: () => {
        eoseB += 1;
      },
    });
    expect(b.id).not.toBe(a.id);
    const reqs = framesOf(ws, "REQ") as Array<[string, string]>;
    expect(reqs).toHaveLength(2);
    expect(reqs[1]![1]).toBe(b.id);
    expect(eoseB).toBe(0);

    // The new wire replays everything the relay still holds for the filter.
    ws.receive(JSON.stringify(["EVENT", b.id, old]));
    expect(bEvents).toStrictEqual([old.id]);
    ws.receive(JSON.stringify(["EOSE", b.id]));
    expect(eoseB).toBe(1);
    relay.close();
  });

  test("post-EOSE wires detach independently of each other", async () => {
    const relay = await Relay.connect("wss://coal-detach.example");
    const a = relay.subscribe([{ kinds: [1] }]);
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EOSE", a.id]));
    // B opens a fresh wire; C coalesces into it since it has not EOSE'd.
    const b = relay.subscribe([{ kinds: [1] }]);
    const c = relay.subscribe([{ kinds: [1] }]);
    expect(b.id).not.toBe(a.id);
    expect(c.id).toBe(b.id);
    expect(framesOf(ws, "REQ")).toHaveLength(2);
    expect(relay.subscriptionCount).toBe(2);

    // Closing A's whole group sends CLOSE for its wire only; B/C stay live.
    a.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(1);
    expect((framesOf(ws, "CLOSE")[0] as [string, string])[1]).toBe(a.id);
    expect(b.closed).toBe(false);
    expect(c.closed).toBe(false);
    expect(relay.subscriptionCount).toBe(1);

    // Forgetting the old group must not unlink B's fingerprint slot: a fourth
    // subscriber still coalesces into the open B wire.
    const d = relay.subscribe([{ kinds: [1] }]);
    expect(d.id).toBe(b.id);
    expect(framesOf(ws, "REQ")).toHaveLength(2);

    c.close();
    d.close();
    expect(b.closed).toBe(false);
    b.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(2);
    expect((framesOf(ws, "CLOSE")[1] as [string, string])[1]).toBe(b.id);
    expect(relay.subscriptionCount).toBe(0);
    relay.close();
  });

  test("reconnect resends one REQ per wire, both pre- and post-EOSE groups", async () => {
    const relay = new Relay("wss://coal-re2.example", {
      enableReconnect: true,
      reconnectBackoffMs: [10, 20],
      websocketImplementation: MockWebSocketCtor,
    });
    await relay.connect();
    const a = relay.subscribe([{ kinds: [1] }]);
    const first = MockWebSocket.last();
    first.receive(JSON.stringify(["EOSE", a.id]));
    const b = relay.subscribe([{ kinds: [1] }]);
    expect(b.id).not.toBe(a.id);
    expect(framesOf(first, "REQ")).toHaveLength(2);

    first.close();
    await waitUntil(
      all(
        () => relay.connected,
        () => MockWebSocket.instances.length >= 2,
        () => framesOf(MockWebSocket.last(), "REQ").length === 2,
      ),
    );
    const second = MockWebSocket.last();
    expect(second).not.toBe(first);
    const replayed = framesOf(second, "REQ") as Array<[string, string]>;
    expect(replayed.map((m) => m[1]).toSorted()).toStrictEqual([a.id, b.id].toSorted());
    relay.close();
  });

  test("authors hex case and order canonicalize to one REQ", async () => {
    const relay = await Relay.connect("wss://coal-authors.example");
    const pkA = "aa".repeat(32);
    const pkB = "bb".repeat(32);
    const a = relay.subscribe([
      { authors: [pkA.toUpperCase(), pkB], kinds: [2, 1], "#t": ["z", "a"] },
    ]) as Subscription;
    const b = relay.subscribe([
      { authors: [pkB.toUpperCase(), pkA.toLowerCase()], kinds: [1, 2], "#t": ["a", "z"] },
    ]);
    expect(b.id).toBe(a.id);
    const reqs = framesOf(MockWebSocket.last(), "REQ");
    expect(reqs).toHaveLength(1);
    const payload = reqs[0]![2] as { authors: string[]; kinds: number[]; "#t": string[] };
    expect(payload.authors).toStrictEqual([pkA, pkB]);
    expect(payload.kinds).toStrictEqual([1, 2]);
    expect(payload["#t"]).toStrictEqual(["a", "z"]);
    expect(a.filters[0]?.authors).toStrictEqual(payload.authors);
    expect(a.filters[0]?.kinds).toStrictEqual(payload.kinds);
    expect(a.filters[0]?.["#t"]).toStrictEqual(payload["#t"]);
    relay.close();
  });

  test("closeOnEose false and omitted both coalesce; true does not", async () => {
    const relay = await Relay.connect("wss://coal-flag.example");
    const omitted = relay.subscribe([{ kinds: [1] }]);
    const explicitFalse = relay.subscribe([{ kinds: [1] }], { closeOnEose: false });
    const oneShot = relay.subscribe([{ kinds: [1] }], { closeOnEose: true });
    expect(explicitFalse.id).toBe(omitted.id);
    expect(oneShot.id).not.toBe(omitted.id);
    const ws = MockWebSocket.last();
    expect(framesOf(ws, "REQ")).toHaveLength(2);
    ws.receive(JSON.stringify(["EOSE", oneShot.id]));
    expect(oneShot.closed).toBe(true);
    expect(omitted.closed).toBe(false);
    expect(framesOf(ws, "CLOSE").some((m) => m[1] === oneShot.id)).toBe(true);
    expect(framesOf(ws, "CLOSE").some((m) => m[1] === omitted.id)).toBe(false);
    relay.close();
  });

  test("alreadyHaveEvent skips that listener only; verify once", async () => {
    let verifies = 0;
    const relay = await Relay.connect("wss://coal-have.example", {
      verifyEvent: (event) => {
        verifies += 1;
        return verifyEvent(event);
      },
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("dup").createdAt(1).signWithKeys(keys);
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const received: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], {
      alreadyHaveEvent: () => true,
      receivedEvent: (id) => received.push(`a:${id}`),
      onevent: (e) => aEvents.push(e.id),
    }) as Subscription;
    const b = relay.subscribe([{ kinds: [1] }], {
      alreadyHaveEvent: () => false,
      receivedEvent: (id) => received.push(`b:${id}`),
      onevent: (e) => bEvents.push(e.id),
    }) as Subscription;
    expect(b.id).toBe(a.id);
    MockWebSocket.last().receive(JSON.stringify(["EVENT", a.id, note]));
    expect(verifies).toBe(1);
    expect(aEvents).toStrictEqual([]);
    expect(bEvents).toStrictEqual([note.id]);
    expect(received).toStrictEqual([`a:${note.id}`, `b:${note.id}`]);
    expect(a.lastCreatedAt).toBeUndefined();
    expect(b.lastCreatedAt).toBe(note.created_at);
    relay.close();
  });

  test("CLOSED on the wire id closes every attachment", async () => {
    const relay = await Relay.connect("wss://coal-closed.example");
    const reasons: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], {
      onclose: (r) => reasons.push(`a:${r}`),
    });
    const b = relay.subscribe([{ kinds: [1] }], {
      onclose: (r) => reasons.push(`b:${r}`),
    });
    MockWebSocket.last().receive(JSON.stringify(["CLOSED", a.id, "bye"]));
    expect(a.closed).toBe(true);
    expect(b.closed).toBe(true);
    expect(reasons).toStrictEqual(["a:bye", "b:bye"]);
    expect(relay.subscriptionCount).toBe(0);
    relay.close();
  });

  test("subset authors and missing authors [] do not coalesce", async () => {
    const relay = await Relay.connect("wss://coal-subset.example");
    const pkA = "aa".repeat(32);
    const pkB = "bb".repeat(32);
    const full = relay.subscribe([{ authors: [pkA, pkB] }]);
    const subset = relay.subscribe([{ authors: [pkA] }]);
    const missing = relay.subscribe([{ kinds: [1] }]);
    const empty = relay.subscribe([{ kinds: [1], authors: [] }]);
    expect(new Set([full.id, subset.id, missing.id, empty.id]).size).toBe(4);
    expect(framesOf(MockWebSocket.last(), "REQ")).toHaveLength(4);
    relay.close();
  });

  test("reconnect resubscribes one REQ for a coalesced group; both get EVENT", async () => {
    const relay = new Relay("wss://coal-re.example", {
      enableReconnect: true,
      reconnectBackoffMs: [10, 20],
      websocketImplementation: MockWebSocketCtor,
    });
    await relay.connect();
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("after").createdAt(1).signWithKeys(keys);
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], { onevent: (e) => aEvents.push(e.id) });
    const b = relay.subscribe([{ kinds: [1] }], { onevent: (e) => bEvents.push(e.id) });
    const first = MockWebSocket.last();
    expect(framesOf(first, "REQ")).toHaveLength(1);
    first.close();
    await waitUntil(
      all(
        () => relay.connected,
        () => MockWebSocket.instances.length >= 2,
        () => framesOf(MockWebSocket.last(), "REQ").length > 0,
      ),
    );
    const second = MockWebSocket.last();
    expect(second).not.toBe(first);
    expect(framesOf(second, "REQ")).toHaveLength(1);
    expect((framesOf(second, "REQ")[0] as [string, string])[1]).toBe(a.id);
    second.receive(JSON.stringify(["EVENT", a.id, note]));
    expect(aEvents).toStrictEqual([note.id]);
    expect(bEvents).toStrictEqual([note.id]);
    expect(b.id).toBe(a.id);
    relay.close();
  });

  test("aborted signal at subscribe does not send REQ", async () => {
    const relay = await Relay.connect("wss://coal-abort-new.example");
    const ac = new AbortController();
    ac.abort();
    const sub = relay.subscribe([{ kinds: [1] }], { signal: ac.signal });
    expect(sub.closed).toBe(true);
    const ws = MockWebSocket.last();
    expect(framesOf(ws, "REQ")).toHaveLength(0);
    expect(relay.subscriptionCount).toBe(0);
    const live = relay.subscribe([{ kinds: [1] }]);
    expect(live.closed).toBe(false);
    expect(framesOf(ws, "REQ")).toHaveLength(1);
    expect(relay.subscriptionCount).toBe(1);
    relay.close();
  });

  test("abort one attachment does not CLOSE; remaining still live", async () => {
    const relay = await Relay.connect("wss://coal-abort-one.example");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("stay").createdAt(1).signWithKeys(keys);
    const ac = new AbortController();
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = relay.subscribe([{ kinds: [1] }], {
      signal: ac.signal,
      onevent: (e) => aEvents.push(e.id),
    });
    const b = relay.subscribe([{ kinds: [1] }], { onevent: (e) => bEvents.push(e.id) });
    const ws = MockWebSocket.last();
    expect(framesOf(ws, "REQ")).toHaveLength(1);
    ac.abort();
    expect(a.closed).toBe(true);
    expect(b.closed).toBe(false);
    expect(framesOf(ws, "CLOSE")).toHaveLength(0);
    ws.receive(JSON.stringify(["EVENT", b.id, note]));
    expect(aEvents).toStrictEqual([]);
    expect(bEvents).toStrictEqual([note.id]);
    relay.close();
  });

  test("onevent/oneose/onclose throw on A still delivers to B", async () => {
    const relay = await Relay.connect("wss://coal-isolate.example");
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("iso").createdAt(1).signWithKeys(keys);
    const bEvents: string[] = [];
    let eoseB = 0;
    const a = relay.subscribe([{ kinds: [1] }], {
      onevent: () => {
        throw new Error("a-onevent");
      },
      oneose: () => {
        throw new Error("a-oneose");
      },
      onclose: () => {
        throw new Error("a-onclose");
      },
    });
    const b = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => bEvents.push(e.id),
      oneose: () => {
        eoseB += 1;
      },
    });
    const ws = MockWebSocket.last();
    const { reported, restore } = stubReportError();
    try {
      ws.receive(JSON.stringify(["EVENT", a.id, note]));
      expect(bEvents).toStrictEqual([note.id]);
      ws.receive(JSON.stringify(["EOSE", a.id]));
      expect(eoseB).toBe(1);
      ws.receive(JSON.stringify(["CLOSED", a.id, "bye"]));
      expect(b.closed).toBe(true);
      expect(a.closed).toBe(true);
      relay.close();
    } finally {
      restore();
    }
    expect(reported.map(errText)).toStrictEqual(["a-onevent", "a-oneose", "a-onclose"]);
  });

  test("Pool.subscribe twice same URL+filters sends one REQ", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const url = "wss://coal-pool.example";
    const relay = await pool.ensureRelay(url);
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("p").createdAt(1).signWithKeys(keys);
    const aEvents: string[] = [];
    const bEvents: string[] = [];
    const a = pool.subscribe([url], [{ kinds: [1] }], {
      onevent: (e) => aEvents.push(e.id),
    });
    const b = pool.subscribe([url], [{ kinds: [1] }], {
      onevent: (e) => bEvents.push(e.id),
    });
    const ws = socketFor("coal-pool.example");
    await waitUntil(
      all(
        () => relay.subscriptionCount === 1,
        () => framesOf(ws, "REQ").length > 0,
      ),
    );
    await Promise.resolve();
    await Promise.resolve();
    expect(framesOf(ws, "REQ")).toHaveLength(1);
    const [, id] = framesOf(ws, "REQ")[0] as [string, string];
    ws.receive(JSON.stringify(["EVENT", id, note]));
    expect(aEvents).toStrictEqual([note.id]);
    expect(bEvents).toStrictEqual([note.id]);
    a.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(0);
    b.close();
    expect(framesOf(ws, "CLOSE")).toHaveLength(1);
    pool.close();
  });

  test("Pool late attach after EOSE opens a fresh REQ on a new wire", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const url = "wss://coal-pool-late.example";
    const relay = await pool.ensureRelay(url);
    let eoseA = 0;
    let eoseB = 0;
    const a = pool.subscribe([url], [{ kinds: [1] }], {
      oneose: () => {
        eoseA += 1;
      },
    });
    const ws = socketFor("coal-pool-late.example");
    await waitUntil(
      all(
        () => relay.subscriptionCount === 1,
        () => framesOf(ws, "REQ").length > 0,
      ),
    );
    const [, id] = framesOf(ws, "REQ")[0] as [string, string];
    ws.receive(JSON.stringify(["EOSE", id]));
    expect(eoseA).toBe(1);
    const b = pool.subscribe([url], [{ kinds: [1] }], {
      oneose: () => {
        eoseB += 1;
      },
    });
    // The coalesced wire already ended; the second subscribe gets its own REQ.
    await waitUntil(() => framesOf(ws, "REQ").length === 2);
    const [, idB] = framesOf(ws, "REQ")[1] as [string, string];
    expect(idB).not.toBe(id);
    ws.receive(JSON.stringify(["EOSE", idB]));
    await waitUntil(() => eoseB === 1);
    expect(eoseA).toBe(1);
    a.close();
    b.close();
    pool.close();
  });
});

describe("issue #125", () => {
  test("#14 maxRelays does not close a relay that is still connecting", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor, maxRelays: 1 });
    const results = await Promise.allSettled([
      pool.ensureRelay("wss://a.example"),
      pool.ensureRelay("wss://b.example"),
      pool.ensureRelay("wss://c.example"),
    ]);
    expect(results.map((r) => r.status)).toStrictEqual(["fulfilled", "fulfilled", "fulfilled"]);
    pool.close();
  });

  test("#15 AUTH retries after a timed-out or rejected AUTH frame", async () => {
    const keys = Keys.fromSecretKey(SK);
    const signer = new KeysSigner(keys);
    const sign = async (template: EventTemplate): Promise<Event> =>
      signer.signEvent({ ...template, pubkey: keys.publicKey });

    // a timed-out AUTH must not poison the challenge for the rest of the connection
    const relay = await Relay.connect("wss://auth-timeout.example", {
      websocketImplementation: MockWebSocketCtor,
      publishTimeoutMs: 40,
      enableReconnect: false,
    });
    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["AUTH", "chal"]));

    let signs = 0;
    const timedOutSign = async (template: EventTemplate): Promise<Event> => {
      signs += 1;
      return sign(template);
    };
    const firstAuthErr = await captureError(relay.auth(timedOutSign));
    expect(firstAuthErr).toBeInstanceOf(RelayTimeoutError);
    expect((firstAuthErr as Error).message).toMatch(/auth timed out/);
    const secondAuthErr = await captureError(relay.auth(timedOutSign));
    expect(secondAuthErr).toBeInstanceOf(RelayTimeoutError);
    expect(signs).toBe(2);
    expect(sentAuthEvents(ws)).toHaveLength(2);
    relay.close();

    // a rejected AUTH is cached for that challenge: a repeated auth() replays
    // the rejection without signing again, until resetAuth() clears it
    const relay2 = await Relay.connect("wss://auth-reject.example", {
      websocketImplementation: MockWebSocketCtor,
      publishTimeoutMs: 2000,
      enableReconnect: false,
    });
    const ws2 = MockWebSocket.last();
    ws2.receive(JSON.stringify(["AUTH", "chal2"]));

    let signs2 = 0;
    const sign2 = async (template: EventTemplate): Promise<Event> => {
      signs2 += 1;
      return sign(template);
    };
    const first = relay2.auth(sign2);
    await waitUntil(() => sentAuthEvents(ws2).length === 1);
    ws2.receive(JSON.stringify(["OK", sentAuthEvents(ws2)[0]!.id, false, "error: rejected"]));
    const firstResult = await first;
    expect(firstResult.ok).toBe(false);

    const cached = await relay2.auth(sign2);
    expect(cached.ok).toBe(false);
    expect(signs2).toBe(1);
    expect(sentAuthEvents(ws2)).toHaveLength(1);

    relay2.resetAuth();
    const second = relay2.auth(sign2);
    await waitUntil(() => sentAuthEvents(ws2).length === 2);
    ws2.receive(JSON.stringify(["OK", sentAuthEvents(ws2)[1]!.id, true, ""]));
    const secondResult = await second;
    expect(secondResult.ok).toBe(true);
    expect(signs2).toBe(2);
    relay2.close();
  });
});

describe("issue #130", () => {
  test("connect timeout rejects with RelayTimeoutError", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://connect-timeout.example", {
      websocketImplementation: MockWebSocketCtor,
      connectTimeoutMs: 30,
      enableReconnect: false,
    });
    const err = await captureError(relay.connect());
    expect(err).toBeInstanceOf(RelayTimeoutError);
    expect((err as Error).message).toMatch(/connection timed out/);
    relay.close();
  });

  test("connect aborts with signal.reason", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://connect-abort.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const ac = new AbortController();
    const reason = new Error("cancelled by caller");
    const connectP = relay.connect({ signal: ac.signal });
    ac.abort(reason);
    await expect(connectP).rejects.toBe(reason);
    relay.close();
  });

  test("publish timeout rejects with RelayTimeoutError", async () => {
    const keys = Keys.fromSecretKey(SK);
    const relay = await Relay.connect("wss://pub-timeout.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const note = EventBuilder.textNote("never acked").createdAt(2).signWithKeys(keys);
    const err = await captureError(relay.publish(note, { timeoutMs: 40 }));
    expect(err).toBeInstanceOf(RelayTimeoutError);
    expect((err as Error).message).toMatch(/publish timed out/);
    relay.close();
  });

  test("Relay.fetch aborts mid-flight with signal.reason", async () => {
    const relay = await Relay.connect("wss://fetch-abort.example", {
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const ac = new AbortController();
    const reason = new Error("user aborted");
    const fetchP = relay.fetch([{ kinds: [1] }], { timeoutMs: 2000, signal: ac.signal });
    ac.abort(reason);
    await expect(fetchP).rejects.toBe(reason);
    relay.close();
  });

  test("Pool.fetch aborts mid-flight with signal.reason", async () => {
    const pool = new Pool({ websocketImplementation: MockWebSocketCtor });
    const ac = new AbortController();
    const reason = new Error("user aborted");
    const fetchP = pool.fetch(["wss://pool-abort.example"], [{ kinds: [1] }], {
      timeoutMs: 2000,
      signal: ac.signal,
    });
    await waitUntil(() => MockWebSocket.instances.length === 1);
    ac.abort(reason);
    await expect(fetchP).rejects.toBe(reason);
    pool.close();
  });

  test("throwing notice and close listeners are reported without breaking teardown", async () => {
    const { reported, restore } = stubReportError();
    try {
      const relay = await Relay.connect("wss://cb-throw.example", {
        websocketImplementation: MockWebSocketCtor,
        enableReconnect: false,
      });
      const noticeBoom = new Error("notice boom");
      const closeBoom = new Error("close boom");
      relay.on("notice", () => {
        throw noticeBoom;
      });
      relay.on("close", () => {
        throw closeBoom;
      });
      MockWebSocket.last().receive(JSON.stringify(["NOTICE", "heads up"]));
      expect(reported).toStrictEqual([noticeBoom]);
      expect(relay.connected).toBe(true);

      relay.close();
      expect(reported).toStrictEqual([noticeBoom, closeBoom]);
      expect(relay.status).toBe(RelayStatus.Closed);
    } finally {
      restore();
    }
  });
});

describe("connect ownership (issue #134)", () => {
  test("starter abort rejects only the starter; the joiner resolves and live subscriptions work", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://relay.example.com");
    const reason = new Error("caller aborted");
    const ctrl = new AbortController();
    const pA = relay.connect({ signal: ctrl.signal });
    const pB = relay.connect();
    const errA = captureError(pA);
    ctrl.abort(reason);
    await expect(errA).resolves.toBe(reason);
    expect(relay.connected).toBe(false);

    // The shared attempt is still in flight and completes for the joiner.
    MockWebSocket.last().open();
    await pB;
    expect(relay.connected).toBe(true);

    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("hi").createdAt(1).signWithKeys(keys);
    const events: Event[] = [];
    const sub = relay.subscribe([{ kinds: [1] }], {
      onevent: (e) => events.push(e),
    });
    MockWebSocket.last().receive(JSON.stringify(["EVENT", sub.id, note]));
    expect(events).toHaveLength(1);
    relay.close();
  });

  test("a joiner's own signal aborts only its wait", async () => {
    MockWebSocket.autoConnect = false;
    const relay = new Relay("wss://relay.example.com");
    const pA = relay.connect();
    const reason = new Error("joiner aborted");
    const ctrl = new AbortController();
    const pB = relay.connect({ signal: ctrl.signal });
    const errB = captureError(pB);
    ctrl.abort(reason);
    await expect(errB).resolves.toBe(reason);

    MockWebSocket.last().open();
    await pA;
    expect(relay.connected).toBe(true);
    relay.close();
  });

  test("a pre-aborted signal rejects without opening a socket", async () => {
    const relay = new Relay("wss://relay.example.com");
    const reason = new Error("aborted before connect");
    const ctrl = new AbortController();
    ctrl.abort(reason);
    const err = await captureError(relay.connect({ signal: ctrl.signal }));
    expect(err).toBe(reason);
    expect(MockWebSocket.instances).toHaveLength(0);
    expect(relay.connected).toBe(false);
  });
});

describe("subscriptionToAsyncIterable close semantics (issue #134)", () => {
  function makeIterable(opts?: { signal?: AbortSignal; includeEose?: boolean }) {
    let handlers: SubscriptionHandlers | undefined;
    const closeReasons: string[] = [];
    const iterable = subscriptionToAsyncIterable((h) => {
      handlers = h;
      return {
        close: (reason = "closed by client") => {
          closeReasons.push(reason);
          handlers?.onclose?.(reason);
        },
      };
    }, opts);
    return { iterable, fire: () => handlers!, closeReasons };
  }

  const keys = Keys.fromSecretKey(SK);
  const note = (content: string, created_at: number) =>
    EventBuilder.textNote(content).createdAt(created_at).signWithKeys(keys);

  test("remote close drains queued events, then throws RelayClosedError", async () => {
    const { iterable, fire } = makeIterable();
    const a = note("a", 1);
    const b = note("b", 2);
    fire().onevent?.(a);
    fire().onevent?.(b);
    fire().onclose?.("relay went away");

    const it = iterable[Symbol.asyncIterator]();
    const nextA = await it.next();
    expect(nextA.value?.id).toBe(a.id);
    const nextB = await it.next();
    expect(nextB.value?.id).toBe(b.id);
    const err = await it.next().then(
      () => {
        throw new Error("expected throw");
      },
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(RelayClosedError);
    expect((err as RelayClosedError).message).toBe("relay went away");
  });

  test("iterator return() is a local close and completes normally", async () => {
    const { iterable, fire, closeReasons } = makeIterable();
    fire().onevent?.(note("a", 1));
    const got: string[] = [];
    for await (const e of iterable) {
      got.push(e.id);
      break;
    }
    expect(got).toHaveLength(1);
    expect(closeReasons).toStrictEqual(["iterator returned"]);
  });

  test("signal abort is a local close and drains queued events", async () => {
    const ctrl = new AbortController();
    const { iterable, fire, closeReasons } = makeIterable({ signal: ctrl.signal });
    const a = note("a", 1);
    fire().onevent?.(a);
    ctrl.abort(new Error("stop"));
    const it = iterable[Symbol.asyncIterator]();
    const abortedNext = await it.next();
    expect(abortedNext.value?.id).toBe(a.id);
    const abortedDone = await it.next();
    expect(abortedDone.done).toBe(true);
    expect(closeReasons).toStrictEqual(["aborted"]);
  });

  test("EOSE with includeEose:false closes locally and completes normally", async () => {
    const { iterable, fire, closeReasons } = makeIterable({ includeEose: false });
    const a = note("a", 1);
    fire().onevent?.(a);
    fire().oneose?.();
    const it = iterable[Symbol.asyncIterator]();
    const eoseNext = await it.next();
    expect(eoseNext.value?.id).toBe(a.id);
    const eoseDone = await it.next();
    expect(eoseDone.done).toBe(true);
    expect(closeReasons).toStrictEqual(["eose"]);
  });

  test("iterable.close() is a local close and completes normally", async () => {
    const { iterable, fire, closeReasons } = makeIterable();
    fire().onevent?.(note("a", 1));
    iterable.close();
    const it = iterable[Symbol.asyncIterator]();
    await it.next();
    const closedNext = await it.next();
    expect(closedNext.done).toBe(true);
    expect(closeReasons).toStrictEqual(["closed by client"]);
  });
});

describe("relay.stream abort semantics (issue #134)", () => {
  test("signal abort mid-stream drains queued events and completes without throwing", async () => {
    const relay = await Relay.connect("wss://stream-abort.example", {
      websocketImplementation: MockWebSocketCtor,
    });
    const keys = Keys.fromSecretKey(SK);
    const a = EventBuilder.textNote("a").createdAt(1).signWithKeys(keys);
    const b = EventBuilder.textNote("b").createdAt(2).signWithKeys(keys);
    const ctrl = new AbortController();
    const stream = relay.stream([{ kinds: [1] }], { signal: ctrl.signal });
    const it = stream[Symbol.asyncIterator]();

    const ws = MockWebSocket.last();
    const req = ws.lastSent() as [string, string, ...unknown[]];
    expect(req[0]).toBe("REQ");
    const [, subId] = req;
    ws.receive(JSON.stringify(["EVENT", subId, a]));
    ws.receive(JSON.stringify(["EVENT", subId, b]));

    // The Subscription's abort listener fires before the iterable wrapper's;
    // both are local closes, so no RelayClosedError reaches the consumer.
    ctrl.abort(new Error("caller aborted"));
    const drainA = await it.next();
    expect(drainA.value?.id).toBe(a.id);
    const drainB = await it.next();
    expect(drainB.value?.id).toBe(b.id);
    await expect(it.next()).resolves.toStrictEqual({ value: undefined, done: true });
    relay.close();
  });
});

describe("duplicate publish and abort-listener cleanup", () => {
  let net: FakeRelayNetwork;

  beforeEach(() => {
    net = createFakeRelayNetwork();
  });

  afterEach(() => {
    net.close();
  });

  const note = (content: string): Event =>
    EventBuilder.textNote(content).createdAt(1).signWithKeys(Keys.fromSecretKey(SK));

  /** Net "abort" listeners on one signal via an instance-level monkeypatch. */
  const trackAbortListeners = (signal: AbortSignal): { added: number; removed: number } => {
    const tracked = { added: 0, removed: 0 };
    const add = signal.addEventListener.bind(signal);
    const remove = signal.removeEventListener.bind(signal);
    signal.addEventListener = (type: string, listener: unknown, opts?: unknown) => {
      if (type === "abort") {
        tracked.added += 1;
      }
      return add(type, listener as EventListener, opts as AddEventListenerOptions);
    };
    signal.removeEventListener = (type: string, listener: unknown, opts?: unknown) => {
      if (type === "abort") {
        tracked.removed += 1;
      }
      return remove(type, listener as EventListener, opts as EventListenerOptions);
    };
    return tracked;
  };

  const netListeners = (tracked: { added: number; removed: number }): number =>
    tracked.added - tracked.removed;

  test("two concurrent relay.publish calls of the same event both resolve ok", async () => {
    const relay = new Relay("wss://dup-publish.example", {
      websocketImplementation: net.websocketImplementation,
      publishTimeoutMs: 300,
      enableReconnect: false,
    });
    try {
      await relay.connect();
      const ev = note("dup");
      const [a, b] = await Promise.allSettled([relay.publish(ev), relay.publish(ev)]);
      expect(a).toStrictEqual({ status: "fulfilled", value: { ok: true, message: "" } });
      expect(b).toStrictEqual({ status: "fulfilled", value: { ok: true, message: "" } });
    } finally {
      relay.close();
    }
  });

  test("pool.publish dedupes equivalent URL spellings to a single relay entry", async () => {
    const pool = new Pool({
      websocketImplementation: net.websocketImplementation,
      publishTimeoutMs: 300,
      enableReconnect: false,
    });
    try {
      const results = await pool.publish(["wss://dup.example", "wss://dup.example/"], note("dup"));
      expect(results).toStrictEqual([{ url: "wss://dup.example/", status: "ok", message: "" }]);
    } finally {
      pool.close();
    }
  });

  test("relay.fetch leaves no abort listeners after 5 EOSE-completed fetches", async () => {
    const relay = new Relay("wss://fetch.example", {
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      await relay.connect();
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        // oxlint-disable-next-line no-await-in-loop -- sequential fetches must finish before the listener count is read
        const result = await relay.fetch([{ kinds: [1] }], {
          signal: controller.signal,
          timeoutMs: 300,
        });
        expect(result.end.type).toBe("eose");
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      relay.close();
    }
  });

  test("pool.fetch leaves no abort listeners after 5 EOSE-completed fetches", async () => {
    const pool = new Pool({
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        // oxlint-disable-next-line no-await-in-loop -- sequential fetches must finish before the listener count is read
        const events = await pool.fetch(["wss://fetch.example"], [{ kinds: [1] }], {
          signal: controller.signal,
          timeoutMs: 300,
        });
        expect(events).toStrictEqual([]);
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      pool.close();
    }
  });

  test("pool.fetchEach leaves no abort listeners after 5 EOSE-completed fetches", async () => {
    const pool = new Pool({
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        // oxlint-disable-next-line no-await-in-loop -- sequential fetches must finish before the listener count is read
        const results = await pool.fetchEach(["wss://fetch.example"], [{ kinds: [1] }], {
          signal: controller.signal,
          timeoutMs: 300,
        });
        expect(results).toHaveLength(1);
        expect(results[0]!.end.type).toBe("eose");
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      pool.close();
    }
  });

  test("pool.subscribe close leaves no abort listeners", async () => {
    const pool = new Pool({
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        const sub = pool.subscribe(["wss://sub.example"], [{ kinds: [1] }], {
          signal: controller.signal,
        });
        sub.close("done");
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      pool.close();
    }
  });

  test("relay.stream broken out of the iterator leaves no abort listeners", async () => {
    const relay = new Relay("wss://stream.example", {
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      await relay.connect();
      const seeded = note("seeded");
      net.relay("wss://stream.example").seed([seeded]);
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        const seen: string[] = [];
        // oxlint-disable-next-line no-await-in-loop -- sequential streams must finish before the listener count is read
        for await (const e of relay.stream([{ kinds: [1] }], { signal: controller.signal })) {
          seen.push(e.id);
          break;
        }
        expect(seen).toStrictEqual([seeded.id]);
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      relay.close();
    }
  });

  test("relay.count leaves no abort listeners after 5 completed counts", async () => {
    const relay = new Relay("wss://count.example", {
      websocketImplementation: net.websocketImplementation,
      enableReconnect: false,
    });
    try {
      await relay.connect();
      const controller = new AbortController();
      const tracked = trackAbortListeners(controller.signal);
      for (let i = 0; i < 5; i++) {
        // oxlint-disable-next-line no-await-in-loop -- sequential counts must finish before the listener count is read
        const result = await relay.count([{ kinds: [1] }], {
          signal: controller.signal,
          timeoutMs: 300,
        });
        expect(result.count).toBe(0);
      }
      await sleep(10);
      expect(netListeners(tracked)).toBe(0);
    } finally {
      relay.close();
    }
  });
});
