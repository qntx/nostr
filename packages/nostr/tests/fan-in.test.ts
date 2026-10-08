import { describe, expect, test } from "vite-plus/test";

import { EventBuilder, Keys, RelayClosedError } from "../src/index.ts";
import type { Event, Filter } from "../src/index.ts";
import { fanIn, fetchRouted } from "../src/relay/fan-in.ts";
import type { RoutedJob } from "../src/relay/fan-in.ts";
import type { Pool } from "../src/relay/pool.ts";
import type { Closer, SubscribeOptions } from "../src/relay/subscription.ts";
import { stubReportError } from "./helpers/report-error.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

// fanIn normalizes job URLs (normalizeURL appends "/" to a bare host); relay.url is the
// normalized form, so the stubs are keyed on it.
const A = "wss://a/";
const B = "wss://b/";

const settle = async (): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve));
};
const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const job = (urls: ReadonlyArray<string>, id?: string): RoutedJob => ({
  urls,
  filters: [{ kinds: [1] }],
  id,
});

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
} {
  let res!: (value: T) => void;
  let rej!: (error: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    res = resolve;
    rej = reject;
  });
  return { promise, resolve: res, reject: rej };
}

/** Minimal scripted subscription: mirrors Subscription's close/EOSE contract for fanIn. */
class StubSub implements Closer {
  closed = false;
  readonly #handlers: SubscribeOptions;

  constructor(handlers: SubscribeOptions) {
    this.#handlers = handlers;
  }

  /** Deliver an event through the same gate order the wire runtime uses. */
  event(event: Event): void {
    this.#handlers.receivedEvent?.(event.id);
    if (this.#handlers.alreadyHaveEvent?.(event.id) === true) {
      return;
    }
    this.#handlers.onevent?.(event);
  }

  /** Remote EOSE; closes the sub when the REQ was closeOnEose. */
  eose(): void {
    this.#handlers.oneose?.();
    if (this.#handlers.closeOnEose === true) {
      this.close("eose");
    }
  }

  /** Remote CLOSE (or socket drop): the sub ends with the relay's reason. */
  remoteClose(reason: string): void {
    this.close(reason);
  }

  close(reason?: string): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.#handlers.onclose?.(reason ?? "closed by client");
  }
}

class StubRelay {
  readonly url: string;
  readonly subs: StubSub[] = [];
  subscribeError: unknown;
  fetchResult: { events: Event[] } | Error | undefined;

  constructor(url: string) {
    this.url = url;
  }

  subscribe(_filters: ReadonlyArray<Filter>, handlers: SubscribeOptions): StubSub {
    if (this.subscribeError !== undefined) {
      throw this.subscribeError;
    }
    const sub = new StubSub(handlers);
    this.subs.push(sub);
    return sub;
  }

  async fetch(_filters: ReadonlyArray<Filter>, _opts?: unknown): Promise<{ events: Event[] }> {
    await Promise.resolve();
    if (this.fetchResult instanceof Error) {
      throw this.fetchResult;
    }
    return this.fetchResult ?? { events: [] };
  }
}

type EnsureResult = StubRelay | Promise<StubRelay> | Error;

/** Pool stub: `scripts` maps a normalized URL to its relay, a deferred relay, or a failure. */
function makePool(scripts: ReadonlyMap<string, EnsureResult>): Pool {
  return {
    ensureRelay: async (url: string) => {
      const hit = scripts.get(url);
      if (hit === undefined) {
        throw new Error(`down: ${url}`);
      }
      if (hit instanceof Error) {
        throw hit;
      }
      return hit;
    },
    getRelay: () => undefined,
  } as unknown as Pool;
}

function makeEvent(content = "x", createdAt = 1): Event {
  return EventBuilder.textNote(content).createdAt(createdAt).signWithKeys(Keys.fromSecretKey(SK));
}

describe("fanIn", () => {
  test("attach + EOSE-close, then connect failure: onclose fires once with the sub's reason", async () => {
    const a = new StubRelay(A);
    const dA = deferred<StubRelay>();
    const dB = deferred<StubRelay>();
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, dA.promise],
        [B, dB.promise],
      ]),
    );

    let closes = 0;
    let closed: string | undefined;
    let eose = 0;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      closeOnEose: true,
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });

    dA.resolve(a);
    await settle();
    a.subs[0]!.eose();
    dB.reject(new Error("connect timeout"));
    await settle();

    expect(eose).toBe(1);
    expect(closes).toBe(1);
    expect(closed).toBe("eose");
  });

  test("attach + remote CLOSED, then connect failure: onclose fires once with A's reason", async () => {
    const a = new StubRelay(A);
    const dA = deferred<StubRelay>();
    const dB = deferred<StubRelay>();
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, dA.promise],
        [B, dB.promise],
      ]),
    );

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });

    dA.resolve(a);
    await settle();
    a.subs[0]!.remoteClose("closed: duplicate");
    dB.reject(new Error("connect timeout"));
    await settle();

    expect(closes).toBe(1);
    expect(closed).toBe("closed: duplicate");
  });

  test("connect failure first, then attach + close: onclose fires once", async () => {
    const a = new StubRelay(A);
    const dA = deferred<StubRelay>();
    const dB = deferred<StubRelay>();
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, dA.promise],
        [B, dB.promise],
      ]),
    );

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });

    dB.reject(new Error("connect timeout"));
    await settle();
    dA.resolve(a);
    await settle();
    a.subs[0]!.remoteClose("shutdown");
    await settle();

    expect(closes).toBe(1);
    expect(closed).toBe("shutdown");
  });

  test("all connect failures: onclose fires once with 'all relays failed'", async () => {
    const pool = makePool(new Map<string, EnsureResult>());

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });
    await settle();

    expect(closes).toBe(1);
    expect(closed).toBe("all relays failed");
  });

  test("attach throwing RelayClosedError retires the URL", async () => {
    const a = new StubRelay(A);
    const b = new StubRelay(B);
    b.subscribeError = new RelayClosedError("relay closed");
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, a],
        [B, b],
      ]),
    );

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });
    await settle();

    expect(closes).toBe(0);
    a.subs[0]!.remoteClose("gone");
    await settle();

    expect(closes).toBe(1);
    expect(closed).toBe("gone");
  });

  test("attach throwing a non-RelayClosedError retires the URL without an unhandled rejection", async () => {
    const a = new StubRelay(A);
    const b = new StubRelay(B);
    b.subscribeError = new TypeError("buggy relay");
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, a],
        [B, b],
      ]),
    );

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });
    await settle();

    expect(closes).toBe(0);
    a.subs[0]!.remoteClose("gone");
    await settle();

    expect(closes).toBe(1);
    expect(closed).toBe("gone");
  });

  test("eoseTimeoutMs fires oneose once; a later real EOSE does not refire it", async () => {
    const a = new StubRelay(A);
    const pool = makePool(new Map<string, EnsureResult>([[A, a]]));

    let eose = 0;
    fanIn(pool, [job(["wss://a"])], {
      eoseTimeoutMs: 20,
      oneose: () => {
        eose += 1;
      },
    });
    await sleep(40);
    expect(eose).toBe(1);

    a.subs[0]!.eose();
    await settle();
    expect(eose).toBe(1);
  });

  test("duplicate URL entries across jobs attach once each and aggregate one EOSE", async () => {
    const a = new StubRelay(A);
    const pool = makePool(new Map<string, EnsureResult>([[A, a]]));

    let eose = 0;
    let closes = 0;
    const closer = fanIn(pool, [job(["wss://a", "wss://a/"]), job(["wss://a"])], {
      oneose: () => {
        eose += 1;
      },
      onclose: () => {
        closes += 1;
      },
    });
    await settle();
    expect(a.subs).toHaveLength(2);

    a.subs[0]!.eose();
    expect(eose).toBe(0);
    a.subs[1]!.eose();
    expect(eose).toBe(1);
    expect(closes).toBe(0);

    closer.close();
    expect(closes).toBe(1);
  });

  test("events dedupe across relays while receivedEvent counts every delivery", async () => {
    const a = new StubRelay(A);
    const b = new StubRelay(B);
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, a],
        [B, b],
      ]),
    );

    let events = 0;
    let received = 0;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      onevent: () => {
        events += 1;
      },
      receivedEvent: () => {
        received += 1;
      },
    });
    await settle();

    const ev = makeEvent();
    a.subs[0]!.event(ev);
    b.subs[0]!.event(ev);
    expect(events).toBe(1);
    expect(received).toBe(2);
  });

  test("signal aborted after attach closes every sub and fires onclose once", async () => {
    const a = new StubRelay(A);
    const b = new StubRelay(B);
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, a],
        [B, b],
      ]),
    );
    const controller = new AbortController();

    let closes = 0;
    let closed: string | undefined;
    fanIn(pool, [job(["wss://a", "wss://b"])], {
      signal: controller.signal,
      onclose: (reason) => {
        closes += 1;
        closed = reason;
      },
    });
    await settle();

    controller.abort();
    await settle();

    expect(a.subs[0]!.closed).toBe(true);
    expect(b.subs[0]!.closed).toBe(true);
    expect(closes).toBe(1);
    expect(closed).toBe("aborted");
  });

  test("signal aborted up front fires onclose('aborted') and attaches nothing", async () => {
    const a = new StubRelay(A);
    const pool = makePool(new Map<string, EnsureResult>([[A, a]]));
    const controller = new AbortController();
    controller.abort();

    let closed: string | undefined;
    fanIn(pool, [job(["wss://a"])], {
      signal: controller.signal,
      onclose: (reason) => {
        closed = reason;
      },
    });
    await settle();

    expect(closed).toBe("aborted");
    expect(a.subs).toHaveLength(0);
  });

  test("empty URL list reports 'no relays' on a microtask", async () => {
    const pool = makePool(new Map<string, EnsureResult>());

    let closed: string | undefined;
    fanIn(pool, [job([])], {
      onclose: (reason) => {
        closed = reason;
      },
    });
    expect(closed).toBeUndefined();
    await settle();
    expect(closed).toBe("no relays");
  });
});

describe("fetchRouted", () => {
  test("returns events from reachable relays and skips connect failures", async () => {
    const a = new StubRelay(A);
    const ev = makeEvent();
    a.fetchResult = { events: [ev] };
    const pool = makePool(new Map<string, EnsureResult>([[A, a]]));

    const events = await fetchRouted(pool, [job(["wss://a", "wss://b"])]);
    expect(events.map((e) => e.id)).toStrictEqual([ev.id]);
  });

  test("dedupes events across relays by id", async () => {
    const a = new StubRelay(A);
    const b = new StubRelay(B);
    const ev = makeEvent();
    a.fetchResult = { events: [ev] };
    b.fetchResult = { events: [ev] };
    const pool = makePool(
      new Map<string, EnsureResult>([
        [A, a],
        [B, b],
      ]),
    );

    const events = await fetchRouted(pool, [job(["wss://a", "wss://b"])]);
    expect(events).toHaveLength(1);
  });

  test("a throwing onevent does not drop events from the result", async () => {
    const { reported, restore } = stubReportError();
    try {
      const a = new StubRelay(A);
      const ev = makeEvent();
      a.fetchResult = { events: [ev] };
      const pool = makePool(new Map<string, EnsureResult>([[A, a]]));

      const events = await fetchRouted(pool, [job(["wss://a"])], {
        onevent: () => {
          throw new Error("listener boom");
        },
      });
      expect(events).toHaveLength(1);
      expect(reported).toHaveLength(1);
    } finally {
      restore();
    }
  });

  test("an abort mid-flight rejects with the signal reason", async () => {
    const controller = new AbortController();
    const pool = makePool(new Map<string, EnsureResult>([[A, new Error("down")]]));

    const promise = fetchRouted(pool, [job(["wss://a"])], { signal: controller.signal });
    controller.abort();
    await expect(promise).rejects.toBe(controller.signal.reason);
  });
});
