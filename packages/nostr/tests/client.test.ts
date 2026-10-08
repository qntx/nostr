import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import {
  Client,
  EventBuilder,
  EventValidationError,
  Kind,
  Keys,
  KeysSigner,
  MemoryEventStore,
  MessageError,
  normalizeURL,
  RelayTimeoutError,
  relayListEventBuilder,
  useWebSocketImplementation,
  verifyEvent,
} from "../src/index.ts";
import type { Event } from "../src/index.ts";
import { MockWebSocket, MockWebSocketCtor } from "./helpers/mock-ws.ts";
import { stubReportError } from "./helpers/report-error.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const SK2 = "0000000000000000000000000000000000000000000000000000000000000001";

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const all =
  (...preds: ReadonlyArray<() => boolean>) =>
  (): boolean =>
    preds.every((pred) => pred());

const allReqReady =
  (...parts: ReadonlyArray<string>) =>
  (): boolean =>
    parts.every((part) => reqReady(part));

const socketsExist =
  (...parts: ReadonlyArray<string>) =>
  (): boolean =>
    parts.every((part) => findWs(part) !== undefined);

const everySocketSentReq = (): boolean =>
  MockWebSocket.instances.every((ws) => sentMessages(ws).some((m) => m[0] === "REQ"));

const twoReqTargets = (a: string, b: string) => (): boolean => {
  const targets = MockWebSocket.instances.filter((ws) => ws.url.includes(a) || ws.url.includes(b));
  return (
    targets.length === 2 && targets.every((ws) => sentMessages(ws).some((m) => m[0] === "REQ"))
  );
};

const eventFrameOf = (ws: MockWebSocket): [string, Event] => {
  const frame = ws.sent.map((s) => JSON.parse(s) as unknown[]).find((m) => m[0] === "EVENT") as
    | [string, Event]
    | undefined;
  if (frame === undefined) {
    throw new Error("expected an EVENT frame");
  }
  return frame;
};

const replyOkToEvent = (ws: MockWebSocket): void => {
  const eventMsg = ws.sent.map((s) => JSON.parse(s) as unknown[]).find((m) => m[0] === "EVENT") as
    | [string, { id: string }]
    | undefined;
  if (eventMsg) {
    ws.receive(JSON.stringify(["OK", eventMsg[1].id, true, ""]));
  }
};

const replyOkToEventChecked = (ws: MockWebSocket): void => {
  const eventMsg = ws.sent.map((s) => JSON.parse(s) as unknown[]).find((m) => m[0] === "EVENT") as
    | [string, { id: string; kind: number }]
    | undefined;
  if (eventMsg) {
    expect(eventMsg[1].kind).not.toBe(Kind.RelayList);
    ws.receive(JSON.stringify(["OK", eventMsg[1].id, true, ""]));
  }
};

const answerReqsForAuthor = (ws: MockWebSocket, note: Event): void => {
  for (const msg of sentMessages(ws)) {
    if (msg[0] !== "REQ") {
      continue;
    }
    const filter = msg[2] as { authors?: string[] };
    if (filter.authors?.includes(note.pubkey)) {
      ws.receive(JSON.stringify(["EVENT", msg[1], note]));
    }
    ws.receive(JSON.stringify(["EOSE", msg[1]]));
  }
};

const assertNoReqOnFor = async (urlPart: string, ms: number): Promise<void> => {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const hit = MockWebSocket.instances.some(
      (ws) => ws.url.includes(urlPart) && sentMessages(ws).some((m) => m[0] === "REQ"),
    );
    if (hit) {
      throw new Error(`unexpected REQ on ${urlPart}`);
    }
    // oxlint-disable-next-line no-await-in-loop -- negative assertion must poll continuously
    await sleep(5);
  }
};

async function waitUntil(pred: () => boolean, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling helper must sleep between checks
    await sleep(5);
  }
  throw new Error("timeout waiting for condition");
}

function sentMessages(ws: MockWebSocket): unknown[][] {
  return ws.sent.map((s) => JSON.parse(s) as unknown[]);
}

function lastReqId(ws: MockWebSocket): string {
  const reqs = ws.sent.map((s) => JSON.parse(s) as unknown[]).filter((m) => m[0] === "REQ");
  const last = reqs.at(-1) as [string, string] | undefined;
  if (!last) {
    throw new Error("no REQ");
  }
  return last[1];
}

function findWs(part: string): MockWebSocket | undefined {
  return MockWebSocket.instances.find((ws) => ws.url.includes(part));
}

function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`expected ${what}`);
  }
  return value;
}

function reqReady(part: string): boolean {
  const ws = findWs(part);
  return Boolean(ws && sentMessages(ws).some((m) => m[0] === "REQ"));
}

function reqAuthors(ws: MockWebSocket): string[] {
  return sentMessages(ws)
    .filter((m) => m[0] === "REQ")
    .flatMap((m) => m.slice(2) as Array<{ authors?: string[] }>)
    .flatMap((f) => f.authors ?? []);
}

function reqPTags(ws: MockWebSocket): string[] {
  return sentMessages(ws)
    .filter((m) => m[0] === "REQ")
    .flatMap((m) => m.slice(2) as Array<{ "#p"?: string[] }>)
    .flatMap((f) => f["#p"] ?? []);
}

function hasClose(ws: MockWebSocket): boolean {
  return sentMessages(ws).some((m) => m[0] === "CLOSE");
}

function dummyPingReqs(ws: MockWebSocket): unknown[][] {
  return ws.sent
    .map((s) => JSON.parse(s) as unknown[])
    .filter((m) => m[0] === "REQ" && String(m[1]).startsWith("__ping__"));
}

beforeEach(() => {
  MockWebSocket.reset();
  useWebSocketImplementation(MockWebSocketCtor);
});

afterEach(() => {
  MockWebSocket.reset();
});

describe("Client", () => {
  test("builder publish + fetchEvents end to end on mock relays", async () => {
    const client = new Client({
      signer: new KeysSigner(SK),
      relays: ["wss://a.example", "wss://b.example"],
      websocketImplementation: MockWebSocketCtor,
    });

    await client.connect();
    expect(MockWebSocket.instances).toHaveLength(2);

    const publishP = client.publish(EventBuilder.textNote("hello from client").createdAt(10));
    await new Promise((resolve) => setTimeout(resolve, 10));

    for (const ws of MockWebSocket.instances) {
      const eventMsg = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "EVENT") as [
        string,
        { id: string; content: string; kind: number },
      ];
      expect(eventMsg[1].content).toBe("hello from client");
      expect(eventMsg[1].kind).toBe(Kind.TextNote);
      ws.receive(JSON.stringify(["OK", eventMsg[1].id, true, ""]));
    }

    const published = await publishP;
    expect(published.every((r) => r.status === "ok")).toBe(true);

    const [, note] = eventFrameOf(MockWebSocket.instances[0]!);

    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [note.pubkey], limit: 5 },
      { timeoutMs: 2000 },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));

    for (const ws of MockWebSocket.instances) {
      const req = ws.sent.map((s) => JSON.parse(s)).find((m) => m[0] === "REQ") as [string, string];
      // last REQ after fetch
      const reqs = ws.sent.map((s) => JSON.parse(s)).filter((m) => m[0] === "REQ");
      const lastReq = reqs.at(-1) as [string, string];
      ws.receive(JSON.stringify(["EVENT", lastReq[1], note]));
      ws.receive(JSON.stringify(["EOSE", lastReq[1]]));
      void req;
    }

    const notes = await fetchP;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.content).toBe("hello from client");

    await client.shutdown();
    expect(client.isShutdown).toBe(true);
  });

  test("fetchEach reports per-relay ends and ingests events with seenOn", async () => {
    const client = new Client({
      relays: ["wss://a.example", "wss://b.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    const keys = Keys.fromSecretKey(SK);
    const shared = EventBuilder.textNote("shared").createdAt(1).signWithKeys(keys);
    const onlyA = EventBuilder.textNote("only a").createdAt(2).signWithKeys(keys);

    const fetchP = client.fetchEach({ kinds: [1] }, { timeoutMs: 2000 });
    await waitUntil(all(socketsExist("a.example", "b.example"), everySocketSentReq));
    const aWs = must(findWs("a.example"), "socket on a.example");
    const bWs = must(findWs("b.example"), "socket on b.example");
    const reqA = lastReqId(aWs);
    const reqB = lastReqId(bWs);
    aWs.receive(JSON.stringify(["EVENT", reqA, shared]));
    aWs.receive(JSON.stringify(["EVENT", reqA, onlyA]));
    aWs.receive(JSON.stringify(["EOSE", reqA]));
    bWs.receive(JSON.stringify(["EVENT", reqB, shared]));
    bWs.receive(JSON.stringify(["CLOSED", reqB, "rate-limited: slow down"]));

    const results = await fetchP;
    expect(results).toHaveLength(2);
    const aRes = results.find((r) => r.url.includes("a.example"));
    const bRes = results.find((r) => r.url.includes("b.example"));
    expect(aRes?.end).toStrictEqual({ type: "eose" });
    expect(aRes?.events.map((e) => e.id).toSorted()).toStrictEqual(
      [shared.id, onlyA.id].toSorted(),
    );
    expect(bRes?.end).toStrictEqual({ type: "closed", reason: "rate-limited: slow down" });
    expect(bRes?.events.map((e) => e.id)).toStrictEqual([shared.id]);

    // Index ingestion carries each relay's URL; storage persistence matches fetchEvents.
    expect(client.index.get(shared.id)?.id).toBe(shared.id);
    expect([...client.index.seenOn(shared.id)].toSorted()).toStrictEqual(
      [normalizeURL("wss://a.example"), normalizeURL("wss://b.example")].toSorted(),
    );
    expect(client.index.seenOn(onlyA.id)).toStrictEqual([normalizeURL("wss://a.example")]);

    await client.shutdown();
    const stored = await client.storage.query([{ kinds: [1] }]);
    expect(stored.map((e) => e.id).toSorted()).toStrictEqual([shared.id, onlyA.id].toSorted());
  });

  test("fetchEach skips observe when asked", async () => {
    const client = new Client({
      relays: ["wss://quiet.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("not stored").createdAt(1).signWithKeys(keys);

    const fetchP = client.fetchEach({ kinds: [1] }, { timeoutMs: 2000, observe: false });
    await waitUntil(all(socketsExist("quiet.example"), everySocketSentReq));
    const ws = must(findWs("quiet.example"), "socket on quiet.example");
    const req = lastReqId(ws);
    ws.receive(JSON.stringify(["EVENT", req, note]));
    ws.receive(JSON.stringify(["EOSE", req]));

    const results = await fetchP;
    expect(results[0]?.events).toHaveLength(1);
    await client.shutdown();
    expect(client.index.get(note.id)).toBeUndefined();
    await expect(client.storage.query([{ kinds: [1] }])).resolves.toStrictEqual([]);
  });

  test("publish requires signer when given EventBuilder", async () => {
    const client = new Client({
      relays: ["wss://a.example"],
    });
    await expect(client.publish(EventBuilder.textNote("x"))).rejects.toThrow(/signer/);
  });

  test("Client pool ensureRelay defaults to 5000ms when connectTimeoutMs is unset", async () => {
    MockWebSocket.autoConnect = false;
    const client = new Client({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    try {
      const pending = client.pool.ensureRelay("wss://hang.example");
      await waitUntil(() => MockWebSocket.instances.length === 1);
      expect(MockWebSocket.last().readyState).toBe(MockWebSocket.CONNECTING);
      const status = await Promise.race([
        pending.then(
          () => "resolved" as const,
          () => "rejected" as const,
        ),
        sleep(3500).then(() => "pending" as const),
      ]);
      expect(status).toBe("pending");
      await expect(pending).rejects.toThrow(RelayTimeoutError);
    } finally {
      await client.shutdown();
    }
  }, 8000);

  test("gossip publish fans out to author write and tagged read relays", async () => {
    const author = new KeysSigner(SK);
    const tagged = Keys.fromSecretKey(
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const client = new Client({
      signer: author,
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    await client.connect();

    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://author-write.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(Keys.fromSecretKey(SK)),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://tagged-read.example", marker: "read" }])
        .createdAt(1)
        .signWithKeys(tagged),
    );

    const publishP = client.publish(
      EventBuilder.textNote("hi").tag(["p", tagged.publicKey]).createdAt(1),
      { gossip: true },
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    const urls = MockWebSocket.instances.map((ws) => ws.url);
    expect(urls.some((u) => u.includes("author-write.example"))).toBe(true);
    expect(urls.some((u) => u.includes("tagged-read.example"))).toBe(true);

    for (const ws of MockWebSocket.instances) {
      replyOkToEvent(ws);
    }
    const results = await publishP;
    expect(results.some((r) => r.status === "ok")).toBe(true);
    await client.shutdown();
  });

  test("subscribe two relays with eoseTimeoutMs fires oneose once", async () => {
    const client = new Client({
      relays: ["wss://a.example", "wss://b.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    let eose = 0;
    const closer = client.subscribe(
      { kinds: [1] },
      {
        eoseTimeoutMs: 50,
        oneose: () => {
          eose += 1;
        },
      },
    );
    await waitUntil(all(() => MockWebSocket.instances.length === 2, everySocketSentReq));
    const loud = MockWebSocket.instances.find((ws) => ws.url.includes("a.example"))!;
    const silent = MockWebSocket.instances.find((ws) => ws.url.includes("b.example"))!;
    const req = sentMessages(loud).find((m) => m[0] === "REQ") as [string, string];
    loud.receive(JSON.stringify(["EOSE", req[1]]));
    expect(eose).toBe(0);
    await waitUntil(() => eose === 1);
    expect(eose).toBe(1);
    expect(sentMessages(silent).some((m) => m[0] === "CLOSE")).toBe(false);
    closer.close();
    await client.shutdown();
  });

  test("gossip subscribe with eoseTimeoutMs fires oneose once", async () => {
    const author = Keys.fromSecretKey(SK);
    const tagged = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(author),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-b.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(tagged),
    );

    let eose = 0;
    const closer = client.subscribe(
      { kinds: [1], authors: [author.publicKey, tagged.publicKey] },
      {
        gossip: true,
        eoseTimeoutMs: 50,
        oneose: () => {
          eose += 1;
        },
      },
    );
    await waitUntil(twoReqTargets("out-a.example", "out-b.example"));
    const loud = MockWebSocket.instances.find((ws) => ws.url.includes("out-a.example"))!;
    const silent = MockWebSocket.instances.find((ws) => ws.url.includes("out-b.example"))!;
    const req = sentMessages(loud).find((m) => m[0] === "REQ") as [string, string];
    loud.receive(JSON.stringify(["EOSE", req[1]]));
    expect(eose).toBe(0);
    await waitUntil(() => eose === 1);
    expect(eose).toBe(1);
    expect(sentMessages(silent).some((m) => m[0] === "CLOSE")).toBe(false);
    closer.close();
    await client.shutdown();
  });

  test("gossip subscribe leftover authors REQ default relays", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const closer = client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      { gossip: true },
    );
    await waitUntil(allReqReady("out-a.example", "default.example"));

    const outA = findWs("out-a.example")!;
    const def = findWs("default.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey]);
    expect(reqAuthors(def)).toStrictEqual([b.publicKey]);
    closer.close();
    await client.shutdown();
  });

  test("gossip fetchEvents leftover authors read notes from default relays", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const noteA = EventBuilder.textNote("from-a").createdAt(1).signWithKeys(a);
    const noteB = EventBuilder.textNote("from-b").createdAt(2).signWithKeys(b);

    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      { gossip: true, timeoutMs: 2000 },
    );
    await waitUntil(allReqReady("out-a.example", "default.example"));

    const outA = findWs("out-a.example")!;
    const def = findWs("default.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey]);
    expect(reqAuthors(def)).toStrictEqual([b.publicKey]);

    answerReqsForAuthor(outA, noteA);
    answerReqsForAuthor(def, noteB);

    const notes = await fetchP;
    expect(notes.map((n) => n.id).toSorted()).toStrictEqual([noteA.id, noteB.id].toSorted());
    expect(notes.find((n) => n.id === noteB.id)?.content).toBe("from-b");
    await client.shutdown();
  });

  test("gossip fetchEvents leftover skips a failed outbox relay", async () => {
    MockWebSocket.autoConnect = false;
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      connectTimeoutMs: 40,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const noteB = EventBuilder.textNote("from-b").createdAt(2).signWithKeys(b);
    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      { gossip: true, timeoutMs: 200 },
    );
    await waitUntil(socketsExist("out-a.example", "default.example"));
    const def = findWs("default.example")!;
    def.open();
    await waitUntil(() => reqReady("default.example"));
    expect(reqAuthors(def)).toStrictEqual([b.publicKey]);
    def.receive(JSON.stringify(["EVENT", lastReqId(def), noteB]));
    def.receive(JSON.stringify(["EOSE", lastReqId(def)]));

    const notes = await fetchP;
    expect(notes.map((n) => n.id)).toStrictEqual([noteB.id]);
    expect(findWs("out-a.example")!.readyState).not.toBe(MockWebSocket.OPEN);
    await client.shutdown();
  });

  test("gossip leftover with empty Client.relays throws before attach", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const leftover = { kinds: [1], authors: [a.publicKey, b.publicKey] };
    expect(() => client.subscribe(leftover, { gossip: true })).toThrow(/no relays configured/);
    await expect(client.fetchEvents(leftover, { gossip: true })).rejects.toThrow(
      /no relays configured/,
    );
    expect(() =>
      client.subscribe([{ kinds: [1], authors: [a.publicKey] }, leftover], { gossip: true }),
    ).toThrow(/no relays configured/);
    await expect(
      client.fetchEvents([{ kinds: [1], authors: [a.publicKey] }, leftover], { gossip: true }),
    ).rejects.toThrow(/no relays configured/);

    await assertNoReqOnFor("out-a.example", 50);

    await client.shutdown();
  });

  test("gossip all-routed authors skip empty Client.relays", async () => {
    const a = Keys.fromSecretKey(SK);
    const client = new Client({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const closer = client.subscribe({ kinds: [1], authors: [a.publicKey] }, { gossip: true });
    await waitUntil(() => reqReady("out-a.example"));
    const outA = findWs("out-a.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey]);
    closer.close();
    await client.shutdown();
  });

  test("gossip fetchEvents all-routed authors skip empty Client.relays", async () => {
    const a = Keys.fromSecretKey(SK);
    const client = new Client({
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const noteA = EventBuilder.textNote("routed-a").createdAt(1).signWithKeys(a);
    const fetchP = client.fetchEvents(
      { kinds: [1], authors: [a.publicKey] },
      { gossip: true, timeoutMs: 2000 },
    );
    await waitUntil(() => reqReady("out-a.example"));
    expect(MockWebSocket.instances.every((ws) => ws.url.includes("out-a.example"))).toBe(true);
    const outA = findWs("out-a.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey]);
    outA.receive(JSON.stringify(["EVENT", lastReqId(outA), noteA]));
    outA.receive(JSON.stringify(["EOSE", lastReqId(outA)]));
    const notes = await fetchP;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.id).toBe(noteA.id);
    await client.shutdown();
  });

  test("gossip subscribe leftover #p REQ default relays", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://in-a.example", marker: "read" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const closer = client.subscribe(
      { kinds: [1], "#p": [a.publicKey, b.publicKey] },
      { gossip: true },
    );
    await waitUntil(allReqReady("in-a.example", "default.example"));
    expect(reqPTags(findWs("in-a.example")!)).toStrictEqual([a.publicKey]);
    expect(reqPTags(findWs("default.example")!)).toStrictEqual([b.publicKey]);
    closer.close();
    await client.shutdown();
  });

  test("gossip subscribe leftover authors+#p REQ original filter on defaults", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const filter = {
      kinds: [1],
      authors: [a.publicKey, b.publicKey],
      "#p": [a.publicKey],
    };
    const closer = client.subscribe(filter, { gossip: true });
    await waitUntil(allReqReady("out-a.example", "default.example"));
    const outA = findWs("out-a.example")!;
    const def = findWs("default.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey, b.publicKey]);
    expect(reqPTags(outA)).toStrictEqual([a.publicKey]);
    expect(reqAuthors(def)).toStrictEqual([a.publicKey, b.publicKey]);
    expect(reqPTags(def)).toStrictEqual([a.publicKey]);
    closer.close();
    await client.shutdown();
  });

  test("gossip subscribe close fires onclose once across two outboxes", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-b.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(b),
    );

    let closes = 0;
    const closer = client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      {
        gossip: true,
        onclose: () => {
          closes += 1;
        },
      },
    );
    await waitUntil(allReqReady("out-a.example", "out-b.example"));
    const outA = findWs("out-a.example")!;
    const outB = findWs("out-b.example")!;
    closer.close();
    expect(closes).toBe(1);
    expect(hasClose(outA)).toBe(true);
    expect(hasClose(outB)).toBe(true);
    await client.shutdown();
  });

  test("gossip subscribe CLOSED waits for every outbox before onclose", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-b.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(b),
    );

    let closes = 0;
    client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      {
        gossip: true,
        onclose: () => {
          closes += 1;
        },
      },
    );
    await waitUntil(twoReqTargets("out-a.example", "out-b.example"));
    const outA = MockWebSocket.instances.find((ws) => ws.url.includes("out-a.example"))!;
    const outB = MockWebSocket.instances.find((ws) => ws.url.includes("out-b.example"))!;
    outA.receive(JSON.stringify(["CLOSED", lastReqId(outA), "bye-a"]));
    expect(closes).toBe(0);
    outB.receive(JSON.stringify(["CLOSED", lastReqId(outB), "bye-b"]));
    expect(closes).toBe(1);
    await client.shutdown();
  });

  test("gossip leftover plus two outboxes close fires onclose once", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const c = Keys.fromSecretKey(
      "0000000000000000000000000000000000000000000000000000000000000002",
    );
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-b.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(b),
    );

    let closes = 0;
    const closer = client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey, c.publicKey] },
      {
        gossip: true,
        onclose: () => {
          closes += 1;
        },
      },
    );
    await waitUntil(allReqReady("out-a.example", "out-b.example", "default.example"));
    const outA = findWs("out-a.example")!;
    const outB = findWs("out-b.example")!;
    const def = findWs("default.example")!;
    closer.close();
    expect(closes).toBe(1);
    expect(hasClose(outA)).toBe(true);
    expect(hasClose(outB)).toBe(true);
    expect(hasClose(def)).toBe(true);
    await client.shutdown();
  });

  test("gossip leftover CLOSED waits for fallback pool before onclose", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    let closes = 0;
    client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      {
        gossip: true,
        onclose: () => {
          closes += 1;
        },
      },
    );
    await waitUntil(allReqReady("out-a.example", "default.example"));
    const outA = findWs("out-a.example")!;
    const def = findWs("default.example")!;
    outA.receive(JSON.stringify(["CLOSED", lastReqId(outA), "bye-a"]));
    expect(closes).toBe(0);
    def.receive(JSON.stringify(["CLOSED", lastReqId(def), "bye-default"]));
    expect(closes).toBe(1);
    await client.shutdown();
  });

  test("gossip leftover two default relays stay one fallback pool", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default-a.example", "wss://default-b.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    let closes = 0;
    client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      {
        gossip: true,
        onclose: () => {
          closes += 1;
        },
      },
    );
    await waitUntil(allReqReady("out-a.example", "default-a.example", "default-b.example"));
    const outA = findWs("out-a.example")!;
    const defA = findWs("default-a.example")!;
    const defB = findWs("default-b.example")!;
    expect(reqAuthors(outA)).toStrictEqual([a.publicKey]);
    expect(reqAuthors(defA)).toStrictEqual([b.publicKey]);
    expect(reqAuthors(defB)).toStrictEqual([b.publicKey]);

    outA.receive(JSON.stringify(["CLOSED", lastReqId(outA), "bye-out"]));
    expect(closes).toBe(0);
    defA.receive(JSON.stringify(["CLOSED", lastReqId(defA), "bye-a"]));
    expect(closes).toBe(0);
    defB.receive(JSON.stringify(["CLOSED", lastReqId(defB), "bye-b"]));
    expect(closes).toBe(1);
    await client.shutdown();
  });

  test("gossip empty filters fire oneose without opening sockets", async () => {
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    let eose = 0;
    let closed: string | undefined;
    client.subscribe([], {
      gossip: true,
      oneose: () => {
        eose += 1;
      },
      onclose: (reason) => {
        closed = reason;
      },
    });
    await waitUntil(() => eose === 1);
    expect(eose).toBe(1);
    expect(closed).toBeUndefined();
    expect(MockWebSocket.instances).toHaveLength(0);
    await client.shutdown();
  });

  test("subscribe empty filters without gossip throws via Pool", async () => {
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    expect(() => client.subscribe([])).toThrow(MessageError);
    expect(() => client.subscribe([])).toThrow("REQ requires at least one filter");
    expect(MockWebSocket.instances).toHaveLength(0);
    await Promise.resolve();
    expect(MockWebSocket.instances).toHaveLength(0);
    await client.shutdown();
  });

  test("fetchEvents empty filters without gossip throws via Pool.fetch", async () => {
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    await expect(client.fetchEvents([])).rejects.toThrow(MessageError);
    await expect(client.fetchEvents([])).rejects.toThrow("REQ requires at least one filter");
    expect(MockWebSocket.instances).toHaveLength(0);
    await client.shutdown();
  });

  test("fetchEvents empty filters with gossip stays []", async () => {
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    await expect(client.fetchEvents([], { gossip: true })).resolves.toStrictEqual([]);
    expect(MockWebSocket.instances).toHaveLength(0);
    await client.shutdown();
  });

  test("gossip leftover and two generic filters do not forward caller id", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );

    const leftover = client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey] },
      { gossip: true, id: "caller-id" },
    );
    await waitUntil(allReqReady("out-a.example", "default.example"));
    const leftoverIds = MockWebSocket.instances.flatMap((ws) =>
      sentMessages(ws)
        .filter((m) => m[0] === "REQ")
        .map((m) => m[1] as string),
    );
    expect(leftoverIds.length).toBeGreaterThan(1);
    expect(leftoverIds.every((id) => id !== "caller-id")).toBe(true);
    leftover.close();
    await client.shutdown();
    MockWebSocket.reset();

    const genericClient = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const generics = genericClient.subscribe([{ kinds: [1] }, { kinds: [0] }], {
      gossip: true,
      id: "caller-id",
    });
    await waitUntil(() => reqReady("default.example"));
    const genericIds = sentMessages(findWs("default.example")!)
      .filter((m) => m[0] === "REQ")
      .map((m) => m[1] as string);
    expect(genericIds).toHaveLength(2);
    expect(genericIds.every((id) => id !== "caller-id")).toBe(true);
    expect(new Set(genericIds).size).toBe(2);
    generics.close();
    await genericClient.shutdown();
  });

  test("gossip close still CLOSEs inners when onclose throws", async () => {
    const a = Keys.fromSecretKey(SK);
    const b = Keys.fromSecretKey(SK2);
    const c = Keys.fromSecretKey(
      "0000000000000000000000000000000000000000000000000000000000000002",
    );
    const client = new Client({
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-a.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(a),
    );
    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://out-b.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(b),
    );

    const closer = client.subscribe(
      { kinds: [1], authors: [a.publicKey, b.publicKey, c.publicKey] },
      {
        gossip: true,
        onclose: () => {
          throw new Error("boom");
        },
      },
    );
    await waitUntil(allReqReady("out-a.example", "out-b.example", "default.example"));
    const outA = findWs("out-a.example")!;
    const outB = findWs("out-b.example")!;
    const def = findWs("default.example")!;
    const { reported, restore } = stubReportError();
    try {
      closer.close();
      expect(hasClose(outA)).toBe(true);
      expect(hasClose(outB)).toBe(true);
      expect(hasClose(def)).toBe(true);
    } finally {
      restore();
    }
    expect(reported).toHaveLength(1);
    expect(reported[0]).toBeInstanceOf(Error);
    expect((reported[0] as Error).message).toMatch(/boom/);
    await client.shutdown();
  });

  test("custom verifyEvent returning false drops events on subscribe", async () => {
    let verifies = 0;
    const client = new Client({
      relays: ["wss://verify-drop.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      verifyEvent: () => {
        verifies += 1;
        return false;
      },
    });

    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("rejected").createdAt(1).signWithKeys(keys);
    const received: string[] = [];

    await client.connect();
    const sub = client.subscribe({ kinds: [1] }, { onevent: (e) => received.push(e.id) });
    await sleep(10);

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", lastReqId(ws), note]));
    expect(verifies).toBe(1);
    expect(received).toHaveLength(0);

    const local = await client.queryLocal({ kinds: [1] });
    expect(local).toHaveLength(0);

    sub.close();
    await client.shutdown();
  });

  test("custom verifyEvent returning true still delivers events on subscribe", async () => {
    let verifies = 0;
    const client = new Client({
      relays: ["wss://verify-pass.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      verifyEvent: () => {
        verifies += 1;
        return true;
      },
    });

    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("accepted").createdAt(1).signWithKeys(keys);
    const received: string[] = [];

    await client.connect();
    const sub = client.subscribe({ kinds: [1] }, { onevent: (e) => received.push(e.id) });
    await sleep(10);

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", lastReqId(ws), note]));
    expect(verifies).toBe(1);
    expect(received).toStrictEqual([note.id]);

    sub.close();
    await client.shutdown();
  });

  test("ClientOptions.verifyEvent on the constructor drops subscribe events", async () => {
    const client = new Client({
      relays: ["wss://verify-ctor.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      verifyEvent: () => false,
    });

    const keys = Keys.fromSecretKey(SK);
    const note = EventBuilder.textNote("ctor-drop").createdAt(1).signWithKeys(keys);
    const received: string[] = [];

    await client.connect();
    const sub = client.subscribe({ kinds: [1] }, { onevent: (e) => received.push(e.id) });
    await sleep(10);

    const ws = MockWebSocket.last();
    ws.receive(JSON.stringify(["EVENT", lastReqId(ws), note]));
    expect(received).toHaveLength(0);

    sub.close();
    await client.shutdown();
  });

  test("enablePing forwards interval so relays send dummy ping REQ", async () => {
    const client = new Client({
      relays: ["wss://ping.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      enablePing: true,
      pingIntervalMs: 30,
      pingTimeoutMs: 400,
    });

    await client.connect();
    const ws = MockWebSocket.last();
    await waitUntil(() => dummyPingReqs(ws).length > 0);
    expect(dummyPingReqs(ws)[0]![2]).toStrictEqual({ ids: ["a".repeat(64)], limit: 0 });
    await client.shutdown();
  });

  test("enablePing stays off by default", async () => {
    const client = new Client({
      relays: ["wss://no-ping.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      pingIntervalMs: 10,
    });

    await client.connect();
    const ws = MockWebSocket.last();
    await sleep(50);
    expect(dummyPingReqs(ws)).toHaveLength(0);
    await client.shutdown();
  });

  test("unanswered dummy ping closes the socket using forwarded pingTimeoutMs", async () => {
    const client = new Client({
      relays: ["wss://ping-timeout.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
      enablePing: true,
      pingIntervalMs: 20,
      pingTimeoutMs: 40,
    });

    await client.connect();
    const ws = MockWebSocket.last();
    await waitUntil(() => dummyPingReqs(ws).length > 0);
    await waitUntil(() => ws.readyState === MockWebSocket.CLOSED);
    expect(ws.readyState).toBe(MockWebSocket.CLOSED);
    await client.shutdown();
  });

  test("gossip publish includes e/a relay hints and skips invalid ones", async () => {
    const author = new KeysSigner(SK);
    const client = new Client({
      signer: author,
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    await client.connect();

    client.gossip.ingest(
      relayListEventBuilder([{ url: "wss://author-write.example", marker: "write" }])
        .createdAt(1)
        .signWithKeys(Keys.fromSecretKey(SK)),
    );

    const eId = "aa".repeat(32);
    const publishP = client.publish(
      EventBuilder.textNote("hi")
        .tag(["e", eId, "wss://e-hint.example"])
        .tag(["a", `30023:${Keys.fromSecretKey(SK).publicKey}:x`, "wss://a-hint.example"])
        .tag(["e", "bb".repeat(32), "not a url"])
        .tag(["e", "cc".repeat(32), ""])
        .tag(["p", "dd".repeat(32), "wss://p-hint.example"])
        .createdAt(1),
      { gossip: true },
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    const eventUrls = MockWebSocket.instances
      .filter((ws) => ws.sent.some((s) => (JSON.parse(s) as unknown[])[0] === "EVENT"))
      .map((ws) => ws.url);
    expect(eventUrls.some((u) => u.includes("author-write.example"))).toBe(true);
    expect(eventUrls.some((u) => u.includes("e-hint.example"))).toBe(true);
    expect(eventUrls.some((u) => u.includes("a-hint.example"))).toBe(true);
    expect(eventUrls.some((u) => u.includes("p-hint.example"))).toBe(false);

    for (const ws of MockWebSocket.instances) {
      replyOkToEventChecked(ws);
    }
    const results = await publishP;
    expect(results.some((r) => r.status === "ok")).toBe(true);
    await client.shutdown();
  });

  test("gossip publish caps e/a hints at 5 unique URLs", async () => {
    const author = new KeysSigner(SK);
    const client = new Client({
      signer: author,
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    await client.connect();

    const note = EventBuilder.textNote("hints").createdAt(1);
    for (let i = 0; i < 6; i++) {
      note.tag(["e", i.toString(16).padStart(64, "0"), `wss://hint${i}.example`]);
    }
    note.tag(["e", "f".repeat(64), "wss://hint0.example"]);

    const publishP = client.publish(note, { gossip: true });
    await new Promise((resolve) => setTimeout(resolve, 20));

    const eventUrls = MockWebSocket.instances
      .filter((ws) => ws.sent.some((s) => (JSON.parse(s) as unknown[])[0] === "EVENT"))
      .map((ws) => ws.url);
    expect(eventUrls.filter((u) => u.includes("hint"))).toHaveLength(5);
    expect(eventUrls.some((u) => u.includes("hint5.example"))).toBe(false);
    expect(eventUrls.some((u) => u.includes("default.example"))).toBe(false);

    for (const ws of MockWebSocket.instances) {
      replyOkToEvent(ws);
    }
    await publishP;
    await client.shutdown();
  });

  test("gossip publish with only invalid hints uses default relays", async () => {
    const author = new KeysSigner(SK);
    const client = new Client({
      signer: author,
      relays: ["wss://default.example"],
      websocketImplementation: MockWebSocketCtor,
    });
    await client.connect();

    const publishP = client.publish(
      EventBuilder.textNote("no routes")
        .tag(["e", "aa".repeat(32), "not a url"])
        .createdAt(1),
      { gossip: true },
    );
    await new Promise((resolve) => setTimeout(resolve, 20));

    const eventUrls = MockWebSocket.instances
      .filter((ws) => ws.sent.some((s) => (JSON.parse(s) as unknown[])[0] === "EVENT"))
      .map((ws) => ws.url);
    expect(eventUrls.some((u) => u.includes("default.example"))).toBe(true);

    for (const ws of MockWebSocket.instances) {
      replyOkToEvent(ws);
    }
    const results = await publishP;
    expect(results.some((r) => r.status === "ok")).toBe(true);
    await client.shutdown();
  });
});

describe("issue #130", () => {
  test("fetchEvents aborts mid-flight with signal.reason", async () => {
    const client = new Client({
      relays: ["wss://abort.example"],
      websocketImplementation: MockWebSocketCtor,
      enableReconnect: false,
    });
    const ac = new AbortController();
    const reason = new Error("user aborted");
    const fetchP = client.fetchEvents({ kinds: [1] }, { signal: ac.signal });
    await waitUntil(() => MockWebSocket.instances.length === 1);
    ac.abort(reason);
    await expect(fetchP).rejects.toBe(reason);
    await client.shutdown();
  });

  test("throwing storageerror listener is reported and storage errors still surface", async () => {
    const { reported, restore } = stubReportError();
    const boom = new Error("callback boom");
    try {
      const inner = new MemoryEventStore();
      const client = new Client({
        relays: ["wss://a.example"],
        websocketImplementation: MockWebSocketCtor,
        enableReconnect: false,
        storage: {
          put: async (e) => inner.put(e),
          putMany: async () => Promise.reject(new Error("disk full")),
          get: async (id) => inner.get(id),
          query: async (filters) => inner.query(filters),
          count: async (filters) => inner.count(filters),
          negentropyItems: async (filter) => inner.negentropyItems(filter),
          remove: async (ids) => inner.remove(ids),
          clear: async () => inner.clear(),
          getOutboxBound: async (pubkey, kind) => inner.getOutboxBound(pubkey, kind),
          setOutboxBound: async (pubkey, kind, bound) => inner.setOutboxBound(pubkey, kind, bound),
        },
      });
      client.on("storageerror", () => {
        throw boom;
      });
      await client.connect();
      const keys = Keys.fromSecretKey(SK);
      const note = EventBuilder.textNote("hi").createdAt(1).signWithKeys(keys);
      const fetchP = client.fetchEvents({ kinds: [1] }, { timeoutMs: 2000 });
      await waitUntil(() => MockWebSocket.instances.length === 1);
      const ws = MockWebSocket.last();
      const req = ws.sent.map((s) => JSON.parse(s) as unknown[]).find((m) => m[0] === "REQ") as [
        string,
        string,
      ];
      ws.receive(JSON.stringify(["EVENT", req[1], note]));
      ws.receive(JSON.stringify(["EOSE", req[1]]));
      await fetchP;
      await waitUntil(() => reported.length === 1);
      expect(reported).toStrictEqual([boom]);
      await client.shutdown();
    } finally {
      restore();
    }
  });
});

describe("Client.observe verification", () => {
  test("observe rejects a tampered event without ingesting it", async () => {
    const client = new Client({ websocketImplementation: MockWebSocketCtor });
    try {
      const keys = Keys.fromSecretKey(SK);
      const list = relayListEventBuilder([{ url: "wss://r.example", marker: "read" }])
        .createdAt(1)
        .signWithKeys(keys);
      const tampered: Event = { ...list, content: "{}" };
      expect(verifyEvent(tampered)).toBe(false);
      expect(() => client.observe(tampered)).toThrow(EventValidationError);
      expect(() => client.observe(tampered)).toThrow("observe requires a verified event");
      expect(client.index.get(tampered.id)).toBeUndefined();
      expect(client.gossip.getRoutes(keys.publicKey)).toBeUndefined();

      client.observe(list);
      expect(client.index.get(list.id)?.id).toBe(list.id);
      expect(client.gossip.getRoutes(keys.publicKey)).toBeDefined();
    } finally {
      await client.shutdown();
    }
  });

  test("observeAll is all-or-nothing: one bad event rejects the batch", async () => {
    const client = new Client({ websocketImplementation: MockWebSocketCtor });
    try {
      const keys = Keys.fromSecretKey(SK);
      const good = EventBuilder.textNote("good").createdAt(1).signWithKeys(keys);
      const bad = EventBuilder.textNote("bad").createdAt(2).signWithKeys(keys);
      const tampered: Event = { ...bad, content: "forged" };
      expect(() => client.observeAll([good, tampered])).toThrow(EventValidationError);
      expect(client.index.get(good.id)).toBeUndefined();
      expect(client.index.get(tampered.id)).toBeUndefined();

      client.observeAll([good]);
      expect(client.index.get(good.id)?.id).toBe(good.id);
    } finally {
      await client.shutdown();
    }
  });
});
