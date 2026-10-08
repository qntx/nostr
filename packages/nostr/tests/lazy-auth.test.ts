import { describe, expect, test } from "vite-plus/test";

import { Client, EventBuilder, Keys, KeysSigner, Pool, finalizeEvent } from "../src/index.ts";
import type { NostrSigner, UnsignedEvent } from "../src/index.ts";
import { createFakeRelayNetwork } from "../src/testing/index.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const GATED = "wss://gated.example";

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(pred: () => boolean, timeoutMs = 500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pred()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling must wait between iterations
    await sleep(5);
  }
  throw new Error("timeout waiting for condition");
}

const challengeOf = (template: UnsignedEvent): string =>
  template.tags.find((t) => t[0] === "challenge")?.[1] ?? "";

function authFrames(net: ReturnType<typeof createFakeRelayNetwork>, url: string): unknown[] {
  return net
    .relay(url)
    .clientMessages()
    .filter((m) => Array.isArray(m) && m[0] === "AUTH");
}

function gatedClient(net: ReturnType<typeof createFakeRelayNetwork>, signer?: NostrSigner): Client {
  return new Client({
    relays: [GATED],
    websocketImplementation: net.websocketImplementation,
    enableReconnect: false,
    signer,
  });
}

describe("lazy NIP-42 AUTH", () => {
  test("setSigner after connect takes effect: auth-gated write succeeds", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      const client = gatedClient(net);
      await client.connect();
      await sleep(20);
      // Challenge arrived before any signer existed: ignored, nothing sent.
      expect(authFrames(net, GATED)).toHaveLength(0);

      client.setSigner(new KeysSigner(keys));
      const note = EventBuilder.textNote("late signer").createdAt(5).signWithKeys(keys);
      const results = await client.publish(note);
      expect(results[0]?.status).toBe("ok");
      expect(authFrames(net, GATED)).toHaveLength(1);

      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("no signer: challenge ignored, socket stays open, gated write gets auth-required", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      const client = gatedClient(net);
      await client.connect();
      await sleep(20);

      const note = EventBuilder.textNote("anon").createdAt(6).signWithKeys(keys);
      const results = await client.publish(note);
      expect(results[0]).toMatchObject({
        status: "rejected",
        message: expect.stringContaining("auth-required"),
      });
      expect(client.pool.getRelay(GATED)?.connected).toBe(true);
      expect(authFrames(net, GATED)).toHaveLength(0);

      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("removing the signer ignores later challenges after reconnect", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      const client = gatedClient(net, new KeysSigner(keys));
      await client.connect();
      const note = EventBuilder.textNote("authed").createdAt(7).signWithKeys(keys);
      const published = await client.publish(note);
      expect(published[0]?.status).toBe("ok");
      expect(authFrames(net, GATED)).toHaveLength(1);

      client.setSigner(undefined);
      net.relay(GATED).disconnect();
      await client.pool.ensureRelay(GATED);
      await sleep(20);

      const second = EventBuilder.textNote("after removal").createdAt(8).signWithKeys(keys);
      const results = await client.publish(second);
      expect(results[0]).toMatchObject({
        status: "rejected",
        message: expect.stringContaining("auth-required"),
      });
      expect(authFrames(net, GATED)).toHaveLength(1);

      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("automaticAuth false never answers challenges", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      const manual = new Client({
        signer: new KeysSigner(keys),
        relays: [GATED],
        websocketImplementation: net.websocketImplementation,
        enableReconnect: false,
        automaticAuth: false,
      });
      await manual.connect();
      await sleep(20);
      const note = EventBuilder.textNote("no auth").createdAt(9).signWithKeys(keys);
      const manualResult = await manual.publish(note);
      expect(manualResult[0]?.status).toBe("rejected");
      expect(authFrames(net, GATED)).toHaveLength(0);
      await manual.shutdown();
    } finally {
      net.close();
    }
  });

  test("rejected AUTH is not treated as authed and the same challenge is not re-signed", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      let signCalls = 0;
      // The signed AUTH event tags a different relay URL, so the relay
      // answers OK false — the challenge was answered but auth failed.
      const pool = new Pool({
        websocketImplementation: net.websocketImplementation,
        enableReconnect: false,
        automaticallyAuth: () => async (template) => {
          signCalls += 1;
          await Promise.resolve();
          return EventBuilder.textNote("")
            .kind(template.kind)
            .tags([
              ["relay", "wss://elsewhere.example"],
              ["challenge", "c1"],
            ])
            .createdAt(template.created_at)
            .signWithKeys(keys);
        },
      });
      try {
        const relay = await pool.ensureRelay(GATED);
        await waitUntil(() => authFrames(net, GATED).length === 1);
        await sleep(20);

        const note = EventBuilder.textNote("gated").createdAt(12).signWithKeys(keys);
        const result = await relay.publish(note);
        expect(result.ok).toBe(false);
        expect(result.message).toContain("auth-required");
        expect(signCalls).toBe(1);
      } finally {
        pool.close();
      }
    } finally {
      net.close();
    }
  });

  test("setSigner re-arms a relay whose AUTH was rejected", async () => {
    const net = createFakeRelayNetwork();
    try {
      net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      // A signer whose AUTH tags the wrong relay URL: the relay answers OK false.
      const wrongRelaySigner: NostrSigner = {
        getPublicKey: async () => {
          await Promise.resolve();
          return keys.publicKey;
        },
        signEvent: async (unsigned) => {
          const challenge = challengeOf(unsigned);
          await Promise.resolve();
          return finalizeEvent(
            {
              ...unsigned,
              tags: [
                ["relay", "wss://elsewhere.example"],
                ["challenge", challenge],
              ],
            },
            keys.secretKey,
          );
        },
      };
      const client = gatedClient(net, wrongRelaySigner);
      await client.connect();
      await waitUntil(() => authFrames(net, GATED).length === 1);
      await sleep(20);

      const note = EventBuilder.textNote("gated").createdAt(13).signWithKeys(keys);
      const rejected = await client.publish(note);
      expect(rejected[0]?.status).toBe("rejected");

      client.setSigner(new KeysSigner(keys));
      await waitUntil(() => authFrames(net, GATED).length === 2);
      const secondPublished = await client.publish(note);
      expect(secondPublished[0]?.status).toBe("ok");

      await client.shutdown();
    } finally {
      net.close();
    }
  });

  test("a new challenge value after reconnect signs again", async () => {
    const net = createFakeRelayNetwork();
    try {
      const relay = net.relay(GATED, { auth: { challenge: "c1", writes: true } });
      const keys = Keys.fromSecretKey(SK);
      const client = gatedClient(net, new KeysSigner(keys));
      await client.connect();
      const note = EventBuilder.textNote("one").createdAt(10).signWithKeys(keys);
      const published = await client.publish(note);
      expect(published[0]?.status).toBe("ok");
      expect(authFrames(net, GATED)).toHaveLength(1);

      relay.configure({ auth: { challenge: "c2", writes: true } });
      relay.disconnect();
      await client.pool.ensureRelay(GATED);
      await sleep(20);
      const second = EventBuilder.textNote("two").createdAt(11).signWithKeys(keys);
      const secondResult = await client.publish(second);
      expect(secondResult[0]?.status).toBe("ok");
      expect(authFrames(net, GATED)).toHaveLength(2);

      await client.shutdown();
    } finally {
      net.close();
    }
  });
});
