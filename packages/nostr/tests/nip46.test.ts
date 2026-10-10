import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import { nowSeconds } from "../src/core/util.ts";
import {
  EventBuilder,
  Keys,
  Kind,
  Nip46Signer,
  Pool,
  finalizeEvent,
  getPublicKey,
  verifyEvent,
} from "../src/index.ts";
import type { Nip46SubscribeOptions, Nip46Transport } from "../src/index.ts";
import {
  getConversationKey,
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
} from "../src/nips/nip44.ts";
import {
  Nip46Error,
  createNostrConnectURI,
  decodeNip46Request,
  decodeNip46Response,
  encodeNip46Response,
  parseBunkerURL,
  parseNostrConnectURI,
  toBunkerURL,
} from "../src/nips/nip46.ts";
import type { Nip46Response } from "../src/nips/nip46.ts";
import { createFakeNip46Signer, createFakeRelayNetwork } from "../src/testing/index.ts";
import type { FakeRelayNetwork } from "../src/testing/index.ts";
import { stubReportError } from "./helpers/report-error.ts";

const BUNKER_SK = "0000000000000000000000000000000000000000000000000000000000000001";
const CLIENT_SK = "0000000000000000000000000000000000000000000000000000000000000002";
const USER_SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

let net: FakeRelayNetwork;

function testPool() {
  return new Pool({
    websocketImplementation: net.websocketImplementation,
    enableReconnect: true,
  });
}

// Some remote signers serialize absent fields as explicit nulls.
const nullsEncoder = (res: Nip46Response): string =>
  JSON.stringify({
    id: res.id,
    result: res.result ?? null,
    error: res.error ?? null,
  });

beforeEach(() => {
  net = createFakeRelayNetwork();
});

afterEach(() => {
  net.close();
});

async function waitFor(check: () => boolean | Promise<boolean>, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    // oxlint-disable-next-line no-await-in-loop -- polling helper must check between sleeps
    if (await check()) {
      return;
    }
    // oxlint-disable-next-line no-await-in-loop -- polling helper must check between sleeps
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out");
}

describe("nip46 protocol", () => {
  test("bunker URL round-trip", () => {
    const pointer = {
      pubkey: getPublicKey(BUNKER_SK),
      relays: ["wss://relay.example", "wss://b.example"],
      secret: "s3cret",
    };
    const url = toBunkerURL(pointer);
    expect(url.startsWith("bunker://")).toBe(true);
    expect(parseBunkerURL(url)).toStrictEqual({
      pubkey: pointer.pubkey,
      relays: pointer.relays,
      secret: "s3cret",
    });
  });

  test("bunker URL round-trips a secret with reserved characters", () => {
    const pointer = {
      pubkey: getPublicKey(BUNKER_SK),
      relays: ["wss://relay.example"],
      secret: "a b+c~d&e=f",
    };
    expect(parseBunkerURL(toBunkerURL(pointer))).toStrictEqual({
      pubkey: pointer.pubkey,
      relays: pointer.relays,
      secret: "a b+c~d&e=f",
    });
  });

  test("nostrconnect URI round-trip", () => {
    const clientPubkey = getPublicKey(CLIENT_SK);
    const uri = createNostrConnectURI({
      clientPubkey,
      relays: ["wss://relay.example"],
      secret: "hello",
      name: "test",
      perms: ["sign_event"],
    });
    expect(uri.startsWith("nostrconnect://")).toBe(true);
    const parsed = parseNostrConnectURI(uri);
    expect(parsed.clientPubkey).toBe(clientPubkey);
    expect(parsed.secret).toBe("hello");
    expect(parsed.relays).toStrictEqual(["wss://relay.example"]);
    expect(parsed.name).toBe("test");
    expect(parsed.perms).toStrictEqual(["sign_event"]);
  });

  test("parseBunkerURL rejects NIP-05 identifiers and other non-bunker strings", () => {
    expect(parseBunkerURL("alice@example.com")).toBeUndefined();
    expect(parseBunkerURL("bunker@example.com")).toBeUndefined();
    expect(parseBunkerURL("example.com")).toBeUndefined();
    expect(parseBunkerURL("")).toBeUndefined();
    expect(parseBunkerURL("not a bunker")).toBeUndefined();
    expect(parseBunkerURL("bunker://")).toBeUndefined();
    expect(parseBunkerURL(`bunker://${getPublicKey(BUNKER_SK).slice(0, 63)}`)).toBeUndefined();
    expect(parseBunkerURL(getPublicKey(BUNKER_SK))).toBeUndefined();
    expect(
      parseBunkerURL(
        createNostrConnectURI({
          clientPubkey: getPublicKey(CLIENT_SK),
          relays: ["wss://relay.example"],
          secret: "hello",
        }),
      ),
    ).toBeUndefined();
  });

  test("decodeNip46Response treats explicit nulls as absent", () => {
    expect(decodeNip46Response('{"id":"a","result":null,"error":null}')).toStrictEqual({
      id: "a",
    });
    expect(decodeNip46Response('{"id":"a","result":"ack","error":null}')).toStrictEqual({
      id: "a",
      result: "ack",
    });
    expect(decodeNip46Response('{"id":"a","result":null,"error":"boom"}')).toStrictEqual({
      id: "a",
      error: "boom",
    });
  });

  // N10: `JSON.parse` accepts `\ud800`-style lone surrogates while serde_json
  // (nk-nips) rejects them — the codec rejects them as invalid JSON so both
  // sides agree.
  test("decodeNip46Request rejects lone surrogates in strings and keys", () => {
    const surrogate = String.raw`\ud800`;
    for (const json of [
      `{"id":"${surrogate}","method":"m","params":[]}`,
      `{"id":"i","method":"m","params":["${surrogate}"]}`,
      `{"${surrogate}":"x","id":"i","method":"m","params":[]}`,
    ]) {
      expect(() => decodeNip46Request(json)).toThrow(new Nip46Error("invalid NIP-46 request JSON"));
    }
  });

  test("decodeNip46Response rejects lone surrogates", () => {
    const surrogate = String.raw`\ud800`;
    for (const json of [`{"id":"r","result":"${surrogate}"}`, `{"id":"${surrogate}"}`]) {
      expect(() => decodeNip46Response(json)).toThrow(
        new Nip46Error("invalid NIP-46 response JSON"),
      );
    }
  });

  // N11: the URI may carry the `secret` — errors must never echo it.
  test("parseNostrConnectURI errors do not echo the URI", () => {
    const secretUri = "not%20a%20uri%20with%20secret";
    const attempt = () => parseNostrConnectURI(secretUri);
    expect(attempt).toThrow(Nip46Error);
    expect(attempt).toThrow("invalid nostrconnect URI");
    // The thrown message must not contain any part of the rejected URI.
    expect(attempt).toThrow(/^(?!.*not%20a%20uri%20with%20secret)[\s\S]*$/);
    const secretRelay = `https://${getPublicKey(CLIENT_SK)}.example?secret=shh-secret`;
    const wrongScheme = () => parseNostrConnectURI(secretRelay);
    expect(wrongScheme).toThrow("expected nostrconnect: scheme, got https:");
    expect(wrongScheme).toThrow(/^(?!.*shh-secret)[\s\S]*$/);
  });
});

describe("Nip46Signer", () => {
  test("connect, getPublicKey, signEvent via mock bunker", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const url = toBunkerURL({
      pubkey: bunkerPk,
      relays: ["wss://bunker.example"],
      secret: "tok",
    });

    const requests: Array<{ method: string; params: string[] }> = [];
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      requests,
    });

    try {
      const signer = await Nip46Signer.connect(url, {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        timeoutMs: 3000,
      });

      expect(requests.map((r) => r.method)).toStrictEqual([
        "connect",
        "switch_relays",
        "get_public_key",
      ]);
      await expect(signer.getPublicKey()).resolves.toBe(getPublicKey(USER_SK));

      const unsigned = EventBuilder.textNote("remote sign")
        .createdAt(100)
        .buildUnsigned(getPublicKey(USER_SK));
      const signed = await signer.signEvent(unsigned);
      expect(verifyEvent(signed)).toBe(true);
      expect(signed.content).toBe("remote sign");
      expect(signed.pubkey).toBe(getPublicKey(USER_SK));

      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("explicit null result/error fields on the wire behave as absent", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const url = toBunkerURL({
      pubkey: bunkerPk,
      relays: ["wss://bunker.example"],
      secret: "tok",
    });
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      encodeResponse: nullsEncoder,
      emptyMethods: ["nip44_decrypt"],
    });

    try {
      const signer = await Nip46Signer.connect(url, {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        timeoutMs: 3000,
      });

      // {"result":"pong","error":null} resolves.
      await expect(signer.ping()).resolves.toBeUndefined();
      // {"result":null,"error":"…"} rejects with the error.
      await expect(signer.nip04Decrypt(getPublicKey(USER_SK), "ciphertext")).rejects.toThrow(
        /unsupported method nip04_decrypt/,
      );
      // {"result":null} alone rejects like a missing result.
      await expect(signer.nip44Decrypt(getPublicKey(USER_SK), "ciphertext")).rejects.toThrow(
        /empty NIP-46 response/,
      );

      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("connect requires pool or createPool", async () => {
    const url = toBunkerURL({
      pubkey: getPublicKey(BUNKER_SK),
      relays: ["wss://bunker.example"],
      secret: undefined,
    });
    await expect(Nip46Signer.connect(url, { clientSecretKey: CLIENT_SK })).rejects.toThrow(
      /pool or createPool/,
    );
  });

  test("onAuthUrl fired then request completes", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const url = toBunkerURL({
      pubkey: bunkerPk,
      relays: ["wss://bunker.example"],
      secret: "tok",
    });

    const authUrls: string[] = [];
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      authUrl: "https://auth.example/approve",
      authUrlMethods: ["connect"],
    });

    try {
      const signer = await Nip46Signer.connect(url, {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        timeoutMs: 3000,
        onAuthUrl: (u) => authUrls.push(u),
      });
      expect(authUrls).toStrictEqual(["https://auth.example/approve"]);
      await expect(signer.getPublicKey()).resolves.toBe(getPublicKey(USER_SK));
      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("connect rejects NIP-05 identifiers", async () => {
    await expect(
      Nip46Signer.connect("alice@example.com", {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        timeoutMs: 3000,
        secret: "tok",
        relays: ["wss://bunker.example"],
      }),
    ).rejects.toThrow(/invalid bunker input/);
    await expect(
      Nip46Signer.connect("bunker@example.com", {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        relays: ["wss://bunker.example"],
      }),
    ).rejects.toThrow(/invalid bunker input/);
  });

  test("connect rejects empty, garbage, and nostrconnect strings", async () => {
    const opts = {
      clientSecretKey: CLIENT_SK,
      createPool: testPool,
      relays: ["wss://bunker.example"],
    };
    await expect(Nip46Signer.connect("", opts)).rejects.toThrow(/invalid bunker input/);
    await expect(Nip46Signer.connect("not a bunker", opts)).rejects.toThrow(/invalid bunker input/);
    await expect(Nip46Signer.connect(getPublicKey(BUNKER_SK), opts)).rejects.toThrow(
      /invalid bunker input/,
    );
    const nc = createNostrConnectURI({
      clientPubkey: getPublicKey(CLIENT_SK),
      relays: ["wss://nc.example"],
      secret: "hello",
    });
    await expect(Nip46Signer.connect(nc, opts)).rejects.toThrow(/invalid bunker input/);
  });

  test("fromBunker does not send connect", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const signer = Nip46Signer.fromBunker(
      {
        pubkey: bunkerPk,
        relays: ["wss://bunker.example"],
        secret: "tok",
      },
      {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        timeoutMs: 3000,
      },
    );

    await waitFor(() => net.relay("wss://bunker.example").clientMessages().length > 0);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const frames = net.relay("wss://bunker.example").clientMessages();
    expect(frames.some((m) => (m as unknown[])[0] === "REQ")).toBe(true);
    expect(frames.some((m) => (m as unknown[])[0] === "EVENT")).toBe(false);

    await signer.close();
  });

  test("fromBunker requires clientSecretKey", () => {
    expect(() =>
      Nip46Signer.fromBunker(
        {
          pubkey: getPublicKey(BUNKER_SK),
          relays: ["wss://bunker.example"],
          secret: undefined,
        },
        { createPool: testPool } as never,
      ),
    ).toThrow(/fromBunker requires clientSecretKey/);
  });

  test("connectRemote accepts the bunker secret as connect result", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const secret = "tok";
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      connectResult: secret,
    });
    try {
      const signer = await Nip46Signer.connect(
        { pubkey: bunkerPk, relays: ["wss://bunker.example"], secret },
        { clientSecretKey: CLIENT_SK, createPool: testPool, timeoutMs: 3000 },
      );
      await expect(signer.getPublicKey()).resolves.toBe(getPublicKey(USER_SK));
      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("connectRemote rejects a connect result that is not ack or secret", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      connectResult: "ok",
    });
    try {
      await expect(
        Nip46Signer.connect(
          { pubkey: bunkerPk, relays: ["wss://bunker.example"], secret: "tok" },
          { clientSecretKey: CLIENT_SK, createPool: testPool, timeoutMs: 3000 },
        ),
      ).rejects.toThrow(/connect result is not ack or secret: ok/);
    } finally {
      remote.close();
    }
  });

  test("connectRemote rejects a mismatched secret", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      connectResult: "other-secret",
    });
    try {
      await expect(
        Nip46Signer.connect(
          { pubkey: bunkerPk, relays: ["wss://bunker.example"], secret: "tok" },
          { clientSecretKey: CLIENT_SK, createPool: testPool, timeoutMs: 3000 },
        ),
      ).rejects.toThrow(/connect result is not ack or secret: other-secret/);
    } finally {
      remote.close();
    }
  });

  test("connectRemote without a pointer secret rejects a non-ack result", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      connectResult: "tok",
    });
    try {
      await expect(
        Nip46Signer.connect(
          {
            pubkey: bunkerPk,
            relays: ["wss://bunker.example"],
            secret: undefined,
          },
          { clientSecretKey: CLIENT_SK, createPool: testPool, timeoutMs: 3000 },
        ),
      ).rejects.toThrow(/connect result is not ack or secret: tok/);
    } finally {
      remote.close();
    }
  });

  test("connect closes signer when connectRemote fails", async () => {
    let poolClosed = false;
    let subClosed = false;
    await expect(
      Nip46Signer.connect(
        {
          pubkey: getPublicKey(BUNKER_SK),
          relays: ["wss://bunker.example"],
          secret: "tok",
        },
        {
          clientSecretKey: CLIENT_SK,
          createPool: () => ({
            subscribe: () => ({
              close: () => {
                subClosed = true;
              },
            }),
            publish: async () => {
              await Promise.resolve();
              return [{ status: "ok", message: "" }];
            },
            close: () => {
              poolClosed = true;
            },
          }),
          timeoutMs: 50,
        },
      ),
    ).rejects.toThrow(/timed out/);
    expect(subClosed).toBe(true);
    expect(poolClosed).toBe(true);
  });

  test("fromNostrConnectURI completes handshake", async () => {
    const clientPk = getPublicKey(CLIENT_SK);
    const secret = "hs-secret";
    const uri = createNostrConnectURI({
      clientPubkey: clientPk,
      relays: ["wss://nc.example"],
      secret,
    });

    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://nc.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
    });
    try {
      const handshake = Nip46Signer.fromNostrConnectURI(uri, {
        clientSecretKey: CLIENT_SK,
        createPool: testPool,
        handshakeTimeoutMs: 3000,
        timeoutMs: 3000,
      });

      await waitFor(() =>
        net
          .relay("wss://nc.example")
          .clientMessages()
          .some((m) => (m as unknown[])[0] === "REQ"),
      );
      remote.confirmHandshake(secret);

      const signer = await handshake;
      expect(signer.bunker.pubkey).toBe(getPublicKey(BUNKER_SK));
      expect(signer.clientPublicKey).toBe(clientPk);
      await expect(signer.getPublicKey()).resolves.toBe(getPublicKey(USER_SK));
      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("connect sends perms and metadata", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const requests: Array<{ method: string; params: string[] }> = [];
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      requests,
    });
    try {
      const signer = await Nip46Signer.connect(
        toBunkerURL({
          pubkey: bunkerPk,
          relays: ["wss://bunker.example"],
          secret: "tok",
        }),
        {
          clientSecretKey: CLIENT_SK,
          createPool: testPool,
          timeoutMs: 3000,
          perms: ["sign_event:1", "nip44_encrypt"],
          metadata: { name: "test-client", url: "https://example.com" },
        },
      );
      const connect = requests.find((r) => r.method === "connect");
      expect(connect?.params).toStrictEqual([
        bunkerPk,
        "tok",
        "sign_event:1,nip44_encrypt",
        JSON.stringify({ name: "test-client", url: "https://example.com" }),
      ]);
      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("switchRelays updates bunker relays; logout acks and closes", async () => {
    const bunkerPk = getPublicKey(BUNKER_SK);
    const clientPk = getPublicKey(CLIENT_SK);
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      switchRelays: ["wss://new.example"],
    });
    remote.attach("wss://new.example");
    try {
      const signer = await Nip46Signer.connect(
        toBunkerURL({
          pubkey: bunkerPk,
          relays: ["wss://bunker.example"],
          secret: "tok",
        }),
        { clientSecretKey: CLIENT_SK, createPool: testPool, timeoutMs: 3000 },
      );
      expect(signer.bunker.relays).toStrictEqual(["wss://new.example"]);
      await signer.logout();
    } finally {
      remote.close();
    }
  });
});

describe("issue #130", () => {
  test("auth_url keeps the request alive past timeoutMs and resolves on the later response", async () => {
    const clientPk = getPublicKey(CLIENT_SK);
    const authUrls: string[] = [];
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      authUrl: "https://auth.example/approve",
      authUrlMethods: ["ping"],
      authReplyDelayMs: 150,
    });

    try {
      const signer = Nip46Signer.fromBunker(
        {
          pubkey: getPublicKey(BUNKER_SK),
          relays: ["wss://bunker.example"],
          secret: undefined,
        },
        {
          clientSecretKey: CLIENT_SK,
          createPool: testPool,
          timeoutMs: 60,
          authTimeoutMs: 2000,
          onAuthUrl: (u) => authUrls.push(u),
        },
      );
      const started = Date.now();
      await expect(signer.ping()).resolves.toBeUndefined();
      expect(Date.now() - started).toBeGreaterThanOrEqual(140);
      expect(authUrls).toStrictEqual(["https://auth.example/approve"]);
      await signer.close();
    } finally {
      remote.close();
    }
  });

  test("publish rejected by every relay fails fast", async () => {
    const signer = Nip46Signer.fromBunker(
      {
        pubkey: getPublicKey(BUNKER_SK),
        relays: ["wss://bunker.example"],
        secret: undefined,
      },
      {
        clientSecretKey: CLIENT_SK,
        createPool: () => ({
          subscribe: () => ({ close: () => {} }),
          publish: async () => {
            await Promise.resolve();
            return [
              { status: "failed", error: new Error("blocked: spam") },
              { status: "rejected", message: "restricted: no" },
            ];
          },
          close: () => {},
        }),
        timeoutMs: 500,
      },
    );
    await expect(signer.ping()).rejects.toThrow(
      /request not accepted by any relay: blocked: spam; restricted: no/,
    );
    await signer.close();
  });

  test("throwing onAuthUrl is reported and the request still resolves", async () => {
    const { reported, restore } = stubReportError();
    const clientPk = getPublicKey(CLIENT_SK);
    const boom = new Error("auth callback boom");
    const remote = createFakeNip46Signer({
      network: net,
      relayUrl: "wss://bunker.example",
      bunkerSk: BUNKER_SK,
      userSk: USER_SK,
      clientPubkey: clientPk,
      authUrl: "https://auth.example/approve",
      authUrlMethods: ["ping"],
    });

    try {
      const signer = Nip46Signer.fromBunker(
        {
          pubkey: getPublicKey(BUNKER_SK),
          relays: ["wss://bunker.example"],
          secret: undefined,
        },
        {
          clientSecretKey: CLIENT_SK,
          createPool: testPool,
          timeoutMs: 2000,
          onAuthUrl: () => {
            throw boom;
          },
        },
      );
      await expect(signer.ping()).resolves.toBeUndefined();
      expect(reported).toStrictEqual([boom]);
      await signer.close();
    } finally {
      restore();
      remote.close();
    }
  });
});

describe("Nip46Signer.fromNostrConnectURI hardening", () => {
  type CapturedSub = {
    opts?: Nip46SubscribeOptions | undefined;
    closes: string[];
  };

  /**
   * Mock NIP-46 transport: captures every subscribe and answers `get_public_key` RPCs by delivering
   * a response event to the newest subscription; other methods get an error.
   */
  function mockNostrConnectTransport(opts?: { getPublicKeyError?: string | undefined }): {
    transport: Nip46Transport;
    subs: CapturedSub[];
    handshakeEvent: (secret: string, nonce: number) => ReturnType<typeof finalizeEvent>;
  } {
    const clientPk = getPublicKey(CLIENT_SK);
    const bunkerKeys = Keys.fromSecretKey(BUNKER_SK);
    const convKey = getConversationKey(bunkerKeys.secretKey.bytes, clientPk);
    const subs: CapturedSub[] = [];
    const respond = (id: string, result?: string, error?: string): void => {
      const resp = finalizeEvent(
        {
          kind: Kind.NostrConnect,
          tags: [["p", clientPk]],
          content: nip44Encrypt(encodeNip46Response({ id, result, error }), convKey),
          created_at: nowSeconds(),
        },
        bunkerKeys.secretKey,
      );
      // RPCs are sent on the signer's own subscription — the newest one.
      subs.at(-1)?.opts?.onevent?.(resp);
    };
    const transport: Nip46Transport = {
      subscribe: (_relays, _filters, o) => {
        const entry: CapturedSub = { opts: o, closes: [] };
        subs.push(entry);
        return {
          close: (reason?: string) => {
            entry.closes.push(reason ?? "");
          },
        };
      },
      publish: async (_relays, event) => {
        await Promise.resolve();
        const req = decodeNip46Request(nip44Decrypt(event.content, convKey));
        if (req.method === "get_public_key") {
          if (opts?.getPublicKeyError === undefined) {
            respond(req.id, getPublicKey(USER_SK));
          } else {
            respond(req.id, undefined, opts.getPublicKeyError);
          }
        } else {
          respond(req.id, undefined, `unsupported method ${req.method}`);
        }
        return [{ status: "ok", message: "" }];
      },
      close: () => {},
    };
    const handshakeEvent = (secret: string, nonce: number): ReturnType<typeof finalizeEvent> =>
      finalizeEvent(
        {
          kind: Kind.NostrConnect,
          tags: [["p", clientPk]],
          content: nip44Encrypt(encodeNip46Response({ id: `hs${nonce}`, result: secret }), convKey),
          created_at: nowSeconds() - nonce,
        },
        bunkerKeys.secretKey,
      );
    return { transport, subs, handshakeEvent };
  }

  const connectURI = (): string =>
    createNostrConnectURI({
      clientPubkey: getPublicKey(CLIENT_SK),
      relays: ["wss://nc.example"],
      secret: "hs-secret",
    });

  test("pre-aborted signal rejects promptly without creating a pool", async () => {
    const controller = new AbortController();
    controller.abort();
    let poolCreated = false;
    const reason = await Nip46Signer.fromNostrConnectURI(connectURI(), {
      clientSecretKey: CLIENT_SK,
      signal: controller.signal,
      handshakeTimeoutMs: 300,
      createPool: () => {
        poolCreated = true;
        return mockNostrConnectTransport().transport;
      },
    }).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(reason).toBe(controller.signal.reason);
    expect(poolCreated).toBe(false);
  });

  test("duplicate handshake events create exactly one signer", async () => {
    const { transport, subs, handshakeEvent } = mockNostrConnectTransport();
    const handshake = Nip46Signer.fromNostrConnectURI(connectURI(), {
      clientSecretKey: CLIENT_SK,
      pool: transport,
      handshakeTimeoutMs: 3000,
      timeoutMs: 3000,
    });
    const hs = subs.at(0)?.opts;
    hs?.onevent?.(handshakeEvent("hs-secret", 0));
    hs?.onevent?.(handshakeEvent("hs-secret", 1));
    const signer = await handshake;
    expect(signer.clientPublicKey).toBe(getPublicKey(CLIENT_SK));
    // handshake subscription + one signer RPC subscription — not two signers.
    expect(subs).toHaveLength(2);
    await signer.close();
  });

  test("getPublicKey failure closes the signer's subscription", async () => {
    const { transport, subs, handshakeEvent } = mockNostrConnectTransport({
      getPublicKeyError: "boom",
    });
    const handshake = Nip46Signer.fromNostrConnectURI(connectURI(), {
      clientSecretKey: CLIENT_SK,
      pool: transport,
      handshakeTimeoutMs: 3000,
      timeoutMs: 3000,
    });
    subs.at(0)?.opts?.onevent?.(handshakeEvent("hs-secret", 0));
    await expect(handshake).rejects.toThrow(/boom/);
    expect(subs).toHaveLength(2);
    expect(subs.at(0)?.closes).toStrictEqual(["failed"]);
    expect(subs.at(1)?.closes).toStrictEqual(["signer closed"]);
  });
});
