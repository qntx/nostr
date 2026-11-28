/* oxlint-disable vitest/no-conditional-in-test -- asynchronous wire predicates and matrix-driven negative cases use boolean composition rather than test branching */
import { sha256 } from "@noble/hashes/sha2.js";
import { afterEach, beforeEach, describe, expect, test } from "vite-plus/test";

import type { Event } from "../src/core/index.ts";
import { bytesToHex, hexToBytes } from "../src/core/index.ts";
import { Keys, finalizeEvent } from "../src/core/key.ts";
import { nowSeconds } from "../src/core/util.ts";
import {
  NwcClient,
  NwcError,
  NwcTimeoutError,
  NwcWalletError,
  decodeResponse,
  encodeRequest,
  parseNwcUri,
} from "../src/nips/nip47.ts";
import type { NwcSigner, NwcTransport } from "../src/nips/nip47.ts";
import { parseBolt11 } from "../src/nips/nip57.ts";
import { Pool } from "../src/relay/pool.ts";
import { KeysSigner } from "../src/signer/keys.ts";
import { createFakeNwcWallet, createFakeRelayNetwork } from "../src/testing/index.ts";
import type {
  FakeRelayNetwork,
  FakeNwcWallet,
  FakeNwcWalletOptions,
} from "../src/testing/index.ts";

const URL1 = "wss://nwc-one.test";
const URL2 = "wss://nwc-two.test";

let net: FakeRelayNetwork;
const closers: Array<() => void> = [];

beforeEach(() => {
  net = createFakeRelayNetwork();
});

afterEach(() => {
  for (const close of closers.splice(0)) {
    close();
  }
  net.close();
});

function pool(): Pool {
  return new Pool({ websocketImplementation: net.websocketImplementation, enableReconnect: true });
}

async function setup(
  opts: Omit<FakeNwcWalletOptions, "relays"> = {},
  relays: ReadonlyArray<string> = [URL1],
): Promise<{
  wallet: FakeNwcWallet;
  client: NwcClient;
  signer: KeysSigner;
  pool: Pool;
  secretHex: string;
}> {
  const wallet = createFakeNwcWallet({
    balance: 100_000,
    ...opts,
    relays,
    websocketImplementation: net.websocketImplementation,
  });
  await wallet.ready();
  const connection = parseNwcUri(wallet.uri);
  const secretHex = bytesToHex(connection.secret);
  const signer = new KeysSigner(connection.secret);
  connection.secret.fill(0);
  const clientPool = pool();
  const client = new NwcClient({
    connection: { walletPubkey: connection.walletPubkey, relays: connection.relays },
    signer,
    pool: clientPool,
    timeoutMs: 1500,
  });
  closers.push(() => {
    client.close();
    signer.dispose();
    clientPool.close();
    wallet.close();
  });
  return { wallet, client, signer, pool: clientPool, secretHex };
}

async function waitFor(check: () => boolean, timeoutMs = 1500): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (check()) {
      return;
    }
    // oxlint-disable-next-line eslint/no-await-in-loop -- polling requires sequential sleeps
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for condition");
}

async function waitForNotificationReq(kind: number): Promise<void> {
  await waitFor(() =>
    clientMessages().some(
      (msg) =>
        Array.isArray(msg) &&
        msg[0] === "REQ" &&
        Array.isArray((msg[2] as { kinds?: number[] }).kinds) &&
        ((msg[2] as { kinds?: number[] }).kinds ?? []).includes(kind),
    ),
  );
}

function clientMessages(url = URL1): ReadonlyArray<unknown> {
  return net.relay(url).clientMessages();
}

describe("NwcClient negotiation", () => {
  test.each([
    [["nip44_v2", "nip04"], "nip44_v2"],
    [["nip44_v2"], "nip44_v2"],
    [["nip04"], "nip04"],
    [null, "nip04"],
  ] as const)("encryption %s negotiates to %s", async (encryptions, expected) => {
    const { wallet, client } = await setup({ encryptions });
    await client.getBalance();
    expect(wallet.requests.at(-1)?.encryption).toBe(expected);
    expect(wallet.requests.at(-1)?.event.tags).toContainEqual(["encryption", expected]);
  });

  test("unknown-only encryption and missing info event are local errors", async () => {
    const unknown = await setup({ encryptions: ["future_x"] });
    await expect(unknown.client.getBalance()).rejects.toThrow(NwcError);
    const missing = await setup({ publishInfo: false });
    await expect(missing.client.getBalance()).rejects.toThrow(NwcError);
  });

  test("a signer without nip04 cannot use a nip04-only wallet", async () => {
    const { wallet, signer } = await setup({ encryptions: null });
    const restricted: NwcSigner = {
      getPublicKey: async () => signer.getPublicKey(),
      signEvent: async (event) => signer.signEvent(event),
      nip44Encrypt: async (peer, plaintext) => signer.nip44Encrypt(peer, plaintext),
      nip44Decrypt: async (peer, ciphertext) => signer.nip44Decrypt(peer, ciphertext),
    };
    const legacyClient = new NwcClient({
      connection: { walletPubkey: wallet.walletPubkey, relays: [URL1] },
      signer: restricted,
      pool: pool(),
    });
    await expect(legacyClient.getBalance()).rejects.toThrow(NwcError);
    legacyClient.close();
  });

  test("Pool is assignable to NwcTransport and KeysSigner to NwcSigner", () => {
    const realPool = pool();
    const realSigner = new KeysSigner(Keys.generate());
    const transport: NwcTransport = realPool;
    const signer: NwcSigner = realSigner;
    expect(transport).toBeDefined();
    expect(signer).toBeDefined();
    realPool.close();
    realSigner.dispose();
  });
});

describe("NwcClient methods and errors", () => {
  test("happy path: info, balance, invoice lifecycle, transactions, and budget", async () => {
    const budget = {
      used_budget: 0,
      total_budget: 10_000,
      renews_at: nowSeconds() + 1000,
      renewal_period: "monthly" as const,
    };
    const { client } = await setup({ budget });
    const info = await client.getInfo();
    expect(info.methods).toContain("pay_invoice");
    const initialBalance = await client.getBalance();
    expect(initialBalance.balance).toBe(100_000);

    const invoice = await client.makeInvoice({ amount: 2100, description: "coffee", expiry: 600 });
    expect(invoice.state).toBe("pending");
    const decoded = parseBolt11(invoice.invoice ?? "");
    expect(decoded?.amountMsats).toBe(2100);
    expect(bytesToHex(decoded?.paymentHash ?? new Uint8Array())).toBe(invoice.payment_hash);
    expect(decoded?.description).toBe("coffee");

    const pay = await client.payInvoice({ invoice: invoice.invoice ?? "" });
    expect(bytesToHex(sha256(hexToBytes(pay.preimage)))).toBe(invoice.payment_hash);
    const afterPayment = await client.getBalance();
    expect(afterPayment.balance).toBe(100_000);

    const byHash = await client.lookupInvoice({ payment_hash: invoice.payment_hash });
    const byInvoice = await client.lookupInvoice({ invoice: invoice.invoice ?? "" });
    expect(byHash.state).toBe("settled");
    expect(byInvoice.payment_hash).toBe(invoice.payment_hash);

    const all = await client.listTransactions();
    expect(all.total_count).toBe(2);
    expect(all.transactions.map((tx) => tx.type)).toStrictEqual(["incoming", "outgoing"]);
    const incoming = await client.listTransactions({ type: "incoming" });
    expect(incoming.transactions).toHaveLength(1);
    const unpaid = await client.listTransactions({ unpaid: true });
    expect(unpaid.transactions).toHaveLength(2);
    await client.makeInvoice({ amount: 500, description: "unpaid" });
    const visibleByDefault = await client.listTransactions();
    expect(visibleByDefault.total_count).toBe(2);
    const includingUnpaid = await client.listTransactions({ unpaid: true });
    expect(includingUnpaid.total_count).toBe(3);
    expect(includingUnpaid.transactions.some((tx) => tx.state === "pending")).toBe(true);
    const page = await client.listTransactions({ limit: 1, offset: 1 });
    expect(page.transactions).toHaveLength(1);
    const before = await client.listTransactions({ until: 1 });
    expect(before.transactions).toHaveLength(0);
    await expect(client.getBudget()).resolves.toMatchObject({
      used_budget: 2100,
      total_budget: 10_000,
    });
  });

  test("get_budget is undefined when no budget is configured", async () => {
    const { client } = await setup();
    await expect(client.getBudget()).resolves.toBeUndefined();
  });

  test("every wire error code becomes NwcWalletError, unknown codes map to OTHER", async () => {
    const { wallet, client } = await setup();
    const codes = [
      "RATE_LIMITED",
      "NOT_IMPLEMENTED",
      "INSUFFICIENT_BALANCE",
      "QUOTA_EXCEEDED",
      "RESTRICTED",
      "UNAUTHORIZED",
      "INTERNAL",
      "UNSUPPORTED_ENCRYPTION",
      "OTHER",
      "PAYMENT_FAILED",
      "NOT_FOUND",
    ];
    for (const code of codes) {
      wallet.setResponse("get_balance", { error: { code, message: `wire ${code}` } });
      // oxlint-disable-next-line eslint/no-await-in-loop -- each override must be consumed before the next
      const failure = await client.getBalance().catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(NwcWalletError);
      expect((failure as NwcWalletError).code).toBe(code);
      expect((failure as NwcWalletError).walletCode).toBe(code);
    }
    wallet.setResponse("get_balance", { error: { code: "BAD_REQUEST", message: "bad" } });
    const failure = await client.getBalance().catch((error: unknown) => error);
    expect((failure as NwcWalletError).code).toBe("OTHER");
    expect((failure as NwcWalletError).walletCode).toBe("BAD_REQUEST");
  });

  test("one aborted caller does not reject a concurrent caller sharing the info fetch", async () => {
    const { client } = await setup();
    const controller = new AbortController();
    const reason = new Error("first caller gone");
    const aborted = client.getBalance({ signal: controller.signal });
    const survivor = client.getBalance();
    controller.abort(reason);
    await expect(aborted).rejects.toBe(reason);
    await expect(survivor).resolves.toMatchObject({ balance: 100_000 });
  });

  test("natural errors: balance, quota, not found, not implemented, unauthorized", async () => {
    const budget = {
      used_budget: 0,
      total_budget: 3000,
      renewal_period: "never" as const,
    };
    const { client, signer } = await setup({ budget });
    const small = await client.makeInvoice({ amount: 1500 });
    await client.payInvoice({ invoice: small.invoice ?? "" });
    const quota = await client.makeInvoice({ amount: 2000 });
    await expect(client.payInvoice({ invoice: quota.invoice ?? "" })).rejects.toMatchObject({
      name: "NwcWalletError",
      code: "QUOTA_EXCEEDED",
    });
    const huge = await client.makeInvoice({ amount: 200_000 });
    await expect(client.payInvoice({ invoice: huge.invoice ?? "" })).rejects.toMatchObject({
      code: "INSUFFICIENT_BALANCE",
    });
    await expect(client.lookupInvoice({ payment_hash: "00".repeat(32) })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });

    const limited = await setup({ methods: ["get_balance"] });
    await expect(limited.client.getInfo()).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });

    const attacker = new KeysSigner(Keys.generate());
    const attackerClient = new NwcClient({
      connection: { walletPubkey: limited.wallet.walletPubkey, relays: [URL1] },
      signer: attacker,
      pool: limited.pool,
    });
    await expect(attackerClient.getBalance()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    attacker.dispose();
    signer.dispose();
  });

  test("hand-encoded nip04 request to a nip44-only wallet returns UNSUPPORTED_ENCRYPTION", async () => {
    const { wallet, signer, pool: clientPool } = await setup({ encryptions: ["nip44_v2"] });
    const sent = await encodeRequest(
      signer,
      wallet.walletPubkey,
      {
        method: "get_balance",
        params: {},
      },
      { encryption: "nip04" },
    );
    const responsePromise = new Promise<Event>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("response timeout")), 1200);
      const sub = clientPool.subscribe([URL1], [{ kinds: [23195], "#e": [sent.event.id] }], {
        onEvent: (event) => {
          clearTimeout(timer);
          sub.close();
          resolve(event);
        },
      });
    });
    await clientPool.publish([URL1], sent.event);
    const decoded = await decodeResponse(signer, await responsePromise, sent);
    expect(decoded).toMatchObject({
      ok: false,
      error: { code: "UNSUPPORTED_ENCRYPTION" },
    });
  });

  test("malformed authentic responses and preimage mismatches are immediate NwcError", async () => {
    const { wallet, client } = await setup();
    wallet.setResponse("get_balance", { result: { balance: "100" } });
    await expect(client.getBalance()).rejects.toThrow(NwcError);
    wallet.setResponse("get_balance", undefined);

    wallet.setResponse("pay_invoice", {
      result: { preimage: "00".repeat(32), fees_paid: 0 },
    });
    const invoice = await client.makeInvoice({ amount: 1000 });
    await expect(client.payInvoice({ invoice: invoice.invoice ?? "" })).rejects.toThrow(NwcError);
  });

  test("foreign valid bolt11 fails payment without revealing a bad preimage", async () => {
    const payer = await setup();
    const foreign = await setup();
    const invoice = await foreign.client.makeInvoice({ amount: 1000 });
    await expect(payer.client.payInvoice({ invoice: invoice.invoice ?? "" })).rejects.toMatchObject(
      {
        code: "PAYMENT_FAILED",
      },
    );
  });
});

describe("NwcClient transport behavior", () => {
  test("timeout carries expiration, rejects with NwcTimeoutError, and closes the subscription", async () => {
    const { wallet, client } = await setup();
    wallet.setSilent(true);
    await expect(client.getBalance({ timeoutMs: 120 })).rejects.toBeInstanceOf(NwcTimeoutError);
    const request = wallet.requests.at(-1);
    expect(request).toBeUndefined();
    const relayMessages = clientMessages();
    const eventMsg = relayMessages.find(
      (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
    ) as [string, Event] | undefined;
    expect(eventMsg).toBeDefined();
    const expiration = eventMsg?.[1].tags.find(([name]) => name === "expiration")?.[1];
    expect(Number(expiration)).toBe((eventMsg?.[1].created_at ?? 0) + 1);
    expect(relayMessages.some((msg) => Array.isArray(msg) && msg[0] === "CLOSE")).toBe(true);
  });

  test("abort rejects with exactly signal.reason for pre-aborted and mid-flight calls", async () => {
    const { wallet, client } = await setup();
    wallet.setSilent(true);
    const pre = new AbortController();
    const reason = new Error("stop now");
    pre.abort(reason);
    await expect(client.getBalance({ signal: pre.signal })).rejects.toBe(reason);
    const mid = new AbortController();
    const pending = client.getBalance({ signal: mid.signal });
    await waitFor(() =>
      clientMessages().some(
        (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
      ),
    );
    mid.abort(reason);
    await expect(pending).rejects.toBe(reason);
    await waitFor(() => clientMessages().some((msg) => Array.isArray(msg) && msg[0] === "CLOSE"));
  });

  test("publish refused by every relay fails immediately instead of timing out", async () => {
    const { client } = await setup();
    net.relay(URL1, { rateLimited: true });
    const start = Date.now();
    await expect(client.getBalance({ timeoutMs: 1000 })).rejects.toThrow(NwcError);
    expect(Date.now() - start).toBeLessThan(600);
  });

  test("instant replies survive relay latency (REQ reaches the relay before EVENT)", async () => {
    const url = "wss://nwc-latency.test";
    net.relay(url, { latencyMs: 20 });
    const { client } = await setup({}, [url]);
    const latencyBalance = await client.getBalance();
    expect(latencyBalance.balance).toBe(100_000);
    const messages = clientMessages(url);
    const reqIndex = messages.findIndex(
      (msg) =>
        Array.isArray(msg) &&
        msg[0] === "REQ" &&
        ((msg[2] as { kinds?: number[] }).kinds ?? []).includes(23195),
    );
    const eventIndex = messages.findIndex(
      (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
    );
    expect(reqIndex).toBeGreaterThanOrEqual(0);
    expect(eventIndex).toBeGreaterThan(reqIndex);
  });

  test("multi-relay connection returns one result when one relay refuses publishes", async () => {
    const { client } = await setup({}, [URL1, URL2]);
    net.relay(URL2, { rateLimited: true });
    const multiBalance = await client.getBalance();
    expect(multiBalance.balance).toBe(100_000);
  });

  test("a timeout before any relay is ready is NwcError rather than NwcTimeoutError", async () => {
    const { client } = await setup();
    net.relay(URL1, { latencyMs: 400 });
    const failure = await client.getBalance({ timeoutMs: 60 }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(NwcError);
    expect(failure).not.toBeInstanceOf(NwcTimeoutError);
    expect((failure as Error).message).toContain("no wallet relay became ready");
  });

  test("multi-relay call succeeds when the second relay stalls", async () => {
    const { client } = await setup({}, [URL1, URL2]);
    net.relay(URL2, { latencyMs: 3000 });
    await expect(client.getBalance({ timeoutMs: 700 })).resolves.toMatchObject({
      balance: 100_000,
    });
  });

  test("close rejects in-flight requests with NwcError and messages never leak the secret", async () => {
    const { wallet, client, secretHex } = await setup();
    wallet.setSilent(true);
    const pending = client.getBalance({ timeoutMs: 2000 });
    client.close();
    const failure = await pending.catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(NwcError);
    expect((failure as Error).message).not.toContain(secretHex);
    expect((failure as Error).message).not.toContain(wallet.uri);
    let parseFailure: unknown;
    try {
      parseNwcUri(`nostr+walletconnect://zz?secret=${secretHex}`);
    } catch (error) {
      parseFailure = error;
    }
    expect(parseFailure).toBeInstanceOf(NwcError);
    expect((parseFailure as Error).message).not.toContain(secretHex);
  });
});

describe("NIP-04 wallets and notifications", () => {
  test("legacy nip04-only wallet completes requests and kind-23196 notifications", async () => {
    const { client, wallet } = await setup({ encryptions: null });
    expect(wallet.requests).toHaveLength(0);
    const legacyBalance = await client.getBalance();
    expect(legacyBalance.balance).toBe(100_000);
    expect(wallet.requests.at(-1)?.encryption).toBe("nip04");
    const seen: string[] = [];
    const sub = await client.subscribeNotifications((n) => seen.push(n.type));
    await waitForNotificationReq(23196);
    await wallet.receive({ amount: 500, description: "gift" });
    await waitFor(() => seen.includes("payment_received"));
    sub.close();
    expect(seen).toStrictEqual(["payment_received"]);
  });

  test("dual-scheme notifications arrive once; payment_sent, close, abort, and forged events", async () => {
    const { client, wallet } = await setup();
    const seen: string[] = [];
    const sub = await client.subscribeNotifications((n) => seen.push(n.type));
    await waitForNotificationReq(23197);
    await wallet.receive({ amount: 400 });
    await waitFor(() => seen.length === 1);
    const invoice = await client.makeInvoice({ amount: 1000 });
    await client.payInvoice({ invoice: invoice.invoice ?? "" });
    await waitFor(() => seen.includes("payment_sent"));
    expect(seen.filter((type) => type === "payment_received")).toHaveLength(2);
    expect(seen.filter((type) => type === "payment_sent")).toHaveLength(1);

    const forgedKey = Keys.generate();
    const forged = finalizeEvent(
      {
        kind: 23197,
        tags: [["p", wallet.clientPubkey]],
        content: "forged",
        created_at: nowSeconds(),
      },
      forgedKey,
    );
    net.relay(URL1).deliver(forged);
    await new Promise((resolve) => setTimeout(resolve, 30));
    const delivered = seen.length;
    expect(delivered).toBe(3);

    sub.close();
    await wallet.receive({ amount: 400 });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(seen).toHaveLength(delivered);

    const controller = new AbortController();
    await client.subscribeNotifications((n) => seen.push(n.type), {
      signal: controller.signal,
    });
    controller.abort();
    await wallet.receive({ amount: 400 });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(seen).toHaveLength(delivered);
    forgedKey.secretKey.zeroize();
  });
});

describe("forged and replayed responses", () => {
  test("wrong author, replay, wrong recipient, tampered content, and wrong kind are ignored", async () => {
    const walletSk = "07".padStart(64, "0");
    const walletKeys = Keys.fromSecretKey(walletSk);
    const walletSigner = new KeysSigner(Keys.fromSecretKey(walletSk));
    const { wallet, client, pool: clientPool } = await setup({ replyDelayMs: 150, walletSk });
    try {
      const captured: Event[] = [];
      const capture = clientPool.subscribe([URL1], [{ kinds: [23195] }], {
        onEvent: (event) => captured.push(event),
      });
      await waitFor(() =>
        clientMessages().some(
          (msg) =>
            Array.isArray(msg) &&
            msg[0] === "REQ" &&
            ((msg[2] as { kinds?: number[] }).kinds ?? []).includes(23195),
        ),
      );
      const first = await client.getBalance();
      expect(first.balance).toBe(100_000);
      await waitFor(() => captured.length === 1);
      capture.close();
      const [replayed] = captured;
      expect(replayed).toBeDefined();
      if (replayed === undefined) {
        throw new Error("missing captured genuine response");
      }
      await wallet.receive({ amount: 700 });

      const pending = client.getBalance({ timeoutMs: 1200 });
      await waitFor(
        () =>
          clientMessages().filter(
            (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
          ).length === 2,
      );
      const requestMessages = clientMessages().filter(
        (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
      );
      const [, requestMessage] = requestMessages as Array<[string, Event]>;
      expect(requestMessage).toBeDefined();
      if (requestMessage === undefined) {
        throw new Error("missing second request");
      }
      const [, request] = requestMessage;
      const attacker = new KeysSigner(Keys.generate());
      const wrongAuthorContent = await attacker.nip44Encrypt(
        request.pubkey,
        JSON.stringify({
          result_type: "get_balance",
          result: { balance: 1 },
          error: null,
        }),
      );
      const wrongAuthor = finalizeEvent(
        {
          kind: 23195,
          tags: [
            ["e", request.id],
            ["p", request.pubkey],
          ],
          content: wrongAuthorContent,
          created_at: nowSeconds(),
        },
        attacker.keys,
      );

      const walletContent = await walletSigner.nip44Encrypt(
        request.pubkey,
        JSON.stringify({
          result_type: "get_balance",
          result: { balance: 2 },
          error: null,
        }),
      );
      const correctEnvelope = {
        tags: [
          ["e", request.id],
          ["p", request.pubkey],
        ],
        content: walletContent,
        created_at: nowSeconds(),
      };
      const wrongP = finalizeEvent(
        {
          ...correctEnvelope,
          kind: 23195,
          tags: [
            ["e", request.id],
            ["p", Keys.generate().publicKey],
          ],
        },
        walletKeys,
      );
      const correct = finalizeEvent({ ...correctEnvelope, kind: 23195 }, walletKeys);
      const tampered = { ...correct, content: `${walletContent}00` };
      const wrongKind = finalizeEvent({ ...correctEnvelope, kind: 23194 }, walletKeys);

      net.relay(URL1).deliver(wrongAuthor);
      net.relay(URL1).deliver({ ...replayed });
      net.relay(URL1).deliver(wrongP);
      net.relay(URL1).deliver(tampered);
      net.relay(URL1).deliver(wrongKind);
      attacker.dispose();
      await expect(pending).resolves.toMatchObject({ balance: 100_700 });
    } finally {
      walletSigner.dispose();
      walletKeys.secretKey.zeroize();
    }
  }, 5000);

  test("a silent wallet plus only forged responses times out", async () => {
    const walletSk = "08".padStart(64, "0");
    const walletKeys = Keys.fromSecretKey(walletSk);
    const walletSigner = new KeysSigner(Keys.fromSecretKey(walletSk));
    const { wallet, client } = await setup({ walletSk });
    try {
      wallet.setSilent(true);
      const pending = client.getBalance({ timeoutMs: 300 });
      await waitFor(() =>
        clientMessages().some(
          (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
        ),
      );
      const requestMessage = clientMessages().find(
        (msg) => Array.isArray(msg) && msg[0] === "EVENT" && (msg[1] as Event).kind === 23194,
      ) as [string, Event] | undefined;
      expect(requestMessage).toBeDefined();
      if (requestMessage === undefined) {
        throw new Error("missing request");
      }
      const [, request] = requestMessage;
      const content = await walletSigner.nip44Encrypt(
        request.pubkey,
        JSON.stringify({
          result_type: "get_balance",
          result: { balance: 1 },
          error: null,
        }),
      );
      const wrongP = finalizeEvent(
        {
          kind: 23195,
          tags: [
            ["e", request.id],
            ["p", Keys.generate().publicKey],
          ],
          content,
          created_at: nowSeconds(),
        },
        walletKeys,
      );
      net.relay(URL1).deliver(wrongP);
      await expect(pending).rejects.toBeInstanceOf(NwcTimeoutError);
    } finally {
      walletSigner.dispose();
      walletKeys.secretKey.zeroize();
    }
  });
});
