/* oxlint-disable vitest/no-conditional-in-test -- interop handlers and scheme matrix cases branch on wire inputs */
import { NWCClient, NWCWalletService, NWCWalletServiceKeyPair } from "@getalby/sdk/nwc";
import type { Nip47Transaction, NWCWalletServiceRequestHandler } from "@getalby/sdk/nwc";
import { describe, expect, test } from "vite-plus/test";

import { hexToBytes } from "../src/core/index.ts";
import { finalizeEvent, Keys } from "../src/core/key.ts";
import { nowSeconds } from "../src/core/util.ts";
import { NwcClient, parseNwcUri } from "../src/nips/nip47.ts";
import { Pool } from "../src/relay/pool.ts";
import { KeysSigner } from "../src/signer/keys.ts";
import { createFakeNwcWallet } from "../src/testing/nwc.ts";
import { serveFakeRelay } from "../src/testing/serve.ts";

const WALLET_SK = "05".padStart(64, "0");
const CLIENT_SK = "06".padStart(64, "0");

const tx = (overrides: Partial<Nip47Transaction> = {}): Nip47Transaction => ({
  type: "incoming",
  state: "settled",
  invoice: "lnbcrt21000p1interop",
  description: "interop",
  description_hash: "",
  preimage: "ab".repeat(32),
  payment_hash: "cd".repeat(32),
  amount: 21_000,
  fees_paid: 0,
  settled_at: nowSeconds(),
  created_at: nowSeconds() - 10,
  expires_at: nowSeconds() + 3600,
  ...overrides,
});

async function waitFor(check: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (check()) {
      return;
    }
    // oxlint-disable-next-line eslint/no-await-in-loop -- subscription registration is inherently polled
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("timed out waiting for condition");
}

function ourClient(uri: string, signer: KeysSigner, pool: Pool): NwcClient {
  const connection = parseNwcUri(uri);
  return new NwcClient({
    connection: { walletPubkey: connection.walletPubkey, relays: connection.relays },
    signer,
    pool,
    timeoutMs: 8000,
  });
}

describe("NwcClient × @getalby/sdk NWCWalletService", () => {
  test("methods, errors, notifications, and a nip04 renegotiation round-trip", async () => {
    const served = await serveFakeRelay();
    const clientSecret = hexToBytes(CLIENT_SK);
    const signer = new KeysSigner(clientSecret);
    const clientKeys = Keys.fromSecretKey(clientSecret);
    const walletKeys = Keys.fromSecretKey(hexToBytes(WALLET_SK));
    const keypair = new NWCWalletServiceKeyPair(WALLET_SK, clientKeys.publicKey);
    const service = new NWCWalletService({ relayUrls: [served.url] });
    const pool = new Pool({ enableReconnect: true, allowInsecure: true });
    const uri = `nostr+walletconnect://${keypair.walletPubkey}?relay=${encodeURIComponent(served.url)}&secret=${CLIENT_SK}`;
    const client = ourClient(uri, signer, pool);
    let stop: (() => void) | undefined;
    try {
      /* oxlint-disable typescript/require-await -- the SDK handler contract is async */
      const handlers: NWCWalletServiceRequestHandler = {
        getInfo: async () => ({
          result: {
            alias: "alby-interop",
            color: "00ff00",
            pubkey: "00".repeat(32),
            network: "regtest",
            block_height: 7,
            block_hash: "11".repeat(32),
            methods: [
              "get_info",
              "get_balance",
              "pay_invoice",
              "make_invoice",
              "lookup_invoice",
              "list_transactions",
            ],
          },
          error: undefined,
        }),
        getBalance: async () => ({ result: { balance: 12_345 }, error: undefined }),
        makeInvoice: async () => ({
          result: tx({ state: "pending", settled_at: 0 }),
          error: undefined,
        }),
        payInvoice: async (request) =>
          request.invoice === "fail-me"
            ? { result: undefined, error: { code: "INSUFFICIENT_BALANCE", message: "no funds" } }
            : { result: { preimage: "ab".repeat(32), fees_paid: 0 }, error: undefined },
        lookupInvoice: async () => ({ result: tx(), error: undefined }),
        listTransactions: async () => ({
          result: { transactions: [tx()], total_count: 1 },
          error: undefined,
        }),
      };
      /* oxlint-enable typescript/require-await */
      await service.publishWalletServiceInfoEvent(
        WALLET_SK,
        [
          "get_info",
          "get_balance",
          "pay_invoice",
          "make_invoice",
          "lookup_invoice",
          "list_transactions",
        ],
        ["payment_received"],
      );
      stop = await service.subscribe(keypair, handlers);
      await waitFor(() => served.relay.events().some((event) => event.kind === 13194));

      const info = await client.getInfo();
      expect(info.alias).toBe("alby-interop");
      const balance = await client.getBalance();
      expect(balance.balance).toBe(12_345);
      const created = await client.makeInvoice({ amount: 2100 });
      expect(created.invoice).toContain("lnbcrt");
      await expect(client.payInvoice({ invoice: "not-a-valid-invoice" })).resolves.toMatchObject({
        preimage: "ab".repeat(32),
      });
      const lookedUp = await client.lookupInvoice({ payment_hash: "cd".repeat(32) });
      expect(lookedUp.payment_hash).toBe("cd".repeat(32));
      const list = await client.listTransactions({ limit: 1 });
      expect(list.transactions).toHaveLength(1);
      await expect(client.payInvoice({ invoice: "fail-me" })).rejects.toMatchObject({
        code: "INSUFFICIENT_BALANCE",
      });
      await expect(client.getBudget()).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });

      const seen: string[] = [];
      const notifications = await client.subscribeNotifications((notification) => {
        seen.push(notification.type);
      });
      await service.publishNotification(keypair, {
        notification_type: "payment_received",
        notification: tx(),
      });
      await waitFor(() => seen.length === 1);
      expect(seen).toStrictEqual(["payment_received"]);
      notifications.close();

      const legacyInfo = finalizeEvent(
        {
          kind: 13194,
          tags: [["encryption", "nip04"]],
          content: "get_info get_balance pay_invoice make_invoice lookup_invoice list_transactions",
          created_at: nowSeconds() + 5,
        },
        walletKeys,
      );
      await pool.publish([served.url], legacyInfo);
      const legacyPool = new Pool({ enableReconnect: true, allowInsecure: true });
      const legacy = ourClient(uri, signer, legacyPool);
      const legacyBalance = await legacy.getBalance();
      expect(legacyBalance.balance).toBe(12_345);
      const legacyRequest = served.relay
        .clientMessages()
        .find(
          (msg) =>
            Array.isArray(msg) &&
            msg[0] === "EVENT" &&
            (msg[1] as { kind?: number }).kind === 23194 &&
            ((msg[1] as { tags?: string[][] }).tags ?? []).some(
              ([name, value]) => name === "encryption" && value === "nip04",
            ),
        );
      expect(legacyRequest).toBeDefined();
      legacy.close();
      legacyPool.close();
    } finally {
      client.close();
      pool.close();
      signer.dispose();
      stop?.();
      service.close();
      await served.close();
    }
  }, 25_000);
});

describe("@getalby/sdk NWCClient × createFakeNwcWallet", () => {
  test.each([
    ["nip44_v2", undefined],
    ["nip04", null],
  ] as const)(
    "%s wallet interop",
    async (scheme, encryptions) => {
      const served = await serveFakeRelay();
      const wallet = createFakeNwcWallet({
        relays: [served.url],
        balance: 100_000,
        encryptions,
        walletSk: WALLET_SK,
        clientSk: CLIENT_SK,
        budget: { used_budget: 0, total_budget: 50_000, renewal_period: "never" },
      });
      const alby = new NWCClient({ nostrWalletConnectUrl: wallet.uri });
      let unsubscribe: (() => void) | undefined;
      try {
        await wallet.ready();
        const albyInfo = await alby.getInfo();
        expect(albyInfo.methods).toContain("pay_invoice");
        const initialBalance = await alby.getBalance();
        expect(initialBalance.balance).toBe(100_000);
        const invoice = await alby.makeInvoice({ amount: 2100, description: "alby interop" });
        expect(invoice.invoice).toContain("lnbcrt");
        const paid = await alby.payInvoice({ invoice: invoice.invoice });
        expect(paid.preimage).toMatch(/^[0-9a-f]{64}$/);
        const afterPayment = await alby.getBalance();
        expect(afterPayment.balance).toBe(100_000);
        const settled = await alby.lookupInvoice({ invoice: invoice.invoice });
        expect(settled.state).toBe("settled");
        const transactions = await alby.listTransactions({ limit: 10 });
        expect(transactions.transactions.length).toBeGreaterThan(0);
        await expect(alby.getBudget()).resolves.toMatchObject({
          used_budget: 2100,
          total_budget: 50_000,
        });

        const seen: string[] = [];
        unsubscribe = await alby.subscribeNotifications((notification) => {
          seen.push(notification.notification_type);
        });
        await new Promise((resolve) => setTimeout(resolve, 200));
        await wallet.receive({ amount: 500 });
        await waitFor(() => seen.includes("payment_received"));
        expect(wallet.requests.every((request) => request.encryption === scheme)).toBe(true);
      } finally {
        unsubscribe?.();
        alby.close();
        wallet.close();
        await served.close();
      }
    },
    25_000,
  );
});
