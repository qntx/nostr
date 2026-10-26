import { NWCWalletService, NWCWalletServiceKeyPair } from "@getalby/sdk/nwc";
import type { NWCWalletServiceRequestHandler, Nip47PayResponse } from "@getalby/sdk/nwc";
import { describe, expect, test } from "vite-plus/test";

import { hexToBytes } from "../src/core/index.ts";
import type { Event } from "../src/core/index.ts";
import { Keys } from "../src/core/key.ts";
import {
  decodeResponse,
  encodeRequest,
  parseConnectionUri,
  parseInfoEvent,
} from "../src/nips/nip47.ts";
import type { NwcMethod } from "../src/nips/nip47.ts";
import { Relay } from "../src/relay/relay.ts";
import { KeysSigner } from "../src/signer/keys.ts";
import { serveFakeRelay } from "../src/testing/serve.ts";

const WALLET_SK = "05".padStart(64, "0");
const CLIENT_SK = "06".padStart(64, "0");

/* oxlint-disable typescript/require-await -- NWCWalletServiceRequestHandler mandates Promise returns */
const handlers: NWCWalletServiceRequestHandler = {
  getInfo: async () => ({
    result: {
      alias: "test-node",
      color: "00ff00",
      pubkey: "00".repeat(32),
      network: "regtest",
      block_height: 1,
      block_hash: "00".repeat(32),
      methods: ["get_info", "get_balance", "pay_invoice"],
    },
    error: undefined,
  }),
  getBalance: async () => ({ result: { balance: 12_345 }, error: undefined }),
  payInvoice: async (
    request,
  ): Promise<{
    result: Nip47PayResponse | undefined;
    error: { code: string; message: string } | undefined;
  }> => {
    if (request.invoice === "fail-me") {
      return {
        result: undefined,
        error: { code: "INSUFFICIENT_BALANCE", message: "no funds" },
      };
    }
    return { result: { preimage: "ab".repeat(32), fees_paid: 0 }, error: undefined };
  },
};
/* oxlint-enable typescript/require-await */

const waitForLiveSub = async (
  served: Awaited<ReturnType<typeof serveFakeRelay>>,
  probe: Event,
): Promise<void> => {
  for (let i = 0; i < 100 && served.relay.matchingLiveSubscribers(probe) === 0; i += 1) {
    // oxlint-disable-next-line eslint/no-await-in-loop -- REQ registration is async; sequential polling is the contract
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  if (served.relay.matchingLiveSubscribers(probe) === 0) {
    throw new Error("service subscription never registered");
  }
};

const ask = async (
  relay: Relay,
  signer: KeysSigner,
  walletPubkey: string,
  method: NwcMethod,
  params: Record<string, unknown>,
) => {
  const sent = await encodeRequest(signer, walletPubkey, {
    method,
    params: params as never,
  });
  let fire: (e: Event) => void = () => {};
  const got = new Promise<Event>((resolve) => {
    fire = resolve;
  });
  const sub = relay.subscribe([{ kinds: [23195] }], {
    onEvent: (e) => fire(e),
  });
  await relay.publish(sent.event);
  const response = await Promise.race([
    got,
    new Promise<never>((_resolve, reject) =>
      setTimeout(() => reject(new Error("response timeout")), 8000),
    ),
  ]);
  sub.close();
  return decodeResponse(signer, response, sent);
};

describe("nip47 × @getalby/sdk NWCWalletService", () => {
  test("get_info, get_balance, pay_invoice and an error arm round-trip over the relay", async () => {
    const served = await serveFakeRelay();
    const relay = await Relay.connect(served.url);
    const signer = new KeysSigner(hexToBytes(CLIENT_SK));
    const clientPub = Keys.fromSecretKey(hexToBytes(CLIENT_SK)).publicKey;
    const service = new NWCWalletService({ relayUrls: [served.url] });
    const keypair = new NWCWalletServiceKeyPair(WALLET_SK, clientPub);
    const walletPub = keypair.walletPubkey;
    let stop: (() => void) | undefined;
    try {
      await service.publishWalletServiceInfoEvent(
        WALLET_SK,
        ["get_info", "get_balance", "pay_invoice"],
        [],
      );
      stop = await service.subscribe(keypair, handlers);
      const probe: Event = {
        id: "00".repeat(32),
        kind: 23194,
        pubkey: clientPub,
        created_at: 0,
        tags: [["p", walletPub]],
        content: "",
        sig: "00".repeat(64),
      };
      await waitForLiveSub(served, probe);

      const conn = parseConnectionUri(
        `nostr+walletconnect://${walletPub}?relay=${encodeURIComponent(served.url)}&secret=${CLIENT_SK}`,
      );
      const infoEvent = served.relay.events().find((e) => e.kind === 13194);
      const info = parseInfoEvent(infoEvent!);
      expect(info.nip44).toBe(true);
      expect(info.methods).toContain("pay_invoice");

      const gi = await ask(relay, signer, conn.walletPubkey, "get_info", {});
      expect(gi.result).toMatchObject({ method: "get_info", alias: "test-node" });
      const gb = await ask(relay, signer, conn.walletPubkey, "get_balance", {});
      expect(gb.result).toMatchObject({ method: "get_balance", balance: 12_345 });
      const pi = await ask(relay, signer, conn.walletPubkey, "pay_invoice", {
        invoice: "lnbc1ok",
      });
      expect(pi.result).toMatchObject({ method: "pay_invoice" });
      const err = await ask(relay, signer, conn.walletPubkey, "pay_invoice", {
        invoice: "fail-me",
      });
      expect(err.error).toMatchObject({ code: "INSUFFICIENT_BALANCE" });
    } finally {
      signer.dispose();
      relay.close();
      stop?.();
      service.close();
      await served.close();
    }
  }, 20_000);
});
