import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";

import type { Event } from "../core/event.ts";
import { Keys, finalizeEvent } from "../core/key.ts";
import {
  bytesToHex,
  hexToBytes,
  isRecord,
  nowSeconds,
  randomBytes,
  utf8Encoder,
} from "../core/util.ts";
import * as nip04 from "../nips/nip04.ts";
import * as nip44 from "../nips/nip44.ts";
import type {
  NwcBudget,
  NwcEncryption,
  NwcMethod,
  NwcNotification,
  NwcTransaction,
} from "../nips/nip47.ts";
import {
  NWC_INFO_KIND,
  NWC_NOTIFICATION_KIND,
  NWC_NOTIFICATION_NIP04_KIND,
  NWC_REQUEST_KIND,
  NWC_RESPONSE_KIND,
} from "../nips/nip47.ts";
import { parseBolt11 } from "../nips/nip57.ts";
import { Pool } from "../relay/pool.ts";
import type { WebSocketConstructor } from "../relay/websocket.ts";

export type FakeNwcWalletOptions = {
  readonly relays: ReadonlyArray<string>;
  readonly websocketImplementation?: WebSocketConstructor | undefined;
  readonly walletSk?: string | undefined;
  readonly clientSk?: string | undefined;
  /** Null = info event without an encryption tag (legacy NIP-04 wallet). */
  // oxlint-disable-next-line typescript/no-restricted-types -- null explicitly denotes a legacy NIP-04-only info event
  readonly encryptions?: ReadonlyArray<string> | null | undefined;
  readonly methods?: ReadonlyArray<NwcMethod> | undefined;
  readonly notifications?: ReadonlyArray<"payment_received" | "payment_sent"> | undefined;
  readonly balance?: number | undefined;
  readonly budget?: NwcBudget | undefined;
  readonly lud16?: string | undefined;
  readonly publishInfo?: boolean | undefined;
  readonly replyDelayMs?: number | undefined;
};

export type FakeNwcWallet = {
  readonly uri: string;
  readonly walletPubkey: string;
  readonly clientPubkey: string;
  readonly requests: ReadonlyArray<{
    method: string;
    params: unknown;
    encryption: NwcEncryption;
    event: Event;
  }>;
  readonly ready: () => Promise<void>;
  readonly setResponse: (
    method: NwcMethod,
    outcome: { result: unknown } | { error: { code: string; message: string } } | undefined,
  ) => void;
  readonly setSilent: (silent: boolean) => void;
  readonly receive: (params: {
    amount: number;
    description?: string | undefined;
  }) => Promise<NwcTransaction>;
  readonly close: () => void;
};

type Tx = NwcTransaction;
type InvoiceEntry = { transaction: Tx; preimage: Uint8Array };
type Override = { result: unknown } | { error: { code: string; message: string } } | undefined;

const ALL_METHODS: ReadonlyArray<NwcMethod> = [
  "pay_invoice",
  "make_invoice",
  "lookup_invoice",
  "get_balance",
  "get_info",
  "list_transactions",
  "get_budget",
];

function intToWords(value: number): number[] {
  const words: number[] = [];
  let remaining = value;
  do {
    words.unshift(remaining % 32);
    remaining = Math.trunc(remaining / 32);
  } while (remaining > 0);
  return words;
}

function wordsField(type: number, data: ReadonlyArray<number>): number[] {
  return [type, Math.floor(data.length / 32), data.length % 32, ...data];
}

function bytesField(type: number, bytes: Uint8Array): number[] {
  return wordsField(type, [...bech32.toWords(bytes)]);
}

function wordsToBytesPadded(words: ReadonlyArray<number>): Uint8Array {
  const out: number[] = [];
  let acc = 0n;
  let bits = 0;
  for (const word of words) {
    acc = acc * 32n + BigInt(word);
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push(Number((acc / 2n ** BigInt(bits)) % 256n));
    }
  }
  if (bits > 0) {
    out.push(Number((acc * 2n ** BigInt(8 - bits)) % 256n));
  }
  return new Uint8Array(out);
}

function bolt11Invoice(opts: {
  amount: number;
  paymentHash: Uint8Array;
  description?: string | undefined;
  descriptionHash?: string | undefined;
  expiry?: number | undefined;
  timestamp: number;
  signingKey: Uint8Array;
}): string {
  const words = intToWords(opts.timestamp);
  while (words.length < 7) {
    words.unshift(0);
  }
  words.push(...bytesField(1, opts.paymentHash));
  if (opts.description !== undefined) {
    words.push(...bytesField(13, utf8Encoder.encode(opts.description)));
  }
  if (opts.descriptionHash !== undefined) {
    words.push(...bytesField(23, hexToBytes(opts.descriptionHash)));
  }
  if (opts.expiry !== undefined) {
    words.push(...wordsField(6, intToWords(opts.expiry)));
  }
  const hrp = `lnbcrt${opts.amount * 10}p`;
  const hrpBytes = utf8Encoder.encode(hrp);
  const dataBytes = wordsToBytesPadded(words);
  const message = new Uint8Array(hrpBytes.length + dataBytes.length);
  message.set(hrpBytes);
  message.set(dataBytes, hrpBytes.length);
  const digest = sha256(message);
  let recovered: Uint8Array | undefined;
  try {
    recovered = secp256k1.sign(digest, opts.signingKey, {
      format: "recovered",
      prehash: false,
    });
    const signature = new Uint8Array(65);
    signature.set(recovered.subarray(1), 0);
    signature[64] = recovered[0] ?? 0;
    words.push(...bech32.toWords(signature));
    signature.fill(0);
    return bech32.encode(hrp, words, false);
  } finally {
    digest.fill(0);
    message.fill(0);
    dataBytes.fill(0);
    recovered?.fill(0);
  }
}

const cloneTx = (tx: Tx): Tx => ({ ...tx });

function payloadFor(resultType: string, outcome: { result: unknown } | { error: unknown }): string {
  if ("result" in outcome) {
    return JSON.stringify({ result_type: resultType, result: outcome.result, error: null });
  }
  return JSON.stringify({ result_type: resultType, result: null, error: outcome.error });
}

function encryptionOf(event: Event): NwcEncryption | undefined {
  const value = event.tags.find(([name]) => name === "encryption")?.[1];
  if (value === undefined || value === "nip04") {
    return "nip04";
  }
  if (value === "nip44_v2") {
    return "nip44_v2";
  }
  return undefined;
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (error: Error) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((_resolve, _reject) => {
    resolve = _resolve;
    reject = _reject;
  });
  return { promise, resolve, reject };
}

/**
 * In-process NWC wallet service backed by a real Pool. It keeps a small invoice/transaction ledger,
 * answers every NIP-47 method it advertises, enforces budget/balance failures, and emits NWC-02
 * notifications. Intended for tests and local development only.
 */
export function createFakeNwcWallet(opts: FakeNwcWalletOptions): FakeNwcWallet {
  const walletKeys =
    opts.walletSk === undefined ? Keys.generate() : Keys.fromSecretKey(opts.walletSk);
  const clientKeys =
    opts.clientSk === undefined ? Keys.generate() : Keys.fromSecretKey(opts.clientSk);
  const encryptNip44 = (peer: string, plaintext: string): string => {
    const secret = walletKeys.secretKey.bytes;
    let conversation: Uint8Array;
    try {
      conversation = nip44.getConversationKey(secret, peer, walletKeys.backend);
    } finally {
      secret.fill(0);
    }
    try {
      return nip44.encrypt(plaintext, conversation);
    } finally {
      conversation.fill(0);
    }
  };
  const decryptNip44 = (peer: string, ciphertext: string): string => {
    const secret = walletKeys.secretKey.bytes;
    let conversation: Uint8Array;
    try {
      conversation = nip44.getConversationKey(secret, peer, walletKeys.backend);
    } finally {
      secret.fill(0);
    }
    try {
      return nip44.decrypt(ciphertext, conversation);
    } finally {
      conversation.fill(0);
    }
  };
  const encryptNip04 = (peer: string, plaintext: string): string => {
    const secret = walletKeys.secretKey.bytes;
    try {
      return nip04.encryptToPubkey(plaintext, secret, peer, walletKeys.backend);
    } finally {
      secret.fill(0);
    }
  };
  const decryptNip04 = (peer: string, ciphertext: string): string => {
    const secret = walletKeys.secretKey.bytes;
    try {
      return nip04.decryptFromPubkey(ciphertext, secret, peer, walletKeys.backend);
    } finally {
      secret.fill(0);
    }
  };
  const methods = [...(opts.methods ?? ALL_METHODS)];
  const encryptions = opts.encryptions === undefined ? ["nip44_v2", "nip04"] : opts.encryptions;
  const offered = encryptions === null ? ["nip04"] : [...encryptions];
  const notifications = [...(opts.notifications ?? ["payment_received", "payment_sent"])];
  const publishInfo = opts.publishInfo ?? true;
  const replyDelayMs = opts.replyDelayMs ?? 0;
  const pool = new Pool({
    websocketImplementation: opts.websocketImplementation,
    allowInsecure: true,
    enableReconnect: true,
  });
  const requests: Array<{
    method: string;
    params: unknown;
    encryption: NwcEncryption;
    event: Event;
  }> = [];
  const overrides = new Map<NwcMethod, Override>();
  const invoices = new Map<string, InvoiceEntry>();
  const transactions: Tx[] = [];
  let balance = opts.balance ?? 0;
  let usedBudget = opts.budget?.used_budget ?? 0;
  let silent = false;
  let closed = false;
  const ready = deferred<undefined>();
  const readyPromise = ready.promise;
  const readyResolve = (): void => ready.resolve(undefined);
  const readyReject = (error: Error): void => ready.reject(error);
  let subscriptionReady = false;
  let infoReady = !publishInfo;

  const finishReadyIfDone = (): void => {
    if (subscriptionReady && infoReady) {
      readyResolve();
    }
  };

  const uri = `nostr+walletconnect://${walletKeys.publicKey}?${opts.relays
    .map((relay) => `relay=${encodeURIComponent(relay)}`)
    .join("&")}&secret=${clientKeys.secretKey.toHex()}${
    opts.lud16 === undefined ? "" : `&lud16=${encodeURIComponent(opts.lud16)}`
  }`;

  const txBase = (type: Tx["type"], amount: number): Tx => ({
    type,
    payment_hash: bytesToHex(randomBytes(32)),
    amount,
    created_at: nowSeconds(),
  });

  const insertTx = (tx: Tx): Tx => {
    const copy = cloneTx(tx);
    transactions.push(copy);
    return cloneTx(copy);
  };

  const updateTx = (paymentHash: string, update: Partial<Tx>): void => {
    const index = transactions.findIndex((tx) => tx.payment_hash === paymentHash);
    const current = transactions[index];
    if (current !== undefined) {
      transactions[index] = {
        ...current,
        ...update,
        type: update.type ?? current.type,
        payment_hash: update.payment_hash ?? current.payment_hash,
        amount: update.amount ?? current.amount,
        created_at: update.created_at ?? current.created_at,
      };
    }
  };

  const publishNotification = async (
    type: NwcNotification["type"],
    transaction: Tx,
  ): Promise<void> => {
    if (closed || !notifications.includes(type)) {
      return;
    }
    const payload = JSON.stringify({
      notification_type: type,
      notification: cloneTx(transaction),
    });
    const jobs: Array<Promise<unknown>> = [];
    if (offered.includes("nip44_v2")) {
      jobs.push(
        (async () => {
          const content = encryptNip44(clientKeys.publicKey, payload);
          const event = finalizeEvent(
            {
              kind: NWC_NOTIFICATION_KIND,
              tags: [["p", clientKeys.publicKey]],
              content,
              created_at: nowSeconds(),
            },
            walletKeys,
          );
          await pool.publish(opts.relays, event);
        })(),
      );
    }
    if (offered.includes("nip04")) {
      jobs.push(
        (async () => {
          const content = encryptNip04(clientKeys.publicKey, payload);
          const event = finalizeEvent(
            {
              kind: NWC_NOTIFICATION_NIP04_KIND,
              tags: [["p", clientKeys.publicKey]],
              content,
              created_at: nowSeconds(),
            },
            walletKeys,
          );
          await pool.publish(opts.relays, event);
        })(),
      );
    }
    await Promise.all(jobs);
  };

  const infoResult = (): Record<string, unknown> => ({
    alias: "fake-nwc-wallet",
    color: "ffaa00",
    pubkey: walletKeys.publicKey,
    network: "regtest",
    block_height: 1,
    block_hash: "00".repeat(32),
    methods,
    notifications,
  });

  const budgetResult = (): Record<string, unknown> => {
    if (opts.budget === undefined) {
      return {};
    }
    return {
      used_budget: usedBudget,
      total_budget: opts.budget.total_budget,
      ...(opts.budget.renews_at === undefined ? {} : { renews_at: opts.budget.renews_at }),
      renewal_period: opts.budget.renewal_period,
    };
  };

  const listResult = (params: Record<string, unknown>): Record<string, unknown> => {
    const now = nowSeconds();
    const from = typeof params["from"] === "number" ? params["from"] : 0;
    const until = typeof params["until"] === "number" ? params["until"] : now;
    const offset = typeof params["offset"] === "number" ? params["offset"] : 0;
    const filtered = transactions
      .filter((tx) => tx.created_at >= from && tx.created_at <= until)
      .filter((tx) =>
        params["type"] === "incoming" || params["type"] === "outgoing"
          ? tx.type === params["type"]
          : true,
      )
      .filter(
        (tx) => params["unpaid"] === true || tx.type !== "incoming" || tx.settled_at !== undefined,
      )
      .map(cloneTx)
      .sort((a, b) => b.created_at - a.created_at);
    const limit = typeof params["limit"] === "number" ? params["limit"] : filtered.length;
    return {
      transactions: filtered.slice(offset, offset + limit),
      total_count: filtered.length,
    };
  };

  const makeInvoice = (params: Record<string, unknown>): { result?: unknown; error?: unknown } => {
    const { amount } = params;
    if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount < 0) {
      return { error: { code: "OTHER", message: "invalid amount" } };
    }
    const preimage = randomBytes(32);
    const paymentHash = bytesToHex(sha256(preimage));
    const createdAt = nowSeconds();
    const expiry = typeof params["expiry"] === "number" ? params["expiry"] : undefined;
    const description =
      typeof params["description"] === "string" ? params["description"] : undefined;
    const descriptionHash =
      typeof params["description_hash"] === "string" ? params["description_hash"] : undefined;
    const signingKey = walletKeys.secretKey.bytes;
    let invoice: string;
    try {
      invoice = bolt11Invoice({
        amount,
        paymentHash: hexToBytes(paymentHash),
        ...(description === undefined ? {} : { description }),
        ...(descriptionHash === undefined ? {} : { descriptionHash }),
        ...(expiry === undefined ? {} : { expiry }),
        timestamp: createdAt,
        signingKey,
      });
    } finally {
      signingKey.fill(0);
    }
    const tx: Tx = {
      type: "incoming",
      state: "pending",
      invoice,
      ...(description === undefined ? {} : { description }),
      ...(descriptionHash === undefined ? {} : { description_hash: descriptionHash }),
      payment_hash: paymentHash,
      amount,
      created_at: createdAt,
      ...(expiry === undefined ? {} : { expires_at: createdAt + expiry }),
      ...(isRecord(params["metadata"]) ? { metadata: params["metadata"] } : {}),
    };
    invoices.set(paymentHash, { transaction: tx, preimage });
    insertTx(tx);
    return { result: cloneTx(tx) };
  };

  const payInvoice = async (
    params: Record<string, unknown>,
  ): Promise<{ result?: unknown; error?: unknown }> => {
    const invoiceText = params["invoice"];
    if (typeof invoiceText !== "string") {
      return { error: { code: "OTHER", message: "invalid invoice" } };
    }
    const decoded = parseBolt11(invoiceText);
    if (decoded === undefined) {
      return { error: { code: "OTHER", message: "invalid invoice" } };
    }
    const explicit = params["amount"];
    const amount =
      typeof explicit === "number" && Number.isSafeInteger(explicit) && explicit >= 0
        ? explicit
        : decoded.amountMsats;
    if (amount === undefined) {
      return { error: { code: "OTHER", message: "amount required" } };
    }
    if (amount > balance) {
      return { error: { code: "INSUFFICIENT_BALANCE", message: "insufficient balance" } };
    }
    if (opts.budget !== undefined && usedBudget + amount > opts.budget.total_budget) {
      return { error: { code: "QUOTA_EXCEEDED", message: "budget exceeded" } };
    }
    const paymentHash =
      decoded.paymentHash === undefined ? undefined : bytesToHex(decoded.paymentHash);
    const entry = paymentHash === undefined ? undefined : invoices.get(paymentHash);
    if (entry === undefined) {
      return { error: { code: "PAYMENT_FAILED", message: "no route" } };
    }
    balance -= amount;
    usedBudget += amount;
    const settledAt = nowSeconds();
    updateTx(entry.transaction.payment_hash, { state: "settled", settled_at: settledAt });
    entry.transaction = {
      ...entry.transaction,
      state: "settled",
      settled_at: settledAt,
    };
    const outgoing = insertTx({
      ...txBase("outgoing", amount),
      payment_hash: entry.transaction.payment_hash,
      invoice: invoiceText,
      preimage: bytesToHex(entry.preimage),
      state: "settled",
      settled_at: settledAt,
      fees_paid: 0,
    });
    balance += amount;
    await publishNotification("payment_sent", outgoing);
    await publishNotification("payment_received", entry.transaction);
    return { result: { preimage: bytesToHex(entry.preimage), fees_paid: 0 } };
  };

  const lookupInvoice = (
    params: Record<string, unknown>,
  ): { result?: unknown; error?: unknown } => {
    let paymentHash =
      typeof params["payment_hash"] === "string" ? params["payment_hash"] : undefined;
    if (paymentHash === undefined && typeof params["invoice"] === "string") {
      const decoded = parseBolt11(params["invoice"]);
      paymentHash =
        decoded?.paymentHash === undefined ? undefined : bytesToHex(decoded.paymentHash);
    }
    const tx = transactions.find(
      (entry) => entry.type === "incoming" && entry.payment_hash === paymentHash,
    );
    if (tx === undefined) {
      return { error: { code: "NOT_FOUND", message: "invoice not found" } };
    }
    return { result: cloneTx(tx) };
  };

  const evaluate = async (
    method: NwcMethod,
    params: Record<string, unknown>,
  ): Promise<{ result?: unknown; error?: unknown }> => {
    const override = overrides.get(method);
    if (override !== undefined) {
      return "result" in override ? { result: override.result } : { error: override.error };
    }
    if (!methods.includes(method)) {
      return { error: { code: "NOT_IMPLEMENTED", message: "method not implemented" } };
    }
    if (method === "get_info") {
      return { result: infoResult() };
    }
    if (method === "get_balance") {
      return { result: { balance } };
    }
    if (method === "make_invoice") {
      return makeInvoice(params);
    }
    if (method === "pay_invoice") {
      return payInvoice(params);
    }
    if (method === "lookup_invoice") {
      return lookupInvoice(params);
    }
    if (method === "list_transactions") {
      return { result: listResult(params) };
    }
    return { result: budgetResult() };
  };

  const decryptRequest = (event: Event, encryption: NwcEncryption): Record<string, unknown> => {
    const plaintext =
      encryption === "nip44_v2"
        ? decryptNip44(event.pubkey, event.content)
        : decryptNip04(event.pubkey, event.content);
    const parsed: unknown = JSON.parse(plaintext);
    if (!isRecord(parsed)) {
      throw new Error("invalid request payload");
    }
    return parsed;
  };

  const respond = async (
    request: Event,
    encryption: NwcEncryption,
    resultType: string,
    outcome: { result?: unknown; error?: unknown },
  ): Promise<void> => {
    if (closed) {
      return;
    }
    const plaintext = payloadFor(
      resultType,
      outcome.result === undefined
        ? { error: outcome.error ?? { code: "OTHER", message: "wallet error" } }
        : { result: outcome.result },
    );
    const content =
      encryption === "nip44_v2"
        ? encryptNip44(request.pubkey, plaintext)
        : encryptNip04(request.pubkey, plaintext);
    const event = finalizeEvent(
      {
        kind: NWC_RESPONSE_KIND,
        tags: [
          ["e", request.id],
          ["p", request.pubkey],
        ],
        content,
        created_at: nowSeconds(),
      },
      walletKeys,
    );
    await pool.publish(opts.relays, event);
  };

  const handleRequest = (event: Event): void => {
    if (closed || silent || event.kind !== NWC_REQUEST_KIND) {
      return;
    }
    const expiration = event.tags.find(([name]) => name === "expiration")?.[1];
    if (expiration !== undefined && Number(expiration) <= nowSeconds()) {
      return;
    }
    void (async (): Promise<void> => {
      const encryption = encryptionOf(event);
      if (encryption === undefined) {
        return;
      }
      let method: string;
      let params: Record<string, unknown>;
      try {
        const payload = decryptRequest(event, encryption);
        method = typeof payload["method"] === "string" ? payload["method"] : "";
        const rawParams = payload["params"];
        params = isRecord(rawParams) ? rawParams : {};
      } catch {
        return;
      }
      requests.push({ method, params, encryption, event });
      const reply = async (outcome: { result?: unknown; error?: unknown }): Promise<void> => {
        if (replyDelayMs > 0) {
          await new Promise<void>((resolve) => {
            setTimeout(() => {
              resolve();
            }, replyDelayMs);
          });
        }
        await respond(event, encryption, method, outcome);
      };
      if (event.pubkey !== clientKeys.publicKey) {
        await reply({ error: { code: "UNAUTHORIZED", message: "unauthorized client" } });
        return;
      }
      if (!offered.includes(encryption)) {
        await reply({
          error: { code: "UNSUPPORTED_ENCRYPTION", message: "unsupported encryption" },
        });
        return;
      }
      const knownMethod = ALL_METHODS.find((candidate) => candidate === method);
      if (knownMethod === undefined) {
        await reply({ error: { code: "NOT_IMPLEMENTED", message: "method not implemented" } });
        return;
      }
      await reply(await evaluate(knownMethod, params));
      // oxlint-disable-next-line promise/prefer-await-to-then -- fire-and-forget teardown must suppress rejections
    })().catch(() => {
      // a closed signer/pool during teardown must not create an unhandled rejection
    });
  };

  const sub = pool.subscribe(
    opts.relays,
    [{ kinds: [NWC_REQUEST_KIND], "#p": [walletKeys.publicKey] }],
    {
      onEvent: handleRequest,
      onEose: () => {
        subscriptionReady = true;
        finishReadyIfDone();
      },
      onClose: (reason) => {
        if (!closed) {
          readyReject(new Error(`wallet request subscription closed: ${reason}`));
        }
      },
    },
  );

  if (publishInfo) {
    const tags: string[][] = [];
    if (encryptions !== null) {
      tags.push(["encryption", offered.join(" ")]);
    }
    if (notifications.length > 0) {
      tags.push(["notifications", notifications.join(" ")]);
    }
    const info = finalizeEvent(
      {
        kind: NWC_INFO_KIND,
        tags,
        content: methods.join(" "),
        created_at: nowSeconds(),
      },
      walletKeys,
    );
    void (async (): Promise<void> => {
      try {
        const outcomes = await pool.publish(opts.relays, info);
        if (!outcomes.some((outcome) => outcome.status === "ok")) {
          throw new Error("wallet info publish refused");
        }
        infoReady = true;
        finishReadyIfDone();
      } catch (error) {
        readyReject(error instanceof Error ? error : new Error(String(error)));
      }
    })();
  }

  return {
    uri,
    walletPubkey: walletKeys.publicKey,
    clientPubkey: clientKeys.publicKey,
    requests,
    ready: async () => readyPromise,
    setResponse(method, outcome) {
      if (outcome === undefined) {
        overrides.delete(method);
      } else {
        overrides.set(method, outcome);
      }
    },
    setSilent(value) {
      silent = value;
    },
    async receive(params) {
      const preimage = randomBytes(32);
      const tx = insertTx({
        ...txBase("incoming", params.amount),
        payment_hash: bytesToHex(sha256(preimage)),
        state: "settled",
        preimage: bytesToHex(preimage),
        settled_at: nowSeconds(),
        ...(params.description === undefined ? {} : { description: params.description }),
      });
      balance += params.amount;
      await publishNotification("payment_received", tx);
      return cloneTx(tx);
    },
    close() {
      if (closed) {
        return;
      }
      closed = true;
      sub.close("wallet closed");
      pool.close();
      walletKeys.secretKey.zeroize();
      clientKeys.secretKey.zeroize();
    },
  };
}
