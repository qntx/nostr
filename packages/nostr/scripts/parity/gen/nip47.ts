/// <reference types="node" />
// Generates vectors/nip47.json — deterministic: fixed keys, fixed NIP-44 nonce,
// fixed schnorr aux, so the ciphertexts/signatures are stable across runs.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { hexToBytes } from "@noble/hashes/utils.js";

import { bytesToHex } from "../../../src/core/index.ts";
import { Keys, signEvent } from "../../../src/core/key.ts";
import * as nip44 from "../../../src/nips/nip44.ts";

const pkgRoot = join(import.meta.dirname, "../../..");
const root = join(pkgRoot, "../..");

const CLIENT_SK = hexToBytes("03".padStart(64, "0"));
const WALLET_SK = hexToBytes("04".padStart(64, "0"));
const client = Keys.fromSecretKey(CLIENT_SK);
const wallet = Keys.fromSecretKey(WALLET_SK);
const NONCE = hexToBytes("01".repeat(32));
const AUX = new Uint8Array(32);

const convFor = (sk: Uint8Array, peerX: string) => nip44.getConversationKey(sk, peerX);

function signedResponse(
  payload: Record<string, unknown>,
  requestId: string,
): Record<string, unknown> {
  const content = nip44.encrypt(
    JSON.stringify(payload),
    convFor(WALLET_SK, client.publicKey),
    NONCE,
  );
  return signEvent(
    {
      kind: 23195,
      pubkey: wallet.publicKey,
      created_at: 1_700_000_000,
      tags: [
        ["p", client.publicKey],
        ["e", requestId],
      ],
      content,
    },
    WALLET_SK,
    AUX,
  );
}

const requestEvent = signEvent(
  {
    kind: 23194,
    pubkey: client.publicKey,
    created_at: 1_699_999_999,
    tags: [
      ["p", wallet.publicKey],
      ["encryption", "nip44_v2"],
    ],
    content: nip44.encrypt(
      JSON.stringify({ method: "get_balance", params: {} }),
      convFor(CLIENT_SK, wallet.publicKey),
      NONCE,
    ),
  },
  CLIENT_SK,
  AUX,
) as { id: string };

const uriBase =
  "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss%3A%2F%2Frelay.damus.io&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";

const cases = [
  { id: "uri-spec", kind: "uri", input: uriBase, ok: true },
  {
    id: "uri-multi-relay-lud16",
    kind: "uri",
    input: `${uriBase}&relay=wss%3A%2F%2Frelay2.example&lud16=alice%40wallet.example`,
    ok: true,
  },
  {
    id: "uri-ws-localhost",
    kind: "uri",
    input: uriBase.replace("wss%3A%2F%2Frelay.damus.io", "ws%3A%2F%2Flocalhost%3A7777"),
    ok: true,
  },
  {
    id: "uri-scheme",
    kind: "uri",
    input: uriBase.replace("nostr+walletconnect", "https"),
    ok: false,
  },
  { id: "uri-bad-pubkey", kind: "uri", input: uriBase.replace("b889", "zz89"), ok: false },
  { id: "uri-no-secret", kind: "uri", input: uriBase.replace(/&secret=\w+/, ""), ok: false },
  {
    id: "uri-no-relay",
    kind: "uri",
    input: uriBase.replace(/relay=wss%3A%2F%2Frelay.damus.io&/, ""),
    ok: false,
  },
  {
    id: "uri-ws-remote",
    kind: "uri",
    input: uriBase.replace("wss%3A%2F%2Frelay.damus.io", "ws%3A%2F%2Frelay.example"),
    ok: false,
  },
  {
    id: "info-spec",
    kind: "info",
    input: {
      kind: 13194,
      pubkey: "c04ccd5c82fc1ea3499b9c6a5c0a7ab627fbe00a0116110d4c750faeaecba1e2",
      created_at: 1713883677,
      tags: [
        ["encryption", "nip44_v2 nip04"],
        ["extensions", "02 03 04 06 07 08"],
      ],
      content: "pay_invoice get_balance get_info make_invoice lookup_invoice",
      id: "df467db0a9f9ec77ffe6f561811714ccaa2e26051c20f58f33c3d66d6c2b4d1c",
      sig: "31f57b369459b5306a5353aa9e03be7fbde169bc881c3233625605dd12f53548179def16b9fe1137e6465d7e4d5bb27ce81fd6e75908c46b06269f4233c845d8",
    },
    ok: true,
    expect: {
      methods: ["pay_invoice", "get_balance", "get_info", "make_invoice", "lookup_invoice"],
      nip44: true,
    },
  },
  {
    id: "info-no-encryption-tag",
    kind: "info",
    input: {
      kind: 13194,
      pubkey: "c04ccd5c82fc1ea3499b9c6a5c0a7ab627fbe00a0116110d4c750faeaecba1e2",
      created_at: 1713883677,
      tags: [],
      content: "get_balance",
      id: "df467db0a9f9ec77ffe6f561811714ccaa2e26051c20f58f33c3d66d6c2b4d1c",
      sig: "31f57b369459b5306a5353aa9e03be7fbde169bc881c3233625605dd12f53548179def16b9fe1137e6465d7e4d5bb27ce81fd6e75908c46b06269f4233c845d8",
    },
    ok: true,
    expect: { methods: ["get_balance"], nip44: false },
  },
  {
    id: "resp-get-balance-ok",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      { result_type: "get_balance", result: { balance: 10_000 }, error: null },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: true,
    expect: { balance: 10_000 },
  },
  {
    id: "resp-pay-invoice-ok",
    kind: "response",
    method: "pay_invoice",
    input: signedResponse(
      {
        result_type: "pay_invoice",
        result: { preimage: "ab".repeat(32), fees_paid: 123 },
        error: null,
      },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: true,
  },
  {
    id: "resp-error-arm",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      {
        result_type: "get_balance",
        result: null,
        error: { code: "UNAUTHORIZED", message: "no wallet" },
      },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: true,
    expect: { code: "UNAUTHORIZED" },
  },
  {
    id: "resp-both-fields",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      {
        result_type: "get_balance",
        result: { balance: 1 },
        error: { code: "OTHER", message: "x" },
      },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: false,
  },
  {
    id: "resp-wrong-method",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      { result_type: "pay_invoice", result: { preimage: "ab" }, error: null },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: false,
  },
  {
    id: "resp-bad-code",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      { result_type: "get_balance", result: null, error: { code: "NOT_A_CODE", message: "x" } },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: false,
  },
  {
    id: "resp-negative-amount",
    kind: "response",
    method: "get_balance",
    input: signedResponse(
      { result_type: "get_balance", result: { balance: -5 }, error: null },
      requestEvent.id,
    ),
    request: requestEvent,
    ok: false,
  },
];

const doc = {
  schema: 1,
  capability: "nip47",
  source: { kind: "generated" },
  keys: {
    clientSecret: bytesToHex(CLIENT_SK),
    walletSecret: bytesToHex(WALLET_SK),
    clientPubkey: client.publicKey,
    walletPubkey: wallet.publicKey,
  },
  cases,
};
mkdirSync(join(root, "vectors"), { recursive: true });
writeFileSync(join(root, "vectors", "nip47.json"), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`wrote vectors/nip47.json (${cases.length} cases)`);
