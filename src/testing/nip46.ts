import { Keys, finalizeEvent } from "../core/index.ts";
import { Kind } from "../core/kind.ts";
import { isTag } from "../core/tag.ts";
import { isRecord, nowSeconds } from "../core/util.ts";
import {
  getConversationKey,
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
} from "../nips/nip44.ts";
import { decodeNip46Request, encodeNip46Response } from "../nips/nip46.ts";
import type { Nip46Response } from "../nips/nip46.ts";
import type { FakeRelayNetwork } from "./network.ts";

export type FakeNip46SignerOptions = {
  /** The network the fake signer joins as a client of `relayUrl`. */
  network: FakeRelayNetwork;
  relayUrl: string;
  /** Pubkey of the NIP-46 client under test. */
  clientPubkey: string;
  /** Remote-signer key; random when omitted. */
  bunkerSk?: string | undefined;
  /** The user key the signer signs for; random when omitted. */
  userSk?: string | undefined;
  /** First answer `auth_url` (result) with this URL in the error field, then the real response. */
  authUrl?: string | undefined;
  authUrlMethods?: ReadonlyArray<string> | undefined;
  /** Delay in ms before the real response after an `auth_url` reply. */
  authReplyDelayMs?: number | undefined;
  /** Collected RPC requests (mutated as they arrive). */
  requests?: Array<{ method: string; params: string[] }> | undefined;
  /** `switch_relays` result. Default `"null"`. */
  switchRelays?: string[] | undefined;
  /** Override `connect` RPC result. Default `"ack"`. */
  connectResult?: string | undefined;
  /** Reply with neither `result` nor `error` for these methods. */
  emptyMethods?: ReadonlyArray<string> | undefined;
  /**
   * Serialize the response JSON; default {@link encodeNip46Response}, which omits absent fields.
   * Lets tests put explicit `null`s on the wire like some remote signers do.
   */
  encodeResponse?: ((res: Nip46Response) => string) | undefined;
};

export type FakeNip46Signer = {
  readonly bunkerPubkey: string;
  readonly userPublicKey: string;
  /** Also answer RPCs on another relay of the same network (e.g. after switch_relays). */
  attach: (relayUrl: string) => void;
  /** Publish the nostrconnect handshake secret confirmation as the bunker. */
  confirmHandshake: (secret: string) => void;
  close: () => void;
};

/**
 * In-process NIP-46 remote signer: subscribes to kind:24133 requests on `relayUrl` and answers as a
 * bunker, encrypted to `clientPubkey` with NIP-44.
 */
export function createFakeNip46Signer(opts: FakeNip46SignerOptions): FakeNip46Signer {
  const bunkerKeys =
    opts.bunkerSk !== undefined && opts.bunkerSk !== ""
      ? Keys.fromSecretKey(opts.bunkerSk)
      : Keys.generate();
  const userKeys =
    opts.userSk !== undefined && opts.userSk !== ""
      ? Keys.fromSecretKey(opts.userSk)
      : Keys.generate();
  const convKey = getConversationKey(bunkerKeys.secretKey.bytes, opts.clientPubkey);
  const handled = new Set<string>();
  const authPending = new Set<string>();
  const authMethods = new Set(opts.authUrlMethods ?? ["connect"]);
  let closed = false;

  const sockets = new Set<{ close: () => void }>();
  const listen = (relayUrl: string): void => {
    const ws = new opts.network.websocketImplementation(relayUrl);
    ws.addEventListener("open", () => {
      ws.send(
        JSON.stringify([
          "REQ",
          "fake-nip46-signer",
          { kinds: [Kind.NostrConnect], "#p": [bunkerKeys.publicKey] },
        ]),
      );
    });
    ws.addEventListener("message", (ev) => onMessage(ev, ws));
    sockets.add(ws);
  };

  const onMessage = (ev: unknown, ws: { send: (data: string) => void }): void => {
    if (typeof ev !== "object" || ev === null || !("data" in ev)) {
      return;
    }
    const { data } = ev;
    let msg: unknown;
    try {
      msg = JSON.parse(String(data));
    } catch {
      return;
    }
    if (!Array.isArray(msg) || msg[0] !== "EVENT") {
      return;
    }
    const parts: unknown[] = msg;
    const rawEvent = parts.at(2);
    if (!isRecord(rawEvent)) {
      return;
    }
    const { kind, pubkey, content, id } = rawEvent;
    if (kind !== Kind.NostrConnect) {
      return;
    }
    if (typeof pubkey !== "string" || typeof content !== "string" || typeof id !== "string") {
      return;
    }
    if (pubkey !== opts.clientPubkey || handled.has(id)) {
      return;
    }

    try {
      const req = decodeNip46Request(nip44Decrypt(content, convKey));
      if (
        opts.authUrl !== undefined &&
        opts.authUrl !== "" &&
        authMethods.has(req.method) &&
        !authPending.has(req.id)
      ) {
        authPending.add(req.id);
        reply(ws, opts.clientPubkey, req.id, "auth_url", opts.authUrl);
      }
      handled.add(id);
      opts.requests?.push({ method: req.method, params: req.params });

      let result: string | undefined;
      let error: string | undefined;
      switch (opts.emptyMethods?.includes(req.method) === true ? "#empty" : req.method) {
        case "connect":
          result = opts.connectResult ?? "ack";
          break;
        case "get_public_key":
          result = userKeys.publicKey;
          break;
        case "ping":
          result = "pong";
          break;
        case "switch_relays":
          result = opts.switchRelays === undefined ? "null" : JSON.stringify(opts.switchRelays);
          break;
        case "logout":
          result = "ack";
          break;
        case "sign_event": {
          const rawTemplate: unknown = JSON.parse(req.params.at(0) ?? "null");
          if (
            !isRecord(rawTemplate) ||
            typeof rawTemplate["kind"] !== "number" ||
            !Array.isArray(rawTemplate["tags"]) ||
            !rawTemplate["tags"].every(isTag) ||
            typeof rawTemplate["content"] !== "string" ||
            typeof rawTemplate["created_at"] !== "number"
          ) {
            throw new Error("invalid sign_event template");
          }
          result = JSON.stringify(
            finalizeEvent(
              {
                kind: rawTemplate["kind"],
                tags: rawTemplate["tags"],
                content: rawTemplate["content"],
                created_at: rawTemplate["created_at"],
              },
              userKeys.secretKey,
            ),
          );
          break;
        }
        case "#empty":
          break;
        default:
          error = `unsupported method ${req.method}`;
      }
      if (authPending.has(req.id) && opts.authReplyDelayMs !== undefined) {
        const pendingId = req.id;
        const pendingResult = result;
        const pendingError = error;
        setTimeout(
          () => reply(ws, opts.clientPubkey, pendingId, pendingResult, pendingError),
          opts.authReplyDelayMs,
        );
      } else {
        reply(ws, opts.clientPubkey, req.id, result, error);
      }
    } catch {
      handled.add(id);
    }
  };

  const reply = (
    ws: { send: (data: string) => void },
    clientPubkey: string,
    id: string,
    result?: string,
    error?: string,
  ): void => {
    if (closed) {
      return;
    }
    const payload = (opts.encodeResponse ?? encodeNip46Response)({ id, result, error });
    const event = finalizeEvent(
      {
        kind: Kind.NostrConnect,
        tags: [["p", clientPubkey]],
        content: nip44Encrypt(payload, convKey),
        created_at: nowSeconds(),
      },
      bunkerKeys.secretKey,
    );
    ws.send(JSON.stringify(["EVENT", event]));
  };

  listen(opts.relayUrl);

  return {
    bunkerPubkey: bunkerKeys.publicKey,
    userPublicKey: userKeys.publicKey,
    confirmHandshake(secret: string): void {
      const payload = encodeNip46Response({ id: "handshake", result: secret });
      const event = finalizeEvent(
        {
          kind: Kind.NostrConnect,
          tags: [["p", opts.clientPubkey]],
          content: nip44Encrypt(payload, convKey),
          created_at: nowSeconds(),
        },
        bunkerKeys.secretKey,
      );
      opts.network.relay(opts.relayUrl).inject(event);
    },
    attach(relayUrl: string): void {
      listen(relayUrl);
    },
    close(): void {
      closed = true;
      for (const ws of sockets) {
        ws.close();
      }
      sockets.clear();
    },
  };
}
