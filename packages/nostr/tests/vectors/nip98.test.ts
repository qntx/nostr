import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vite-plus/test";

import type { Event, EventTemplate } from "../../src/core/event.ts";
import { Keys, signEvent } from "../../src/core/key.ts";
import { hexToBytes } from "../../src/core/util.ts";
import {
  Nip98Error,
  getToken,
  unpackEventFromToken,
  validateAuthEvent,
} from "../../src/nips/nip98.ts";

// Shared vectors consumed by the nk-* Rust crates as well; regenerate with
// `bun packages/nostr/scripts/parity/gen/all.ts`.
type AuthCase = {
  url: string;
  method: string;
  payload_hex?: string;
  payload_json?: unknown;
  content: string;
  created_at: number;
  event: Event;
  token: string;
  header: string;
  rust?: false;
};

type UnpackOk = { token: string; event: Event };
type UnpackErr = { token: string; error: string };

type ValidateCase = {
  event: Event;
  url: string;
  method: string;
  payload_hex?: string;
  payload_json?: unknown;
  now: number;
  max_skew_secs: number;
  result: boolean;
  rust?: false;
};

const vector = JSON.parse(
  readFileSync(join(import.meta.dirname, "../../../../vectors/nip98/codec.json"), "utf8"),
) as {
  secret_key: string;
  aux: string;
  auth: AuthCase[];
  unpack: Array<UnpackOk | UnpackErr>;
  validate: ValidateCase[];
};

const aux = hexToBytes(vector.aux);
const keys = Keys.fromSecretKey(vector.secret_key);

/** Deterministic signer: fixed key + fixed aux → the vector's id/sig. */
function sign(template: EventTemplate): Event {
  return signEvent({ ...template, pubkey: keys.publicKey }, keys, aux);
}

function payloadOf(c: { payload_hex?: string; payload_json?: unknown }): unknown {
  if (c.payload_json !== undefined) {
    return c.payload_json;
  }
  if (c.payload_hex === undefined) {
    return undefined;
  }
  return hexToBytes(c.payload_hex);
}

const unpackOk = vector.unpack.filter((c): c is UnpackOk => "event" in c);
const unpackErr = vector.unpack.filter((c): c is UnpackErr => "error" in c);

const realDateNow = Date.now;
afterEach(() => {
  Date.now = realDateNow;
});

describe("vectors/nip98 auth_event + token", () => {
  test.each(vector.auth)("case %#", async (c) => {
    const signed: Event[] = [];
    const token = await getToken(
      c.url,
      c.method,
      (t) => {
        const event = sign(t);
        signed.push(event);
        return event;
      },
      { content: c.content, payload: payloadOf(c), now: c.created_at },
    );
    expect(signed).toHaveLength(1);
    expect(signed[0]).toStrictEqual(c.event);
    // `getToken` emits canonical wire order — byte-identical to the pinned
    // token and to Rust's `token`.
    expect(token).toBe(c.token);
    expect(c.header).toBe(`Nostr ${c.token}`);
  });
});

describe("vectors/nip98 unpack", () => {
  test.each(unpackOk)("ok case %#", (c) => {
    expect(unpackEventFromToken(c.token)).toStrictEqual(c.event);
  });

  test.each(unpackErr)("error case %#", (c) => {
    expect(() => unpackEventFromToken(c.token)).toThrow(new Nip98Error(c.error));
  });
});

describe("vectors/nip98 validate_auth_event", () => {
  test.each(vector.validate)("case %#", (c) => {
    Date.now = () => c.now * 1000;
    expect(
      validateAuthEvent(c.event, c.url, c.method, {
        payload: payloadOf(c),
        maxSkewSec: c.max_skew_secs,
      }),
    ).toBe(c.result);
  });
});
