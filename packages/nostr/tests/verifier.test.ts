import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, test } from "vite-plus/test";

import { isMarkedFailed, isMarkedVerified, serializeEvent } from "../src/core/event.ts";
import type { Event } from "../src/core/event.ts";
import { bytesToHex, utf8Encoder } from "../src/core/util.ts";
import type { SerializedEventVerifier } from "../src/core/verifier.ts";
import { createEventVerifier, finalizeEvent, Kind, verifyEvent } from "../src/index.ts";

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";
const OTHER_SK_HEX = "0000000000000000000000000000000000000000000000000000000000000001";

function freshEvent(): Event {
  return finalizeEvent(
    {
      kind: Kind.TextNote,
      tags: [["t", "verifier"]],
      content: "Hello, verifier!",
      created_at: 1617932115,
    },
    SK_HEX,
  );
}

function flipFirstHexChar(hex: string): string {
  return (hex.startsWith("0") ? "1" : "0") + hex.slice(1);
}

// A caller-provided backend built from the library's own primitives: hash check plus BIP-340.
const nobleBackend: SerializedEventVerifier = (serializedUtf8, id, pubkey, sig) => {
  try {
    const digest = sha256(serializedUtf8);
    if (!digest.every((byte, i) => byte === id[i])) {
      return false;
    }
    return schnorr.verify(sig, id, pubkey);
  } catch {
    return false;
  }
};

describe("createEventVerifier", () => {
  test("passes serialized bytes and decoded id/pubkey/sig to the backend", () => {
    const seen: Array<{ serialized: string; id: string; pubkey: string; sig: string }> = [];
    const verify = createEventVerifier((serializedUtf8, id, pubkey, sig) => {
      seen.push({
        serialized: new TextDecoder().decode(serializedUtf8),
        id: bytesToHex(id),
        pubkey: bytesToHex(pubkey),
        sig: bytesToHex(sig),
      });
      return true;
    });
    const event = freshEvent();
    expect(verify({ ...event })).toBe(true);
    expect(seen).toStrictEqual([
      {
        serialized: serializeEvent(event),
        id: event.id,
        pubkey: event.pubkey,
        sig: event.sig,
      },
    ]);
  });

  describe("agrees with verifyEvent", () => {
    const verify = createEventVerifier(nobleBackend);

    const cases: Array<[string, (e: Event) => Event]> = [
      ["valid event", (e) => e],
      ["tampered content", (e) => ({ ...e, content: "tampered" })],
      ["tampered id", (e) => ({ ...e, id: flipFirstHexChar(e.id) })],
      ["tampered sig", (e) => ({ ...e, sig: flipFirstHexChar(e.sig) })],
      [
        "tampered pubkey",
        (e) => ({
          ...e,
          pubkey: finalizeEvent({ kind: 1, tags: [], content: "x", created_at: 1 }, OTHER_SK_HEX)
            .pubkey,
        }),
      ],
      ["uppercase id", (e) => ({ ...e, id: e.id.toUpperCase() })],
      ["uppercase pubkey", (e) => ({ ...e, pubkey: e.pubkey.toUpperCase() })],
      ["uppercase sig", (e) => ({ ...e, sig: e.sig.toUpperCase() })],
      ["non-hex pubkey", (e) => ({ ...e, pubkey: `zz${e.pubkey.slice(2)}` })],
      ["short sig", (e) => ({ ...e, sig: e.sig.slice(0, -2) })],
      ["non-integer kind", (e) => ({ ...e, kind: 1.5 })],
      ["negative created_at", (e) => ({ ...e, created_at: -1 })],
      ["missing tags", (e) => ({ ...e, tags: undefined as never })],
    ];

    test.each(cases)("%s", (_name, mutate) => {
      const event = freshEvent();
      const forDefault = mutate({ ...event });
      const forCustom = mutate({ ...event });
      expect(verify(forCustom)).toBe(verifyEvent(forDefault));
    });

    test("non-object input throws like verifyEvent", () => {
      expect(() => verify(null as unknown as Event)).toThrow(TypeError);
      expect(() => verifyEvent(null as unknown as Event)).toThrow(TypeError);
    });
  });

  describe("cache behaviour", () => {
    test("backend is called once per event object, then cached", () => {
      let calls = 0;
      const verify = createEventVerifier((...args) => {
        calls += 1;
        return nobleBackend(...args);
      });
      const event = { ...freshEvent() };
      expect(verify(event)).toBe(true);
      expect(verify(event)).toBe(true);
      expect(calls).toBe(1);
      expect(isMarkedVerified(event)).toBe(true);
    });

    test("finalizeEvent output is already verified and never hits the backend", () => {
      let calls = 0;
      const verify = createEventVerifier((...args) => {
        calls += 1;
        return nobleBackend(...args);
      });
      expect(verify(freshEvent())).toBe(true);
      expect(calls).toBe(0);
    });

    test("a failed event is cached and never re-verified", () => {
      let calls = 0;
      const verify = createEventVerifier((...args) => {
        calls += 1;
        return nobleBackend(...args);
      });
      const bad = { ...freshEvent(), content: "tampered" };
      expect(verify(bad)).toBe(false);
      expect(verify(bad)).toBe(false);
      expect(calls).toBe(1);
      expect(isMarkedFailed(bad)).toBe(true);
    });

    test("structurally invalid events are rejected without calling the backend", () => {
      let calls = 0;
      const verify = createEventVerifier((...args) => {
        calls += 1;
        return nobleBackend(...args);
      });
      const bad = { ...freshEvent(), pubkey: "zz" };
      expect(verify(bad)).toBe(false);
      expect(calls).toBe(0);
      expect(isMarkedFailed(bad)).toBe(true);
    });
  });

  describe("backend exceptions", () => {
    test("propagate to the caller and leave the event unmarked", () => {
      let calls = 0;
      const verify = createEventVerifier(() => {
        calls += 1;
        throw new Error("backend exploded");
      });
      const event = { ...freshEvent() };
      expect(() => verify(event)).toThrow("backend exploded");
      expect(isMarkedVerified(event)).toBe(false);
      expect(isMarkedFailed(event)).toBe(false);
      expect(() => verify(event)).toThrow("backend exploded");
      expect(calls).toBe(2);
    });
  });

  test("shares the verification cache with verifyEvent", () => {
    let calls = 0;
    const verify = createEventVerifier((...args) => {
      calls += 1;
      return nobleBackend(...args);
    });
    const event = { ...freshEvent() };
    expect(verify(event)).toBe(true);
    expect(calls).toBe(1);
    // Same object verified by the default verifier hits the shared cache.
    expect(verifyEvent(event)).toBe(true);
    expect(calls).toBe(1);
  });

  test("serializes as UTF-8 before calling the backend", () => {
    const bytes: Uint8Array[] = [];
    const verify = createEventVerifier((serializedUtf8) => {
      bytes.push(serializedUtf8);
      return true;
    });
    const event = finalizeEvent(
      { kind: 1, tags: [], content: "héllo ünïcode", created_at: 1617932115 },
      SK_HEX,
    );
    // A fresh object bypasses the finalizeEvent verification mark.
    expect(verify({ ...event })).toBe(true);
    expect(bytes[0]).toStrictEqual(utf8Encoder.encode(serializeEvent(event)));
  });
});
