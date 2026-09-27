import { hexToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { HexError } from "../src/core/error.ts";
import { bytesToHex } from "../src/core/util.ts";
import {
  decodeNostrURI,
  getPublicKey,
  Nip19Error,
  naddrEncode,
  neventEncode,
  nip19Decode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
  SecretKey,
} from "../src/index.ts";
import type {
  AddressPointer,
  DecodedResult,
  EventPointer,
  ProfilePointer,
} from "../src/nips/nip19.ts";

const nsecBytes = (r: DecodedResult): Uint8Array => {
  if (r.type !== "nsec") {
    throw new Error(`expected nsec, got ${r.type}`);
  }
  return r.data;
};

const npubHex = (r: DecodedResult): string => {
  if (r.type !== "npub") {
    throw new Error(`expected npub, got ${r.type}`);
  }
  return r.data;
};

const nprofileData = (r: DecodedResult): ProfilePointer => {
  if (r.type !== "nprofile") {
    throw new Error(`expected nprofile, got ${r.type}`);
  }
  return r.data;
};

const neventData = (r: DecodedResult): EventPointer => {
  if (r.type !== "nevent") {
    throw new Error(`expected nevent, got ${r.type}`);
  }
  return r.data;
};

const naddrData = (r: DecodedResult): AddressPointer => {
  if (r.type !== "naddr") {
    throw new Error(`expected naddr, got ${r.type}`);
  }
  return r.data;
};

describe("nip19", () => {
  test("nsec / npub / note round-trip", () => {
    const sk = SecretKey.generate();
    const nsec = nsecEncode(sk.bytes);
    expect(nsec).toMatch(/^nsec1/);
    const decoded = nip19Decode(nsec);
    expect(decoded.type).toBe("nsec");
    expect([...nsecBytes(decoded)]).toStrictEqual([...sk.bytes]);

    const pk = getPublicKey(sk);
    const npub = npubEncode(pk);
    expect(nip19Decode(npub)).toStrictEqual({ type: "npub", data: pk });

    const note = noteEncode(pk);
    expect(nip19Decode(note)).toStrictEqual({ type: "note", data: pk });
  });

  test("npub/note/nsec reject payloads that are not 32 bytes", () => {
    const short = bech32.encode("npub", bech32.toWords(new Uint8Array(16)), 1000);
    expect(() => nip19Decode(short)).toThrow(/32 bytes/);
  });

  test("nprofile / nevent / naddr round-trip", () => {
    const pk = getPublicKey(SecretKey.generate());
    const relays = ["wss://relay.example.com", "wss://nostr.banana.com"];

    const nprofile = nprofileEncode({ pubkey: pk, relays });
    const profile = nip19Decode(nprofile);
    expect(profile.type).toBe("nprofile");
    const profileData = nprofileData(profile);
    expect(profileData.pubkey).toBe(pk);
    expect(profileData.relays).toStrictEqual(expect.arrayContaining(relays));

    const nevent = neventEncode({ id: pk, relays, kind: 1, author: pk });
    const event = nip19Decode(nevent);
    expect(event.type).toBe("nevent");
    const eventData = neventData(event);
    expect(eventData.id).toBe(pk);
    expect(eventData.kind).toBe(1);
    expect(eventData.author).toBe(pk);

    const naddr = naddrEncode({
      identifier: "banana",
      pubkey: pk,
      kind: 30023,
      relays,
    });
    const addr = nip19Decode(naddr);
    expect(addr.type).toBe("naddr");
    const addrData = naddrData(addr);
    expect(addrData.identifier).toBe("banana");
    expect(addrData.kind).toBe(30023);
    expect(addrData.pubkey).toBe(pk);
  });

  test("decodeNostrURI handles prefix and invalid", () => {
    const pk = getPublicKey(SecretKey.generate());
    const npub = npubEncode(pk);
    const ok = decodeNostrURI(`nostr:${npub}`);
    expect(ok.type).toBe("npub");
    expect(decodeNostrURI("not-a-code").type).toBe("invalid");
  });

  test("decodeNostrURI rejects nostr:nsec but bare nsec still decodes", () => {
    const sk = SecretKey.generate();
    const nsec = nsecEncode(sk.bytes);
    expect(decodeNostrURI(`nostr:${nsec}`)).toStrictEqual({ type: "invalid", data: undefined });
    const bare = nip19Decode(nsec);
    expect(bare.type).toBe("nsec");
  });
});

describe("nip19 spec examples", () => {
  test("npub / nsec examples decode and re-encode", () => {
    const npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
    const pk = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    expect(nip19Decode(npub)).toStrictEqual({ type: "npub", data: pk });
    expect(npubEncode(pk)).toBe(npub);

    const nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const sk = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    const decoded = nip19Decode(nsec);
    expect(decoded.type).toBe("nsec");
    expect(bytesToHex(nsecBytes(decoded))).toBe(sk);
    expect(nsecEncode(hexToBytes(sk))).toBe(nsec);
  });

  test("nprofile example decodes pubkey and both relays", () => {
    const nprofile =
      "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    const decoded = nip19Decode(nprofile);
    expect(decoded.type).toBe("nprofile");
    const decodedData = nprofileData(decoded);
    expect(decodedData.pubkey).toBe(
      "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
    );
    expect(decodedData.relays).toStrictEqual(["wss://r.x.com", "wss://djbas.sadkb.com"]);
  });
});

describe("issue #130 encoder validation", () => {
  const pk = getPublicKey(SecretKey.generate());

  test("hex inputs are validated and normalized to lowercase", () => {
    const decoded = nip19Decode(npubEncode(pk.toUpperCase()));
    expect(decoded.type).toBe("npub");
    expect(npubHex(decoded)).toBe(pk);
    expect(() => npubEncode("nothex")).toThrow(HexError);
    expect(() => noteEncode("ab")).toThrow(HexError);
    expect(() => nprofileEncode({ pubkey: "zz" })).toThrow(HexError);
    expect(() => neventEncode({ id: "xyz" })).toThrow(HexError);
    expect(() => neventEncode({ id: pk, author: "nope" })).toThrow(HexError);
    expect(() => naddrEncode({ kind: 1, identifier: "x", pubkey: "0" })).toThrow(HexError);
  });

  test("nsecEncode requires exactly 32 bytes", () => {
    expect(() => nsecEncode(new Uint8Array(16))).toThrow(HexError);
    expect(() => nsecEncode(new Uint8Array(33))).toThrow(HexError);
    const decoded = nip19Decode(nsecEncode(new Uint8Array(32).fill(7)));
    expect(decoded.type).toBe("nsec");
  });

  test("kind must be an integer in 0..2^32-1", () => {
    expect(() => naddrEncode({ kind: -1, identifier: "x", pubkey: pk })).toThrow(Nip19Error);
    expect(() => naddrEncode({ kind: 2 ** 32, identifier: "x", pubkey: pk })).toThrow(Nip19Error);
    expect(() => naddrEncode({ kind: 1.5, identifier: "x", pubkey: pk })).toThrow(Nip19Error);
    expect(() => neventEncode({ id: pk, kind: 2 ** 32 })).toThrow(Nip19Error);
    expect(naddrEncode({ kind: 0xffffffff, identifier: "x", pubkey: pk })).toMatch(/^naddr1/);
  });

  test("TLV values over 255 bytes throw Nip19Error", () => {
    const longRelay = `wss://${"a".repeat(300)}`;
    expect(() => nprofileEncode({ pubkey: pk, relays: [longRelay] })).toThrow(Nip19Error);
    expect(() => naddrEncode({ kind: 30023, identifier: "x".repeat(300), pubkey: pk })).toThrow(
      Nip19Error,
    );
  });
});
