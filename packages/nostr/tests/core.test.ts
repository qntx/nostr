import { schnorr } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { expect, test, describe } from "vite-plus/test";

import { containsLoneSurrogate, normalizeRelayUrls } from "../src/core/util.ts";
import {
  Kind,
  Keys,
  MessageError,
  UrlError,
  SUBSCRIPTION_ID_MAX_CHARS,
  CryptoError,
  SecretKey,
  assertSubscriptionId,
  canonicalizeFilter,
  canonicalizeFilters,
  classifyKind,
  createSubscriptionId,
  eventAddress,
  formatEventAddress,
  encodeClientMessage,
  finalizeEvent,
  getEventHash,
  getPublicKey,
  isAddressableKind,
  isEphemeralKind,
  isRegularKind,
  isReplaceableKind,
  filterFingerprint,
  getFilterLimit,
  matchFilter,
  EventValidationError,
  matchFilters,
  parseClientMessage,
  parseEventAddress,
  parseRelayMessage,
  serializeEvent,
  signEvent,
  bytesToHex,
  normalizeURL,
  Tag,
  validateEvent,
  validateSignedEvent,
  verifyEvent,
} from "../src/index.ts";
import type { ClientMessage, Event, Filter } from "../src/index.ts";

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

describe("keys", () => {
  test("generate secret key as 32 bytes / 64 hex", () => {
    const sk = SecretKey.generate();
    expect(sk.bytes).toHaveLength(32);
    expect(sk.toHex()).toMatch(/^[0-9a-f]{64}$/);
    sk.zeroize();
  });

  test("public key is deterministic", () => {
    const sk = SecretKey.fromHex(SK_HEX);
    const pk = getPublicKey(sk);
    expect(pk).toMatch(/^[0-9a-f]{64}$/);
    expect(getPublicKey(sk)).toBe(pk);
    expect(getPublicKey(SK_HEX)).toBe(pk);
  });

  test("Keys.generate produces matching pair", () => {
    const keys = Keys.generate();
    expect(getPublicKey(keys.secretKey)).toBe(keys.publicKey);
  });
});

describe("events", () => {
  test("finalizeEvent signs a text note that verifies", () => {
    const event = finalizeEvent(
      {
        kind: Kind.TextNote,
        tags: [],
        content: "Hello, world!",
        created_at: 1617932115,
      },
      SK_HEX,
    );

    expect(event.pubkey).toBe(getPublicKey(SK_HEX));
    expect(event.id).toMatch(/^[0-9a-f]{64}$/);
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyEvent(event)).toBe(true);
    // WeakSet cache path
    expect(verifyEvent(event)).toBe(true);
  });

  test("signEvent with explicit auxRand matches schnorr.sign and is reproducible", () => {
    const keys = Keys.fromSecretKey(SK_HEX);
    const unsigned = {
      kind: Kind.TextNote,
      tags: [],
      content: "hi",
      created_at: 1,
      pubkey: keys.publicKey,
    };
    const aux = hexToBytes("42".repeat(32));
    const a = signEvent(unsigned, keys, aux);
    const b = signEvent(unsigned, keys, aux);
    expect(b).toStrictEqual(a);
    const expected = schnorr.sign(hexToBytes(getEventHash(unsigned)), keys.secretKey.bytes, aux);
    expect(a.sig).toBe(bytesToHex(expected));
    // finalizeEvent forwards auxRand: same template + aux → same signature.
    const finalized = finalizeEvent(
      { kind: unsigned.kind, tags: unsigned.tags, content: unsigned.content, created_at: 1 },
      SK_HEX,
      aux,
    );
    expect(finalized.sig).toBe(a.sig);
  });

  test.each([31, 33])("signEvent rejects a %d-byte auxRand", (len) => {
    const keys = Keys.fromSecretKey(SK_HEX);
    const unsigned = {
      kind: Kind.TextNote,
      tags: [],
      content: "hi",
      created_at: 1,
      pubkey: keys.publicKey,
    };
    expect(() => signEvent(unsigned, keys, new Uint8Array(len))).toThrow(CryptoError);
    expect(() => signEvent(unsigned, keys, new Uint8Array(len))).toThrow(
      "auxRand must be 32 bytes",
    );
    expect(() =>
      finalizeEvent(
        { kind: Kind.TextNote, tags: [], content: "hi", created_at: 1 },
        SK_HEX,
        new Uint8Array(len),
      ),
    ).toThrow("auxRand must be 32 bytes");
  });

  test("signEvent on a structurally invalid unsigned event throws EventValidationError", () => {
    const keys = Keys.fromSecretKey(SK_HEX);
    expect(() =>
      signEvent(
        {
          kind: Kind.TextNote,
          tags: [],
          content: "hi",
          created_at: 1.5,
          pubkey: keys.publicKey,
        },
        keys,
      ),
    ).toThrow(EventValidationError);
  });

  test("validateEvent rejects kind outside 0..65535", () => {
    const pubkey = getPublicKey(SK_HEX);
    expect(
      validateEvent({
        kind: 65536,
        tags: [],
        content: "",
        created_at: 1,
        pubkey,
      }),
    ).toBe(false);
    expect(
      validateEvent({
        kind: -1,
        tags: [],
        content: "",
        created_at: 1,
        pubkey,
      }),
    ).toBe(false);
  });

  test("serializeEvent matches NIP-01 array form", () => {
    const pubkey = getPublicKey(SK_HEX);
    const unsigned = {
      kind: Kind.TextNote,
      tags: [] as [],
      content: "Hello, world!",
      created_at: 1617932115,
      pubkey,
    };
    expect(serializeEvent(unsigned)).toBe(
      JSON.stringify([0, pubkey, 1617932115, Kind.TextNote, [], "Hello, world!"]),
    );
    expect(getEventHash(unsigned)).toHaveLength(64);
  });

  test("validateEvent rejects bad shapes", () => {
    expect(validateEvent("")).toBe(false);
    expect(validateEvent({})).toBe(false);
    expect(
      validateEvent({
        kind: 1,
        tags: [],
        content: "hi",
        created_at: 1,
        pubkey: "not-hex",
      }),
    ).toBe(false);
  });

  test("tampered content fails verify", () => {
    const event = finalizeEvent(
      {
        kind: Kind.TextNote,
        tags: [],
        content: "original",
        created_at: 1617932115,
      },
      SK_HEX,
    );
    const bad: Event = { ...event, content: "tampered" };
    expect(verifyEvent(bad)).toBe(false);
  });

  test("non-canonical uppercase hex fields are rejected everywhere", () => {
    const event = finalizeEvent(
      { kind: Kind.TextNote, tags: [], content: "case", created_at: 1 },
      SK_HEX,
    );
    const upperId: Event = { ...event, id: event.id.toUpperCase() };
    const upperPk: Event = { ...event, pubkey: event.pubkey.toUpperCase() };
    const upperSig: Event = { ...event, sig: event.sig.toUpperCase() };
    for (const bad of [upperId, upperPk, upperSig]) {
      expect(validateSignedEvent(bad)).toBe(false);
      expect(verifyEvent(bad)).toBe(false);
    }
    // serializeEvent must not silently lowercase a non-canonical pubkey
    expect(() => serializeEvent(upperPk)).toThrow(EventValidationError);
  });
});

describe("kinds", () => {
  test("classification ranges", () => {
    expect(isRegularKind(1)).toBe(true);
    expect(isRegularKind(7)).toBe(true);
    expect(isRegularKind(1111)).toBe(true);
    expect(isRegularKind(45)).toBe(false);
    expect(isRegularKind(999)).toBe(false);
    expect(isRegularKind(44)).toBe(true);
    expect(isReplaceableKind(0)).toBe(true);
    expect(isReplaceableKind(10002)).toBe(true);
    expect(isEphemeralKind(22242)).toBe(true);
    expect(isAddressableKind(30023)).toBe(true);
    expect(classifyKind(1)).toBe("regular");
    expect(classifyKind(30023)).toBe("addressable");
    // NIP-01 leaves 45–999 and 40000+ undefined; relays store them like regular events.
    for (const kind of [45, 999, 40000, 65535]) {
      expect(classifyKind(kind)).toBe("regular");
    }
    expect(classifyKind(1000)).toBe("regular");
  });

  test("catalog is the 28 production names", () => {
    expect(Kind).toStrictEqual({
      Metadata: 0,
      TextNote: 1,
      Contacts: 3,
      EventDeletion: 5,
      Repost: 6,
      Reaction: 7,
      Seal: 13,
      PrivateDirectMessage: 14,
      GenericRepost: 16,
      GiftWrap: 1059,
      ZapRequest: 9734,
      Zap: 9735,
      MuteList: 10000,
      PinList: 10001,
      RelayList: 10002,
      BookmarkList: 10003,
      FavoriteRelays: 10012,
      UserEmojiList: 10030,
      DirectMessageRelaysList: 10050,
      BlossomServerList: 10063,
      GiftWrapEphemeral: 21059,
      ClientAuth: 22242,
      NostrConnect: 24133,
      BlobsAuth: 24242,
      HttpAuth: 27235,
      RelaySets: 30002,
      EmojiSet: 30030,
      StarterPack: 39089,
    });
    expect(Object.keys(Kind)).toHaveLength(28);
    expect("EncryptionKeyAnnouncement" in Kind).toBe(false);
    expect("ClientKeyAnnouncement" in Kind).toBe(false);
    expect("KeyTransfer" in Kind).toBe(false);
  });

  test("event address coordinates", () => {
    const pk = "aa".repeat(32);
    expect(parseEventAddress(`30023:${pk}:hello:world`)).toStrictEqual({
      kind: 30023,
      pubkey: pk,
      identifier: "hello:world",
    });
    expect(parseEventAddress(`0:${pk}:`)).toStrictEqual({ kind: 0, pubkey: pk, identifier: "" });
    expect(parseEventAddress("0:short:")).toBeUndefined();
    // The kind segment is one to five decimal digits only — no other Number() syntax.
    for (const bad of ["1e4", "0x10", " 1", "+1", "1.0", "123456", ""]) {
      expect(parseEventAddress(`${bad}:${pk}:d`)).toBeUndefined();
    }
    expect(parseEventAddress(`65535:${pk}:d`)).toStrictEqual({
      kind: 65535,
      pubkey: pk,
      identifier: "d",
    });
    expect(formatEventAddress(0, pk)).toBe(`0:${pk}:`);
    expect(eventAddress({ kind: 1, pubkey: pk, tags: [] })).toBeUndefined();
    expect(eventAddress({ kind: 0, pubkey: pk, tags: [] })).toBe(`0:${pk}:`);
    expect(eventAddress({ kind: 30023, pubkey: pk, tags: [["d", "x"]] })).toBe(`30023:${pk}:x`);
  });
});

describe("tags", () => {
  const id = "ab".repeat(32);
  const pk = "cd".repeat(32);

  test("Tag.e lowercases hex slots and leaves relay URL and marker", () => {
    expect(Tag.e(id.toUpperCase(), "wss://Relay.Example", "Root", pk.toUpperCase())).toStrictEqual([
      "e",
      id,
      "wss://Relay.Example",
      "Root",
      pk,
    ]);
    expect(Tag.e(id.toUpperCase())).toStrictEqual(["e", id]);
  });

  test("Tag.e pads absent positions before present ones", () => {
    expect(Tag.e(id, undefined, "root")).toStrictEqual(["e", id, "", "root"]);
    expect(Tag.e(id, undefined, undefined, pk)).toStrictEqual(["e", id, "", "", pk]);
    expect(Tag.e(id, "wss://r", undefined, pk)).toStrictEqual(["e", id, "wss://r", "", pk]);
    expect(Tag.e(id, undefined, "reply")).toStrictEqual(["e", id, "", "reply"]);
    expect(Tag.e(id, "wss://r")).toStrictEqual(["e", id, "wss://r"]);
    expect(Tag.e(id, "wss://r", "mention")).toStrictEqual(["e", id, "wss://r", "mention"]);
  });

  test("Tag.p lowercases pubkey and leaves relay URL and petname", () => {
    expect(Tag.p(pk.toUpperCase(), "wss://Relay.Example", "Alice")).toStrictEqual([
      "p",
      pk,
      "wss://Relay.Example",
      "Alice",
    ]);
    expect(Tag.p(pk.toUpperCase())).toStrictEqual(["p", pk]);
  });

  test("Tag.p pads absent relay before petname", () => {
    expect(Tag.p(pk, undefined, "alice")).toStrictEqual(["p", pk, "", "alice"]);
    expect(Tag.p(pk, "wss://r")).toStrictEqual(["p", pk, "wss://r"]);
    expect(Tag.p(pk, "wss://r", "bob")).toStrictEqual(["p", pk, "wss://r", "bob"]);
  });
});

describe("filter", () => {
  const base = finalizeEvent(
    {
      kind: 1,
      tags: [
        ["t", "nostr"],
        ["p", "abc"],
      ],
      content: "x",
      created_at: 150,
    },
    SK_HEX,
  );

  test("matchFilter positive and negative", () => {
    expect(matchFilter({ kinds: [1], since: 100, until: 200 }, base)).toBe(true);
    expect(matchFilter({ kinds: [2] }, base)).toBe(false);
    expect(matchFilter({ since: 200 }, base)).toBe(false);
    expect(matchFilter({ "#t": ["nostr"] }, base)).toBe(true);
    expect(matchFilter({ "#t": ["other"] }, base)).toBe(false);
    expect(matchFilter({ authors: [base.pubkey.toUpperCase()] }, base)).toBe(true);
    expect(matchFilter({ ids: [base.id.toUpperCase()] }, base)).toBe(true);
  });

  test("matchFilter ignores multi-letter # keys per NIP-01", () => {
    expect(matchFilter({ "#custom": ["v1"] }, base)).toBe(true);
    expect(matchFilter({ "#missing": ["x"] }, base)).toBe(true);
    expect(matchFilter({ "#1": ["x"] }, base)).toBe(true);
  });

  test("matchFilter ignores NIP-50 search", () => {
    expect(matchFilter({ search: "nope" }, base)).toBe(true);
    expect(matchFilter({ kinds: [1], search: "nope" }, base)).toBe(true);
    expect(matchFilter({ kinds: [2], search: "nope" }, base)).toBe(false);
  });

  test("matchFilters is OR across filters", () => {
    expect(matchFilters([{ kinds: [2] }, { kinds: [1] }], base)).toBe(true);
    expect(matchFilters([{ kinds: [2] }, { kinds: [3] }], base)).toBe(false);
  });

  test("filterFingerprint sorts keys, list items, and filter order", () => {
    const pk = "aa".repeat(32);
    expect(filterFingerprint([{ kinds: [1], authors: [pk] }])).toBe(
      filterFingerprint([{ authors: [pk], kinds: [1] }]),
    );
    expect(filterFingerprint([{ kinds: [2, 1] }])).toBe(filterFingerprint([{ kinds: [1, 2] }]));
    expect(filterFingerprint([{ kinds: [1] }, { kinds: [2] }])).toBe(
      filterFingerprint([{ kinds: [2] }, { kinds: [1] }]),
    );
  });

  test("filterFingerprint lowercases hex ids/authors/#e/#p and preserves #t case", () => {
    const id = "ab".repeat(32);
    const pk = "cd".repeat(32);
    expect(filterFingerprint([{ ids: [id.toUpperCase()] }])).toBe(
      filterFingerprint([{ ids: [id] }]),
    );
    expect(filterFingerprint([{ authors: [pk.toUpperCase()] }])).toBe(
      filterFingerprint([{ authors: [pk] }]),
    );
    expect(filterFingerprint([{ "#e": [id.toUpperCase()] }])).toBe(
      filterFingerprint([{ "#e": [id] }]),
    );
    expect(filterFingerprint([{ "#p": [pk.toUpperCase()] }])).toBe(
      filterFingerprint([{ "#p": [pk] }]),
    );
    expect(filterFingerprint([{ "#t": ["b", "a"] }])).toBe(
      filterFingerprint([{ "#t": ["a", "b"] }]),
    );
    expect(filterFingerprint([{ "#t": ["Nostr"] }])).not.toBe(
      filterFingerprint([{ "#t": ["nostr"] }]),
    );
  });

  test("filterFingerprint includes since/until/limit/search; missing key is not []", () => {
    expect(filterFingerprint([{ kinds: [1], limit: 10 }])).not.toBe(
      filterFingerprint([{ kinds: [1], limit: 50 }]),
    );
    expect(filterFingerprint([{ kinds: [1], since: 1 }])).not.toBe(
      filterFingerprint([{ kinds: [1] }]),
    );
    expect(filterFingerprint([{ kinds: [1], until: 1 }])).not.toBe(
      filterFingerprint([{ kinds: [1] }]),
    );
    expect(filterFingerprint([{ search: "x" }])).not.toBe(filterFingerprint([{ search: "X" }]));
    expect(filterFingerprint([{ kinds: [1] }])).not.toBe(
      filterFingerprint([{ kinds: [1], authors: [] }]),
    );
    expect(filterFingerprint([{ kinds: [1] }])).not.toBe(
      filterFingerprint([{ kinds: [1], "#t": [] }]),
    );
    expect(filterFingerprint([{ kinds: [1] }])).not.toBe(filterFingerprint([{ kinds: [1, 2] }]));
  });

  test("canonicalizeFilter lowercases hex lists, sorts every array, omits undefined", () => {
    const id = "ab".repeat(32);
    const pkA = "aa".repeat(32);
    const pkB = "cd".repeat(32);
    const filter: Filter = {
      ids: [id.toUpperCase()],
      authors: [pkB.toUpperCase(), pkA],
      kinds: [2, 1],
      "#e": [id.toUpperCase()],
      "#p": [pkB.toUpperCase(), pkA],
      "#t": ["b", "a"],
    };
    const withUndef = { ...filter, since: undefined } as Filter;
    const out = canonicalizeFilter(filter);
    expect(out.ids).toStrictEqual([id]);
    expect(out.authors).toStrictEqual([pkA, pkB]);
    expect(out.kinds).toStrictEqual([1, 2]);
    expect(out["#e"]).toStrictEqual([id]);
    expect(out["#p"]).toStrictEqual([pkA, pkB]);
    expect(out["#t"]).toStrictEqual(["a", "b"]);
    expect(canonicalizeFilter({ "#t": ["Nostr"] })["#t"]).toStrictEqual(["Nostr"]);
    expect("since" in canonicalizeFilter(withUndef)).toBe(false);
    expect(canonicalizeFilter({ kinds: [1], authors: [] })).toStrictEqual({
      authors: [],
      kinds: [1],
    });
    expect(canonicalizeFilter({ kinds: [1] })).toStrictEqual({ kinds: [1] });
    expect(filter.authors).toStrictEqual([pkB.toUpperCase(), pkA]);
    expect(filter.kinds).toStrictEqual([2, 1]);
  });

  test("canonicalizeFilter dedupes and drops non-NIP-01 keys", () => {
    const id = "ab".repeat(32);
    expect(
      canonicalizeFilter({
        ids: [id, id.toUpperCase(), id],
        kinds: [1, 1, 0],
        "#t": ["b", "a", "b"],
        "#e": [id.toUpperCase(), id],
        "#custom": ["x"],
        "#missing": ["y"],
        zzz: "keep",
        custom: ["b", "a"],
      } as Filter),
    ).toStrictEqual({
      ids: [id],
      kinds: [0, 1],
      "#t": ["a", "b"],
      "#e": [id],
    });
  });

  test("getFilterLimit counts unique values", () => {
    const id = "ab".repeat(32);
    const pk = "cd".repeat(32);
    expect(getFilterLimit({ ids: [id, id.toUpperCase()] })).toBe(1);
    expect(getFilterLimit({ kinds: [0, 0, 3], authors: [pk, pk.toUpperCase()] })).toBe(2);
    expect(getFilterLimit({ kinds: [30023], authors: [pk], "#d": ["a", "a"] })).toBe(1);
    expect(getFilterLimit({ ids: [id, id], limit: 10 })).toBe(1);
  });

  test("canonicalizeFilters maps each filter; fingerprint matches stored form", () => {
    const filters: Filter[] = [
      { kinds: [2, 1], authors: ["BB".repeat(32), "aa".repeat(32)] },
      { "#t": ["z", "a"] },
    ];
    const canonical = canonicalizeFilters(filters);
    expect(canonical).toStrictEqual([
      { authors: ["aa".repeat(32), "bb".repeat(32)], kinds: [1, 2] },
      { "#t": ["a", "z"] },
    ]);
    expect(filterFingerprint(canonical)).toBe(filterFingerprint(filters));
  });
});

function eventPayload(message: ClientMessage): Event {
  if (message[0] !== "EVENT") {
    throw new Error("expected an EVENT client message");
  }
  return message[1];
}

describe("messages", () => {
  test("encode and parse EVENT client message", () => {
    const event = finalizeEvent(
      { kind: 1, tags: [], content: "hi", created_at: 1 },
      hexToBytes(SK_HEX),
    );
    const raw = encodeClientMessage(["EVENT", event]);
    const parsed = parseClientMessage(raw);
    expect(parsed[0]).toBe("EVENT");
    expect(eventPayload(parsed).id).toBe(event.id);
  });

  test("parse relay EVENT / EOSE / OK", () => {
    const event = finalizeEvent({ kind: 1, tags: [], content: "hi", created_at: 1 }, SK_HEX);
    const sub = createSubscriptionId("sub1");
    const eventMsg = parseRelayMessage(JSON.stringify(["EVENT", sub, event]));
    expect(eventMsg[0]).toBe("EVENT");
    // Non-canonical events are rejected at the wire boundary
    expect(() =>
      parseRelayMessage(JSON.stringify(["EVENT", sub, { ...event, id: event.id.toUpperCase() }])),
    ).toThrow(MessageError);
    expect(parseRelayMessage(JSON.stringify(["EOSE", sub]))[0]).toBe("EOSE");
    expect(parseRelayMessage(JSON.stringify(["OK", event.id, true, ""]))[0]).toBe("OK");
  });

  test("REQ round-trip", () => {
    const filter: Filter = { kinds: [1], limit: 10 };
    const raw = encodeClientMessage(["REQ", "abc", filter]);
    const msg = parseClientMessage(raw);
    expect(msg[0]).toBe("REQ");
  });

  test("REQ with no filters is invalid REQ client message", () => {
    expect(() => parseClientMessage(JSON.stringify(["REQ", "abc"]))).toThrow(MessageError);
    expect(() => parseClientMessage(JSON.stringify(["REQ", "abc"]))).toThrow(
      "invalid REQ client message",
    );
  });

  test("encodeClientMessage canonicalizes REQ, COUNT, and NEG-OPEN filters", () => {
    const id = "ab".repeat(32);
    const messy = { kinds: [2, 1], ids: [id.toUpperCase(), id], "#custom": ["x"] } as Filter;
    expect(JSON.parse(encodeClientMessage(["REQ", "s", messy]))).toStrictEqual([
      "REQ",
      "s",
      { ids: [id], kinds: [1, 2] },
    ]);
    expect(JSON.parse(encodeClientMessage(["COUNT", "s", messy]))).toStrictEqual([
      "COUNT",
      "s",
      { ids: [id], kinds: [1, 2] },
    ]);
    expect(JSON.parse(encodeClientMessage(["NEG-OPEN", "s", messy, "aabb"]))).toStrictEqual([
      "NEG-OPEN",
      "s",
      { ids: [id], kinds: [1, 2] },
      "aabb",
    ]);
  });

  test("parseClientMessage validates and normalizes wire filters", () => {
    const id = "ab".repeat(32);
    const parsed = parseClientMessage(
      JSON.stringify([
        "REQ",
        "s",
        { ids: [id.toUpperCase()], "#e": [id.toUpperCase()], "#custom": ["x"], junk: 1 },
      ]),
    );
    expect(parsed).toStrictEqual(["REQ", "s", { "#e": [id], ids: [id] }]);
    expect(() => parseClientMessage(JSON.stringify(["REQ", "s", { kinds: [65536] }]))).toThrow(
      MessageError,
    );
    expect(() => parseClientMessage(JSON.stringify(["REQ", "s", { ids: ["zz"] }]))).toThrow(
      MessageError,
    );
    expect(() => parseClientMessage(JSON.stringify(["REQ", "s", { since: -1 }]))).toThrow(
      MessageError,
    );
    expect(() => parseClientMessage(JSON.stringify(["COUNT", "s", { "#t": [1] }]))).toThrow(
      MessageError,
    );
    expect(() =>
      parseClientMessage(JSON.stringify(["NEG-OPEN", "s", { search: 1 }, "aabb"])),
    ).toThrow(MessageError);
  });

  test("assertSubscriptionId accepts 1..max and rejects empty/too long", () => {
    expect(assertSubscriptionId("a")).toBe("a");
    expect(assertSubscriptionId("x".repeat(SUBSCRIPTION_ID_MAX_CHARS))).toBe(
      "x".repeat(SUBSCRIPTION_ID_MAX_CHARS),
    );
    expect(() => assertSubscriptionId("")).toThrow(MessageError);
    expect(() => assertSubscriptionId("")).toThrow(/1\.\./);
    expect(() => assertSubscriptionId("x".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1))).toThrow(
      MessageError,
    );
    expect(() => assertSubscriptionId("x".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1))).toThrow(/1\.\./);
    // Scalar values, not UTF-16 code units: 64 astral chars are allowed.
    expect(assertSubscriptionId("\u{1F600}".repeat(SUBSCRIPTION_ID_MAX_CHARS))).toBe(
      "\u{1F600}".repeat(SUBSCRIPTION_ID_MAX_CHARS),
    );
    expect(() => assertSubscriptionId("\u{1F600}".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1))).toThrow(
      MessageError,
    );
  });

  test("createSubscriptionId validates or generates 8-byte hex", () => {
    expect(createSubscriptionId("sub1")).toBe("sub1");
    expect(() => createSubscriptionId("")).toThrow(MessageError);
    expect(() => createSubscriptionId("x".repeat(SUBSCRIPTION_ID_MAX_CHARS + 1))).toThrow(
      MessageError,
    );
    const generated = createSubscriptionId();
    expect(generated).toMatch(/^[0-9a-f]{16}$/);
    expect(generated).not.toBe(createSubscriptionId());
  });
});

describe("normalizeURL", () => {
  test("rejects non-websocket schemes", () => {
    expect(() => normalizeURL("ftp://x")).toThrow(UrlError);
    expect(() => normalizeURL("ftp://x")).toThrow(/scheme/);
  });

  test("rewrites http(s) and canonicalizes the URL", () => {
    expect(normalizeURL("https://Relay.Example:443/a//b/?z=1&a=2#f")).toBe(
      "wss://relay.example/a/b?a=2&z=1",
    );
    expect(normalizeURL("http://Relay.Example")).toBe("ws://relay.example/");
    expect(normalizeURL("wss://Relay.Example/")).toBe("wss://relay.example/");
    expect(normalizeURL("Relay.Example")).toBe("wss://relay.example/");
  });
});

describe("normalizeRelayUrls", () => {
  test("skips empty/invalid entries and dedupes in first-seen order", () => {
    expect(
      normalizeRelayUrls([
        "",
        "wss://a.example",
        "not a url",
        "wss://a.example/",
        "ftp://x",
        "relay.example",
        "wss://b.example/",
      ]),
    ).toStrictEqual(["wss://a.example/", "wss://relay.example/", "wss://b.example/"]);
  });
});

describe("containsLoneSurrogate", () => {
  test("detects lone surrogates in nested strings and record keys", () => {
    const lone = "\uD800";
    expect(containsLoneSurrogate(lone)).toBe(true);
    expect(containsLoneSurrogate(["ok", [lone]])).toBe(true);
    expect(containsLoneSurrogate({ [lone]: "value" })).toBe(true);
    expect(containsLoneSurrogate({ key: { nested: lone } })).toBe(true);
  });

  test("accepts paired surrogates and non-string values", () => {
    expect(containsLoneSurrogate("paired 𐐷 ok")).toBe(false);
    expect(containsLoneSurrogate(["a", { b: [1, 2] }, null, true, undefined])).toBe(false);
    expect(containsLoneSurrogate({})).toBe(false);
    expect(containsLoneSurrogate(null)).toBe(false);
    expect(containsLoneSurrogate(42)).toBe(false);
  });
});
