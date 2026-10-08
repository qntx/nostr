import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

import { finalizeEvent } from "@qntx/nostr";
import type { Event } from "@qntx/nostr";
import { Kind } from "@qntx/nostr/core";

// Packed entry exists only after `build:wasm`.
import { loadNostrWasm } from "../dist/browser.mjs";
import { readBuiltWasm } from "./read-wasm.ts";

const SK_HEX = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

function helloEvent(): Event {
  return finalizeEvent(
    {
      kind: Kind.TextNote,
      tags: [],
      content: "hello",
      created_at: 1617932115,
    },
    SK_HEX,
  );
}

describe("packed dist/browser.mjs", () => {
  test("contains no node: specifier", async () => {
    const src = await readFile("dist/browser.mjs", "utf8");
    expect(src).not.toMatch(/["']node:/);
  });

  test("loadNostrWasm({ module: bytes }) instantiates and verifies", async () => {
    const wasm = await loadNostrWasm({ module: await readBuiltWasm() });
    const event = helloEvent();
    expect(wasm.verifyEvent(event)).toBe(true);
    expect(wasm.verifyEvent({ ...event, content: "tampered" })).toBe(false);
  });
});
