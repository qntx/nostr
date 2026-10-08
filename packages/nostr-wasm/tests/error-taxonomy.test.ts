import { describe, expect, test } from "vite-plus/test";

import { EventBuilder, Keys } from "@qntx/nostr";
import { CryptoError, NostrError, WasmPoisonedError } from "@qntx/nostr/core";

import { createWasmEventVerifier } from "../src/adapter.ts";
import { createNostrWasmLoader, fetchWasmUrl, isWasmBytes } from "../src/instance.ts";
import { loadNostrWasm as loadNostrWasmBrowser } from "../src/load.browser.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

async function captureError(p: Promise<unknown>): Promise<unknown> {
  return p.then(
    () => {
      throw new Error("expected reject");
    },
    (error: unknown) => error,
  );
}

function syncThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected throw");
}

type MinimalFetchResponse = {
  ok: boolean;
  status: number;
  arrayBuffer: () => Promise<ArrayBuffer>;
};

function notFoundFetch(
  href: string,
  prev: typeof fetch,
  onCall: () => void,
): (input: URL | string) => Promise<Response | MinimalFetchResponse> {
  return async (input: URL | string) => {
    const url = input instanceof URL ? input.href : input;
    if (url !== href) {
      return prev(input);
    }
    onCall();
    return {
      ok: false,
      status: 404,
      arrayBuffer: async () => {
        await Promise.resolve();
        return new ArrayBuffer(0);
      },
    };
  };
}

describe("wasm HTTP load", () => {
  const loader = createNostrWasmLoader(async (opts) => {
    const source = opts?.module;
    if (source instanceof URL) {
      return fetchWasmUrl(source);
    }
    if (source !== undefined && isWasmBytes(source)) {
      return source;
    }
    throw new CryptoError("expected wasm module source");
  });

  test("fetch 404 throws CryptoError", async () => {
    const href = "https://wasm-404.qntx.test/nk_wasm.wasm";
    const prev = globalThis.fetch;
    let fetchCalls = 0;
    Reflect.set(
      globalThis,
      "fetch",
      notFoundFetch(href, prev, () => {
        fetchCalls += 1;
      }),
    );
    try {
      const err = await captureError(loader.loadNostrWasm({ module: new URL(href) }));
      expect(fetchCalls).toBe(1);
      expect(err).toBeInstanceOf(CryptoError);
      expect((err as CryptoError).message).toBe(`failed to fetch wasm: 404 ${href}`);
    } finally {
      globalThis.fetch = prev;
    }
  });

  test("browser loader rejects file: URLs", async () => {
    const href = "file:///wasm-404.qntx.test/nk_wasm.wasm";
    const err = await captureError(loadNostrWasmBrowser({ module: new URL(href) }));
    expect(err).toBeInstanceOf(CryptoError);
    expect((err as CryptoError).message).toBe(`cannot fetch wasm from ${href}`);
  });
});

describe("WasmPoisonedError", () => {
  test("wasm verifier RuntimeError poisons as WasmPoisonedError", () => {
    const poison: { error?: Error } = {};
    let calls = 0;
    const fn = createWasmEventVerifier(() => {
      calls += 1;
      throw new WebAssembly.RuntimeError("trap");
    }, poison);
    const signed = EventBuilder.textNote("hello")
      .createdAt(1617932115)
      .signWithKeys(Keys.fromSecretKey(SK));
    const event = { ...signed };
    const err = syncThrow(() => fn(event));
    expect(err).toBeInstanceOf(WasmPoisonedError);
    expect(err).toBeInstanceOf(NostrError);
    expect(poison.error).toBe(err);
    expect(poison.error?.name).toBe("WasmPoisonedError");
    expect((err as WasmPoisonedError).cause).toBeInstanceOf(WebAssembly.RuntimeError);
    expect(calls).toBe(1);
    const sticky = syncThrow(() => fn({ ...event }));
    expect(sticky).toBe(poison.error);
    expect(calls).toBe(1);
  });
});
