import { describe, expect, test } from "vite-plus/test";

import {
  Nip96Error,
  fetchNip96Info,
  parseNip96UploadResponse,
  uploadNip96,
} from "../src/nips/nip96.ts";
import type { Nip96Fetch, Nip96UploadResult } from "../src/nips/nip96.ts";

const SERVICE = "https://files.example";
const INFO_URL = "https://files.example/.well-known/nostr/nip96.json";
const API_URL = "https://files.example/upload";
const FILE_URL = "https://cdn.example/719171db.png";
const OX = "719171db19525d9d08dd69cb716a18158a249b7b3b3ec4bbdec5698dca104b7b";

const SUCCESS_BODY = {
  status: "success",
  message: "Upload successful.",
  nip94_event: {
    tags: [
      ["url", FILE_URL],
      ["ox", OX],
      ["m", "image/png"],
    ],
    content: "",
  },
};

async function captureError(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (error) {
    return error;
  }
  throw new Error("expected rejection");
}

const uploadSuccess = (
  r: Nip96UploadResult,
): { status: "success"; url: string; tags: string[][] } => {
  if (r.status !== "success") {
    throw new Error("expected success");
  }
  return r;
};

const delegatedInfo = (callCount: number): unknown =>
  callCount === 1
    ? { api_url: "", delegated_to_url: "https://other.example" }
    : { api_url: "https://other.example/upload" };

function jsonResponse(status: number, body: unknown): Awaited<ReturnType<Nip96Fetch>> {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => {
      await Promise.resolve();
      return body;
    },
    arrayBuffer: async () => {
      await Promise.resolve();
      return new ArrayBuffer(0);
    },
  };
}

function abortError(): Error {
  const err = new Error("aborted");
  err.name = "AbortError";
  return err;
}

function redirectOf(init: unknown): string | undefined {
  if (!init || typeof init !== "object" || !("redirect" in init)) {
    return undefined;
  }
  const value = (init as { redirect?: unknown }).redirect;
  return typeof value === "string" ? value : undefined;
}

describe("nip96 server info", () => {
  test("fetches well-known JSON and ignores extra fields", async () => {
    const calls: Array<{ url: string; init?: Parameters<Nip96Fetch>[1] }> = [];
    const fetchImpl: Nip96Fetch = async (url, init) => {
      calls.push({ url, init });
      await Promise.resolve();
      return jsonResponse(200, {
        api_url: API_URL,
        download_url: "https://cdn.example",
        content_types: ["image/jpeg", "video/webm"],
        supported_nips: [60],
        plans: { free: { name: "Free" } },
      });
    };

    const info = await fetchNip96Info(`${SERVICE}/`, { fetch: fetchImpl });
    expect(info).toStrictEqual({
      api_url: API_URL,
      download_url: "https://cdn.example",
      content_types: ["image/jpeg", "video/webm"],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(INFO_URL);
    expect(calls[0]?.init?.signal).toBeUndefined();
    expect(redirectOf(calls[0]?.init)).toBe("manual");
  });

  test("network TypeError wraps Nip96Error", async () => {
    const net = new TypeError("fetch failed");
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      throw net;
    };
    const error = await captureError(fetchNip96Info(SERVICE, { fetch: fetchImpl }));
    expect(error).toBeInstanceOf(Nip96Error);
    expect((error as Nip96Error).cause).toBe(net);
    expect(error).not.toBe(net);
  });

  test("AbortError is not wrapped into Nip96Error", async () => {
    const aborted = abortError();
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      throw aborted;
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toBe(aborted);
  });

  test("missing api_url throws", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(200, { download_url: "https://cdn.example" });
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(Nip96Error);
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(/missing api_url/);
  });

  test("non-OK including redirects throws", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(302, { api_url: API_URL });
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(Nip96Error);
  });

  test("follows delegated_to_url exactly one hop", async () => {
    const calls: string[] = [];
    const fetchImpl: Nip96Fetch = async (url) => {
      calls.push(url);
      await Promise.resolve();
      return jsonResponse(200, delegatedInfo(calls.length));
    };
    const info = await fetchNip96Info(SERVICE, { fetch: fetchImpl });
    expect(calls).toStrictEqual([INFO_URL, "https://other.example/.well-known/nostr/nip96.json"]);
    expect(info).toStrictEqual({ api_url: "https://other.example/upload" });
  });

  test("a second delegation throws", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(200, { api_url: "", delegated_to_url: "https://other.example" });
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(Nip96Error);
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(/one hop/);
  });

  test("non-OK info includes JSON message", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(404, { status: "error", message: "not found" });
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(
      /^NIP-96 server info HTTP 404: not found$/,
    );
  });

  test("non-OK info with an empty message has no trailing separator", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(404, { status: "error", message: "" });
    };
    await expect(fetchNip96Info(SERVICE, { fetch: fetchImpl })).rejects.toThrow(
      /^NIP-96 server info HTTP 404$/,
    );
  });
});

describe("nip96 upload parse", () => {
  test("parseNip96UploadResponse reads url tag and tags", () => {
    expect(parseNip96UploadResponse(SUCCESS_BODY)).toStrictEqual({
      status: "success",
      url: FILE_URL,
      tags: [
        ["url", FILE_URL],
        ["ox", OX],
        ["m", "image/png"],
      ],
    });
  });

  test("parseNip96UploadResponse returns a processing result for HTTP 202", () => {
    expect(
      parseNip96UploadResponse(
        { status: "processing", processing_url: "https://files.example/status/1" },
        202,
      ),
    ).toStrictEqual({
      status: "processing",
      processingUrl: "https://files.example/status/1",
      tags: [],
    });
    // HTTP 200 with a processing status is honored the same way.
    expect(
      parseNip96UploadResponse({
        status: "processing",
        processing_url: "https://files.example/status/1",
      }),
    ).toStrictEqual({
      status: "processing",
      processingUrl: "https://files.example/status/1",
      tags: [],
    });
  });

  test("parseNip96UploadResponse still throws for error responses", () => {
    expect(() => parseNip96UploadResponse({ status: "error", message: "nope" }, 400)).toThrow(
      Nip96Error,
    );
  });

  test("upload response without url throws", () => {
    expect(() => parseNip96UploadResponse({ status: "success" })).toThrow(Nip96Error);
    expect(() => parseNip96UploadResponse({ status: "error", message: "nope" })).toThrow(
      /upload response without url/,
    );
    expect(() =>
      parseNip96UploadResponse({ status: "success", nip94_event: { tags: [["ox", OX]] } }),
    ).toThrow(/upload response without url/);
    expect(() =>
      parseNip96UploadResponse({ status: "success", nip94_event: { tags: [["url", ""]] } }),
    ).toThrow(/upload response without url/);
  });

  test("uploadNip96 posts multipart file with authorization and extra fields", async () => {
    const calls: Array<{ url: string; init?: Parameters<Nip96Fetch>[1] }> = [];
    const fetchImpl: Nip96Fetch = async (url, init) => {
      calls.push({ url, init });
      await Promise.resolve();
      return jsonResponse(201, SUCCESS_BODY);
    };
    const file = new Blob(["hello"], { type: "text/plain" });
    const result = await uploadNip96(API_URL, file, "Nostr tok", {
      fetch: fetchImpl,
      extraFields: { caption: "hi", no_transform: "true" },
    });

    const success = uploadSuccess(result);
    expect(success.url).toBe(FILE_URL);
    expect(result.tags[0]).toStrictEqual(["url", FILE_URL]);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(API_URL);
    expect(calls[0]?.init?.method).toBe("POST");
    expect(redirectOf(calls[0]?.init)).toBe("manual");
    expect(calls[0]?.init?.headers).toStrictEqual({ Authorization: "Nostr tok" });
    expect(calls[0]?.init?.body).toBeInstanceOf(FormData);
    const body = calls[0]?.init?.body as FormData;
    expect(body.get("caption")).toBe("hi");
    expect(body.get("no_transform")).toBe("true");
    expect(body.get("file")).toBeInstanceOf(Blob);
  });

  test("uploadNip96 without url tag throws", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(200, { status: "success", nip94_event: { tags: [] } });
    };
    await expect(
      uploadNip96(API_URL, new Blob(["x"]), "Nostr tok", { fetch: fetchImpl }),
    ).rejects.toThrow(/upload response without url/);
  });

  test("non-OK upload includes JSON message and does not require url", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(403, { status: "error", message: "User is not allowed to upload" });
    };
    await expect(
      uploadNip96(API_URL, new Blob(["x"]), "Nostr tok", { fetch: fetchImpl }),
    ).rejects.toThrow(/^NIP-96 upload HTTP 403: User is not allowed to upload$/);
  });

  test("upload network TypeError wraps Nip96Error", async () => {
    const net = new TypeError("fetch failed");
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      throw net;
    };
    const error = await captureError(
      uploadNip96(API_URL, new Blob(["x"]), "Nostr tok", { fetch: fetchImpl }),
    );
    expect(error).toBeInstanceOf(Nip96Error);
    expect((error as Nip96Error).cause).toBe(net);
    expect(error).not.toBe(net);
  });

  test("upload AbortError is not wrapped into Nip96Error", async () => {
    const aborted = abortError();
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      throw aborted;
    };
    await expect(
      uploadNip96(API_URL, new Blob(["x"]), "Nostr tok", { fetch: fetchImpl }),
    ).rejects.toBe(aborted);
  });

  test("non-OK upload without message falls back to status", async () => {
    const fetchImpl: Nip96Fetch = async () => {
      await Promise.resolve();
      return jsonResponse(413, { status: "error" });
    };
    await expect(
      uploadNip96(API_URL, new Blob(["x"]), "Nostr tok", { fetch: fetchImpl }),
    ).rejects.toThrow(/^NIP-96 upload HTTP 413$/);
  });
});
