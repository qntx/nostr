import { describe, expect, test } from "vite-plus/test";

import {
  EventBuilder,
  Keys,
  Nip07Signer,
  getWindowNostr,
  isNip07Available,
  verifyEvent,
} from "../src/index.ts";
import type { WindowNostr } from "../src/index.ts";

const SK = "d217c1ff2f8a65c3e3a1740db3b9f58b8c848bb45e26d00ed4714e4a0f4ceecf";

const tick = async (): Promise<void> => {
  await Promise.resolve();
};

describe("Nip07Signer", () => {
  test("isNip07Available is false without provider", () => {
    expect(isNip07Available()).toBe(false);
    expect(getWindowNostr()).toBeUndefined();
  });

  test("signs via injected provider", async () => {
    const keys = Keys.fromSecretKey(SK);
    const provider: WindowNostr = {
      async getPublicKey() {
        await tick();
        return keys.publicKey;
      },
      async signEvent(template) {
        await tick();
        return EventBuilder.textNote(template.content)
          .kind(template.kind)
          .tags(template.tags.map((t) => [...t]))
          .createdAt(template.created_at)
          .signWithKeys(keys);
      },
      nip04: {
        async encrypt() {
          await tick();
          return "enc";
        },
        async decrypt() {
          await tick();
          return "plain";
        },
      },
    };

    const signer = new Nip07Signer(provider);
    await expect(signer.getPublicKey()).resolves.toBe(keys.publicKey);

    const event = await EventBuilder.textNote("via nip07").createdAt(42).sign(signer);
    expect(event.pubkey).toBe(keys.publicKey);
    expect(verifyEvent(event)).toBe(true);
    await expect(signer.nip04Encrypt(keys.publicKey, "x")).resolves.toBe("enc");
    await expect(signer.nip04Decrypt(keys.publicKey, "y")).resolves.toBe("plain");
  });

  test("throws when provider missing", async () => {
    const signer = new Nip07Signer();
    await expect(signer.getPublicKey()).rejects.toThrow(/NIP-07/);
  });

  test("rejects a signed event that does not match the template", async () => {
    const keys = Keys.fromSecretKey(SK);
    const provider: WindowNostr = {
      async getPublicKey() {
        await tick();
        return keys.publicKey;
      },
      async signEvent() {
        await tick();
        return EventBuilder.textNote("other").createdAt(1).signWithKeys(keys);
      },
    };
    const signer = new Nip07Signer(provider);
    await expect(EventBuilder.textNote("wanted").createdAt(1).sign(signer)).rejects.toThrow(
      /does not match unsigned template/,
    );
  });

  test("throws when nip44 unsupported", async () => {
    const keys = Keys.fromSecretKey(SK);
    const provider: WindowNostr = {
      async getPublicKey() {
        await tick();
        return keys.publicKey;
      },
      async signEvent(template) {
        await tick();
        return EventBuilder.textNote(template.content)
          .kind(template.kind)
          .tags([])
          .createdAt(template.created_at)
          .signWithKeys(keys);
      },
    };
    const signer = new Nip07Signer(provider);
    await expect(signer.nip44Encrypt(keys.publicKey, "x")).rejects.toThrow(/nip44/);
  });
});
