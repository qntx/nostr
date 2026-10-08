/**
 * NIP-13: Proof of Work. Does not import signer, relay, or client. Does not sign.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/13.md
 */
import { sha256 } from "@noble/hashes/sha2.js";

import { abortReason } from "../core/abort.ts";
import { NostrError } from "../core/error.ts";
import type { UnsignedEvent } from "../core/event.ts";
import { bytesToHex, isHex32, nowSeconds, utf8Encoder } from "../core/util.ts";

export class Nip13Error extends NostrError {
  override name = "Nip13Error";
}

export type MinePowOptions = {
  /** Yield to the event loop after this many hashes. Default 1000. */
  yieldEvery?: number | undefined;
  signal?: AbortSignal | undefined;
};

/** Leading zero bits of a hex event id or raw sha256 bytes. */
export function getPow(idOrHash: string | Uint8Array): number {
  if (typeof idOrHash === "string") {
    if (!isHex32(idOrHash.toLowerCase())) {
      throw new Nip13Error(`expected 64-char hex event id, got ${idOrHash.length} chars`);
    }
    let count = 0;
    for (let i = 0; i < idOrHash.length; i += 8) {
      const chunk = Number.parseInt(idOrHash.slice(i, i + 8), 16);
      if (chunk === 0) {
        count += 32;
      } else {
        count += Math.clz32(chunk);
        break;
      }
    }
    return count;
  }

  let count = 0;
  for (const byte of idOrHash) {
    if (byte === 0) {
      count += 8;
    } else {
      count += Math.clz32(byte) - 24;
      break;
    }
  }
  return count;
}

/**
 * Returns a new unsigned event with nonce tag and computed id. Does not mutate input. `created_at`
 * is advanced to the current second whenever it elapses while mining. Yields every `yieldEvery`
 * hashes.
 */
export async function minePow(
  unsigned: UnsignedEvent,
  difficulty: number,
  opts?: MinePowOptions,
): Promise<UnsignedEvent & { id: string }> {
  const signal = opts?.signal;
  const yieldEvery = Math.max(1, opts?.yieldEvery ?? 1000);

  const nonce: [string, string, string] = ["nonce", "0", String(difficulty)];
  const mined = {
    kind: unsigned.kind,
    tags: [...unsigned.tags, nonce],
    content: unsigned.content,
    created_at: unsigned.created_at,
    pubkey: unsigned.pubkey,
  };

  // Serialize once per created_at second: the reused buffer holds
  //   [0, pubkey, created_at, kind, [...tags, ["nonce","<digits>","<difficulty>"]], content]
  // where `head` ends at the opening quote of the nonce value and `tail` completes the tag, the
  // tags array, and the trailing content element.
  let head = new Uint8Array(0);
  let tail = new Uint8Array(0);
  let buf = new Uint8Array(0);

  const rebuild = (): void => {
    const headText = JSON.stringify([
      0,
      mined.pubkey,
      mined.created_at,
      mined.kind,
      [...unsigned.tags, ["nonce", ""]],
    ]).slice(0, -4);
    head = utf8Encoder.encode(headText);
    tail = utf8Encoder.encode(`","${difficulty}"]],${JSON.stringify(mined.content)}]`);
    buf = new Uint8Array(head.length + 24 + tail.length);
    buf.set(head, 0);
  };
  rebuild();

  let count = 0;
  let iterations = 0;

  while (true) {
    if (signal?.aborted === true) {
      throw abortReason(signal);
    }

    const now = nowSeconds();
    if (now !== mined.created_at) {
      count = 0;
      mined.created_at = now;
      rebuild();
    }

    nonce[1] = String(++count);
    let pos = head.length;
    for (let i = 0; i < nonce[1].length; i++) {
      buf[pos] = nonce[1].codePointAt(i) ?? 0;
      pos += 1;
    }
    buf.set(tail, pos);
    pos += tail.length;
    const hash = sha256(buf.subarray(0, pos));
    if (getPow(hash) >= difficulty) {
      return { ...mined, id: bytesToHex(hash) };
    }

    iterations++;
    if (iterations >= yieldEvery) {
      iterations = 0;
      // oxlint-disable-next-line no-await-in-loop -- the yield is part of each mining round
      await new Promise<void>((resolve) => {
        setTimeout(resolve);
      });
    }
  }
}
