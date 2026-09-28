/**
 * NIP-49: Private Key Encryption (`ncryptsec`).
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/49.md
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

import { NostrError } from "../core/error.ts";
import { assertSecretKeyBytes, utf8Encoder } from "../core/util.ts";
import { Bech32MaxSize, encodeBytes } from "./nip19.ts";

export type Ncryptsec = `ncryptsec1${string}`;
export type KeySecurityByte = 0x00 | 0x01 | 0x02;

export type ScryptParams = { N: number; r: number; p: number; dkLen: number };

/** Derive `params.dkLen` bytes from the NFKC-normalized UTF-8 password and salt (RFC 7914). */
export type Scrypt = (
  password: Uint8Array,
  salt: Uint8Array,
  params: ScryptParams,
) => Promise<Uint8Array>;

export type Nip49EncryptOptions = {
  /** Scrypt log2(N) work factor, 1..22. Defaults to 16. */
  logn?: number;
  /** Key security byte recorded in the payload. Defaults to 0x02. */
  ksb?: KeySecurityByte;
  /** Scrypt implementation. Defaults to noble `scryptAsync`. */
  scrypt?: Scrypt;
};

export type Nip49DecryptOptions = {
  /** Scrypt implementation. Defaults to noble `scryptAsync`. */
  scrypt?: Scrypt;
};

const VERSION = 0x02;
const SALT_LEN = 16;
const NONCE_LEN = 24;
const PAYLOAD_LEN = 91;
const LOGN_MIN = 1;
const LOGN_MAX = 22;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export class Nip49Error extends NostrError {
  override name = "Nip49Error";
}

function assertLogn(logn: number): void {
  if (!Number.isInteger(logn) || logn < LOGN_MIN || logn > LOGN_MAX) {
    throw new Nip49Error(`invalid logn ${logn}, expected integer ${LOGN_MIN}..${LOGN_MAX}`);
  }
}

// noble 2.3: V (N blocks) + p B blocks + one tmp scratch block.
const nobleScrypt: Scrypt = async (password, salt, params) =>
  scryptAsync(password, salt, {
    ...params,
    maxmem: 128 * params.r * (params.N + params.p + 1),
  });

async function deriveKey(
  password: string,
  salt: Uint8Array,
  logn: number,
  kdf: Scrypt,
): Promise<Uint8Array> {
  assertLogn(logn);
  let key: Uint8Array;
  try {
    key = await kdf(utf8Encoder.encode(password.normalize("NFKC")), salt, {
      N: 2 ** logn,
      r: SCRYPT_R,
      p: SCRYPT_P,
      dkLen: 32,
    });
  } catch (error) {
    throw new Nip49Error("scrypt failed", {
      cause: error instanceof Error ? error : undefined,
    });
  }
  if (key.length !== 32) {
    throw new Nip49Error(`scrypt returned ${key.length} bytes, expected 32`);
  }
  return key;
}

/** Encrypt a 32-byte secret key to an `ncryptsec` bech32 string. */
export async function encrypt(
  secretKey: Uint8Array,
  password: string,
  opts?: Nip49EncryptOptions,
): Promise<Ncryptsec> {
  assertSecretKeyBytes(secretKey);
  const logn = opts?.logn ?? 16;
  const salt = randomBytes(SALT_LEN);
  const key = await deriveKey(password, salt, logn, opts?.scrypt ?? nobleScrypt);
  const nonce = randomBytes(NONCE_LEN);
  const aad = Uint8Array.from([opts?.ksb ?? 0x02]);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(secretKey);
  const bytes = concatBytes(
    Uint8Array.from([VERSION]),
    Uint8Array.from([logn]),
    salt,
    nonce,
    aad,
    ciphertext,
  );
  return encodeBytes("ncryptsec", bytes);
}

/** Decrypt an `ncryptsec` bech32 string to a 32-byte secret key. */
export async function decrypt(
  ncryptsec: string,
  password: string,
  opts?: Nip49DecryptOptions,
): Promise<Uint8Array> {
  let prefix: string;
  let b: Uint8Array;
  try {
    const decoded = bech32.decode(ncryptsec, Bech32MaxSize);
    ({ prefix } = decoded);
    b = new Uint8Array(bech32.fromWords(decoded.words));
  } catch (error) {
    throw new Nip49Error("invalid ncryptsec", {
      cause: error instanceof Error ? error : undefined,
    });
  }
  if (prefix !== "ncryptsec") {
    throw new Nip49Error(`invalid prefix ${prefix}, expected 'ncryptsec'`);
  }
  if (b.length !== PAYLOAD_LEN) {
    throw new Nip49Error("invalid ncryptsec length");
  }
  const version = b.at(0);
  if (version === undefined) {
    throw new Nip49Error("invalid ncryptsec length");
  }
  if (version !== VERSION) {
    throw new Nip49Error(`invalid version ${version}, expected 0x02`);
  }
  const logn = b.at(1);
  if (logn === undefined) {
    throw new Nip49Error("invalid ncryptsec length");
  }
  const salt = b.subarray(2, 2 + SALT_LEN);
  const nonce = b.subarray(2 + SALT_LEN, 2 + SALT_LEN + NONCE_LEN);
  const ksb = b.at(2 + SALT_LEN + NONCE_LEN);
  if (ksb === undefined) {
    throw new Nip49Error("invalid ncryptsec length");
  }
  const aad = Uint8Array.from([ksb]);
  const ciphertext = b.subarray(2 + SALT_LEN + NONCE_LEN + 1);
  try {
    const key = await deriveKey(password, salt, logn, opts?.scrypt ?? nobleScrypt);
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch (error) {
    if (error instanceof Nip49Error) {
      throw error;
    }
    throw new Nip49Error("failed to decrypt", {
      cause: error instanceof Error ? error : undefined,
    });
  }
}
