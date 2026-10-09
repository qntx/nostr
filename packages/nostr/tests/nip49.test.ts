import { scryptAsync } from "@noble/hashes/scrypt.js";
import { bech32 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { hexToBytes, nsecEncode } from "../src/index.ts";
import { Bech32MaxSize, encodeBytes } from "../src/nips/nip19.ts";
import { decrypt, encrypt, Nip49Error } from "../src/nips/nip49.ts";
import type { KeySecurityByte, Scrypt, ScryptParams } from "../src/nips/nip49.ts";

describe("nip49", () => {
  test("encrypt and decrypt vectors", async () => {
    await Promise.all(
      vectors.map(async ([password, secret, logn, ksb, ncryptsec]) => {
        const sec = hexToBytes(secret);
        const there = await encrypt(sec, password, { logn, ksb });
        const back = await decrypt(there, password, { maxLogN: logn });
        const again = await decrypt(ncryptsec, password, { maxLogN: logn });
        expect(back).toStrictEqual(again);
        expect(again).toStrictEqual(sec);
      }),
    );
  });

  test("spec vector logn 16", async () => {
    const ncryptsec =
      "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const sec = hexToBytes("3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683");
    await expect(decrypt(ncryptsec, "nostr", { maxLogN: 16 })).resolves.toStrictEqual(sec);
  });

  test("wrong password throws", async () => {
    const [password, secret, logn, ksb, ncryptsec] = vectors[0]!;
    const sec = hexToBytes(secret);
    await expect(decrypt(ncryptsec, "wrong-password", { maxLogN: 22 })).rejects.toThrow(Nip49Error);
    await expect(decrypt(ncryptsec, "wrong-password", { maxLogN: 22 })).rejects.toThrow(
      "failed to decrypt",
    );
    const there = await encrypt(sec, password, { logn, ksb });
    await expect(decrypt(there, "wrong", { maxLogN: 22 })).rejects.toThrow(Nip49Error);
  });

  test("wrong prefix throws", async () => {
    const sec = hexToBytes(vectors[0]![1]);
    await expect(decrypt(nsecEncode(sec), "x", { maxLogN: 22 })).rejects.toThrow(Nip49Error);
  });

  test("excess bech32 padding throws Nip49Error", async () => {
    await expect(decrypt("ncryptsec1pcnlmyt", "x", { maxLogN: 22 })).rejects.toThrow(Nip49Error);
  });

  test("invalid logn throws Nip49Error", async () => {
    const sec = hexToBytes(vectors[0]![1]);
    await expect(encrypt(sec, "pw", { logn: 0 })).rejects.toThrow(Nip49Error);
    await expect(encrypt(sec, "pw", { logn: 23 })).rejects.toThrow(Nip49Error);
    await expect(encrypt(sec, "pw", { logn: 1.5 })).rejects.toThrow(Nip49Error);
  });

  test("injected scrypt receives the NFKC password bytes, salt, and params", async () => {
    const seen: Array<{ password: Uint8Array; salt: Uint8Array; params: ScryptParams }> = [];
    const recording: Scrypt = async (password, salt, params) => {
      seen.push({ password, salt, params });
      return scryptAsync(password, salt, {
        ...params,
        maxmem: 128 * params.r * (params.N + params.p + 1),
      });
    };
    const sec = hexToBytes(vectors[0]![1]);
    // Å decomposed (U+0041 U+030A) normalizes to composed U+00C5 under NFKC.
    const ncryptsec = await encrypt(sec, "A\u030A", { logn: 4, scrypt: recording });
    expect(seen).toHaveLength(1);
    const call = seen[0]!;
    expect(call.password).toStrictEqual(new TextEncoder().encode("\u00C5"));
    expect(call.salt).toHaveLength(16);
    expect(call.params).toStrictEqual({ N: 2 ** 4, r: 8, p: 1, dkLen: 32 });

    await decrypt(ncryptsec, "\u00C5", { maxLogN: 4, scrypt: recording });
    expect(seen).toHaveLength(2);
    expect(seen[1]!.password).toStrictEqual(call.password);
    expect(seen[1]!.salt).toStrictEqual(call.salt);
    expect(seen[1]!.params).toStrictEqual(call.params);
  });

  test("an injected scrypt delegating to noble roundtrips with the default", async () => {
    const sec = hexToBytes(vectors[0]![1]);
    const delegating: Scrypt = async (password, salt, params) =>
      scryptAsync(password, salt, {
        ...params,
        maxmem: 128 * params.r * (params.N + params.p + 1),
      });
    const ncryptsec = await encrypt(sec, "pw", { logn: 4, scrypt: delegating });
    await expect(decrypt(ncryptsec, "pw", { maxLogN: 22 })).resolves.toStrictEqual(sec);
  });

  test("a rejecting scrypt throws scrypt failed with cause", async () => {
    const cause = new Error("native kdf down");
    const failing: Scrypt = async () => Promise.reject(cause);
    const sec = hexToBytes(vectors[0]![1]);
    const err = await encrypt(sec, "pw", { logn: 4, scrypt: failing }).catch(
      (error: unknown) => error,
    );
    expect(err).toBeInstanceOf(Nip49Error);
    expect((err as Error).message).toBe("scrypt failed");
    expect((err as Error).cause).toBe(cause);
  });

  test("a scrypt returning the wrong length throws", async () => {
    const short: Scrypt = async () => Promise.resolve(new Uint8Array(31));
    const sec = hexToBytes(vectors[0]![1]);
    await expect(encrypt(sec, "pw", { logn: 4, scrypt: short })).rejects.toThrow(
      "scrypt returned 31 bytes, expected 32",
    );
  });

  test("a payload logn above maxLogN rejects before scrypt runs", async () => {
    const v = vectors[3]!; // logn 7
    let calls = 0;
    const spy: Scrypt = async () => {
      calls += 1;
      return Promise.resolve(new Uint8Array(32));
    };
    const thrown = await decrypt(v[4], "x", { maxLogN: v[2] - 1, scrypt: spy }).catch(
      (error: unknown) => error,
    );
    expect(thrown).toBeInstanceOf(Nip49Error);
    expect((thrown as Error).message).toBe(`logn ${v[2]} exceeds maxLogN ${v[2] - 1}`);
    expect(calls).toBe(0);
  });

  test("a payload logn equal to maxLogN decrypts", async () => {
    const [password, secret, logn, , ncryptsec] = vectors[3]!;
    await expect(decrypt(ncryptsec, password, { maxLogN: logn })).resolves.toStrictEqual(
      hexToBytes(secret),
    );
  });

  test("an out-of-range maxLogN rejects before decoding the payload", async () => {
    const v = vectors[0]!;
    await Promise.all(
      [0, 23, 1.5].map(async (maxLogN) => {
        const thrown = await decrypt(v[4], "x", { maxLogN }).catch((error: unknown) => error);
        expect(thrown).toBeInstanceOf(Nip49Error);
        expect((thrown as Error).message).toContain(`invalid maxLogN ${maxLogN}`);
      }),
    );
  });

  test("a key security byte outside 0x00..0x02 rejects before scrypt runs", async () => {
    const v = vectors[3]!; // logn 7
    const { words } = bech32.decode(v[4], Bech32MaxSize);
    const bytes = new Uint8Array(bech32.fromWords(words));
    bytes[42] = 0x03;
    const crafted = encodeBytes("ncryptsec", bytes);
    let calls = 0;
    const spy: Scrypt = async () => {
      calls += 1;
      return Promise.resolve(new Uint8Array(32));
    };
    const thrown = await decrypt(crafted, "x", { maxLogN: v[2], scrypt: spy }).catch(
      (error: unknown) => error,
    );
    expect(thrown).toBeInstanceOf(Nip49Error);
    expect((thrown as Error).message).toContain("key security byte");
    expect(calls).toBe(0);
  });

  test("the scrypt-derived key is zero-filled after use", async () => {
    const v = vectors[3]!; // logn 7
    const derived = new Uint8Array(32).fill(7);
    const kdf: Scrypt = async () => Promise.resolve(derived);
    // The derived buffer is not a valid key, so xchacha fails; the wipe must still run.
    await expect(decrypt(v[4], "x", { maxLogN: v[2], scrypt: kdf })).rejects.toThrow(
      "failed to decrypt",
    );
    expect(derived).toStrictEqual(new Uint8Array(32));
  });
});

const vectors: Array<[string, string, number, KeySecurityByte, string]> = [
  [
    ".ksjabdk.aselqwe",
    "14c226dbdd865d5e1645e72c7470fd0a17feb42cc87b750bab6538171b3a3f8a",
    1,
    0x00,
    "ncryptsec1qgqeya6cggg2chdaf48s9evsr0czq3dw059t2khf5nvmq03yeckywqmspcc037l9ajjsq2p08480afuc5hq2zq3rtt454c2epjqxcxll0eff3u7ln2t349t7rc04029q63u28mkeuj4tdazsqqk6p5ky",
  ],
  [
    "skjdaklrnçurbç l",
    "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
    2,
    0x01,
    "ncryptsec1qgp86t7az0u5w0wp8nrjnxu9xhullqt39wvfsljz8289gyxg0thrlzv3k40dsqu32vcqza3m7srzm27mkg929gmv6hv5ctay59jf0h8vsj5pjmylvupkdtvy7fy88et3fhe6m3d84t9m8j2umq0j75lw",
  ],
  [
    "777z7z7z7z7z7z7z",
    "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
    3,
    0x02,
    "ncryptsec1qgpc7jmmzmds376r8slazywlagrm5eerlrx7njnjenweggq2atjl0h9vmpk8f9gad0tqy3pwch8e49kyj5qtehp4mjwpzlshx5f5cce8feukst08w52zf4a7gssdqvt3eselup7x4zzezlme3ydxpjaf",
  ],
  [
    ".ksjabdk.aselqwe",
    "14c226dbdd865d5e1645e72c7470fd0a17feb42cc87b750bab6538171b3a3f8a",
    7,
    0x00,
    "ncryptsec1qgrss6ycqptee05e5anq33x2vz6ljr0rqunsy9xj5gypkp0lucatdf8yhexrztqcy76sqweuzk8yqzep9mugp988vznz5df8urnyrmaa7l7fvvskp4t0ydjtz0zeajtumul8cnsjcksp68xhxggmy4dz",
  ],
  [
    "skjdaklrnçurbç l",
    "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
    8,
    0x01,
    "ncryptsec1qgy0gg98z4wvl35eqlraxf7cyxhfs4968teq59vm97e94gpycmcy6znsc8z82dy5rk8sz0r499ue7xfmd0yuyvzxagtfyxtnwcrcsjavkch8lfseejukwdq7mdcpm43znffngw7texdc5pdujywszhrr",
  ],
  [
    "777z7z7z7z7z7z7z",
    "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
    9,
    0x02,
    "ncryptsec1qgyskhh7mpr0zspg95kv4eefm8233hyz46xyr6s52s6qvan906c2u24gl3dc5f7wytzq9njx7sqksd7snagce3kqth7tv4ug4avlxd5su4vthsh54vk62m88whkazavyc6yefnegf4tx473afssxw4p9",
  ],
  [
    "",
    "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
    4,
    0x00,
    "ncryptsec1qgzv73a9ktnwmgyvv24x2xtr6grup2v6an96xgs64z3pmh5etg2k4yryachtlu3tpqwqphhm0pjnq9zmftr0qf4p5lmah4rlz02ucjkawr2s9quau67p3jq3d7yp3kreghs0wdcqpf6pkc8jcgsqrn5l",
  ],
  [
    "",
    "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
    5,
    0x01,
    "ncryptsec1qgzs50vjjhewdrxnm0z4y77w7juycf6crny9q0kzeg7vxv3erw77qpauthaf7sfwsgnszjzcqh7zql74m8yxnhcj07dry3v5fgr5x42mpzxvfl76gpuayccvk2nczc7ner3q842rj9v033nykvja6cql",
  ],
  [
    "",
    "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
    1,
    0x00,
    "ncryptsec1qgqnx59n7duv6ec3hhrvn33q25u2qfd7m69vv6plsg7spnw6d4r9hq0ayjsnlw99eghqqzj8ps7vfwx40nqp9gpw7yzyy09jmwkq3a3z8q0ph5jahs2hap5k6h2wfrme7w2nuek4jnwpzfht4q3u79ra",
  ],
  [
    "ÅΩẛ̣",
    "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
    9,
    0x01,
    "ncryptsec1qgy5kwr5v8p206vwaflp4g6r083kwts6q5sh8m4d0q56edpxwhrly78ema2z7jpdeldsz7u5wpxpyhs6m0405skdsep9n37uncw7xlc8q8meyw6d6ky47vcl0guhqpt5dx8ejxc8hvzf6y2gwsl5s0nw",
  ],
  [
    "ÅΩṩ",
    "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
    9,
    0x01,
    "ncryptsec1qgy5f4lcx873yarkfpngaudarxfj4wj939xn4azmd66j6jrwcml6av87d6vnelzn70kszgkg4lj9rsdjlqz0wn7m7456sr2q5yjpy72ykgkdwckevl857hpcfnwzswj9lajxtln0tsr9h7xdwqm6pqzf",
  ],
];
