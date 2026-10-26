/*
 * The vendored libsecp256k1 is compiled as a single translation unit inside this file:
 * secp256k1.c includes every implementation header plus the modules enabled with
 * -DENABLE_MODULE_EXTRAKEYS / -DENABLE_MODULE_SCHNORRSIG, so this TU also sees the library's
 * internal SHA-256 (nostr_native_secp256k1_sha256_*) and
 * nostr_native_secp256k1_memclear_explicit. Those are internal APIs of the pinned vendor tree —
 * the NIST SHA-256 vectors in tests/host guard them.
 *
 * The vendor script prefixes every secp256k1_ identifier with nostr_native_ (see
 * scripts/vendor-secp256k1.ts): React Native pods are statically linked into one binary and an
 * unprefixed libsecp256k1 would collide with any other pod embedding it. This is the only TU
 * that may include secp256k1.c — the two precomputed-table TUs stay separate. It must come
 * before nostr_core.h: secp256k1.c defines SECP256K1_BUILD and refuses to be the second
 * includer of its own public header.
 */
#include "../vendor/secp256k1/src/secp256k1.c"
#include "../vendor/secp256k1/include/secp256k1_extrakeys.h"
#include "../vendor/secp256k1/include/secp256k1_ecdh.h"
#include "../vendor/secp256k1/include/secp256k1_schnorrsig.h"

#include "nostr_core.h"

void nostr_core_wipe(void *ptr, size_t len) {
  nostr_native_secp256k1_memclear_explicit(ptr, len);
}

int nostr_core_verify(const nostr_native_secp256k1_context *ctx, const unsigned char id[32],
                      const unsigned char pubkey[32], const unsigned char sig[64]) {
  nostr_native_secp256k1_xonly_pubkey parsed;

  if (ctx == NULL || id == NULL || pubkey == NULL || sig == NULL) {
    return NOSTR_CORE_INVALID_INPUT;
  }
  if (!nostr_native_secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return NOSTR_CORE_INVALID_INPUT;
  }
  return nostr_native_secp256k1_schnorrsig_verify(ctx, sig, id, 32, &parsed)
             ? NOSTR_CORE_OK
             : NOSTR_CORE_VERIFY_FAILED;
}

int nostr_core_verify_serialized(const nostr_native_secp256k1_context *ctx,
                                 const unsigned char *serialized, size_t len,
                                 const unsigned char id[32], const unsigned char pubkey[32],
                                 const unsigned char sig[64]) {
  unsigned char digest[32];
  nostr_native_secp256k1_sha256 sha;
  const nostr_native_secp256k1_hash_ctx *hash_ctx;
  size_t i;

  if (ctx == NULL || serialized == NULL || id == NULL || pubkey == NULL || sig == NULL) {
    return NOSTR_CORE_INVALID_INPUT;
  }

  hash_ctx = nostr_native_secp256k1_get_hash_context(ctx);
  nostr_native_secp256k1_sha256_initialize(&sha);
  nostr_native_secp256k1_sha256_write(hash_ctx, &sha, serialized, len);
  nostr_native_secp256k1_sha256_finalize(hash_ctx, &sha, digest);
  for (i = 0; i < 32; i++) {
    if (digest[i] != id[i]) {
      return NOSTR_CORE_VERIFY_FAILED;
    }
  }
  return nostr_core_verify(ctx, id, pubkey, sig);
}

int nostr_core_sign(const nostr_native_secp256k1_context *ctx, const unsigned char id[32],
                    const unsigned char seckey[32], const unsigned char aux[32],
                    unsigned char out_sig[64]) {
  nostr_native_secp256k1_keypair keypair;
  int ok;

  if (ctx == NULL || id == NULL || seckey == NULL || aux == NULL || out_sig == NULL) {
    return NOSTR_CORE_INVALID_INPUT;
  }

  ok = nostr_native_secp256k1_keypair_create(ctx, &keypair, seckey) &&
       nostr_native_secp256k1_schnorrsig_sign32(ctx, out_sig, id, &keypair, aux);
  nostr_native_secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok ? NOSTR_CORE_OK : NOSTR_CORE_INVALID_INPUT;
}

int nostr_core_public_key(const nostr_native_secp256k1_context *ctx,
                          const unsigned char seckey[32], unsigned char out_xonly[32]) {
  nostr_native_secp256k1_keypair keypair;
  nostr_native_secp256k1_xonly_pubkey pubkey;
  int ok;

  if (ctx == NULL || seckey == NULL || out_xonly == NULL) {
    return NOSTR_CORE_INVALID_INPUT;
  }

  ok = nostr_native_secp256k1_keypair_create(ctx, &keypair, seckey) &&
       nostr_native_secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair) &&
       nostr_native_secp256k1_xonly_pubkey_serialize(ctx, out_xonly, &pubkey);
  nostr_native_secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok ? NOSTR_CORE_OK : NOSTR_CORE_INVALID_INPUT;
}

/* ECDH hash function: writes the shared point's x coordinate, nothing else. */
static int nostr_core_ecdh_xonly_hash(unsigned char *output, const unsigned char *x,
                                    const unsigned char *y, void *data) {
  (void)y;
  (void)data;
  memcpy(output, x, 32);
  return 1;
}

int nostr_core_ecdh_x(const nostr_native_secp256k1_context *ctx, const unsigned char seckey[32],
                      const unsigned char pubkey_x[32], unsigned char out32[32]) {
  unsigned char compressed[33];
  nostr_native_secp256k1_pubkey point;
  int ok;

  if (ctx == NULL || seckey == NULL || pubkey_x == NULL || out32 == NULL) {
    return NOSTR_CORE_INVALID_INPUT;
  }

  compressed[0] = 0x02;
  memcpy(compressed + 1, pubkey_x, 32);
  ok = nostr_native_secp256k1_ec_pubkey_parse(ctx, &point, compressed, 33) &&
       nostr_native_secp256k1_ecdh(ctx, out32, &point, seckey, nostr_core_ecdh_xonly_hash, NULL);
  nostr_native_secp256k1_memclear_explicit(compressed, sizeof(compressed));
  nostr_native_secp256k1_memclear_explicit(&point, sizeof(point));
  return ok ? NOSTR_CORE_OK : NOSTR_CORE_INVALID_INPUT;
}

#ifdef NOSTR_NATIVE_TEST

nostr_native_secp256k1_context *nostr_native_test_context(void) {
  static nostr_native_secp256k1_context *ctx;
  if (ctx == NULL) {
    ctx = nostr_native_secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  }
  return ctx;
}

void nostr_native_test_sha256(const unsigned char *data, size_t len, unsigned char out32[32]) {
  nostr_native_secp256k1_context *ctx = nostr_native_test_context();
  const nostr_native_secp256k1_hash_ctx *hash_ctx = nostr_native_secp256k1_get_hash_context(ctx);
  nostr_native_secp256k1_sha256 sha;
  nostr_native_secp256k1_sha256_initialize(&sha);
  nostr_native_secp256k1_sha256_write(hash_ctx, &sha, data, len);
  nostr_native_secp256k1_sha256_finalize(hash_ctx, &sha, out32);
}

int nostr_native_test_schnorr_verify(const unsigned char *msg, size_t msglen,
                                     const unsigned char pubkey[32], const unsigned char sig[64]) {
  nostr_native_secp256k1_context *ctx = nostr_native_test_context();
  nostr_native_secp256k1_xonly_pubkey parsed;
  if (!nostr_native_secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return 0;
  }
  return nostr_native_secp256k1_schnorrsig_verify(ctx, sig, msg, msglen, &parsed);
}

#endif
