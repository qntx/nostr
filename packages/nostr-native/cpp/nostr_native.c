#include "nostr_native.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
 * unprefixed libsecp256k1 would collide with any other pod embedding it.
 */
#include "../vendor/secp256k1/src/secp256k1.c"
#include "../vendor/secp256k1/include/secp256k1_extrakeys.h"
#include "../vendor/secp256k1/include/secp256k1_schnorrsig.h"

/*
 * One module context for the process, created on first use. CONTEXT_NONE runs the library
 * self test; randomizing with an arc4random seed blinds ecmult_gen against side-channel leakage
 * of the secret key while signing. Every public entry point calls this first.
 */
static nostr_native_secp256k1_context *module_ctx;
static pthread_once_t module_ctx_once = PTHREAD_ONCE_INIT;

static void init_module_context(void) {
  unsigned char seed[32];
  nostr_native_secp256k1_context *created =
      nostr_native_secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (created == NULL) {
    abort();
  }
  arc4random_buf(seed, sizeof(seed));
  if (!nostr_native_secp256k1_context_randomize(created, seed)) {
    abort();
  }
  nostr_native_secp256k1_memclear_explicit(seed, sizeof(seed));
  module_ctx = created;
}

static nostr_native_secp256k1_context *module_context(void) {
  pthread_once(&module_ctx_once, init_module_context);
  return module_ctx;
}

int nostr_native_verify_serialized(const unsigned char *serialized, size_t len,
                                   const unsigned char id[32],
                                   const unsigned char pubkey[32],
                                   const unsigned char sig[64]) {
  unsigned char digest[32];
  nostr_native_secp256k1_sha256 sha;
  nostr_native_secp256k1_xonly_pubkey parsed;
  nostr_native_secp256k1_context *ctx = module_context();
  const nostr_native_secp256k1_hash_ctx *hash_ctx;
  size_t i;

  if (serialized == NULL || id == NULL || pubkey == NULL || sig == NULL) {
    return 0;
  }

  hash_ctx = nostr_native_secp256k1_get_hash_context(ctx);
  nostr_native_secp256k1_sha256_initialize(&sha);
  nostr_native_secp256k1_sha256_write(hash_ctx, &sha, serialized, len);
  nostr_native_secp256k1_sha256_finalize(hash_ctx, &sha, digest);
  for (i = 0; i < 32; i++) {
    if (digest[i] != id[i]) {
      return 0;
    }
  }

  if (!nostr_native_secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return 0;
  }
  return nostr_native_secp256k1_schnorrsig_verify(ctx, sig, id, 32, &parsed);
}

int nostr_native_public_key(const unsigned char seckey[32], unsigned char out_xonly[32]) {
  nostr_native_secp256k1_keypair keypair;
  nostr_native_secp256k1_xonly_pubkey pubkey;
  int ok;
  nostr_native_secp256k1_context *ctx = module_context();

  if (seckey == NULL || out_xonly == NULL) {
    return 0;
  }

  ok = nostr_native_secp256k1_keypair_create(ctx, &keypair, seckey) &&
       nostr_native_secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair) &&
       nostr_native_secp256k1_xonly_pubkey_serialize(ctx, out_xonly, &pubkey);
  nostr_native_secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok;
}

int nostr_native_sign(const unsigned char id[32], const unsigned char seckey[32],
                      const unsigned char aux_rand[32], unsigned char out_sig[64]) {
  nostr_native_secp256k1_keypair keypair;
  int ok;
  nostr_native_secp256k1_context *ctx = module_context();

  if (id == NULL || seckey == NULL || aux_rand == NULL || out_sig == NULL) {
    return 0;
  }

  ok = nostr_native_secp256k1_keypair_create(ctx, &keypair, seckey) &&
       nostr_native_secp256k1_schnorrsig_sign32(ctx, out_sig, id, &keypair, aux_rand);
  nostr_native_secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok;
}

#ifdef NOSTR_NATIVE_TEST

void nostr_native_test_sha256(const unsigned char *data, size_t len, unsigned char out32[32]) {
  nostr_native_secp256k1_context *ctx = module_context();
  const nostr_native_secp256k1_hash_ctx *hash_ctx = nostr_native_secp256k1_get_hash_context(ctx);
  nostr_native_secp256k1_sha256 sha;
  nostr_native_secp256k1_sha256_initialize(&sha);
  nostr_native_secp256k1_sha256_write(hash_ctx, &sha, data, len);
  nostr_native_secp256k1_sha256_finalize(hash_ctx, &sha, out32);
}

int nostr_native_test_schnorr_verify(const unsigned char *msg, size_t msglen,
                                     const unsigned char pubkey[32], const unsigned char sig[64]) {
  nostr_native_secp256k1_context *ctx = module_context();
  nostr_native_secp256k1_xonly_pubkey parsed;
  if (!nostr_native_secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return 0;
  }
  return nostr_native_secp256k1_schnorrsig_verify(ctx, sig, msg, msglen, &parsed);
}

#endif
