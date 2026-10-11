#include "nostr_native.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * The vendored libsecp256k1 is compiled as a single translation unit inside this file:
 * secp256k1.c includes every implementation header plus the modules enabled with
 * -DENABLE_MODULE_EXTRAKEYS / -DENABLE_MODULE_SCHNORRSIG, so this TU also sees the library's
 * internal SHA-256 (secp256k1_sha256_*) and secp256k1_memclear_explicit. Those are internal
 * APIs of the pinned vendor tree — the NIST SHA-256 vectors in tests/host guard them.
 */
#include "../vendor/secp256k1/src/secp256k1.c"
#include "../vendor/secp256k1/include/secp256k1_extrakeys.h"
#include "../vendor/secp256k1/include/secp256k1_schnorrsig.h"

/*
 * One module context for the process, created on first use. CONTEXT_NONE runs the library
 * self test; randomizing with an arc4random seed blinds ecmult_gen against side-channel leakage
 * of the secret key while signing. Every public entry point calls this first.
 */
static secp256k1_context *qntx_ctx;
static pthread_once_t qntx_ctx_once = PTHREAD_ONCE_INIT;

static void qntx_init_context(void) {
  unsigned char seed[32];
  secp256k1_context *created = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (created == NULL) {
    abort();
  }
  arc4random_buf(seed, sizeof(seed));
  if (!secp256k1_context_randomize(created, seed)) {
    abort();
  }
  secp256k1_memclear_explicit(seed, sizeof(seed));
  qntx_ctx = created;
}

static secp256k1_context *qntx_context(void) {
  pthread_once(&qntx_ctx_once, qntx_init_context);
  return qntx_ctx;
}

int qntx_nostr_verify_serialized(const unsigned char *serialized, size_t len,
                                  const unsigned char id[32],
                                  const unsigned char pubkey[32],
                                  const unsigned char sig[64]) {
  unsigned char digest[32];
  secp256k1_sha256 sha;
  secp256k1_xonly_pubkey parsed;
  secp256k1_context *ctx = qntx_context();
  const secp256k1_hash_ctx *hash_ctx;
  size_t i;

  if (serialized == NULL || id == NULL || pubkey == NULL || sig == NULL) {
    return 0;
  }

  hash_ctx = secp256k1_get_hash_context(ctx);
  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(hash_ctx, &sha, serialized, len);
  secp256k1_sha256_finalize(hash_ctx, &sha, digest);
  for (i = 0; i < 32; i++) {
    if (digest[i] != id[i]) {
      return 0;
    }
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return 0;
  }
  return secp256k1_schnorrsig_verify(ctx, sig, id, 32, &parsed);
}

int qntx_nostr_public_key(const unsigned char seckey[32], unsigned char out_xonly[32]) {
  secp256k1_keypair keypair;
  secp256k1_xonly_pubkey pubkey;
  int ok;
  secp256k1_context *ctx = qntx_context();

  if (seckey == NULL || out_xonly == NULL) {
    return 0;
  }

  ok = secp256k1_keypair_create(ctx, &keypair, seckey) &&
       secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair) &&
       secp256k1_xonly_pubkey_serialize(ctx, out_xonly, &pubkey);
  secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok;
}

int qntx_nostr_sign(const unsigned char id[32], const unsigned char seckey[32],
                     const unsigned char aux_rand[32], unsigned char out_sig[64]) {
  secp256k1_keypair keypair;
  int ok;
  secp256k1_context *ctx = qntx_context();

  if (id == NULL || seckey == NULL || aux_rand == NULL || out_sig == NULL) {
    return 0;
  }

  ok = secp256k1_keypair_create(ctx, &keypair, seckey) &&
       secp256k1_schnorrsig_sign32(ctx, out_sig, id, &keypair, aux_rand);
  secp256k1_memclear_explicit(&keypair, sizeof(keypair));
  return ok;
}

#ifdef QNTX_NOSTR_NATIVE_TEST

void qntx_nostr_test_sha256(const unsigned char *data, size_t len, unsigned char out32[32]) {
  secp256k1_context *ctx = qntx_context();
  const secp256k1_hash_ctx *hash_ctx = secp256k1_get_hash_context(ctx);
  secp256k1_sha256 sha;
  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(hash_ctx, &sha, data, len);
  secp256k1_sha256_finalize(hash_ctx, &sha, out32);
}

int qntx_nostr_test_schnorr_verify(const unsigned char *msg, size_t msglen,
                              const unsigned char pubkey[32], const unsigned char sig[64]) {
  secp256k1_context *ctx = qntx_context();
  secp256k1_xonly_pubkey parsed;
  if (!secp256k1_xonly_pubkey_parse(ctx, &parsed, pubkey)) {
    return 0;
  }
  return secp256k1_schnorrsig_verify(ctx, sig, msg, msglen, &parsed);
}

#endif
