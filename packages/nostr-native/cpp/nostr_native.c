#include "nostr_native.h"

#include "nostr_core.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * React Native platform layer: owns the process context (pthread_once creation plus an
 * arc4random seed) and delegates the crypto work to nostr_core.c — the single TU that
 * compiles the vendored libsecp256k1. CONTEXT_NONE runs the library self test; randomizing
 * with an arc4random seed blinds ecmult_gen against side-channel leakage of the secret key
 * while signing. Every public entry point resolves the context first.
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
  nostr_core_wipe(seed, sizeof(seed));
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
  return nostr_core_verify_serialized(module_context(), serialized, len, id, pubkey, sig) ==
         NOSTR_CORE_OK;
}

int nostr_native_public_key(const unsigned char seckey[32], unsigned char out_xonly[32]) {
  return nostr_core_public_key(module_context(), seckey, out_xonly) == NOSTR_CORE_OK;
}

int nostr_native_sign(const unsigned char id[32], const unsigned char seckey[32],
                      const unsigned char aux_rand[32], unsigned char out_sig[64]) {
  return nostr_core_sign(module_context(), id, seckey, aux_rand, out_sig) == NOSTR_CORE_OK;
}
