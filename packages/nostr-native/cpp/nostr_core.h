#ifndef NOSTR_CORE_H
#define NOSTR_CORE_H

#include <stddef.h>

#include "../vendor/secp256k1/include/secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Platform-independent secp256k1 operations shared by the React Native layer
 * (nostr_native.c) and the wasm32 layer (packages/nostr-wasm/c/nostr_wasm.c).
 * Every entry point takes the caller's context; status codes:
 */

/* Success, or the signature verified. */
#define NOSTR_CORE_OK 0
/* The hash or signature check failed. */
#define NOSTR_CORE_VERIFY_FAILED 1
/* NULL argument, invalid scalar, or a non-point public key. */
#define NOSTR_CORE_INVALID_INPUT 2

/* BIP-340 verify of the 32-byte `id` for the x-only `pubkey`. */
int nostr_core_verify(const nostr_native_secp256k1_context *ctx, const unsigned char id[32],
                      const unsigned char pubkey[32], const unsigned char sig[64]);

/* `sha256(serialized[0..len])` must equal `id`, then BIP-340 verify. */
int nostr_core_verify_serialized(const nostr_native_secp256k1_context *ctx,
                                 const unsigned char *serialized, size_t len,
                                 const unsigned char id[32], const unsigned char pubkey[32],
                                 const unsigned char sig[64]);

/* BIP-340 sign the 32-byte `id` with caller-supplied `aux` randomness; writes
 * 64 signature bytes on NOSTR_CORE_OK. The keypair is wiped on every path. */
int nostr_core_sign(const nostr_native_secp256k1_context *ctx, const unsigned char id[32],
                    const unsigned char seckey[32], const unsigned char aux[32],
                    unsigned char out_sig[64]);

/* Write the 32-byte x-only public key of `seckey` to `out_xonly`. */
int nostr_core_public_key(const nostr_native_secp256k1_context *ctx,
                          const unsigned char seckey[32], unsigned char out_xonly[32]);

/* Secure wipe for platform layers that must clear caller-provided regions. */
void nostr_core_wipe(void *ptr, size_t len);

#ifdef NOSTR_NATIVE_TEST
/* Test-only entry points (host suite only): expose the SHA-256 and Schnorr halves individually
 * so BIP-340 vectors with arbitrary-length messages and raw SHA-256 vectors can run. */

/* A lazily created context owned by the test binary; never destroyed. */
nostr_native_secp256k1_context *nostr_native_test_context(void);

void nostr_native_test_sha256(const unsigned char *data, size_t len, unsigned char out32[32]);

int nostr_native_test_schnorr_verify(const unsigned char *msg, size_t msglen,
                                     const unsigned char pubkey[32], const unsigned char sig[64]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NOSTR_CORE_H */
