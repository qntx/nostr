#ifndef QNTX_NOSTR_NATIVE_H
#define QNTX_NOSTR_NATIVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return 1 iff `sha256(serialized[0..len])` equals `id` and `sig` is a valid BIP-340 signature of
 * `id` for the x-only `pubkey`. `id`/`pubkey` are 32 bytes and `sig` is 64 bytes; NULL pointers
 * return 0.
 */
int qntx_nostr_verify_serialized(const unsigned char *serialized, size_t len,
                                  const unsigned char id[32],
                                  const unsigned char pubkey[32],
                                  const unsigned char sig[64]);

/**
 * Write the 32-byte x-only BIP-340 public key of `seckey` to `out_xonly`.
 * Returns 1 on success; 0 on NULL input or an invalid secret key (zero or >= group order).
 */
int qntx_nostr_public_key(const unsigned char seckey[32], unsigned char out_xonly[32]);

/**
 * Write the 64-byte BIP-340 signature of `id` by `seckey` with `aux_rand` auxiliary randomness
 * to `out_sig`. Returns 1 on success; 0 on NULL input or an invalid secret key.
 */
int qntx_nostr_sign(const unsigned char id[32], const unsigned char seckey[32],
                     const unsigned char aux_rand[32], unsigned char out_sig[64]);

#ifdef QNTX_NOSTR_NATIVE_TEST
/* Test-only entry points (host suite only): expose the SHA-256 and Schnorr halves individually
 * so BIP-340 vectors with arbitrary-length messages and raw SHA-256 vectors can run. */

void qntx_nostr_test_sha256(const unsigned char *data, size_t len, unsigned char out32[32]);

int qntx_nostr_test_schnorr_verify(const unsigned char *msg, size_t msglen,
                              const unsigned char pubkey[32], const unsigned char sig[64]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* QNTX_NOSTR_NATIVE_H */
