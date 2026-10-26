/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "../../../include/secp256k1_ecdh.h"
#include "../../ecmult_const_impl.h"

static int ecdh_hash_function_sha256_impl(const nostr_native_secp256k1_hash_ctx *hash_ctx, unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    nostr_native_secp256k1_sha256 sha;
    (void)data;

    nostr_native_secp256k1_sha256_initialize(&sha);
    nostr_native_secp256k1_sha256_write(hash_ctx, &sha, &version, 1);
    nostr_native_secp256k1_sha256_write(hash_ctx, &sha, x32, 32);
    nostr_native_secp256k1_sha256_finalize(hash_ctx, &sha, output);
    nostr_native_secp256k1_sha256_clear(&sha);

    return 1;
}

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    return ecdh_hash_function_sha256_impl(nostr_native_secp256k1_get_hash_context(nostr_native_secp256k1_context_static), output, x32, y32, data);
}

const nostr_native_secp256k1_ecdh_hash_function nostr_native_secp256k1_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const nostr_native_secp256k1_ecdh_hash_function nostr_native_secp256k1_ecdh_hash_function_default = ecdh_hash_function_sha256;

int nostr_native_secp256k1_ecdh(const nostr_native_secp256k1_context* ctx, unsigned char *output, const nostr_native_secp256k1_pubkey *point, const unsigned char *scalar, nostr_native_secp256k1_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    nostr_native_secp256k1_gej res;
    nostr_native_secp256k1_ge pt;
    nostr_native_secp256k1_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    nostr_native_secp256k1_pubkey_load(ctx, &pt, point);
    nostr_native_secp256k1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= nostr_native_secp256k1_scalar_is_zero(&s);
    nostr_native_secp256k1_scalar_cmov(&s, &nostr_native_secp256k1_scalar_one, overflow);

    nostr_native_secp256k1_ecmult_const(&res, &pt, &s);
    nostr_native_secp256k1_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    nostr_native_secp256k1_fe_normalize(&pt.x);
    nostr_native_secp256k1_fe_normalize(&pt.y);
    nostr_native_secp256k1_fe_get_b32(x, &pt.x);
    nostr_native_secp256k1_fe_get_b32(y, &pt.y);

    if (hashfp == NULL || hashfp == nostr_native_secp256k1_ecdh_hash_function_sha256) {
        /* Use ctx-aware function by default */
        ret = ecdh_hash_function_sha256_impl(nostr_native_secp256k1_get_hash_context(ctx), output, x, y, data);
    } else {
        ret = hashfp(output, x, y, data);
    }

    nostr_native_secp256k1_memclear_explicit(x, sizeof(x));
    nostr_native_secp256k1_memclear_explicit(y, sizeof(y));
    nostr_native_secp256k1_scalar_clear(&s);
    nostr_native_secp256k1_ge_clear(&pt);
    nostr_native_secp256k1_gej_clear(&res);

    return !!ret & !overflow;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
