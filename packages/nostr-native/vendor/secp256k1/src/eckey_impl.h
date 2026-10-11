/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_IMPL_H
#define SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "util.h"
#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int nostr_native_secp256k1_eckey_pubkey_parse(nostr_native_secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        nostr_native_secp256k1_fe x;
        return nostr_native_secp256k1_fe_set_b32_limit(&x, pub+1) && nostr_native_secp256k1_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
        nostr_native_secp256k1_fe x, y;
        if (!nostr_native_secp256k1_fe_set_b32_limit(&x, pub+1) || !nostr_native_secp256k1_fe_set_b32_limit(&y, pub+33)) {
            return 0;
        }
        nostr_native_secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            nostr_native_secp256k1_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return nostr_native_secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static void nostr_native_secp256k1_eckey_pubkey_serialize33(nostr_native_secp256k1_ge *elem, unsigned char *pub33) {
    VERIFY_CHECK(!nostr_native_secp256k1_ge_is_infinity(elem));

    nostr_native_secp256k1_fe_normalize_var(&elem->x);
    nostr_native_secp256k1_fe_normalize_var(&elem->y);
    pub33[0] = nostr_native_secp256k1_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    nostr_native_secp256k1_fe_get_b32(&pub33[1], &elem->x);
}

static void nostr_native_secp256k1_eckey_pubkey_serialize65(nostr_native_secp256k1_ge *elem, unsigned char *pub65) {
    VERIFY_CHECK(!nostr_native_secp256k1_ge_is_infinity(elem));

    nostr_native_secp256k1_fe_normalize_var(&elem->x);
    nostr_native_secp256k1_fe_normalize_var(&elem->y);
    pub65[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    nostr_native_secp256k1_fe_get_b32(&pub65[1], &elem->x);
    nostr_native_secp256k1_fe_get_b32(&pub65[33], &elem->y);
}

static int nostr_native_secp256k1_eckey_privkey_tweak_add(nostr_native_secp256k1_scalar *key, const nostr_native_secp256k1_scalar *tweak) {
    nostr_native_secp256k1_scalar_add(key, key, tweak);
    return !nostr_native_secp256k1_scalar_is_zero(key);
}

static int nostr_native_secp256k1_eckey_pubkey_tweak_add(nostr_native_secp256k1_ge *key, const nostr_native_secp256k1_scalar *tweak) {
    nostr_native_secp256k1_gej pt;
    nostr_native_secp256k1_gej_set_ge(&pt, key);
    nostr_native_secp256k1_ecmult(&pt, &pt, &nostr_native_secp256k1_scalar_one, tweak);

    if (nostr_native_secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    nostr_native_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int nostr_native_secp256k1_eckey_privkey_tweak_mul(nostr_native_secp256k1_scalar *key, const nostr_native_secp256k1_scalar *tweak) {
    int ret;
    ret = !nostr_native_secp256k1_scalar_is_zero(tweak);

    nostr_native_secp256k1_scalar_mul(key, key, tweak);
    return ret;
}

static int nostr_native_secp256k1_eckey_pubkey_tweak_mul(nostr_native_secp256k1_ge *key, const nostr_native_secp256k1_scalar *tweak) {
    nostr_native_secp256k1_gej pt;
    if (nostr_native_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    nostr_native_secp256k1_gej_set_ge(&pt, key);
    nostr_native_secp256k1_ecmult(&pt, &pt, tweak, NULL);
    nostr_native_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

#endif /* SECP256K1_ECKEY_IMPL_H */
