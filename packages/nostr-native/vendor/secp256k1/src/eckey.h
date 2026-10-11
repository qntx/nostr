/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_H
#define SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int nostr_native_secp256k1_eckey_pubkey_parse(nostr_native_secp256k1_ge *elem, const unsigned char *pub, size_t size);
/** Serialize a group element (that is not allowed to be infinity) to a compressed public key (33 bytes). */
static void nostr_native_secp256k1_eckey_pubkey_serialize33(nostr_native_secp256k1_ge *elem, unsigned char *pub33);
/** Serialize a group element (that is not allowed to be infinity) to an uncompressed public key (65 bytes). */
static void nostr_native_secp256k1_eckey_pubkey_serialize65(nostr_native_secp256k1_ge *elem, unsigned char *pub65);

static int nostr_native_secp256k1_eckey_privkey_tweak_add(nostr_native_secp256k1_scalar *key, const nostr_native_secp256k1_scalar *tweak);
static int nostr_native_secp256k1_eckey_pubkey_tweak_add(nostr_native_secp256k1_ge *key, const nostr_native_secp256k1_scalar *tweak);
static int nostr_native_secp256k1_eckey_privkey_tweak_mul(nostr_native_secp256k1_scalar *key, const nostr_native_secp256k1_scalar *tweak);
static int nostr_native_secp256k1_eckey_pubkey_tweak_mul(nostr_native_secp256k1_ge *key, const nostr_native_secp256k1_scalar *tweak);

#endif /* SECP256K1_ECKEY_H */
