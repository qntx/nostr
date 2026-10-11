/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_H
#define SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int nostr_native_secp256k1_ecdsa_sig_parse(nostr_native_secp256k1_scalar *r, nostr_native_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int nostr_native_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const nostr_native_secp256k1_scalar *r, const nostr_native_secp256k1_scalar *s);
static int nostr_native_secp256k1_ecdsa_sig_verify(const nostr_native_secp256k1_scalar* r, const nostr_native_secp256k1_scalar* s, const nostr_native_secp256k1_ge *pubkey, const nostr_native_secp256k1_scalar *message);
static int nostr_native_secp256k1_ecdsa_sig_sign(const nostr_native_secp256k1_ecmult_gen_context *ctx, nostr_native_secp256k1_scalar* r, nostr_native_secp256k1_scalar* s, const nostr_native_secp256k1_scalar *seckey, const nostr_native_secp256k1_scalar *message, const nostr_native_secp256k1_scalar *nonce, int *recid);

#endif /* SECP256K1_ECDSA_H */
