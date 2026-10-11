#ifndef SECP256K1_INT128_STRUCT_H
#define SECP256K1_INT128_STRUCT_H

#include <stdint.h>
#include "util.h"

typedef struct {
  uint64_t lo;
  uint64_t hi;
} nostr_native_secp256k1_uint128;

typedef nostr_native_secp256k1_uint128 nostr_native_secp256k1_int128;

#endif
