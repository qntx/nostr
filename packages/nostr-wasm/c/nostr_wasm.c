/*
 * wasm32 platform layer for the shared C core (ABI version 3 of `nostr_wasm.wasm`).
 *
 * Built freestanding (-nostdlib): the minimal libc surface below is all the vendored
 * libsecp256k1 and this file need. The crypto lives in nostr_core.c; this file owns the
 * context lifecycle (nostr_init), the growable scratch region (nostr_buffer), the
 * caller-region secret wipes, and the extern default callbacks.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "nostr_core.h"
#include "secp256k1_preallocated.h"

void *memcpy(void *d, const void *s, size_t n) { return __builtin_memcpy(d, s, n); }
void *memmove(void *d, const void *s, size_t n) { return __builtin_memmove(d, s, n); }
void *memset(void *d, int c, size_t n) { return __builtin_memset(d, c, n); }
int memcmp(const void *a, const void *b, size_t n) {
  const unsigned char *x = a, *y = b;
  for (size_t i = 0; i < n; i++) {
    if (x[i] != y[i]) return x[i] - y[i];
  }
  return 0;
}
void abort(void) { __builtin_trap(); }
void *malloc(size_t n) { (void)n; return NULL; }
void free(void *p) { (void)p; }

/* USE_EXTERNAL_DEFAULT_CALLBACKS: a library misuse or internal error traps the instance. */
void nostr_native_secp256k1_default_illegal_callback_fn(const char *m, void *d) {
  (void)m;
  (void)d;
  __builtin_trap();
}
void nostr_native_secp256k1_default_error_callback_fn(const char *m, void *d) {
  (void)m;
  (void)d;
  __builtin_trap();
}

#define NOSTR_STATUS_OK 0
#define NOSTR_STATUS_INVALID_INPUT 2
#define CTX_MEM_SIZE 1024

static _Alignas(16) unsigned char ctx_mem[CTX_MEM_SIZE];
static nostr_native_secp256k1_context *ctx;
static int initialized;

__attribute__((export_name("nostr_abi_version"))) int nostr_abi_version(void) { return 4; }

/* nostr_init(seed32): create the context once and (re)randomize it with the caller's 32 seed
 * bytes. The seed region is wiped on every path; a second call re-randomizes the same
 * context. Returns 0 on success, 2 on failure; ops return 2 until the first success. */
__attribute__((export_name("nostr_init"))) int nostr_init(unsigned char *seed) {
  int ok;
  if (seed == NULL) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  if (ctx == NULL) {
    if (nostr_native_secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) >
        CTX_MEM_SIZE) {
      nostr_core_wipe(seed, 32);
      return NOSTR_STATUS_INVALID_INPUT;
    }
    ctx = nostr_native_secp256k1_context_preallocated_create(ctx_mem, SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) {
      nostr_core_wipe(seed, 32);
      return NOSTR_STATUS_INVALID_INPUT;
    }
  }
  ok = nostr_native_secp256k1_context_randomize(ctx, seed);
  nostr_core_wipe(seed, 32);
  initialized = ok;
  return ok ? NOSTR_STATUS_OK : NOSTR_STATUS_INVALID_INPUT;
}

/* The scratch region starts at __heap_base (the byte after static data) and grows the
 * linear memory until it covers `len` bytes. Single-threaded wasm32 only: there is one
 * region per instance and each nostr_* call reads it before the next nostr_buffer. */
extern unsigned char __heap_base[];

__attribute__((export_name("nostr_buffer"))) unsigned char *nostr_buffer(size_t len) {
  uintptr_t base = (uintptr_t)__heap_base;
  uintptr_t need = base + len;
  size_t have = __builtin_wasm_memory_size(0) << 16;
  if (need > have) {
    size_t pages = (size_t)((need - have + 65535) >> 16);
    if (__builtin_wasm_memory_grow(0, pages) == (size_t)-1) {
      return NULL;
    }
  }
  return __heap_base;
}

__attribute__((export_name("nostr_verify"))) int nostr_verify(const unsigned char *id,
                                                             const unsigned char *pubkey,
                                                             const unsigned char *sig) {
  if (!initialized) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  return nostr_core_verify(ctx, id, pubkey, sig);
}

__attribute__((export_name("nostr_verify_serialized"))) int nostr_verify_serialized(
    const unsigned char *serialized, size_t len, const unsigned char *id,
    const unsigned char *pubkey, const unsigned char *sig) {
  if (!initialized) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  return nostr_core_verify_serialized(ctx, serialized, len, id, pubkey, sig);
}

/* Copies the caller's 32 secret bytes and zeroes the caller's region, so no path — valid
 * scalar or not — leaves secret material in shared memory. */
static int take_secret(unsigned char *seckey, unsigned char out[32]) {
  if (seckey == NULL) {
    return 0;
  }
  memcpy(out, seckey, 32);
  nostr_core_wipe(seckey, 32);
  return 1;
}

__attribute__((export_name("nostr_sign"))) int nostr_sign(const unsigned char *id,
                                                         unsigned char *seckey,
                                                         const unsigned char *aux,
                                                         unsigned char *out_sig) {
  unsigned char secret[32];
  int status;
  if (!initialized) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  if (!take_secret(seckey, secret)) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  status = nostr_core_sign(ctx, id, secret, aux, out_sig);
  nostr_core_wipe(secret, sizeof(secret));
  return status;
}

__attribute__((export_name("nostr_public_key"))) int nostr_public_key(unsigned char *seckey,
                                                                     unsigned char *out_pubkey) {
  unsigned char secret[32];
  int status;
  if (!initialized) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  if (!take_secret(seckey, secret)) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  status = nostr_core_public_key(ctx, secret, out_pubkey);
  nostr_core_wipe(secret, sizeof(secret));
  return status;
}

/* Same caller-region secret wipe as nostr_sign/nostr_public_key: the shared secret x lands
 * in the caller's out32 region. */
__attribute__((export_name("nostr_ecdh_x"))) int nostr_ecdh_x(unsigned char *seckey,
                                                             const unsigned char *pubkey_x,
                                                             unsigned char *out32) {
  unsigned char secret[32];
  int status;
  if (!initialized) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  if (!take_secret(seckey, secret)) {
    return NOSTR_STATUS_INVALID_INPUT;
  }
  status = nostr_core_ecdh_x(ctx, secret, pubkey_x, out32);
  nostr_core_wipe(secret, sizeof(secret));
  return status;
}
