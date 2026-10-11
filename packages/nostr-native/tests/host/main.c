#include <stdio.h>
#include <string.h>
#include <time.h>

#include "nostr_core.h"
#include "nostr_native.h"

typedef struct {
  const unsigned char *data;
  size_t len;
  unsigned char expected[32];
  const char *name;
} sha_case;

typedef struct {
  const unsigned char *msg;
  size_t msglen;
  unsigned char pubkey[32];
  unsigned char sig[64];
  int expected;
  const char *name;
} schnorr_case;

typedef struct {
  const unsigned char *serialized;
  size_t len;
  unsigned char id[32];
  unsigned char pubkey[32];
  unsigned char sig[64];
  int expected;
  const char *name;
} event_case;

typedef struct {
  unsigned char seckey[32];
  unsigned char aux[32];
  unsigned char msg[32];
  unsigned char sig[64];
  unsigned char pubkey[32];
  const char *name;
} sign_case;

typedef struct {
  unsigned char seckey[32];
  const char *name;
} bad_seckey_case;

#include "vectors.generated.h"

static int checks = 0;
static int failures = 0;

static void check(int got, int want, const char *name) {
  checks += 1;
  if (got != want) {
    failures += 1;
    printf("FAIL %-40s got %d want %d\n", name, got, want);
  }
}

static double monotonic_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(void) {
  size_t i;
  unsigned char out[32];
  unsigned char sig[64];

  for (i = 0; i < sizeof(SHA256_CASES) / sizeof(SHA256_CASES[0]); i++) {
    nostr_native_test_sha256(SHA256_CASES[i].data, SHA256_CASES[i].len, out);
    check(memcmp(out, SHA256_CASES[i].expected, 32), 0, SHA256_CASES[i].name);
  }

  for (i = 0; i < sizeof(SCHNORR_CASES) / sizeof(SCHNORR_CASES[0]); i++) {
    check(nostr_native_test_schnorr_verify(SCHNORR_CASES[i].msg, SCHNORR_CASES[i].msglen,
                                    SCHNORR_CASES[i].pubkey, SCHNORR_CASES[i].sig),
          SCHNORR_CASES[i].expected, SCHNORR_CASES[i].name);
  }

  for (i = 0; i < sizeof(EVENT_CASES) / sizeof(EVENT_CASES[0]); i++) {
    check(nostr_native_verify_serialized(EVENT_CASES[i].serialized, EVENT_CASES[i].len,
                                        EVENT_CASES[i].id, EVENT_CASES[i].pubkey,
                                        EVENT_CASES[i].sig),
          EVENT_CASES[i].expected, EVENT_CASES[i].name);
  }

  /* Sign: C must reproduce the expected signature and x-only public key byte-for-byte. */
  for (i = 0; i < sizeof(SIGN_CASES) / sizeof(SIGN_CASES[0]); i++) {
    check(nostr_native_sign(SIGN_CASES[i].msg, SIGN_CASES[i].seckey, SIGN_CASES[i].aux,
                           sig),
          1, SIGN_CASES[i].name);
    check(memcmp(sig, SIGN_CASES[i].sig, 64), 0, SIGN_CASES[i].name);
    check(nostr_native_public_key(SIGN_CASES[i].seckey, out), 1, SIGN_CASES[i].name);
    check(memcmp(out, SIGN_CASES[i].pubkey, 32), 0, SIGN_CASES[i].name);
  }

  /* Invalid secret keys (zero, n, n+1, all-0xff) must fail both entry points. */
  for (i = 0; i < sizeof(BAD_SECKEYS) / sizeof(BAD_SECKEYS[0]); i++) {
    check(nostr_native_public_key(BAD_SECKEYS[i].seckey, out), 0, BAD_SECKEYS[i].name);
    check(nostr_native_sign(EVENT_CASES[0].id, BAD_SECKEYS[i].seckey,
                           SIGN_CASES[0].aux, sig),
          0, BAD_SECKEYS[i].name);
  }

  /* Robustness: NULL inputs must return 0, never crash. */
  check(nostr_native_verify_serialized(NULL, 0, NULL, NULL, NULL), 0, "null-args");
  check(nostr_native_verify_serialized(EVENT_CASES[0].serialized, EVENT_CASES[0].len,
                                      NULL, EVENT_CASES[0].pubkey, EVENT_CASES[0].sig),
        0, "null-id");
  check(nostr_native_public_key(NULL, out), 0, "null-seckey-pk");
  check(nostr_native_sign(NULL, NULL, NULL, sig), 0, "null-sign");

  /* nostr_core status codes: 0 ok, 1 verification failed, 2 invalid input. */
  {
    nostr_native_secp256k1_context *ctx = nostr_native_test_context();
    const event_case *v = &EVENT_CASES[0];
    unsigned char bad_pubkey[32];
    unsigned char bad_sig[64];
    unsigned char bad_id[32];
    memcpy(bad_pubkey, v->pubkey, 32);
    memcpy(bad_sig, v->sig, 64);
    memcpy(bad_id, v->id, 32);
    /* 0: a valid event verifies through the core entry point. */
    check(nostr_core_verify_serialized(ctx, v->serialized, v->len, v->id, v->pubkey,
                                       v->sig),
          NOSTR_CORE_OK, "core-verify-ok");
    /* 1: a claimed id that does not match sha256(serialized) fails the id check. */
    bad_id[0] = (unsigned char)(bad_id[0] + 1);
    check(nostr_core_verify_serialized(ctx, v->serialized, v->len, bad_id, v->pubkey,
                                       v->sig),
          NOSTR_CORE_VERIFY_FAILED, "core-id-mismatch");
    /* 1: a valid point with a bad signature. */
    bad_sig[7] = (unsigned char)(bad_sig[7] + 1);
    check(nostr_core_verify(ctx, v->id, v->pubkey, bad_sig), NOSTR_CORE_VERIFY_FAILED,
          "core-bad-sig");
    /* 2: x >= field order is not an x-only point. */
    memset(bad_pubkey, 0xff, 32);
    check(nostr_core_verify(ctx, v->id, bad_pubkey, v->sig), NOSTR_CORE_INVALID_INPUT,
          "core-invalid-point");
    /* 2: invalid secret keys for both secret-key entry points. */
    check(nostr_core_sign(ctx, v->id, BAD_SECKEYS[0].seckey, SIGN_CASES[0].aux, sig),
          NOSTR_CORE_INVALID_INPUT, "core-sign-bad-seckey");
    check(nostr_core_public_key(ctx, BAD_SECKEYS[0].seckey, out), NOSTR_CORE_INVALID_INPUT,
          "core-pubkey-bad-seckey");
    /* 2: NULL arguments on every entry point. */
    check(nostr_core_verify(ctx, NULL, v->pubkey, v->sig), NOSTR_CORE_INVALID_INPUT,
          "core-null-verify");
    check(nostr_core_verify_serialized(ctx, NULL, 0, v->id, v->pubkey, v->sig),
          NOSTR_CORE_INVALID_INPUT, "core-null-serialized");
    check(nostr_core_verify_serialized(NULL, v->serialized, v->len, v->id, v->pubkey,
                                       v->sig),
          NOSTR_CORE_INVALID_INPUT, "core-null-ctx");
    check(nostr_core_sign(ctx, NULL, SIGN_CASES[0].seckey, SIGN_CASES[0].aux, sig),
          NOSTR_CORE_INVALID_INPUT, "core-null-sign");
    check(nostr_core_public_key(ctx, NULL, out), NOSTR_CORE_INVALID_INPUT,
          "core-null-pubkey");
  }

  /* Informational throughput: ~2s of verifies of one valid event. */
  {
    const event_case *v = &EVENT_CASES[0];
    double start = monotonic_seconds();
    double elapsed;
    unsigned long iterations = 0;
    do {
      int j;
      for (j = 0; j < 100; j++) {
        nostr_native_verify_serialized(v->serialized, v->len, v->id, v->pubkey, v->sig);
      }
      iterations += 100;
      elapsed = monotonic_seconds() - start;
    } while (elapsed < 2.0);
    printf("host throughput: %.0f verifies/s\n", (double)iterations / elapsed);
  }

  printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
