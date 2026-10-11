#include <stdio.h>
#include <string.h>
#include <time.h>

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
    qntx_nostr_test_sha256(SHA256_CASES[i].data, SHA256_CASES[i].len, out);
    check(memcmp(out, SHA256_CASES[i].expected, 32), 0, SHA256_CASES[i].name);
  }

  for (i = 0; i < sizeof(SCHNORR_CASES) / sizeof(SCHNORR_CASES[0]); i++) {
    check(qntx_nostr_test_schnorr_verify(SCHNORR_CASES[i].msg, SCHNORR_CASES[i].msglen,
                                    SCHNORR_CASES[i].pubkey, SCHNORR_CASES[i].sig),
          SCHNORR_CASES[i].expected, SCHNORR_CASES[i].name);
  }

  for (i = 0; i < sizeof(EVENT_CASES) / sizeof(EVENT_CASES[0]); i++) {
    check(qntx_nostr_verify_serialized(EVENT_CASES[i].serialized, EVENT_CASES[i].len,
                                        EVENT_CASES[i].id, EVENT_CASES[i].pubkey,
                                        EVENT_CASES[i].sig),
          EVENT_CASES[i].expected, EVENT_CASES[i].name);
  }

  /* Sign: C must reproduce the expected signature and x-only public key byte-for-byte. */
  for (i = 0; i < sizeof(SIGN_CASES) / sizeof(SIGN_CASES[0]); i++) {
    check(qntx_nostr_sign(SIGN_CASES[i].msg, SIGN_CASES[i].seckey, SIGN_CASES[i].aux,
                           sig),
          1, SIGN_CASES[i].name);
    check(memcmp(sig, SIGN_CASES[i].sig, 64), 0, SIGN_CASES[i].name);
    check(qntx_nostr_public_key(SIGN_CASES[i].seckey, out), 1, SIGN_CASES[i].name);
    check(memcmp(out, SIGN_CASES[i].pubkey, 32), 0, SIGN_CASES[i].name);
  }

  /* Invalid secret keys (zero, n, n+1, all-0xff) must fail both entry points. */
  for (i = 0; i < sizeof(BAD_SECKEYS) / sizeof(BAD_SECKEYS[0]); i++) {
    check(qntx_nostr_public_key(BAD_SECKEYS[i].seckey, out), 0, BAD_SECKEYS[i].name);
    check(qntx_nostr_sign(EVENT_CASES[0].id, BAD_SECKEYS[i].seckey,
                           SIGN_CASES[0].aux, sig),
          0, BAD_SECKEYS[i].name);
  }

  /* Robustness: NULL inputs must return 0, never crash. */
  check(qntx_nostr_verify_serialized(NULL, 0, NULL, NULL, NULL), 0, "null-args");
  check(qntx_nostr_verify_serialized(EVENT_CASES[0].serialized, EVENT_CASES[0].len,
                                      NULL, EVENT_CASES[0].pubkey, EVENT_CASES[0].sig),
        0, "null-id");
  check(qntx_nostr_public_key(NULL, out), 0, "null-seckey-pk");
  check(qntx_nostr_sign(NULL, NULL, NULL, sig), 0, "null-sign");

  /* Informational throughput: ~2s of verifies of one valid event. */
  {
    const event_case *v = &EVENT_CASES[0];
    double start = monotonic_seconds();
    double elapsed;
    unsigned long iterations = 0;
    do {
      int j;
      for (j = 0; j < 100; j++) {
        qntx_nostr_verify_serialized(v->serialized, v->len, v->id, v->pubkey, v->sig);
      }
      iterations += 100;
      elapsed = monotonic_seconds() - start;
    } while (elapsed < 2.0);
    printf("host throughput: %.0f verifies/s\n", (double)iterations / elapsed);
  }

  printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
