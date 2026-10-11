#ifndef NOSTR_WASM_STDLIB_STDLIB_H
#define NOSTR_WASM_STDLIB_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void free(void *);
void abort(void);
#endif
