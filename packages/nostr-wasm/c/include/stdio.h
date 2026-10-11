#ifndef NOSTR_WASM_STDLIB_STDIO_H
#define NOSTR_WASM_STDLIB_STDIO_H
typedef struct FILE FILE;
extern FILE *stderr;
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
#endif
