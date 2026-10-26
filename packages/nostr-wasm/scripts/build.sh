#!/usr/bin/env bash
set -euo pipefail

# Builds nostr_wasm.wasm from the shared libsecp256k1 C core in packages/nostr-native/cpp
# (nostr_core.c + nostr_wasm.c + the two precomputed-table TUs), clang + wasm-ld only,
# then wasm-opt. The artifact lands in this package's src/.
pkg="$(cd "$(dirname "$0")/.." && pwd)"
native="$(cd "${pkg}/../nostr-native" && pwd)"
cd "$pkg"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
# binaryen (devDependency) provides wasm-opt on PATH inside bun/npm scripts.
need wasm-opt

wasm_cc_hint() {
  echo "set CC_wasm32_unknown_unknown to a wasm-capable clang" >&2
  echo "  macOS: brew install llvm && CC_wasm32_unknown_unknown=\$(brew --prefix llvm)/bin/clang" >&2
  echo "  CI:    CC_wasm32_unknown_unknown=clang" >&2
}

cc_wasm="${CC_wasm32_unknown_unknown:-clang}"
cc_ver="$("${cc_wasm}" --version 2>/dev/null | head -n 1 || true)"
if echo "${cc_ver}" | grep -q "Apple clang"; then
  echo "CC_wasm32_unknown_unknown is Apple clang (no wasm backend): ${cc_wasm}" >&2
  wasm_cc_hint
  exit 1
fi
if ! "${cc_wasm}" --print-targets 2>/dev/null | grep -q wasm32; then
  echo "CC_wasm32_unknown_unknown does not list wasm32 in --print-targets: ${cc_wasm}" >&2
  echo "${cc_ver}" >&2
  wasm_cc_hint
  exit 1
fi
if ! "${cc_wasm}" --target=wasm32-unknown-unknown -nostdlib -Wl,--version \
      -x c /dev/null -o /dev/null 2>/dev/null | grep -qi "lld"; then
  echo "wasm-ld is not reachable from ${cc_wasm}" >&2
  wasm_cc_hint
  exit 1
fi

out="${pkg}/src/nostr_wasm.wasm"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# The stub libc headers in c/include come first; nostr_core.h picks up the vendored
# secp256k1 headers relative to its own directory. nostr_core.c is the single TU that
# includes vendor/secp256k1/src/secp256k1.c — the precomputed tables are separate TUs.
"${cc_wasm}" \
  --target=wasm32-unknown-unknown \
  -O3 -flto -nostdlib -mbulk-memory \
  -I"${pkg}/c/include" \
  -I"${native}/cpp" \
  -I"${native}/vendor/secp256k1/include" \
  -DENABLE_MODULE_ECDH=1 \
  -DENABLE_MODULE_EXTRAKEYS=1 \
  -DENABLE_MODULE_SCHNORRSIG=1 \
  -DUSE_FORCE_WIDEMUL_INT64=1 \
  -DECMULT_WINDOW_SIZE=4 \
  -DCOMB_BLOCKS=2 \
  -DCOMB_TEETH=5 \
  -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 \
  -Wno-unused-function \
  -Wl,--no-entry -Wl,--gc-sections -Wl,--strip-all -Wl,-z,stack-size=65536 \
  -Wl,--export-memory \
  "${native}/cpp/nostr_core.c" \
  "${pkg}/c/nostr_wasm.c" \
  "${native}/vendor/secp256k1/src/precomputed_ecmult.c" \
  "${native}/vendor/secp256k1/src/precomputed_ecmult_gen.c" \
  -o "${tmp}/nostr_wasm.wasm"

wasm-opt -O3 --all-features "${tmp}/nostr_wasm.wasm" -o "${out}"

# Size budget: gzip size must stay under the N19 acceleration budget.
WASM_GZIP_BUDGET=51200
gz_size="$(gzip -cn "${out}" | wc -c | tr -d ' ')"
if [[ "${gz_size}" -gt "${WASM_GZIP_BUDGET}" ]]; then
  echo "wasm gzip size ${gz_size} exceeds the ${WASM_GZIP_BUDGET} byte budget" >&2
  exit 1
fi
br_size=""
if command -v brotli >/dev/null; then
  br_size="$(brotli -cq 11 "${out}" | wc -c | tr -d ' ')"
fi
echo "nostr_wasm.wasm: $(wc -c <"${out}" | tr -d ' ') B raw, ${gz_size} B gzip${br_size:+, ${br_size} B brotli}"
