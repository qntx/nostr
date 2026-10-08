#!/usr/bin/env bash
set -euo pipefail

# Cargo workspace lives at the repo root; the artifact lands in this package's src/.
pkg="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "${pkg}/../.." && pwd)"
cd "$root"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
need rustc
need cargo
# binaryen (devDependency) provides wasm-opt on PATH inside bun/npm scripts.
need wasm-opt

if ! rustup target list --installed | grep -qx "wasm32-unknown-unknown"; then
  echo "rustup target wasm32-unknown-unknown is not installed" >&2
  exit 1
fi

wasm_cc_hint() {
  echo "set CC_wasm32_unknown_unknown to a wasm-capable clang" >&2
  echo "  macOS: brew install llvm && CC_wasm32_unknown_unknown=\$(brew --prefix llvm)/bin/clang" >&2
  echo "  CI:    CC_wasm32_unknown_unknown=clang" >&2
}

# secp256k1-sys: clang must accept --target=wasm32-unknown-unknown (not Apple clang).
if [[ -z "${CC_wasm32_unknown_unknown:-}" ]]; then
  wasm_cc_hint
  exit 1
fi

cc_wasm="${CC_wasm32_unknown_unknown}"
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

export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-llvm-ar}"
export CFLAGS_wasm32_unknown_unknown="${CFLAGS_wasm32_unknown_unknown:---target=wasm32-unknown-unknown -Wno-implicit-function-declaration}"

cargo build --target wasm32-unknown-unknown --release -p nk-wasm

wasm="${root}/target/wasm32-unknown-unknown/release/nk_wasm.wasm"
test -f "${wasm}" || { echo "cargo did not emit ${wasm}" >&2; exit 1; }
# rustc emits SIMD, bulk-memory and friends; allow every feature the module uses.
wasm-opt -Oz --all-features "${wasm}" -o "${wasm}"

# Size budget: measured gzip size rounded up to the next 50 KiB. Bump only after
# re-measuring a legitimate growth (N19).
WASM_GZIP_BUDGET=102400
gz_size="$(gzip -cn "${wasm}" | wc -c | tr -d ' ')"
if [[ "${gz_size}" -gt "${WASM_GZIP_BUDGET}" ]]; then
  echo "wasm gzip size ${gz_size} exceeds the ${WASM_GZIP_BUDGET} byte budget" >&2
  exit 1
fi
cp "${wasm}" "${pkg}/src/nk_wasm.wasm"
