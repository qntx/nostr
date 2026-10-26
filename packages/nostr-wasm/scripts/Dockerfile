# Pinned hermetic builder for the committed nostr_wasm.wasm artifact. LLVM's
# wasm32 codegen depends on the compiler host, so the image digest pins the
# linux/amd64 toolchain and the wrapper always runs it with
# --platform linux/amd64 — CI and developer machines produce byte-identical
# output. Same pinned base as @qntx/spark-wasm so both share one apt archive
# snapshot (and thus one clang/lld version).
FROM rust:1.99.1-slim@sha256:0e1f408a769c6b272da09db934849233beafe1f7cbdff76055cd5bfc2d82a052

ARG BINARYEN_VERSION=132
ARG BINARYEN_SHA256=195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates clang curl lld openssl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/binaryen.tar.gz \
    "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-x86_64-linux.tar.gz" \
 && echo "${BINARYEN_SHA256}  /tmp/binaryen.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/binaryen.tar.gz -C /opt \
 && ln -s "/opt/binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt \
 && rm /tmp/binaryen.tar.gz

WORKDIR /src
