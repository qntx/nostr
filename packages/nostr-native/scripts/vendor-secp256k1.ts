#!/usr/bin/env bun
/**
 * Vendor bitcoin-core/secp256k1 into `vendor/secp256k1`: download the release tarball, verify its
 * pinned SHA-256, and copy the subset needed to compile the verifier (headers, core sources, the
 * extrakeys and schnorrsig modules, precomputed tables). Tests, benches, table generators,
 * assembly, build files, and unused modules are dropped — upgrading the pinned version is a single
 * reviewed diff of this script's output.
 *
 * After copying, every `secp256k1_` identifier in the vendored sources is renamed to
 * `nostr_native_secp256k1_` (public API, internal objects like `secp256k1_context_static`, and the
 * precomputed tables alike): React Native pods are statically linked into one binary, so an
 * unprefixed copy collides with any other pod embedding libsecp256k1 — duplicate-symbol link
 * errors, or worse, silent binding to the other version when only one archive member is pulled.
 * Hidden visibility does not prevent that (hidden symbols still collide in a static link), so the
 * vendored copy must not export `secp256k1_*` at all. Same approach as rust-secp256k1's vendoring.
 * `#include` lines keep their spelling so file names (`secp256k1_extrakeys.h`, `secp256k1.c`, …)
 * stay resolvable; `SECP256K1_*` macro names are uppercase and untouched.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const VERSION = "0.8.0";
const TARBALL_URL = `https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v${VERSION}.tar.gz`;
const TARBALL_SHA256 = "eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb";

const packageDir = join(import.meta.dirname, "..");
const vendorDir = join(packageDir, "vendor", "secp256k1");

/** Src/ subdirectories not needed to build the verifier. */
const SRC_DIR_EXCLUDES = new Set([
  "asm",
  "wycheproof",
  "modules/ecdh",
  "modules/recovery",
  "modules/musig",
  "modules/ellswift",
  "modules/silentpayments",
]);

/** Src/ files not needed: unit/exhaustive/ctime tests, benches, table generators, build files. */
const SRC_FILE_EXCLUDES = new Set([
  "bench.c",
  "bench.h",
  "bench_ecmult.c",
  "bench_internal.c",
  "CMakeLists.txt",
  "ctime_tests.c",
  "precompute_ecmult.c",
  "precompute_ecmult_gen.c",
  "testrand.h",
  "testrand_impl.h",
  "tests.c",
  "tests_common.h",
  "tests_exhaustive.c",
  "testutil.h",
  "unit_test.c",
  "unit_test.h",
]);

/** Module-internal test/bench/build fragments (kept modules ship only `main_impl.h`). */
const MODULE_FILE_RE = /(?:tests_impl|tests_exhaustive_impl|bench_impl)\.h$|Makefile\.am\.include$/;

function copyFiltered(srcDir: string, destDir: string, rel: string): number {
  let copied = 0;
  for (const name of readdirSync(srcDir)) {
    const childRel = rel === "" ? name : `${rel}/${name}`;
    const childSrc = join(srcDir, name);
    if (statSync(childSrc).isDirectory()) {
      if (!SRC_DIR_EXCLUDES.has(childRel)) {
        copied += copyFiltered(childSrc, join(destDir, name), childRel);
      }
      continue;
    }
    if (SRC_FILE_EXCLUDES.has(name) || MODULE_FILE_RE.test(name)) {
      continue;
    }
    mkdirSync(destDir, { recursive: true });
    cpSync(childSrc, join(destDir, name));
    copied += 1;
  }
  return copied;
}

/**
 * Rename `secp256k1_` to `nostr_native_secp256k1_` in every vendored .c/.h (see the header
 * comment). Lines starting with `#include` are left alone so the unchanged file names keep
 * resolving.
 */
function namespaceSymbols(dir: string): number {
  let rewritten = 0;
  for (const name of readdirSync(dir)) {
    const child = join(dir, name);
    if (statSync(child).isDirectory()) {
      rewritten += namespaceSymbols(child);
      continue;
    }
    if (!/\.[ch]$/.test(name)) {
      continue;
    }
    const source = readFileSync(child, "utf8");
    const namespaced = source
      .split("\n")
      .map((line) =>
        line.trimStart().startsWith("#include")
          ? line
          : line.replaceAll("secp256k1_", "nostr_native_secp256k1_"),
      )
      .join("\n");
    if (namespaced !== source) {
      writeFileSync(child, namespaced);
      rewritten += 1;
    }
  }
  return rewritten;
}

async function main(): Promise<void> {
  const response = await fetch(TARBALL_URL);
  if (!response.ok) {
    throw new Error(`download failed: HTTP ${response.status} ${TARBALL_URL}`);
  }
  const tarball = Buffer.from(await response.arrayBuffer());
  const sha256 = createHash("sha256").update(tarball).digest("hex");
  if (sha256 !== TARBALL_SHA256) {
    throw new Error(
      `tarball sha256 mismatch: got ${sha256}, want ${TARBALL_SHA256} — aborting; review the upstream change before updating the pin`,
    );
  }

  const work = mkdtempSync(join(tmpdir(), "secp256k1-vendor-"));
  try {
    const tarballPath = join(work, "secp256k1.tar.gz");
    writeFileSync(tarballPath, tarball);
    execFileSync("tar", ["xzf", tarballPath, "-C", work]);
    const extracted = join(work, `secp256k1-${VERSION}`);

    rmSync(vendorDir, { recursive: true, force: true });
    mkdirSync(vendorDir, { recursive: true });
    cpSync(join(extracted, "COPYING"), join(vendorDir, "COPYING"));
    cpSync(join(extracted, "include"), join(vendorDir, "include"), {
      recursive: true,
    });
    const copied = copyFiltered(join(extracted, "src"), join(vendorDir, "src"), "");
    const namespaced = namespaceSymbols(vendorDir);

    writeFileSync(
      join(vendorDir, "vendored.json"),
      `${JSON.stringify(
        { name: "libsecp256k1", version: VERSION, license: "MIT", url: TARBALL_URL },
        null,
        2,
      )}\n`,
    );
    console.log(
      `vendored secp256k1 v${VERSION}: ${copied} src files + include/ + COPYING, ` +
        `${namespaced} files namespaced to nostr_native_secp256k1_* → ${vendorDir}`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

await main();
