#!/usr/bin/env bun
/**
 * Vendor bitcoin-core/secp256k1 into `vendor/secp256k1`: download the release tarball, verify its
 * pinned SHA-256, and copy the subset needed to compile the verifier (headers, core sources, the
 * extrakeys and schnorrsig modules, precomputed tables). Tests, benches, table generators,
 * assembly, build files, and unused modules are dropped — upgrading the pinned version is a single
 * reviewed diff of this script's output.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
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

    writeFileSync(
      join(vendorDir, "vendored.json"),
      `${JSON.stringify(
        { name: "libsecp256k1", version: VERSION, license: "MIT", url: TARBALL_URL },
        null,
        2,
      )}\n`,
    );
    console.log(
      `vendored secp256k1 v${VERSION}: ${copied} src files + include/ + COPYING → ${vendorDir}`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

await main();
