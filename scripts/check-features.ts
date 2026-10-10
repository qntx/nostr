/// <reference types="node" />
import { readFileSync } from "node:fs";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

type JsonObject = Record<string, unknown>;

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

/** Features that are infrastructure, not NIP modules. */
const INFRA_FEATURES = new Set(["default", "std", "clock", "os-rng"]);

export type FeatureInputs = {
  /** Raw text of `.github/workflows/ci.yml`. */
  ci: string;
  /** Parsed `crates/nk-vectors/Cargo.toml`. */
  vectorsToml: unknown;
  /** Raw text of `crates/nk/README.md`. */
  readme: string;
  /** Raw text of `crates/nk/src/lib.rs`. */
  libRs: string;
};

/**
 * Feature-drift check: the sorted list F of NIP features in `crates/nk`'s `[features]` (everything
 * except `default`/`std`/`clock`/`os-rng`) is the single source of truth and must be reproduced
 * exactly by the portable CI job feature lists, the `nk-vectors` dependency, the README feature
 * table, and the crate-level doc table in `lib.rs`.
 */
export function checkFeatures(nkToml: unknown, inputs: FeatureInputs): string[] {
  const errors: string[] = [];
  const featureKeys = Object.keys(asRecord(asRecord(nkToml)["features"]));
  const allFeatures = new Set(featureKeys);
  const nipFeatures = featureKeys.filter((f) => !INFRA_FEATURES.has(f)).toSorted();

  // --- .github/workflows/ci.yml -------------------------------------------
  // No YAML parser is in the toolchain; the `with.features` line is extracted
  // from the job block located by its two-space `  <name>:` key.
  checkCiJob(
    errors,
    inputs.ci,
    "portable-nips",
    `--no-default-features --features ${nipFeatures.join(",")}`,
    nipFeatures,
  );
  checkCiJob(
    errors,
    inputs.ci,
    "portable-std-nips",
    `--features std,clock,os-rng,${nipFeatures.join(",")}`,
    nipFeatures,
  );

  // --- crates/nk-vectors/Cargo.toml -----------------------------------------
  const vectorsToml = asRecord(inputs.vectorsToml);
  const nkDep =
    asRecord(asRecord(vectorsToml["dev-dependencies"])["nk"])["features"] ??
    asRecord(asRecord(vectorsToml["dependencies"])["nk"])["features"];
  if (nkDep === undefined) {
    errors.push("crates/nk-vectors/Cargo.toml: nk dependency has no features list");
  } else {
    const actual = Array.isArray(nkDep) ? nkDep.map(String) : [];
    const missing = nipFeatures.filter((f) => !actual.includes(f));
    const extra = actual.filter((f) => !nipFeatures.includes(f));
    if (missing.length > 0 || extra.length > 0) {
      errors.push(
        `crates/nk-vectors/Cargo.toml: nk features drift —${describeDrift(
          missing,
          extra,
        )} expected [${nipFeatures.map((f) => `"${f}"`).join(", ")}]`,
      );
    }
  }

  // --- Feature tables --------------------------------------------------------
  checkTable(
    errors,
    "crates/nk/README.md",
    inputs.readme,
    /^\|\s*`([A-Za-z0-9_-]+)`\s*\|/gm,
    nipFeatures,
    allFeatures,
  );
  checkTable(
    errors,
    "crates/nk/src/lib.rs",
    inputs.libRs,
    /^\/\/!\s*\|\s*`([A-Za-z0-9_-]+)`\s*\|/gm,
    nipFeatures,
    allFeatures,
  );

  return errors;
}

function describeDrift(missing: string[], extra: string[]): string {
  const parts: string[] = [];
  if (missing.length > 0) {
    parts.push(`missing ${missing.map((f) => `"${f}"`).join(", ")}`);
  }
  if (extra.length > 0) {
    parts.push(`extra ${extra.map((f) => `"${f}"`).join(", ")}`);
  }
  return ` ${parts.join("; ")};`;
}

/** Extract the indented block of a two-space ` <name>:` job key in a workflow file. */
function jobBlock(yaml: string, job: string): string | undefined {
  const start = yaml.search(new RegExp(`^  ${job}:\\s*$`, "m"));
  if (start === -1) {
    return undefined;
  }
  const lines = yaml.slice(start).split("\n").slice(1);
  const block: string[] = [];
  for (const line of lines) {
    if (line.trim() !== "" && !line.startsWith("    ")) {
      break;
    }
    block.push(line);
  }
  return block.join("\n");
}

function checkCiJob(
  errors: string[],
  ci: string,
  job: string,
  expected: string,
  nipFeatures: string[],
): void {
  const block = jobBlock(ci, job);
  if (block === undefined) {
    errors.push(`.github/workflows/ci.yml: job "${job}" not found`);
    return;
  }
  const match = /^\s+features:\s*(\S[^\n]*?)\s*$/m.exec(block);
  const actual = match?.[1];
  if (actual === undefined) {
    errors.push(`.github/workflows/ci.yml: job "${job}" has no "features:" line`);
    return;
  }
  if (actual === expected) {
    return;
  }
  // Name the drift precisely: the feature set after `--features`.
  const csvMatch = /--features\s+([^\s]+)/.exec(actual);
  const actualList = csvMatch?.[1]?.split(",").filter((f) => !INFRA_FEATURES.has(f)) ?? [];
  const missing = nipFeatures.filter((f) => !actualList.includes(f));
  const extra = actualList.filter((f) => !nipFeatures.includes(f));
  errors.push(
    `.github/workflows/ci.yml: job "${job}" features is "${actual}", expected "${expected}"${describeDrift(
      missing,
      extra,
    )}`,
  );
}

/** A feature table must carry exactly one row per NIP feature and no row for a non-feature. */
function checkTable(
  errors: string[],
  file: string,
  text: string,
  rowRe: RegExp,
  nipFeatures: string[],
  allFeatures: Set<string>,
): void {
  const counts = new Map<string, number>();
  for (const match of text.matchAll(rowRe)) {
    const [, name] = match;
    if (name !== undefined) {
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
  }
  const missing = nipFeatures.filter((f) => !counts.has(f));
  if (missing.length > 0) {
    errors.push(
      `${file}: feature table missing row(s) for ${missing.map((f) => `\`${f}\``).join(", ")}`,
    );
  }
  const duplicated = [...counts.entries()].filter(([f, n]) => allFeatures.has(f) && n > 1);
  if (duplicated.length > 0) {
    errors.push(
      `${file}: feature table has duplicate row(s) for ${duplicated
        .map(([f]) => `\`${f}\``)
        .join(", ")}`,
    );
  }
  const unknown = [...counts.keys()].filter((f) => !allFeatures.has(f));
  if (unknown.length > 0) {
    errors.push(
      `${file}: feature table has row(s) for ${unknown
        .map((f) => `\`${f}\``)
        .join(", ")}, which are not nk [features] keys`,
    );
  }
}

if (import.meta.main) {
  const errors = checkFeatures(Bun.TOML.parse(readFileSync("crates/nk/Cargo.toml", "utf8")), {
    ci: readFileSync(".github/workflows/ci.yml", "utf8"),
    vectorsToml: Bun.TOML.parse(readFileSync("crates/nk-vectors/Cargo.toml", "utf8")),
    readme: readFileSync("crates/nk/README.md", "utf8"),
    libRs: readFileSync("crates/nk/src/lib.rs", "utf8"),
  });
  for (const error of errors) {
    console.error(`check-features: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
