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

function escapeRegExp(text: string): string {
  return text.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/**
 * Lockstep check: package.json `version` must equal `[workspace.package].version`, every internal
 * `crates/` path dependency must pin `=<version>`, and the version string may appear nowhere else
 * in Cargo.toml (bumpp rewrites every occurrence).
 */
export function checkVersion(pkg: unknown, cargoToml: unknown, cargoText: string): string[] {
  const errors: string[] = [];
  const { version: packageVersion } = asRecord(pkg);
  const workspace = asRecord(asRecord(cargoToml)["workspace"]);
  const { version: cargoVersion } = asRecord(workspace["package"]);

  if (typeof packageVersion !== "string") {
    errors.push('package.json: missing string "version"');
  }
  if (typeof cargoVersion !== "string") {
    errors.push("Cargo.toml: missing string [workspace.package].version");
  }
  if (
    typeof packageVersion === "string" &&
    typeof cargoVersion === "string" &&
    packageVersion !== cargoVersion
  ) {
    errors.push(
      `version mismatch: package.json has ${packageVersion}, Cargo.toml has ${cargoVersion}`,
    );
  }

  let internalDeps = 0;
  const dependencies = asRecord(workspace["dependencies"]);
  for (const [name, spec] of Object.entries(dependencies)) {
    const entry = asRecord(spec);
    const { path } = entry;
    if (typeof path !== "string" || !path.startsWith("crates/")) {
      continue;
    }
    internalDeps += 1;
    const expected = `=${typeof cargoVersion === "string" ? cargoVersion : ""}`;
    if (entry["version"] !== expected) {
      errors.push(
        `Cargo.toml: internal dependency "${name}" must use version "${expected}", got ${JSON.stringify(entry["version"])}`,
      );
    }
  }

  if (typeof cargoVersion === "string") {
    const occurrences =
      cargoText.match(new RegExp(`\\b${escapeRegExp(cargoVersion)}\\b`, "g"))?.length ?? 0;
    const expected = 1 + internalDeps;
    if (occurrences !== expected) {
      errors.push(
        `Cargo.toml: "${cargoVersion}" appears ${occurrences} times, expected ${expected} ([workspace.package] plus internal path dependencies)`,
      );
    }
  }

  return errors;
}

if (import.meta.main) {
  const pkg: unknown = JSON.parse(readFileSync("package.json", "utf8"));
  const cargoText = readFileSync("Cargo.toml", "utf8");
  const errors = checkVersion(pkg, Bun.TOML.parse(cargoText), cargoText);
  for (const error of errors) {
    console.error(`check-version: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
