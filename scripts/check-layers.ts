/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

export type CrateInfo = {
  name: string;
  publish: boolean;
  deps: string[];
};

type JsonObject = Record<string, unknown>;

const P_LEVEL = new Set(["nk", "nk-database", "nk-sqlite", "nk-gossip", "nk-wasm", "nk-ffi"]);

const RUNTIME_BANNED = new Set(["tokio", "reqwest", "tokio-tungstenite"]);
const SQLITE = "rusqlite";
const SQLITE_OWNER = "nk-sqlite";

const ALL = "*";
// The crate graph of docs/nk/redesign.mdx: `nk` is the leaf protocol crate,
// everything above depends on it directly or transitively.
const ALLOWED: Record<string, string[]> = {
  nk: [],
  "nk-database": ["nk"],
  "nk-sqlite": ["nk", "nk-database"],
  "nk-gossip": ["nk"],
  "nk-sdk": ["nk", "nk-database", "nk-gossip"],
  "nk-connect": ["nk", "nk-sdk"],
  "nk-blossom": ["nk"],
  "nk-wasm": ["nk"],
  "nk-vectors": [ALL],
  "nk-ffi": ["nk", "nk-sdk"],
};

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function depNames(section: unknown): string[] {
  const names: string[] = [];
  for (const [key, spec] of Object.entries(asRecord(section))) {
    const renamed = asRecord(spec)["package"];
    names.push(typeof renamed === "string" ? renamed : key);
  }
  return names;
}

/**
 * Builds a CrateInfo from a parsed Cargo.toml. Normal deps include `[dependencies]` plus every
 * `[target.<cfg>.dependencies]` table so a P-level crate cannot smuggle a runtime dependency in
 * through a target section.
 */
export function crateFromManifest(manifest: unknown, fallbackName: string): CrateInfo {
  const root = asRecord(manifest);
  const pkg = asRecord(root["package"]);
  const deps = depNames(root["dependencies"]);
  for (const target of Object.values(asRecord(root["target"]))) {
    deps.push(...depNames(asRecord(target)["dependencies"]));
  }
  return {
    name: typeof pkg["name"] === "string" ? pkg["name"] : fallbackName,
    publish: pkg["publish"] !== false,
    deps,
  };
}

export function checkLayers(crates: CrateInfo[]): string[] {
  const errors: string[] = [];
  const byName = new Map<string, CrateInfo>();

  for (const crate of crates) {
    if ((crate.name === "nk" || crate.name.startsWith("nk-")) && !(crate.name in ALLOWED)) {
      errors.push(`unknown crate "${crate.name}"`);
    }
    byName.set(crate.name, crate);
  }

  for (const crate of crates) {
    const allowed = ALLOWED[crate.name] ?? [];
    for (const dep of crate.deps) {
      if (dep === "nk" || dep.startsWith("nk-")) {
        if (!(dep in ALLOWED)) {
          errors.push(`${crate.name}: unknown internal dependency "${dep}"`);
          continue;
        }
        if (!allowed.includes(ALL) && !allowed.includes(dep)) {
          errors.push(`${crate.name}: must not depend on ${dep}`);
        }
        if (crate.publish && byName.get(dep)?.publish === false) {
          errors.push(`${crate.name}: published crate must not depend on ${dep}`);
        }
      }
      if (P_LEVEL.has(crate.name) && RUNTIME_BANNED.has(dep)) {
        errors.push(`${crate.name}: P-level crate must not depend on ${dep}`);
      }
      if (dep === SQLITE && crate.name !== SQLITE_OWNER) {
        errors.push(`${crate.name}: ${SQLITE} is only allowed in ${SQLITE_OWNER}`);
      }
    }
  }

  return errors;
}

if (import.meta.main) {
  const crates: CrateInfo[] = [];
  for (const dir of readdirSync("crates", { withFileTypes: true })) {
    if (!dir.isDirectory()) {
      continue;
    }
    const manifestPath = join("crates", dir.name, "Cargo.toml");
    let manifest: string;
    try {
      manifest = readFileSync(manifestPath, "utf8");
    } catch {
      continue;
    }
    crates.push(crateFromManifest(Bun.TOML.parse(manifest), dir.name));
  }
  const errors = checkLayers(crates);
  for (const error of errors) {
    console.error(`check-layers: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
