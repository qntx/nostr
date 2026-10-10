import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { checkFeatures } from "./check-features.ts";
import type { FeatureInputs } from "./check-features.ts";

const NK_TOML = {
  features: {
    default: ["std", "clock", "os-rng"],
    std: ["serde/std"],
    clock: ["std"],
    "os-rng": ["std", "dep:getrandom"],
    nip04: ["dep:aes"],
    nip13: [],
  },
};

const CI = `jobs:
  portable-nips:
    uses: qntx/workflows/.github/workflows/ci-rust-cross.yml@v2
    with:
      targets: wasm32-unknown-unknown
      packages: nk
      features: --no-default-features --features nip04,nip13
      forbid-deps: getrandom

  portable-std-nips:
    uses: qntx/workflows/.github/workflows/ci-rust-cross.yml@v2
    with:
      targets: aarch64-apple-ios
      packages: nk
      features: --features std,clock,os-rng,nip04,nip13

  other-job:
    runs-on: ubuntu-latest
`;

const VECTORS = {
  "dev-dependencies": {
    nk: { workspace: true, features: ["nip04", "nip13"] },
  },
};

const README = `# nk

| feature  | default | effect |
| -------- | ------- | ------ |
| \`std\`    | yes     | OS facilities |
| \`clock\`  | yes     | wall clock |
| \`os-rng\` | yes     | OS entropy |
| \`nip04\`  | no      | legacy encrypted DMs |
| \`nip13\`  | no      | proof of work |
`;

const LIB_RS = `//! | feature  | default | effect |
//! |----------|---------|--------|
//! | \`std\`    | yes     | OS facilities |
//! | \`clock\`  | yes     | wall clock |
//! | \`os-rng\` | yes     | OS entropy |
//! | \`nip04\`  | no      | legacy encrypted DMs |
//! | \`nip13\`  | no      | proof of work |
`;

const INPUTS: FeatureInputs = {
  ci: CI,
  vectorsToml: VECTORS,
  readme: README,
  libRs: LIB_RS,
};

describe("check-features", () => {
  test("the real tree stays in sync", () => {
    // Runs through bun: the script's TOML parsing uses the Bun.TOML built-in.
    const root = join(import.meta.dirname, "..");
    const result = spawnSync("bun", [join(root, "scripts/check-features.ts")], {
      cwd: root,
      encoding: "utf8",
    });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  test("consistent fixtures produce no errors", () => {
    expect(checkFeatures(NK_TOML, INPUTS)).toStrictEqual([]);
  });

  test("a missing CI feature is reported with the job and feature name", () => {
    const ci = CI.replace(
      "--features nip04,nip13\n      forbid-deps",
      "--features nip04\n      forbid-deps",
    );
    const errors = checkFeatures(NK_TOML, { ...INPUTS, ci });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('ci.yml: job "portable-nips"');
    expect(errors[0]).toContain('missing "nip13"');
  });

  test("an extra nk-vectors feature is reported", () => {
    const vectorsToml = {
      "dev-dependencies": {
        nk: { workspace: true, features: ["nip04", "nip13", "nip99"] },
      },
    };
    const errors = checkFeatures(NK_TOML, { ...INPUTS, vectorsToml });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("crates/nk-vectors/Cargo.toml");
    expect(errors[0]).toContain('extra "nip99"');
  });

  test("a missing README row is reported", () => {
    const readme = README.replace("| `nip13`  | no      | proof of work |\n", "");
    const errors = checkFeatures(NK_TOML, { ...INPUTS, readme });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("crates/nk/README.md");
    expect(errors[0]).toContain("`nip13`");
  });

  test("a table row for a non-feature is reported", () => {
    const readme = `${README}| \`nip99\`  | no      | not a feature |\n`;
    const errors = checkFeatures(NK_TOML, { ...INPUTS, readme });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("`nip99`");
    expect(errors[0]).toContain("not nk [features] keys");
  });

  test("a missing lib.rs doc-table row is reported", () => {
    const libRs = LIB_RS.replace("//! | `nip13`  | no      | proof of work |\n", "");
    const errors = checkFeatures(NK_TOML, { ...INPUTS, libRs });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("crates/nk/src/lib.rs");
    expect(errors[0]).toContain("`nip13`");
  });

  test("a duplicated table row is reported", () => {
    const readme = `${README}| \`nip04\`  | no      | duplicated |\n`;
    const errors = checkFeatures(NK_TOML, { ...INPUTS, readme });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("duplicate");
    expect(errors[0]).toContain("`nip04`");
  });

  test("a missing CI job is reported", () => {
    const ci = CI.replace("  portable-std-nips:", "  portable-std-nips-renamed:");
    const errors = checkFeatures(NK_TOML, { ...INPUTS, ci });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('job "portable-std-nips" not found');
  });
});
