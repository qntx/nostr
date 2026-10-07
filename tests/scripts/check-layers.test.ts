import { describe, expect, test } from "vite-plus/test";

import { checkLayers, crateFromManifest } from "../../scripts/check-layers.ts";
import type { CrateInfo } from "../../scripts/check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers", () => {
  test("accepts the allowed edges", () => {
    const crates = [
      crate("nk-core", []),
      crate("nk-nips", ["nk-core"]),
      crate("nk-signer", ["nk-core", "nk-nips"]),
      crate("nk-relay", ["nk-core", "nk-nips", "nk-signer"]),
      crate("nk-vectors", ["nk-core", "nk-relay"], false),
      crate("nk-wasm", ["nk-core"], false),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("nk-core", ["nk-relay"]), crate("nk-relay", ["nk-core"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["nk-core: must not depend on nk-relay"]);
  });

  test("rejects tokio in a P-level crate", () => {
    const errors = checkLayers([crate("nk-core", ["tokio"])]);
    expect(errors).toStrictEqual(["nk-core: P-level crate must not depend on tokio"]);
  });

  test("rejects tokio hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "nk-core" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { tokio: "1" } } },
      },
      "nk-core",
    );
    expect(checkLayers([info])).toStrictEqual(["nk-core: P-level crate must not depend on tokio"]);
  });

  test("rejects a published crate depending on nk-vectors", () => {
    const crates = [
      crate("nk-core", []),
      crate("nk-relay", ["nk-core", "nk-vectors"]),
      crate("nk-vectors", [], false),
    ];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual([
      "nk-relay: must not depend on nk-vectors",
      "nk-relay: published crate must not depend on nk-vectors",
    ]);
  });

  test("rejects rusqlite outside nk-storage", () => {
    const errors = checkLayers([crate("nk-nips", ["nk-core", "rusqlite"])]);
    expect(errors).toStrictEqual(["nk-nips: rusqlite is only allowed in nk-storage"]);
  });

  test("rejects an unknown nk-* crate", () => {
    const errors = checkLayers([crate("nk-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "nk-mystery"']);
  });
});
