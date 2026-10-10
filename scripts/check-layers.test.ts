import { describe, expect, test } from "vite-plus/test";

import { checkLayers, crateFromManifest } from "./check-layers.ts";
import type { CrateInfo } from "./check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers", () => {
  test("accepts the allowed edges", () => {
    const crates = [
      crate("nk", []),
      crate("nk-database", ["nk"]),
      crate("nk-sqlite", ["nk-database"]),
      crate("nk-gossip", ["nk"]),
      crate("nk-sdk", ["nk", "nk-database", "nk-gossip"]),
      crate("nk-connect", ["nk", "nk-sdk"]),
      crate("nk-blossom", ["nk"]),
      crate("nk-vectors", ["nk", "nk-sdk"], false),
      crate("nk-wasm", ["nk"], false),
      crate("nk-ffi", ["nk", "nk-sdk"]),
    ];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("nk", ["nk-sdk"]), crate("nk-sdk", ["nk"])];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual(["nk: must not depend on nk-sdk"]);
  });

  test("rejects tokio in a P-level crate", () => {
    const errors = checkLayers([crate("nk", ["tokio"])]);
    expect(errors).toStrictEqual(["nk: P-level crate must not depend on tokio"]);
  });

  test("rejects tokio hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "nk" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { tokio: "1" } } },
      },
      "nk",
    );
    expect(checkLayers([info])).toStrictEqual(["nk: P-level crate must not depend on tokio"]);
  });

  test("allows tokio in the sdk layer", () => {
    const crates = [crate("nk", []), crate("nk-sdk", ["nk", "tokio"])];
    expect(checkLayers(crates)).toStrictEqual([]);
  });

  test("rejects a published crate depending on nk-vectors", () => {
    const crates = [
      crate("nk", []),
      crate("nk-sdk", ["nk", "nk-vectors"]),
      crate("nk-vectors", [], false),
    ];
    const errors = checkLayers(crates);
    expect(errors).toStrictEqual([
      "nk-sdk: must not depend on nk-vectors",
      "nk-sdk: published crate must not depend on nk-vectors",
    ]);
  });

  test("rejects rusqlite outside nk-sqlite", () => {
    const errors = checkLayers([crate("nk-gossip", ["nk", "rusqlite"])]);
    expect(errors).toStrictEqual(["nk-gossip: rusqlite is only allowed in nk-sqlite"]);
  });

  test("rejects an unknown nk-* crate", () => {
    const errors = checkLayers([crate("nk-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "nk-mystery"']);
  });
});
