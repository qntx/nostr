# vectors/

Shared cross-language test vectors. Both the TypeScript tests (`tests/vectors/`,
`tests/nip44.test.ts`) and the Rust `nk-*` crates must pass against the same
files, which makes byte-level parity checkable.

## Layout

```text
vectors/<area>/<name>.json    one file per capability, name = capability id
                              without the "<area>." prefix, dots as hyphens
vectors/<area>/<name>.<ext>   official external vectors keep their original
                              format (e.g. bip340/official.csv)
```

`scripts/parity/check.ts` asserts that every file here is referenced by at
least one capability in `parity.json`.

## Schema

JSON files share a single envelope:

```json
{
  "schema": 1,
  "capability": "core.event.serialize",
  "source": { "kind": "generated", "generator": "@qntx/nostr", "version": "0.9.0" },
  "cases": []
}
```

- `schema` — envelope version, currently always `1`.
- `capability` — the `parity.json` capability id this file exercises.
- `source.kind` — `official` (upstream vector, verbatim), `reference`
  (produced by an independent reference implementation; record its name and
  version in `source`), or `generated` (frozen output of the TS
  implementation; `generator` names the producing script/package and
  `version` the package version that produced it).
- `cases` — always an array. Success cases carry inputs and expected outputs;
  failure cases carry an `error` field naming the expected error class
  (`MessageError`, `EventValidationError`) or a null expectation field
  (`parsed: null`, `output: null`). Runners branch on the case fields; a file
  may mix case shapes (e.g. `tag-address.json` uses `op: "parse" | "format"`).

`vectors/core/*.json` are generated deterministically by
`bun packages/nostr/scripts/parity/gen/core.ts`; never edit them by hand.
