# vectors/

Shared cross-language test vectors. The TypeScript tests (`tests/vectors/`,
`tests/nip44.test.ts`) are the reference run; `crates/interop` replays the
same files against rust-nostr's public API and records factual differences in
`crates/interop/divergences.json` (unlisted divergences and stale entries
fail). Capabilities with no rust-nostr counterpart are marked `rust: null` in
`parity.json`.

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
- `nonCanonicalJson` — when `true`, the case's raw JSON input uses a form
  `JSON.parse` accepts but strict parsers must reject: an integral-valued
  number spelled with a fraction or exponent (`1e3`, `1.0`,
  `9007199254740991.0`), the spelling `-0`, or a duplicate object key
  (ADR-0007 rule 4). TypeScript accepts the input (`JSON.parse` normalizes
  it, last duplicate wins); Rust must reject it. The flag only appears on
  raw-text inputs; the field is absent otherwise.

`vectors/core/*.json` are generated deterministically by
`bun packages/nostr/scripts/parity/gen/all.ts` (`gen/core.ts`, `gen/nip19.ts`); never edit them by hand.
