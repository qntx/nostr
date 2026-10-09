/// <reference types="node" />
// Regenerates every vector file: `bun packages/nostr/scripts/parity/gen/all.ts`.
// Each generator writes its vectors/<area>/*.json deterministically; a second
// run must be byte-identical.

await import("./core.ts");
await import("./nip19.ts");
await import("./nip21.ts");
await import("./nip49.ts");
