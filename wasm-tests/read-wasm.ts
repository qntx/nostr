import { readFile } from "node:fs/promises";

export async function readBuiltWasm(): Promise<Uint8Array> {
  return new Uint8Array(await readFile("src/wasm/nk_wasm_bg.wasm"));
}
