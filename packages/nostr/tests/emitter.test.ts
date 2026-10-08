import { describe, expect, test } from "vite-plus/test";

import { Emitter } from "../src/core/emitter.ts";
import { stubReportError } from "./helpers/report-error.ts";

type TestMap = {
  tick: number;
  done: undefined;
};

describe("Emitter", () => {
  test("multiple listeners fire in registration order", () => {
    const emitter = new Emitter<TestMap>();
    const seen: string[] = [];
    emitter.on("tick", (n) => seen.push(`a${n}`));
    emitter.on("tick", (n) => seen.push(`b${n}`));
    emitter.emit("tick", 1);
    emitter.emit("tick", 2);
    expect(seen).toStrictEqual(["a1", "b1", "a2", "b2"]);
  });

  test("the returned unsubscribe stops delivery", () => {
    const emitter = new Emitter<TestMap>();
    const seen: number[] = [];
    const off = emitter.on("tick", (n) => seen.push(n));
    emitter.emit("tick", 1);
    off();
    emitter.emit("tick", 2);
    expect(seen).toStrictEqual([1]);
  });

  test("unsubscribing during dispatch does not skip the snapshot", () => {
    const emitter = new Emitter<TestMap>();
    const seen: string[] = [];
    const unsubscribers: Array<() => void> = [];
    emitter.on("tick", () => {
      seen.push("a");
      unsubscribers[0]?.();
    });
    unsubscribers.push(emitter.on("tick", () => seen.push("b")));
    emitter.on("tick", () => seen.push("c"));
    emitter.emit("tick", 1);
    expect(seen).toStrictEqual(["a", "b", "c"]);
    // b is gone from the next dispatch.
    emitter.emit("tick", 2);
    expect(seen).toStrictEqual(["a", "b", "c", "a", "c"]);
  });

  test("a throwing listener is reported and does not starve the rest", () => {
    const emitter = new Emitter<TestMap>();
    const { reported, restore } = stubReportError();
    const boom = new Error("boom");
    const seen: number[] = [];
    emitter.on("tick", () => {
      throw boom;
    });
    emitter.on("tick", (n) => seen.push(n));
    try {
      emitter.emit("tick", 7);
      expect(seen).toStrictEqual([7]);
      expect(reported).toStrictEqual([boom]);
    } finally {
      restore();
    }
  });
});
