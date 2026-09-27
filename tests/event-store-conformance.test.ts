import { afterEach, beforeEach, describe, test } from "vite-plus/test";

import { IndexedDbEventStore, MemoryEventStore } from "../src/index.ts";
import { eventStoreConformanceCases } from "../src/testing/index.ts";
import { installIdbMock } from "./helpers/idb-mock.ts";
import type { IdbMock } from "./helpers/idb-mock.ts";

describe("MemoryEventStore conformance", () => {
  // oxlint-disable-next-line expect-expect -- assertions live inside each case's run()
  test.each(eventStoreConformanceCases)("$name", async (c) => {
    await c.run(new MemoryEventStore());
  });
});

describe("IndexedDbEventStore conformance", () => {
  let mock: IdbMock;
  let dbSeq = 0;

  beforeEach(() => {
    mock = installIdbMock();
  });

  afterEach(() => {
    mock.uninstall();
  });

  // oxlint-disable-next-line expect-expect -- assertions live inside each case's run()
  test.each(eventStoreConformanceCases)("$name", async (c) => {
    const store = new IndexedDbEventStore({ dbName: `conformance-${dbSeq++}` });
    await store.open();
    try {
      await c.run(store);
    } finally {
      store.close();
    }
  });
});
