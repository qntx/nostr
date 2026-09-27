import { NostrError } from "../core/error.ts";

export class LoaderError extends NostrError {
  override name = "LoaderError";
}

/** Minimal request coalescer. Batches keys within a microtask; no global state. */
export type BatchLoadFn<K, V> = (keys: ReadonlyArray<K>) => Promise<ReadonlyArray<V | Error>>;

export type DataLoaderOptions<K, C = K> = {
  cacheKeyFn?: (key: K) => C;
  maxBatchSize?: number;
  /** When false, only coalesces in-flight requests (no durable memoization). Default true. */
  cache?: boolean;
};

export class DataLoader<K, V, C = K> {
  readonly #batchLoadFn: BatchLoadFn<K, V>;
  readonly #cacheKeyFn: (key: K) => C;
  readonly #maxBatchSize: number;
  readonly #useCache: boolean;
  readonly #cache = new Map<C, Promise<V>>();
  readonly #inflight = new Map<C, Promise<V>>();
  readonly #queue: Array<{
    key: K;
    resolve: (v: V) => void;
    reject: (e: unknown) => void;
  }> = [];
  #scheduled = false;

  constructor(batchLoadFn: BatchLoadFn<K, V>, options: DataLoaderOptions<K, C> = {}) {
    this.#batchLoadFn = batchLoadFn;
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the default C = K makes this the identity for callers that omit cacheKeyFn
    this.#cacheKeyFn = options.cacheKeyFn ?? ((k: K) => k as unknown as C);
    this.#maxBatchSize = options.maxBatchSize ?? Number.POSITIVE_INFINITY;
    this.#useCache = options.cache !== false;
  }

  async load(key: K): Promise<V> {
    const cacheKey = this.#cacheKeyFn(key);
    if (this.#useCache) {
      const cached = this.#cache.get(cacheKey);
      if (cached) {
        return cached;
      }
    }
    const inflight = this.#inflight.get(cacheKey);
    if (inflight) {
      return inflight;
    }

    const pending = new Promise<V>((resolve, reject) => {
      this.#queue.push({ key, resolve, reject });
      if (this.#queue.length >= this.#maxBatchSize) {
        this.#dispatch();
      } else if (!this.#scheduled) {
        this.#scheduled = true;
        queueMicrotask(() => this.#dispatch());
      }
    });
    const promise = (async (): Promise<V> => {
      try {
        return await pending;
      } finally {
        this.#inflight.delete(cacheKey);
      }
    })();

    this.#inflight.set(cacheKey, promise);
    if (this.#useCache) {
      this.#cache.set(cacheKey, promise);
    }
    return promise;
  }

  clear(key: K): void {
    this.#cache.delete(this.#cacheKeyFn(key));
    this.#inflight.delete(this.#cacheKeyFn(key));
  }

  clearAll(): void {
    this.#cache.clear();
    this.#inflight.clear();
  }

  #dispatch(): void {
    this.#scheduled = false;
    const batch = this.#queue.splice(0, this.#maxBatchSize);
    if (batch.length === 0) {
      return;
    }

    const keys = batch.map((b) => b.key);
    void (async () => {
      let values: ReadonlyArray<V | Error>;
      try {
        values = await this.#batchLoadFn(keys);
      } catch (error: unknown) {
        for (const item of batch) {
          item.reject(error);
        }
        return;
      }
      if (values.length !== keys.length) {
        const err = new LoaderError(
          `DataLoader batch function must return array of length ${keys.length}, got ${values.length}`,
        );
        for (const item of batch) {
          item.reject(err);
        }
        return;
      }
      for (const [i, value] of values.entries()) {
        const item = batch[i];
        if (item === undefined) {
          continue;
        }
        if (value instanceof Error) {
          item.reject(value);
        } else {
          item.resolve(value);
        }
      }
    })();

    if (this.#queue.length > 0) {
      this.#scheduled = true;
      queueMicrotask(() => this.#dispatch());
    }
  }
}
