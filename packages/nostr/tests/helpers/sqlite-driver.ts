import type { SqlDriver, SqlValue } from "../../src/storage/sqlite.ts";

/**
 * Minimal synchronous database shape shared by `bun:sqlite`'s `Database` and `node:sqlite`'s
 * `DatabaseSync`.
 */
type RawDb = {
  exec: (sql: string) => void;
  prepare: (sql: string) => {
    run: (...params: SqlValue[]) => { changes: number | bigint };
    all: (...params: SqlValue[]) => unknown[];
  };
  close: () => void;
};

/**
 * In-memory {@link SqlDriver} for tests: `bun:sqlite` under `bun test`, `node:sqlite`
 * (`DatabaseSync`) elsewhere, same async surface under both.
 *
 * `transaction` serializes callbacks on a promise-chain mutex and wraps each in `BEGIN IMMEDIATE` /
 * `COMMIT` / `ROLLBACK`. Statements issued outside a transaction run in autocommit and, per
 * same-connection SQLite semantics, join an already-open transaction — the {@link SqlDriver}
 * contract requires only that _transactions_ never interleave.
 */
export class SqliteTestDriver implements SqlDriver {
  readonly #db: RawDb;
  #txTail: Promise<void> = Promise.resolve();
  #injected: { pattern: RegExp | undefined; error: Error; skip: number } | undefined;

  private constructor(db: RawDb) {
    this.#db = db;
  }

  static async open(): Promise<SqliteTestDriver> {
    if ("Bun" in globalThis) {
      const specifier = "bun:sqlite";
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- bun:sqlite has no importable types; this is the RawDb contract
      const mod = (await import(specifier)) as {
        Database: new (path: string) => RawDb;
      };
      return new SqliteTestDriver(new mod.Database(":memory:"));
    }
    const { DatabaseSync } = await import("node:sqlite");
    return new SqliteTestDriver(new DatabaseSync(":memory:"));
  }

  /**
   * Inject a one-shot failure: the next statement whose SQL matches `pattern` (every statement when
   * omitted) throws `error`. `skip` first lets that many matching statements pass — e.g.
   * `failOn(/^INSERT INTO events/, {skip: 1})` fails a batch's second event insert.
   */
  failOn(pattern?: RegExp, opts?: { error?: Error; skip?: number }): void {
    this.#injected = {
      pattern,
      error: opts?.error ?? new Error("injected sqlite failure"),
      skip: opts?.skip ?? 0,
    };
  }

  #guard(sql: string): void {
    const injected = this.#injected;
    if (!injected) {
      return;
    }
    if (injected.pattern && !injected.pattern.test(sql)) {
      return;
    }
    if (injected.skip > 0) {
      injected.skip -= 1;
      return;
    }
    this.#injected = undefined;
    throw injected.error;
  }

  async exec(sql: string): Promise<void> {
    await Promise.resolve();
    this.#guard(sql);
    this.#db.exec(sql);
  }

  async run(sql: string, params: ReadonlyArray<SqlValue> = []): Promise<{ changes: number }> {
    await Promise.resolve();
    this.#guard(sql);
    const result = this.#db.prepare(sql).run(...params);
    return { changes: Number(result.changes) };
  }

  async all<Row>(sql: string, params: ReadonlyArray<SqlValue> = []): Promise<Row[]> {
    await Promise.resolve();
    this.#guard(sql);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- row shape is the caller-declared Row, same as SqlDriver.all
    return this.#db.prepare(sql).all(...params) as Row[];
  }

  async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
    // oxlint-disable-next-line promise/prefer-await-to-then -- the tail chain is the serialization primitive
    const task = this.#txTail.then(async (): Promise<T> => {
      this.#db.exec("BEGIN IMMEDIATE");
      const tx: SqlDriver = {
        exec: async (sql) => {
          await this.exec(sql);
        },
        run: async (sql, params) => {
          const result = await this.run(sql, params);
          return result;
        },
        all: async <Row>(sql: string, params?: ReadonlyArray<SqlValue>) => {
          const rows = await this.all<Row>(sql, params);
          return rows;
        },
        transaction: async (inner) => {
          const value = await inner(tx);
          return value;
        },
      };
      try {
        const value = await fn(tx);
        this.#db.exec("COMMIT");
        return value;
      } catch (error) {
        try {
          this.#db.exec("ROLLBACK");
        } catch {
          // The engine already rolled back (e.g. a fatal error); surface the
          // original failure.
        }
        throw error;
      }
    });
    // oxlint-disable-next-line promise/prefer-await-to-then -- the tail chain is the serialization primitive
    this.#txTail = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  /** Statement count and rows remain readable in tests. */
  raw(): RawDb {
    return this.#db;
  }

  close(): void {
    this.#db.close();
  }
}
