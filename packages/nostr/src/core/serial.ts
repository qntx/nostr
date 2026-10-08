/** Runs async operations one at a time in submission order; a failed op does not block later ones. */
export class SerialQueue {
  #tail: Promise<void> = Promise.resolve();

  async run<T>(op: () => Promise<T>): Promise<T> {
    const result = (async (): Promise<T> => {
      await this.#tail;
      return op();
    })();
    this.#tail = (async (): Promise<void> => {
      try {
        await result;
      } catch {
        // a failed op must not wedge later ops
      }
    })();
    return result;
  }
}
