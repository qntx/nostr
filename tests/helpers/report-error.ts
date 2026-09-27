/**
 * Capture `globalThis.reportError` calls for the duration of a test. Runner-agnostic (bun:test has
 * no `vi.stubGlobal`): assign directly and restore the previous value in a `finally`.
 */
declare global {
  var reportError: ((error: unknown) => void) | undefined;
}

export function stubReportError(): { reported: unknown[]; restore: () => void } {
  const reported: unknown[] = [];
  const prev = globalThis.reportError;
  globalThis.reportError = (err: unknown) => {
    reported.push(err);
  };
  return {
    reported,
    restore: () => {
      if (prev === undefined) {
        Reflect.deleteProperty(globalThis, "reportError");
      } else {
        globalThis.reportError = prev;
      }
    },
  };
}
