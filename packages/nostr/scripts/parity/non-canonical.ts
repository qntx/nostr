/**
 * True when `raw` JSON text contains a form `JSON.parse` accepts but the canonical wire profile
 * (ADR-0007 rule 4) rejects: an integral-valued number spelled with a fraction or exponent (`1e3`,
 * `1.0`, `1700000000.0`), the spelling `-0`, or a duplicate object key. Strings are skipped, so
 * digits inside quoted text never flag a case.
 */
export function isNonCanonicalJson(raw: string): boolean {
  let i = 0;
  const n = raw.length;
  const skipWs = (): void => {
    while (i < n && (raw[i] === " " || raw[i] === "\t" || raw[i] === "\n" || raw[i] === "\r")) {
      i += 1;
    }
  };
  const scanString = (): void => {
    i += 1;
    while (i < n) {
      const c = raw[i];
      i += 1;
      if (c === "\\") {
        i += 1;
      } else if (c === '"') {
        break;
      }
    }
  };
  const scanValue = (): boolean => {
    skipWs();
    const c = raw[i];
    if (c === '"') {
      scanString();
      return false;
    }
    if (c === "{") {
      i += 1;
      const keys = new Set<string>();
      skipWs();
      if (raw[i] === "}") {
        i += 1;
        return false;
      }
      for (;;) {
        skipWs();
        const start = i;
        scanString();
        const key = raw.slice(start, i);
        if (keys.has(key)) {
          return true;
        }
        keys.add(key);
        skipWs();
        i += 1; // ':'
        if (scanValue()) {
          return true;
        }
        skipWs();
        if (raw[i] === "}") {
          i += 1;
          return false;
        }
        i += 1; // ','
      }
    }
    if (c === "[") {
      i += 1;
      skipWs();
      if (raw[i] === "]") {
        i += 1;
        return false;
      }
      for (;;) {
        if (scanValue()) {
          return true;
        }
        skipWs();
        if (raw[i] === "]") {
          i += 1;
          return false;
        }
        i += 1; // ','
      }
    }
    const m = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(raw.slice(i));
    if (m) {
      const [token] = m;
      i += token.length;
      // A non-integral value (-0.5) is a type error, not a canonicality
      // violation; plain spellings (0, -5, 9007199254740992) are canonical.
      return token !== String(Number(token)) && Number.isSafeInteger(Number(token));
    }
    while (i < n && /[a-zA-Z]/.test(raw[i] ?? "")) {
      i += 1;
    }
    return false;
  };
  return scanValue();
}
