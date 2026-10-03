import { abortReason, onAbort } from "../core/abort.ts";
import type { Filter } from "../core/filter.ts";
import type { ClientMessage } from "../core/message.ts";
import { Nip77Error, runNegSession } from "../nips/nip77.ts";
import type { NegentropyStorageVector } from "../nips/nip77.ts";
import { RelayTimeoutError } from "./error.ts";

export type NegSession = {
  queue: string[];
  waiter:
    | {
        resolve: (hex: string) => void;
        reject: (err: unknown) => void;
      }
    | undefined;
  error: Error | undefined;
};

export function createNegSession(): NegSession {
  return { queue: [], waiter: undefined, error: undefined };
}

export function pushNegMsg(session: NegSession, hex: string): void {
  if (session.waiter) {
    const { waiter } = session;
    session.waiter = undefined;
    waiter.resolve(hex);
  } else {
    session.queue.push(hex);
  }
}

export function failNegSession(session: NegSession, err: Error): void {
  session.error = err;
  if (session.waiter) {
    const { waiter } = session;
    session.waiter = undefined;
    waiter.reject(err);
  }
}

export function failNegErr(session: NegSession, reason: string): void {
  failNegSession(session, new Nip77Error(reason));
}

/** Route a NEG-MSG/NEG-ERR frame to its session; unknown ids are ignored. */
export function dispatchNegMessage(
  sessions: Map<string, NegSession>,
  msg: readonly [type: string, id: string, payload: string],
): void {
  const session = sessions.get(msg[1]);
  if (session === undefined) {
    return;
  }
  if (msg[0] === "NEG-MSG") {
    pushNegMsg(session, msg[2]);
    return;
  }
  failNegErr(session, msg[2]);
}

/** Fail every tracked session (socket teardown). */
export function failAllNegSessions(sessions: Map<string, NegSession>, err: Error): void {
  for (const session of sessions.values()) {
    failNegSession(session, err);
  }
  sessions.clear();
}

/** Wire queue/timeout/abort around `runNegSession`. Not a second session class. */
export async function runWiredNegSession(opts: {
  session: NegSession;
  storage: NegentropyStorageVector;
  filter: Filter;
  id: string;
  timeoutMs: number;
  signal?: AbortSignal | undefined;
  send: (message: ClientMessage) => void;
  url: string;
}): Promise<{ have: string[]; need: string[] }> {
  const { session, storage, filter, id, timeoutMs, signal, send, url } = opts;
  const deadline = Date.now() + timeoutMs;

  const timedOut = (): RelayTimeoutError => new RelayTimeoutError("negentropy timed out", url);

  const remainingMs = (): number => deadline - Date.now();

  const next = async (): Promise<string> => {
    if (session.error !== undefined) {
      throw session.error;
    }
    if (remainingMs() <= 0) {
      throw timedOut();
    }
    const queued = session.queue.shift();
    if (queued !== undefined) {
      return queued;
    }
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        session.waiter = undefined;
        disposeAbort();
        reject(timedOut());
      }, remainingMs());
      const fail = (err: unknown): void => {
        clearTimeout(timer);
        session.waiter = undefined;
        disposeAbort();
        // oxlint-disable-next-line typescript/prefer-promise-reject-errors -- forwards abort/signal reasons verbatim
        reject(err);
      };
      session.waiter = {
        resolve: (hex) => {
          clearTimeout(timer);
          disposeAbort();
          resolve(hex);
        },
        reject: (err) => fail(err),
      };
      const disposeAbort = onAbort(signal, () => {
        if (signal) {
          fail(abortReason(signal));
        }
      });
    });
  };

  return runNegSession({
    storage,
    openingSend: (hex) => {
      send(["NEG-OPEN", id, filter, hex]);
    },
    msgSend: (hex) => {
      send(["NEG-MSG", id, hex]);
    },
    next,
  });
}

/**
 * Drive a NIP-77 reconcile session against the session map: fail a same-id predecessor, register,
 * wire queue/timeout/abort, and send NEG-CLOSE on exit.
 */
export async function runTrackedNegSession(opts: {
  sessions: Map<string, NegSession>;
  id: string;
  storage: NegentropyStorageVector;
  filter: Filter;
  timeoutMs: number;
  signal?: AbortSignal | undefined;
  send: (message: ClientMessage) => void;
  url: string;
}): Promise<{ have: string[]; need: string[] }> {
  const { sessions, id, send } = opts;
  const prev = sessions.get(id);
  if (prev) {
    failNegSession(prev, new Nip77Error("closed: replaced by new NEG-OPEN"));
  }
  const session = createNegSession();
  sessions.set(id, session);
  try {
    return await runWiredNegSession({
      session,
      storage: opts.storage,
      filter: opts.filter,
      id,
      timeoutMs: opts.timeoutMs,
      signal: opts.signal,
      send,
      url: opts.url,
    });
  } finally {
    if (sessions.get(id) === session) {
      sessions.delete(id);
      try {
        send(["NEG-CLOSE", id]);
      } catch {
        // connection already gone
      }
    }
  }
}
