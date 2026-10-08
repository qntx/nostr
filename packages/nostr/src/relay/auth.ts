/**
 * NIP-42 AUTH state machine: the latest challenge, dedup of signed answers across identical
 * challenges, and the `ensureAuthed` retry loop. AUTH frames are sent through an injected
 * `sendAuth` (OkTracker-backed) so the relay's verdict resolves the auth call.
 */
import type { Event, EventTemplate } from "../core/event.ts";
import { makeAuthEvent } from "../nips/nip42.ts";
import { NoSignerError } from "../signer/error.ts";
import { RelayClosedError, RelayError } from "./error.ts";
import type { PublishResult } from "./ok-tracker.ts";

export type RelayAuthDeps = {
  url: string;
  isOpen: () => boolean;
  /** Send an AUTH frame and await the relay's OK verdict. */
  sendAuth: (event: Event, timeoutMs: number) => Promise<PublishResult>;
  defaultTimeoutMs: number;
};

export class RelayAuth {
  #challenge: string | undefined;
  #authedChallenge: string | undefined;
  /** Challenge value already answered on this connection; duplicates are not re-signed. */
  #answeredChallenge: string | undefined;
  /** Settled OK verdict for `#answeredChallenge`; set only once the relay replies. */
  #answeredResult: PublishResult | undefined;
  #authPromise: Promise<PublishResult> | undefined;
  readonly #url: string;
  readonly #isOpen: () => boolean;
  readonly #sendAuth: (event: Event, timeoutMs: number) => Promise<PublishResult>;
  readonly #defaultTimeoutMs: number;

  constructor(deps: RelayAuthDeps) {
    this.#url = deps.url;
    this.#isOpen = deps.isOpen;
    this.#sendAuth = deps.sendAuth;
    this.#defaultTimeoutMs = deps.defaultTimeoutMs;
  }

  /** Latest NIP-42 challenge, if any. */
  get challenge(): string | undefined {
    return this.#challenge;
  }

  /**
   * A re-sent identical challenge keeps the in-flight/settled dedupe; only a new challenge value
   * resets the answer state.
   */
  handleChallenge(challenge: string): void {
    if (challenge !== this.#challenge) {
      this.#authPromise = undefined;
      this.#authedChallenge = undefined;
      this.#answeredChallenge = undefined;
      this.#answeredResult = undefined;
    }
    this.#challenge = challenge;
  }

  /** New connection: challenge and answer state belong to the old socket. */
  resetConnection(): void {
    this.#challenge = undefined;
    this.#authPromise = undefined;
    this.#authedChallenge = undefined;
    this.#answeredChallenge = undefined;
    this.#answeredResult = undefined;
  }

  /** Sign the current challenge and wait for OK. */
  async auth(
    sign: (template: EventTemplate) => Promise<Event>,
    opts?: { timeoutMs?: number | undefined },
  ): Promise<PublishResult> {
    const challenge = this.#challenge;
    if (challenge === undefined || challenge === "") {
      throw new RelayError("no AUTH challenge received from relay", this.#url);
    }
    if (this.#authPromise) {
      return this.#authPromise;
    }
    if (this.#answeredChallenge === challenge && this.#answeredResult !== undefined) {
      return this.#answeredResult;
    }

    const pending = (async () => {
      const template = makeAuthEvent(this.#url, challenge);
      let event: Event;
      try {
        event = await sign(template);
      } catch (error) {
        // A lazy signer may legitimately have nothing to sign with; ignore the
        // challenge quietly — the connection stays open without an AUTH frame.
        if (error instanceof NoSignerError) {
          return { ok: false, message: "auth: no signer" };
        }
        throw error;
      }
      if (!this.#isOpen()) {
        throw new RelayClosedError("not connected", this.#url);
      }
      const result = await this.#sendAuth(event, opts?.timeoutMs ?? this.#defaultTimeoutMs);
      // Cache the relay's settled verdict: a repeated challenge replays it without
      // re-signing. Timeouts and send failures reject before here, so a later auth()
      // signs again.
      if (this.#challenge === challenge) {
        this.#answeredChallenge = challenge;
        this.#answeredResult = result;
      }
      return result;
    })();
    this.#authPromise = pending;
    try {
      const result = await pending;
      if (result.ok && this.#challenge === challenge) {
        this.#authedChallenge = challenge;
      }
      return result;
    } finally {
      if (this.#authPromise === pending) {
        this.#authPromise = undefined;
      }
    }
  }

  async ensureAuthed(
    signer: ((template: EventTemplate) => Promise<Event>) | undefined,
  ): Promise<boolean> {
    if (!signer) {
      return false;
    }
    for (let i = 0; i < 3; i++) {
      if (this.#challenge === undefined || this.#challenge === "") {
        return false;
      }
      if (this.#authedChallenge === this.#challenge) {
        return true;
      }
      const signed = this.#challenge;
      // oxlint-disable-next-line no-await-in-loop -- auth retries are sequential: each round waits for the new AUTH challenge
      const result = await this.auth(signer);
      if (this.#authedChallenge === this.#challenge) {
        return true;
      }
      if (!result.ok) {
        if (this.#challenge === undefined || this.#challenge === "" || this.#challenge === signed) {
          return false;
        }
        continue;
      }
    }
    return this.#authedChallenge === this.#challenge;
  }

  /**
   * Clear a cached AUTH rejection for the current challenge (a successful auth and in-flight
   * answers are kept) and return the unanswered challenge to re-emit, if any.
   */
  resetRejection(): string | undefined {
    if (this.#answeredResult !== undefined && !this.#answeredResult.ok) {
      this.#answeredChallenge = undefined;
      this.#answeredResult = undefined;
    }
    if (this.#challenge !== undefined && this.#challenge !== this.#authedChallenge) {
      return this.#challenge;
    }
    return undefined;
  }
}
