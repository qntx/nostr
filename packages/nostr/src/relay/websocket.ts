/** Minimal WebSocket surface used by Relay (browser or `ws`). */
export type WebSocketLike = {
  readyState: number;
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  addEventListener: (type: string, listener: (ev: unknown) => void) => void;
  removeEventListener: (type: string, listener: (ev: unknown) => void) => void;
  ping?: () => void;
  /** Node `ws` emits `pong` on the EventEmitter; `addEventListener("pong")` is a no-op. */
  once?: (event: string, listener: (...args: unknown[]) => void) => void;
  on?: (event: string, listener: (...args: unknown[]) => void) => void;
  off?: (event: string, listener: (...args: unknown[]) => void) => void;
};

export type WebSocketConstructor = {
  new (url: string): WebSocketLike;
  readonly OPEN: number;
  readonly CONNECTING: number;
  readonly CLOSING: number;
  readonly CLOSED: number;
};
