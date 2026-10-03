/**
 * NIP-46 (Nostr Connect) protocol helpers: bunker URI, nostrconnect URI, RPC JSON.
 * Transport/signing live in {@link Nip46Signer}.
 *
 * @see https://github.com/nostr-protocol/nips/blob/master/46.md
 */
import { NostrError } from "../core/error.ts";
import { isHex32, isRecord } from "../core/util.ts";

export type BunkerPointer = {
  /** Remote signer / bunker public key (hex). */
  pubkey: string;
  relays: string[];
  secret: string | undefined;
};

export type ClientMetadata = {
  name?: string | undefined;
  url?: string | undefined;
  image?: string | undefined;
};

export type NostrConnectParams = {
  clientPubkey: string;
  relays: string[];
  secret: string;
  perms?: string[] | undefined;
} & ClientMetadata;

export type Nip46Request = {
  id: string;
  method: string;
  params: string[];
};

export type Nip46Response = {
  id: string;
  result?: string | undefined;
  error?: string | undefined;
};

export class Nip46Error extends NostrError {
  override name = "Nip46Error";
}

/** Encode a bunker pointer as `bunker://…`. */
export function toBunkerURL(pointer: BunkerPointer): string {
  const url = new URL(`bunker://${pointer.pubkey.toLowerCase()}`);
  for (const relay of pointer.relays) {
    url.searchParams.append("relay", relay);
  }
  if (pointer.secret !== undefined && pointer.secret !== "") {
    url.searchParams.set("secret", pointer.secret);
  }
  return url.toString();
}

/**
 * Parse a `bunker://` URL into a pointer. Returns undefined when the input is not a bunker URL
 * (including NIP-05 identifiers).
 */
export function parseBunkerURL(input: string): BunkerPointer | undefined {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return undefined;
  }
  if (url.protocol !== "bunker:") {
    return undefined;
  }
  const pubkey = url.hostname || url.pathname.replace(/^\/*/, "");
  if (!isHex32(pubkey.toLowerCase())) {
    return undefined;
  }
  return {
    pubkey: pubkey.toLowerCase(),
    relays: url.searchParams.getAll("relay"),
    secret: url.searchParams.get("secret") ?? undefined,
  };
}

/** Build a client-initiated `nostrconnect://` URI. */
export function createNostrConnectURI(params: NostrConnectParams): string {
  if (!isHex32(params.clientPubkey.toLowerCase())) {
    throw new Nip46Error("invalid client pubkey");
  }
  if (!params.secret) {
    throw new Nip46Error("nostrconnect secret is required");
  }
  if (params.relays.length === 0) {
    throw new Nip46Error("at least one relay is required");
  }

  const query = new URLSearchParams();
  for (const relay of params.relays) {
    query.append("relay", relay);
  }
  query.set("secret", params.secret);
  if (params.perms !== undefined && params.perms.length > 0) {
    query.set("perms", params.perms.join(","));
  }
  if (params.name !== undefined && params.name !== "") {
    query.set("name", params.name);
  }
  if (params.url !== undefined && params.url !== "") {
    query.set("url", params.url);
  }
  if (params.image !== undefined && params.image !== "") {
    query.set("image", params.image);
  }

  return `nostrconnect://${params.clientPubkey.toLowerCase()}?${query.toString()}`;
}

/** Parse a `nostrconnect://` URI. */
export function parseNostrConnectURI(uri: string): NostrConnectParams {
  let url: URL;
  try {
    url = new URL(uri);
  } catch (error) {
    throw new Nip46Error(`invalid nostrconnect URI: ${uri}`, {
      cause: error,
    });
  }
  if (url.protocol !== "nostrconnect:") {
    throw new Nip46Error(`expected nostrconnect: scheme, got ${url.protocol}`);
  }
  const clientPubkey = url.hostname || url.pathname.replace(/^\/*/, "");
  if (!isHex32(clientPubkey.toLowerCase())) {
    throw new Nip46Error("invalid client pubkey in nostrconnect URI");
  }
  const secret = url.searchParams.get("secret");
  if (secret === null || secret === "") {
    throw new Nip46Error("missing secret in nostrconnect URI");
  }
  const relays = url.searchParams.getAll("relay");
  if (relays.length === 0) {
    throw new Nip46Error("missing relays in nostrconnect URI");
  }
  const params: NostrConnectParams = {
    clientPubkey: clientPubkey.toLowerCase(),
    relays,
    secret,
  };
  const permsRaw = url.searchParams.get("perms");
  if (permsRaw !== null && permsRaw !== "") {
    params.perms = permsRaw.split(",").filter((p) => p !== "");
  }
  const name = url.searchParams.get("name");
  if (name !== null) {
    params.name = name;
  }
  const metadataUrl = url.searchParams.get("url");
  if (metadataUrl !== null) {
    params.url = metadataUrl;
  }
  const image = url.searchParams.get("image");
  if (image !== null) {
    params.image = image;
  }
  return params;
}

export function encodeNip46Request(req: Nip46Request): string {
  return JSON.stringify({ id: req.id, method: req.method, params: req.params });
}

export function decodeNip46Request(json: string): Nip46Request {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch (error) {
    throw new Nip46Error("invalid NIP-46 request JSON", {
      cause: error,
    });
  }
  if (!isRecord(data) || typeof data["id"] !== "string" || typeof data["method"] !== "string") {
    throw new Nip46Error("invalid NIP-46 request shape");
  }
  if (!Array.isArray(data["params"]) || !data["params"].every((p) => typeof p === "string")) {
    throw new Nip46Error("invalid NIP-46 request params");
  }
  return { id: data["id"], method: data["method"], params: data["params"] };
}

export function encodeNip46Response(res: Nip46Response): string {
  const body: Record<string, string> = { id: res.id };
  if (res.result !== undefined) {
    body["result"] = res.result;
  }
  if (res.error !== undefined) {
    body["error"] = res.error;
  }
  return JSON.stringify(body);
}

export function decodeNip46Response(json: string): Nip46Response {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch (error) {
    throw new Nip46Error("invalid NIP-46 response JSON", {
      cause: error,
    });
  }
  if (!isRecord(data) || typeof data["id"] !== "string") {
    throw new Nip46Error("invalid NIP-46 response shape");
  }
  // Some remote signers send explicit nulls for absent fields.
  const result = data["result"] === null ? undefined : data["result"];
  const error = data["error"] === null ? undefined : data["error"];
  if (result !== undefined && typeof result !== "string") {
    throw new Nip46Error("invalid NIP-46 response result");
  }
  if (error !== undefined && typeof error !== "string") {
    throw new Nip46Error("invalid NIP-46 response error");
  }
  const response: Nip46Response = { id: data["id"] };
  if (result !== undefined) {
    response.result = result;
  }
  if (error !== undefined) {
    response.error = error;
  }
  return response;
}
