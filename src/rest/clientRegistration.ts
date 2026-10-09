// RFC 7592 client configuration — CONTRACT.md §28.12 (contract 1.53).
//
// A client that registered itself through `POST /oauth2/register` (RFC 7591)
// receives, once, a `registration_client_uri` and a
// `registration_access_token`. With those two it can read, replace and delete
// **its own** registration: `AxiamClient.readClientRegistration`,
// `updateClientRegistration` and `deleteClientRegistration`, implemented here.
//
// Four rules shape all three (§28.12.2):
//
//   1. The URI is used verbatim, and only at the configured AXIAM. A URI whose
//      scheme, host or port differs from the client's base URL — or an `http`
//      URI unless the base URL is `http` on a loopback host — is refused
//      locally, before any request: the token is a bearer, and a helper that
//      followed a URI to another origin would hand it to whoever wrote it.
//   2. The token travels in `Authorization: Bearer` only.
//   3. It is not the SDK's session: these requests go out on the bare
//      transport (no cookie jar, no SDK access token, no CSRF header, no
//      redirects), and a `401` never reaches the §9 refresh guard.
//   4. Neither write is retried; the read follows §16, but never on a 4xx
//      other than 408 / 429.

import type { AxiosResponse } from 'axios';
import {
  mapHttpStatusToError,
  NetworkError,
  oauth2ErrorFromBody,
  Sensitive,
  type AxiamError,
} from '../core/index.js';
import { ValidationError } from '../management/errors.js';
import { bareRequest, retryableNetworkError, statusIsRetryable } from './bareTransport.js';
import type { AxiamClient } from './client.js';
import { withRetry } from './retry.js';

/**
 * An RFC 7591 §3.2.1 / RFC 7592 §3 client information response
 * (CONTRACT.md §28.12.1) — a protocol document, so its members keep their wire
 * spelling.
 *
 * @remarks
 * `registration_access_token` and `client_secret` are {@link Sensitive}
 * (§28.12.4): every stringification of this value — `String()`,
 * `JSON.stringify`, `console.log` / `util.inspect` — shows `"[SENSITIVE]"` in
 * their place.
 *
 * Every member the server sent that this type does not name is kept in
 * {@link ClientRegistration.extra} — RFC 7591 §3.2.1 lets a server add
 * members, and because an update is a **full replacement**, a member a read
 * returned and an update left out is a member the server deletes. Passing a
 * read's result straight to `updateClientRegistration` therefore sends it back
 * intact, including `jwks` / `jwks_uri` and the CIBA `backchannel_*` members.
 */
export interface ClientRegistration {
  /** The client's `client_id`. */
  client_id: string;
  /** When the client id was issued (seconds since the epoch). Never sent on an update. */
  client_id_issued_at?: number;
  /** The registered display name. */
  client_name?: string;
  /**
   * The registered redirect URIs. Absent when the read did not carry them as a
   * list of strings — then nothing is sent for them on an update, and a value
   * of another shape stays in {@link ClientRegistration.extra}, sent back as
   * read (contract 1.59, §34.2 P12.4).
   */
  redirect_uris?: string[];
  /** The registered grant types. Absent, and not sent, as {@link ClientRegistration.redirect_uris}. */
  grant_types?: string[];
  /** The registered response types. Absent, and not sent, as {@link ClientRegistration.redirect_uris}. */
  response_types?: string[];
  /** How the client authenticates at the token endpoint. The server refuses an update that changes it. */
  token_endpoint_auth_method?: string;
  /** The registered scope, space-separated. */
  scope?: string;
  /** Where this registration is read, replaced and deleted. Never sent on an update. */
  registration_client_uri?: string;
  /** When the client secret expires (`0` = never). Never sent on an update. */
  client_secret_expires_at?: number;
  /** The client's JWK Set, for a `private_key_jwt` client. */
  jwks?: unknown;
  /** Where the client's JWK Set is published. */
  jwks_uri?: string;
  /** The client secret — present only on the registration response itself, never on a read or an update. Never sent back. */
  client_secret?: Sensitive<string>;
  /**
   * The registration access token — present on the registration response
   * and, **rotated**, on every update response; absent on a read. Never sent
   * in a body.
   */
  registration_access_token?: Sensitive<string>;
  /** Every other member of the response, verbatim. */
  extra: Record<string, unknown>;
}

/**
 * The members `updateClientRegistration` never sends (§28.12.2 rule 4): the
 * first four the server refuses with `400 invalid_request`; `client_secret` it
 * never accepts back.
 */
const SERVER_STATED_MEMBERS = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret_expires_at',
  'client_id_issued_at',
  'client_secret',
] as const;

/**
 * Decode a client information response, tolerating unknown members
 * (§28.12.1: "An SDK MUST decode unknown members without failing").
 *
 * A known member of an unexpected type — a list holding a non-string item
 * included — is kept in `extra` as read rather than dropped or filtered, and a
 * member the response lacks stays absent: a replacement must neither lose what
 * the server holds nor invent what it does not (§28.12.2 rule 4, §34.2 P12.4).
 *
 * @throws NetworkError when the body is not a JSON object or carries no
 * `client_id` — a response this SDK cannot act on.
 */
export function clientRegistrationFromJson(value: unknown): ClientRegistration {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new NetworkError('client registration response is not a JSON object');
  }
  const map: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  const takeString = (key: string): string | undefined => {
    const v = map[key];
    if (typeof v === 'string') {
      delete map[key];
      return v;
    }
    if (v === null) delete map[key];
    return undefined;
  };
  const takeNumber = (key: string): number | undefined => {
    const v = map[key];
    if (typeof v === 'number') {
      delete map[key];
      return v;
    }
    if (v === null) delete map[key];
    return undefined;
  };
  const takeList = (key: string): string[] | undefined => {
    const v = map[key];
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
      delete map[key];
      return v as string[];
    }
    if (v === null) delete map[key];
    return undefined;
  };

  const clientId = takeString('client_id');
  if (clientId === undefined) {
    throw new NetworkError('client registration response carries no client_id');
  }
  let jwks: unknown;
  if ('jwks' in map) {
    jwks = map.jwks === null ? undefined : map.jwks;
    delete map.jwks;
  }
  const out: ClientRegistration = { client_id: clientId, extra: {} };
  const optional: Partial<ClientRegistration> = {
    redirect_uris: takeList('redirect_uris'),
    grant_types: takeList('grant_types'),
    response_types: takeList('response_types'),
    client_id_issued_at: takeNumber('client_id_issued_at'),
    client_name: takeString('client_name'),
    token_endpoint_auth_method: takeString('token_endpoint_auth_method'),
    scope: takeString('scope'),
    registration_client_uri: takeString('registration_client_uri'),
    client_secret_expires_at: takeNumber('client_secret_expires_at'),
    jwks,
    jwks_uri: takeString('jwks_uri'),
  };
  for (const [k, v] of Object.entries(optional)) {
    if (v !== undefined) (out as unknown as Record<string, unknown>)[k] = v;
  }
  const secret = takeString('client_secret');
  if (secret !== undefined) out.client_secret = new Sensitive(secret);
  const token = takeString('registration_access_token');
  if (token !== undefined) out.registration_access_token = new Sensitive(token);
  out.extra = map;
  return out;
}

/**
 * The RFC 7592 §2.2 replacement body: every member but the five the server
 * states (§28.12.2 rule 4), with `client_id` set to the registration's own. A
 * member `metadata` does not carry is not sent — a list included, never as
 * `[]` — and `extra`'s members go back as they were read (§34.2 P12.4).
 *
 * @internal — exported for the tests.
 */
export function clientRegistrationUpdateBody(metadata: ClientRegistration): Record<string, unknown> {
  const body: Record<string, unknown> = { ...metadata.extra };
  for (const key of SERVER_STATED_MEMBERS) delete body[key];
  body.client_id = metadata.client_id;
  const put = (key: string, value: unknown): void => {
    if (value !== undefined) body[key] = value;
  };
  put('client_name', metadata.client_name);
  put('redirect_uris', metadata.redirect_uris);
  put('grant_types', metadata.grant_types);
  put('response_types', metadata.response_types);
  put('token_endpoint_auth_method', metadata.token_endpoint_auth_method);
  put('scope', metadata.scope);
  put('jwks', metadata.jwks);
  put('jwks_uri', metadata.jwks_uri);
  return body;
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** `(scheme, host, port)` as compared for "same origin": lower-cased, port made explicit. */
function originOf(url: URL): string {
  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  const defaultPort = scheme === 'https' ? '443' : scheme === 'http' ? '80' : '';
  return `${scheme}://${url.hostname.toLowerCase()}:${url.port || defaultPort}`;
}

/**
 * §28.12.2 rule 1: accept `uri` only at the configured AXIAM origin.
 *
 * The refusal is a local {@link ValidationError} (§28.7's per-language
 * mapping; `status` 400, no request made) and names no part of the URI: it is
 * caller input, and an error message is the one most often logged.
 *
 * @internal
 */
export function checkRegistrationUri(baseUrl: string, uri: string, operation: string): URL {
  const refuse = (why: string): never => {
    throw new ValidationError(
      operation,
      400,
      `${operation}: registration_client_uri ${why} (CONTRACT.md §28.12.2 rule 1)`,
      [{ field: 'registration_client_uri', message: why }],
    );
  };
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return refuse('is not an absolute URL');
  }
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') {
    return refuse('must be an https URL');
  }
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return refuse('cannot be checked: the client base URL is not absolute');
  }
  if (originOf(parsed) !== originOf(base)) {
    return refuse(
      'is not at the configured AXIAM origin (scheme, host and port must match the client base URL)',
    );
  }
  if (scheme === 'http' && !LOOPBACK_HOSTS.has(base.hostname.toLowerCase())) {
    return refuse('must be https unless the base URL is http on a loopback host');
  }
  return parsed;
}

function expose(token: Sensitive<string> | string): string {
  return typeof token === 'string' ? token : token.expose();
}

/**
 * Map a non-2xx answer: a body with a non-empty `error` is an
 * `OAuthProtocolError` at any status (§28.12.3); anything else follows §2's
 * status rows. The message names the operation and the status only.
 */
function mapRegistrationError(operation: string, response: AxiosResponse): AxiamError {
  const protocol = oauth2ErrorFromBody(response.data);
  if (protocol) return protocol;
  return mapHttpStatusToError(response.status, `${operation}: HTTP ${response.status}`);
}

function decodeRegistration(operation: string, response: AxiosResponse): ClientRegistration {
  let body: unknown = response.data;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      throw new NetworkError(`${operation}: the response is not JSON`);
    }
  }
  return clientRegistrationFromJson(body);
}

/** @internal — `AxiamClient.readClientRegistration`. */
export async function readClientRegistration(
  client: AxiamClient,
  registrationClientUri: string,
  registrationAccessToken: Sensitive<string> | string,
): Promise<ClientRegistration> {
  const operation = 'read_client_registration';
  client.ensureOpen();
  checkRegistrationUri(client.session.baseUrl, registrationClientUri, operation);
  // Rule 1: the URI is used verbatim — query included — never rebuilt.
  const url = registrationClientUri;
  // §16 for the read — but a decisive 4xx (anything but 408 / 429) leaves the
  // runner as a value, so a bodiless 400 (§2: NetworkError) is not retried.
  const outcome = await withRetry<{ value?: ClientRegistration; error?: AxiamError }>(
    async () => {
      const response = await bareRequest(client.session, operation, {
        method: 'GET',
        url,
        headers: { Authorization: `Bearer ${expose(registrationAccessToken)}`, Accept: 'application/json' },
      });
      if (response.status >= 200 && response.status < 300) {
        return { value: decodeRegistration(operation, response) };
      }
      const error = mapRegistrationError(operation, response);
      if (statusIsRetryable(response.status) && error instanceof NetworkError) {
        throw retryableNetworkError(error.message, response);
      }
      return { error };
    },
    client.retryOptions(operation),
  );
  if (outcome.error) throw outcome.error;
  return outcome.value as ClientRegistration;
}

/** @internal — `AxiamClient.updateClientRegistration`. */
export async function updateClientRegistration(
  client: AxiamClient,
  registrationClientUri: string,
  registrationAccessToken: Sensitive<string> | string,
  metadata: ClientRegistration,
): Promise<ClientRegistration> {
  const operation = 'update_client_registration';
  client.ensureOpen();
  checkRegistrationUri(client.session.baseUrl, registrationClientUri, operation);
  // Rule 1: the URI is used verbatim — query included — never rebuilt.
  const url = registrationClientUri;
  // Never retried (§28.12.2 rule 5): one request, whatever happens to it.
  const response = await bareRequest(client.session, operation, {
    method: 'PUT',
    url,
    headers: {
      Authorization: `Bearer ${expose(registrationAccessToken)}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    data: JSON.stringify(clientRegistrationUpdateBody(metadata)),
  });
  if (response.status >= 200 && response.status < 300) {
    return decodeRegistration(operation, response);
  }
  throw mapRegistrationError(operation, response);
}

/** @internal — `AxiamClient.deleteClientRegistration`. */
export async function deleteClientRegistration(
  client: AxiamClient,
  registrationClientUri: string,
  registrationAccessToken: Sensitive<string> | string,
): Promise<void> {
  const operation = 'delete_client_registration';
  client.ensureOpen();
  checkRegistrationUri(client.session.baseUrl, registrationClientUri, operation);
  // Rule 1: the URI is used verbatim — query included — never rebuilt.
  const url = registrationClientUri;
  // Never retried: a retry after a lost 204 would read 401 and report a
  // successful deletion as a failure (§28.12.2 rule 5).
  const response = await bareRequest(client.session, operation, {
    method: 'DELETE',
    url,
    headers: { Authorization: `Bearer ${expose(registrationAccessToken)}` },
  });
  if (response.status >= 200 && response.status < 300) return;
  throw mapRegistrationError(operation, response);
}
