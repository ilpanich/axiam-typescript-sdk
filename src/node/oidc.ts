// OIDC / SSO relying-party helpers — CONTRACT.md §12 (contract 1.4).
//
// The nine canonical §12 operations, under the exact §12.2 TypeScript names:
// oidcDiscover, oidcBegin, oidcExchange, oidcRefresh, loginClientCredentials,
// introspect, revoke, ssoStart, ssoComplete.
//
// ── Why a separate class instead of methods on AxiamClient ─────────────────
// `AxiamClient` lives in the browser-safe `src/rest/` core, and CI's SC#1
// bundle-and-grep gate proves a `/rest` browser bundle pulls in zero Node-only
// code. These helpers need `node:crypto` (CSPRNG + SHA-256 for PKCE) and
// `jose` (ID-token verification), so hanging them off `AxiamClient` would drag
// both into every browser bundle. They therefore live on a Node-only
// `OidcClient` reached through the `axiam-sdk/node` subpath — the same shape
// the repo already uses for the gRPC-only operations (`AuthzGrpcClient`,
// `UserInfoGrpcClient`). §12 fixes the *method names*, not which object hosts
// them, so this is conformant; an SDK without a browser-bundle constraint
// (Rust, Python, Go, Java, Kotlin, C#, PHP) SHOULD put the nine methods
// directly on its existing client, as the plan's T2–T8 items say.
//
// Everything else is reuse, not reimplementation (§12 forbids forking):
//   * transport + §2 error mapping + §3 CSRF + §4 cookie jar + §5 tenant
//     header + §6 TLS  → the SharedSession/NodeSession axios instance;
//   * §9 single-flight refresh                → session.refreshGuard;
//   * §12.4 signature verification            → node/jwks.ts's verifier;
//   * §7/§12.5 redaction                      → core/sensitive.ts.

import type { AxiosRequestConfig, AxiosResponse } from 'axios';
import {
  AuthError,
  AxiamError,
  isOAuth2ErrorBody,
  mapHttpStatusToError,
  NetworkError,
  OAuthProtocolError,
  sanitizeAxiosError,
  Sensitive,
} from '../core/index.js';
import type { SharedSession } from '../rest/session.js';
import { createJwksVerifier, type JwksVerifier } from './jwks.js';
import type { IdTokenClaims } from './oidcIdToken.js';
import {
  CODE_CHALLENGE_METHOD_S256,
  computeCodeChallenge,
  generateCodeVerifier,
  randomUrlSafeToken,
} from './oidcPkce.js';
import type {
  AuthorizationRequest,
  IntrospectParams,
  IntrospectionResponseWire,
  IntrospectionResult,
  LoginClientCredentialsParams,
  OidcBeginParams,
  OidcConfiguration,
  OidcExchangeParams,
  OidcRefreshParams,
  OidcStartResponseWire,
  OidcTokenSet,
  RevokeParams,
  SsoCompleteParams,
  SsoCompleteResult,
  SsoLoginSuccessResponseWire,
  SsoStartParams,
  SsoStartResult,
  TokenResponseWire,
  DeviceAuthorization,
  DeviceAuthorizationResponseWire,
  DeviceAuthorizeParams,
  DeviceLoginParams,
  DevicePollParams,
  ExchangedToken,
  LogoutUrlParams,
  TokenExchangeParams,
  TokenExchangeResponseWire,
  VerifiedLogoutToken,
  RequestedPermission,
  RequestingPartyToken,
  ResourceSet,
  ResourceSetWire,
  RptResponseWire,
  UmaChallenge,
  UmaExchangeTicketParams,
  OidcParParams,
  PushedAuthorizationRequest,
  PushedAuthorizationResponseWire,
} from './oidcTypes.js';

/** Path of the OIDC discovery document, relative to the client base URL. */
export const DISCOVERY_PATH = '/.well-known/openid-configuration';

/** Path of the federation SSO step-1 endpoint. */
export const SSO_START_PATH = '/api/v1/auth/federation/oidc/start';

/** Path of the federation SSO step-2 (callback) endpoint. */
export const SSO_CALLBACK_PATH = '/api/v1/auth/federation/oidc/callback';

/**
 * Minimum — and default — discovery-cache TTL. CONTRACT.md §12.3 rule 6 sets
 * a floor of 5 minutes; a smaller configured value is raised to it.
 */
export const MIN_DISCOVERY_TTL_MS = 300_000;

/** `grant_type` of the device access-token request (RFC 8628 §3.4). */
export const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * Polling interval used when the authorization response omits `interval`
 * (RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT hard-code a faster floor.
 */
export const DEFAULT_POLL_INTERVAL_SECS = 5;

/**
 * Seconds added to the polling interval on each `slow_down` (§14.2 rule 1).
 * The increase is permanent and cumulative.
 */
export const SLOW_DOWN_INCREMENT_SECS = 5;

/** `grant_type` of an RFC 8693 exchange. */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * The `actor_token_type` this SDK sends, and the `subject_token_type` a caller
 * names for the same-domain exchange of §15.1. There is no default: the type is
 * a required member of {@link TokenExchangeParams}.
 */
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * A JWT from a trusted external issuer — the cross-domain exchange of §15.7.
 *
 * @remarks
 * Pass it as {@link TokenExchangeParams.subjectTokenType} to exchange a partner
 * IdP's token. AXIAM also accepts {@link ACCESS_TOKEN_TYPE} for an external
 * issuer, and refuses refresh and ID token types **by name**.
 */
export const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

/** `grant_type` of the UMA ticket grant (UMA 2.0 §3.3.1, CONTRACT.md §20.1). */
export const UMA_TICKET_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:uma-ticket';

/** The scope that makes an access token a Protection API Token (§20.2 rule 1). */
export const UMA_PROTECTION_SCOPE = 'uma_protection';

/** The only `claim_token_format` AXIAM v1 accepts (§20.2 rule 2). */
export const UMA_CLAIM_TOKEN_FORMAT = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * Parse a `WWW-Authenticate: UMA …` header value (CONTRACT.md §20.3).
 *
 * @remarks
 * **This deliberately does not exchange the ticket.** Parsing a challenge and
 * acting on it are separate decisions: the `as_uri` names an authorization
 * server this client has not necessarily chosen to trust, and auto-exchanging
 * would send the requesting party's `claimToken` to whatever host answered the
 * 403. The caller decides.
 *
 * @returns the parsed challenge, or `undefined` when the header is not a UMA
 * challenge.
 */
export function umaParseChallenge(header: string): UmaChallenge | undefined {
  const trimmed = header.trim();
  if (!trimmed.startsWith('UMA')) return undefined;
  const rest = trimmed.slice(3);
  // "UMA" alone is a valid, if useless, challenge; anything else must be
  // separated by whitespace so `UMAX realm="…"` is not read as UMA.
  if (rest.length > 0 && !/^\s/.test(rest)) return undefined;

  const challenge: UmaChallenge = {};
  for (const part of rest.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim().replace(/^"|"$/g, '');
    if (key === 'realm') challenge.realm = value;
    else if (key === 'as_uri') challenge.asUri = value;
    else if (key === 'ticket') challenge.ticket = new Sensitive(value);
  }
  return challenge;
}

/**
 * Format a `WWW-Authenticate: UMA` header value (§20.3, emit half).
 *
 * The resource-server side: having obtained a ticket from `umaRequestTicket`,
 * tell the caller where to redeem it.
 */
export function umaChallengeHeader(
  realm: string,
  asUri: string,
  ticket: Sensitive<string> | string,
): string {
  return `UMA realm="${realm}", as_uri="${asUri}", ticket="${exposeSecret(ticket)}"`;
}

/** Map the camelCase {@link ResourceSet} onto the snake_case wire shape. */
function toResourceSetWire(resource: ResourceSet): ResourceSetWire {
  return {
    name: resource.name,
    ...(resource.type !== undefined ? { type: resource.type } : {}),
    // Always sent, even when empty: an update replaces the scope list, and
    // omitting the key would leave the server's copy untouched (§20.2 rule 8).
    resource_scopes: resource.resourceScopes ?? [],
  };
}

/** Map the wire shape back onto {@link ResourceSet}. */
function fromResourceSetWire(wire: ResourceSetWire): ResourceSet {
  return {
    ...(wire._id != null ? { id: wire._id } : {}),
    name: wire.name,
    ...(wire.type != null ? { type: wire.type } : {}),
    resourceScopes: wire.resource_scopes ?? [],
  };
}

/**
 * The `events` member that distinguishes a logout token from an ID token
 * (OIDC Back-Channel Logout 1.0 §2.4).
 */
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/**
 * Maximum age accepted for a logout token's `iat`, in seconds. AXIAM issues
 * them with a 120 s lifetime; this bound is the same order and stops a token
 * captured from a mis-configured RP being replayed days later.
 */
export const MAX_LOGOUT_TOKEN_AGE_SECS = 300;

/** The claim shape of a back-channel logout token (§12.7.3). */
interface LogoutTokenClaims {
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
  jti?: string;
  sid?: string;
  sub?: string;
  events?: Record<string, unknown>;
  /** Never legitimately present — see `verifyLogoutToken`. */
  nonce?: string;
}

/**
 * The §14.2 polling schedule: the interval, and the deadline it stops at.
 *
 * @remarks
 * Exported so the arithmetic §14.2 rules 1, 2 and 4 describe can be tested
 * exhaustively and instantly. Driving it through a mock HTTP server would
 * test the transport rather than the rule, and would take a real half-minute
 * to assert one `slow_down`.
 *
 * @internal
 */
export class PollSchedule {
  #intervalSecs: number;
  #remainingSecs: number;

  constructor(intervalSecs: number, expiresInSecs: number) {
    this.#intervalSecs = intervalSecs > 0 ? intervalSecs : DEFAULT_POLL_INTERVAL_SECS;
    this.#remainingSecs = expiresInSecs;
  }

  /** The current inter-poll delay, in seconds. */
  get intervalSecs(): number {
    return this.#intervalSecs;
  }

  /** Apply one `slow_down` (§14.2 rule 1): **cumulative, never reset.** */
  slowDown(): void {
    this.#intervalSecs += SLOW_DOWN_INCREMENT_SECS;
  }

  /**
   * Consume one interval's worth of the grant's remaining life.
   *
   * @returns `false` when the deadline has been reached, at which point the
   * caller MUST stop (§14.2 rule 4) — the deadline is authoritative even if
   * the server is still answering `authorization_pending`.
   */
  tick(): boolean {
    if (this.#intervalSecs >= this.#remainingSecs) {
      this.#remainingSecs = 0;
      return false;
    }
    this.#remainingSecs -= this.#intervalSecs;
    return true;
  }
}

/** Await `ms` milliseconds. Extracted so tests can stub the timer. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** The `openid` scope, which every authorization request must carry (§12.1 rule 4). */
const OPENID_SCOPE = 'openid';

/**
 * The eight query parameters `oidcBegin` owns (§12.1 rule 5). Caller-supplied
 * `extraParams` may add to the authorization request but never override these.
 */
const RESERVED_AUTHORIZE_PARAMS = new Set([
  'response_type',
  'client_id',
  'redirect_uri',
  'scope',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
]);

/** Shape of a UUID, used to reject a slug where §12.3 rule 4 requires a UUID. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Configuration for {@link OidcClient}. */
export interface OidcClientOptions {
  /**
   * The relying party's OAuth2 `client_id`. Used on every grant and matched
   * against the ID token's `aud`/`azp` (§12.4 rule 4).
   */
  clientId: string;
  /**
   * The `client_secret` for a confidential client, held behind
   * {@link Sensitive} (§12.5). Omit for a public client — then it is never
   * added to a form body (§12.1 "MUST omit rather than send empty/null").
   *
   * `introspect` and `revoke` REQUIRE it: the server marks `client_secret`
   * non-nullable on both, so a public client cannot call them (§12.1 note 4).
   */
  clientSecret?: Sensitive<string> | string;
  /**
   * Default tenant UUID for the `tenant_id` query parameter the token,
   * introspection and revocation endpoints require. Falls back to the
   * session's configured `tenantId` when it was built in UUID form; a
   * slug-only client must pass `tenantId` per call (§12.3 rule 4).
   */
  tenantId?: string;
  /**
   * Discovery-cache TTL in milliseconds. Defaults to (and is floored at)
   * {@link MIN_DISCOVERY_TTL_MS} — §12.3 rule 6 forbids a TTL under 5 minutes.
   */
  discoveryTtlMs?: number;
  /**
   * Permitted ID-token clock skew in seconds. Defaults to 60 and is clamped to
   * 60 — §12.4 rule 5 forbids configuring it higher.
   */
  clockSkewSec?: number;
}

/** A cached discovery document together with its expiry. */
interface CachedDiscovery {
  document: OidcConfiguration;
  expiresAt: number;
}

/**
 * Origin-keyed discovery cache with single-flight fetching
 * (CONTRACT.md §12.3 rule 6).
 *
 * @remarks
 * The key is the **normalized scheme + host + port** of the base URL the
 * document was fetched from, so a document fetched from one origin can never
 * be served for another (cross-issuer cache poisoning). The cache is *not*
 * keyed on the tenant, and — because each {@link OidcClient} owns its own
 * instance — it is not shared across tenants either, nor process-global.
 *
 * Single-flight uses the same mechanism §9 prescribes for TypeScript: a shared
 * `Promise` held in a map for the duration of the fetch, cleared on settle, so
 * N concurrent callers produce exactly one HTTP request and all receive the
 * same document (or the same failure).
 *
 * @internal
 */
class DiscoveryCache {
  readonly #documents = new Map<string, CachedDiscovery>();
  readonly #inFlight = new Map<string, Promise<OidcConfiguration>>();
  readonly #ttlMs: number;

  constructor(ttlMs: number) {
    this.#ttlMs = Math.max(ttlMs, MIN_DISCOVERY_TTL_MS);
  }

  async get(originKey: string, fetcher: () => Promise<OidcConfiguration>): Promise<OidcConfiguration> {
    const cached = this.#documents.get(originKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.document;
    }

    const pending = this.#inFlight.get(originKey);
    if (pending) {
      return pending;
    }

    const fetch = fetcher()
      .then((document) => {
        this.#documents.set(originKey, { document, expiresAt: Date.now() + this.#ttlMs });
        return document;
      })
      .finally(() => {
        this.#inFlight.delete(originKey);
      });
    this.#inFlight.set(originKey, fetch);
    return fetch;
  }
}

/**
 * Normalize a URL to its cache key: lowercased scheme and host with the port
 * always explicit (§12.3 rule 6). `https://IAM.example.com/` and
 * `https://iam.example.com:443/x` therefore share one key, while
 * `http://iam.example.com` gets its own.
 */
export function normalizeOrigin(url: string): string {
  const parsed = new URL(url);
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const defaultPort = scheme === 'https' ? '443' : scheme === 'http' ? '80' : '';
  const port = parsed.port || defaultPort;
  return `${scheme}://${host}:${port}`;
}

/** Read a secret that the caller may have supplied wrapped or bare. */
function exposeSecret(value: Sensitive<string> | string): string {
  return typeof value === 'string' ? value : value.expose();
}

/** Pull the HTTP status off an axios-shaped error, if any. */
function axiosStatus(err: unknown): number | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    return (err as { response?: { status?: number } }).response?.status;
  }
  return undefined;
}

/** Pull the parsed response body off an axios-shaped error, if any. */
function axiosBody(err: unknown): unknown {
  if (err && typeof err === 'object' && 'response' in err) {
    return (err as { response?: { data?: unknown } }).response?.data;
  }
  return undefined;
}

/** Best-effort human-readable message from a parsed error body. */
function bodyMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const record = body as Record<string, unknown>;
    if (typeof record.error_description === 'string') {
      return record.error_description;
    }
    if (typeof record.message === 'string') {
      return record.message;
    }
  }
  return fallback;
}

/**
 * Map any failure from a §12 wire call onto the §2 taxonomy, routing
 * everything through the single `mapHttpStatusToError` source of truth so the
 * endpoint-qualified `OAuthProtocolError` rows apply (§12.3 rule 3).
 *
 * An error that is *already* an `AxiamError` is passed through untouched: the
 * rest/interceptors.ts response interceptor may have mapped it first (it does
 * exactly that for a 401 on an `/oauth2/*` path), and re-mapping would discard
 * the richer error it built.
 */
function mapOidcError(err: unknown, url: string, fallbackMessage: string): AxiamError {
  if (err instanceof AxiamError) {
    return err;
  }
  const status = axiosStatus(err);
  if (status !== undefined) {
    const body = axiosBody(err);
    return mapHttpStatusToError(status, bodyMessage(body, fallbackMessage), { url, body, cause: err });
  }
  return new NetworkError(fallbackMessage, sanitizeAxiosError(err));
}

/**
 * Map an error from the **uma-ticket grant**, where `access_denied` arrives as
 * HTTP **403** (UMA 2.0 §3.3.6) rather than the 400 every other OAuth2 error
 * uses.
 *
 * @remarks
 * §20.4 requires dispatching on the `error` field rather than the status, so
 * that the code reaches the caller whichever status carries it. This is kept
 * local to the ticket grant on purpose: {@link mapHttpStatusToError}'s §2 rows
 * apply the OAuth2 mapping to 400/401 only, and widening that globally would
 * change how every OAuth2 endpoint's 403 is reported — a cross-cutting change
 * this grant does not need and did not ask for. An ordinary REST 403 keeps
 * mapping to `AuthzError`.
 */
function mapUmaGrantError(err: unknown, url: string, fallbackMessage: string): AxiamError {
  if (err instanceof AxiamError) {
    return err;
  }
  const body = axiosBody(err);
  if (axiosStatus(err) === 403 && isOAuth2ErrorBody(body)) {
    return new OAuthProtocolError(body.error, body.error_description);
  }
  return mapOidcError(err, url, fallbackMessage);
}

/**
 * The OIDC / SSO relying-party client (CONTRACT.md §12).
 *
 * @remarks
 * Build one with {@link createOidcClient}, passing the same session your
 * `AxiamClient` uses so the cookie jar (§4), TLS configuration (§6), tenant
 * header (§5) and single-flight refresh guard (§9) are shared rather than
 * duplicated.
 *
 * **The caller owns the login state.** `oidcBegin` returns `state`, `nonce`
 * and `codeVerifier`; this class stores none of them (§12.3 rule 1). Keep them
 * in your own HTTP session — or use {@link MemoryOidcStateStore} together with
 * the `oidcLoginHandlers` glue from `axiam-sdk/middleware`, which does that
 * bookkeeping for you.
 *
 * @example
 * ```ts
 * const session = createNodeSession({ baseUrl, tenantId });
 * const oidc = createOidcClient(session, { clientId: 'my-app', clientSecret: secret });
 *
 * // 1. redirect the browser
 * const configuration = await oidc.oidcDiscover();
 * const request = oidc.oidcBegin({ configuration, redirectUri, scope: 'openid profile' });
 * // …store request.state / request.nonce / request.codeVerifier in your session…
 * res.redirect(request.url);
 *
 * // 2. on the callback, having checked the returned `state` matches
 * const tokens = await oidc.oidcExchange({
 *   code, codeVerifier: request.codeVerifier, nonce: request.nonce, redirectUri,
 * });
 * console.log(tokens.idClaims?.sub);   // validated ID-token subject
 * ```
 */
export class OidcClient {
  readonly #session: SharedSession;
  readonly #options: OidcClientOptions;
  readonly #discoveryCache: DiscoveryCache;
  /** One verifier per `jwks_uri` — the same node/jwks.ts implementation the §10 middleware uses. */
  readonly #verifiers = new Map<string, JwksVerifier>();
  /** The access token adopted by `loginClientCredentials({ adoptAsCredential: true })`, if any. */
  #adoptedCredential: Sensitive<string> | null = null;
  #adoptionInterceptorInstalled = false;
  /** In-flight `oidcRefresh`, shared by concurrent callers (§9 rule 2). */
  #pendingRefresh: Promise<OidcTokenSet> | null = null;

  constructor(session: SharedSession, options: OidcClientOptions) {
    this.#session = session;
    this.#options = options;
    this.#discoveryCache = new DiscoveryCache(options.discoveryTtlMs ?? MIN_DISCOVERY_TTL_MS);
  }

  // -------------------------------------------------------------------------
  // 1. oidcDiscover
  // -------------------------------------------------------------------------

  /**
   * `GET /.well-known/openid-configuration` (§12.1) — fetch the OIDC discovery
   * document, cached per origin with a ≥5-minute TTL and single-flight
   * de-duplication of concurrent calls (§12.3 rule 6).
   *
   * The document's own `issuer` is authoritative for ID-token validation and
   * may legitimately differ from `baseUrl` behind a proxy, so a mismatch is
   * never treated as an error.
   */
  async oidcDiscover(): Promise<OidcConfiguration> {
    const originKey = normalizeOrigin(this.#session.baseUrl);
    return this.#discoveryCache.get(originKey, async () => {
      const response = await this.#get<OidcConfiguration>(DISCOVERY_PATH, 'oidc discovery request failed');
      return response.data;
    });
  }

  // -------------------------------------------------------------------------
  // 2. oidcBegin
  // -------------------------------------------------------------------------

  /**
   * Build an authorization request (§12.1) — **pure local computation, no
   * network I/O**.
   *
   * Generates a 32-byte CSPRNG `state` and `nonce` (base64url, unpadded) and a
   * fresh PKCE verifier/challenge pair using **S256 only** — `plain` is not
   * implemented anywhere in this SDK. The URL is built from the discovery
   * document's `authorization_endpoint` with exactly the eight parameters
   * §12.1 rule 5 mandates, plus any `extraParams` the caller adds.
   *
   * Nothing is stored: persist the returned `state`, `nonce` and
   * `codeVerifier` yourself (§12.3 rule 1).
   *
   * @throws Error when `extraParams` tries to override one of the eight
   *   SDK-owned parameters — a programming error, caught at call time.
   */
  oidcBegin(params: OidcBeginParams): AuthorizationRequest {
    const state = randomUrlSafeToken();
    const nonce = randomUrlSafeToken();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = computeCodeChallenge(codeVerifier.expose());

    const scope = normalizeScope(params.scope);
    const target = new URL(params.configuration.authorization_endpoint);
    const query = new URLSearchParams(target.search);

    for (const [key, value] of Object.entries(params.extraParams ?? {})) {
      if (RESERVED_AUTHORIZE_PARAMS.has(key)) {
        throw new Error(
          `oidcBegin: extraParams may not override the SDK-owned authorization parameter "${key}" (CONTRACT.md §12.1 rule 5).`,
        );
      }
      query.set(key, value);
    }

    query.set('response_type', 'code');
    query.set('client_id', this.#options.clientId);
    query.set('redirect_uri', params.redirectUri);
    query.set('scope', scope);
    query.set('state', state);
    query.set('nonce', nonce);
    query.set('code_challenge', codeChallenge);
    query.set('code_challenge_method', CODE_CHALLENGE_METHOD_S256);

    // URLSearchParams serializes a space as '+', which is legal in a query
    // string but not RFC 3986 percent-encoding; §12.1 rule 5 asks for the
    // latter, so spaces become %20. Every other character is already
    // percent-encoded correctly by URLSearchParams.
    target.search = query.toString().replace(/\+/g, '%20');

    return { url: target.toString(), state, nonce, codeVerifier };
  }

  // -------------------------------------------------------------------------
  // 3. oidcExchange
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/token` with `grant_type=authorization_code` (§12.1) —
   * exchange an authorization code for a token set, validating the returned
   * ID token in full before returning.
   *
   * The `nonce` argument is mandatory: this grant always requests the `openid`
   * scope, so §12.4 rule 6 always applies. If **any** §12.4 rule fails, the
   * whole token set is discarded and `AuthError` is raised with the matching
   * reason code — the access and refresh tokens from the same response are
   * never returned (§12.4 rule 7).
   */
  async oidcExchange(params: OidcExchangeParams): Promise<OidcTokenSet> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', 'authorization_code');
    form.set('code', params.code);
    form.set('code_verifier', exposeSecret(params.codeVerifier));
    form.set('redirect_uri', params.redirectUri);
    form.set('client_id', this.#options.clientId);
    this.#appendClientSecret(form);

    const wire = await this.#postToken(configuration, form, params.tenantId);
    return this.#toTokenSet(wire, configuration, params.nonce);
  }

  // -------------------------------------------------------------------------
  // 4. oidcRefresh
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1) — refresh an
   * {@link OidcTokenSet}, under the §9 single-flight refresh guard.
   *
   * @remarks
   * This is a **distinct operation** from `AxiamClient.refresh()`, which drives
   * the cookie/opaque-token session path at `POST /api/v1/auth/refresh`. The
   * two are never merged or aliased and neither falls back to the other
   * (§12.1). They do share the session's §9 guard, so at most one refresh of
   * either kind is ever in flight for a session.
   *
   * Concurrent `oidcRefresh` calls collapse into one HTTP request and all
   * receive the same token set — §9 rule 2's result sharing.
   *
   * An `id_token` in the response is validated against §12.4 rules 1–5 and 7;
   * rule 6 (nonce) is skipped, since OIDC Core §12.2 does not require a nonce
   * in a refresh-issued ID token.
   */
  oidcRefresh(params: OidcRefreshParams): Promise<OidcTokenSet> {
    const existing = this.#pendingRefresh;
    if (existing) {
      return existing;
    }
    const pending = this.#refreshUnderGuard(params);
    this.#pendingRefresh = pending;
    const clear = (): void => {
      if (this.#pendingRefresh === pending) {
        this.#pendingRefresh = null;
      }
    };
    pending.then(clear, clear);
    return pending;
  }

  // -------------------------------------------------------------------------
  // 5. loginClientCredentials
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) —
   * service-account machine-to-machine login.
   *
   * Requests no `openid` scope, so the response carries no `id_token`. Pass
   * `adoptAsCredential: true` to additionally use the returned access token as
   * this session's bearer credential for subsequent REST calls (§12.1, a MAY).
   *
   * @throws AuthError when no `clientSecret` is configured — this grant cannot
   *   be performed by a public client.
   */
  async loginClientCredentials(params: LoginClientCredentialsParams = {}): Promise<OidcTokenSet> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', 'client_credentials');
    form.set('client_id', this.#options.clientId);
    form.set('client_secret', this.#requireClientSecret('loginClientCredentials'));
    if (params.scope !== undefined) {
      form.set('scope', params.scope);
    }

    const wire = await this.#postToken(configuration, form, params.tenantId);
    // No nonce: rule 6 does not apply to this grant (§12.4 rule 6).
    const tokenSet = await this.#toTokenSet(wire, configuration, undefined);

    if (params.adoptAsCredential) {
      this.#adoptCredential(tokenSet.accessToken);
    }
    return tokenSet;
  }

  // -------------------------------------------------------------------------
  // 6. introspect
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/introspect` (RFC 7662, §12.1) — ask the server whether a
   * token is active and, if so, for its metadata.
   *
   * Requires confidential-client credentials (§12.1 note 4). A `401` here is a
   * *client-credential* failure surfaced as `OAuthProtocolError`; it never
   * enters the §9 refresh guard, because refreshing the user session cannot
   * fix a bad `client_secret` (§12.3 rule 3).
   *
   * @throws AuthError when no `clientSecret` is configured.
   */
  async introspect(params: IntrospectParams): Promise<IntrospectionResult> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('token', exposeSecret(params.token));
    form.set('client_id', this.#options.clientId);
    form.set('client_secret', this.#requireClientSecret('introspect'));
    if (params.tokenTypeHint !== undefined) {
      form.set('token_type_hint', params.tokenTypeHint);
    }

    const url = this.#endpointUrl(configuration.introspection_endpoint, params.tenantId);
    const response = await this.#postForm<IntrospectionResponseWire>(url, form, 'introspect request failed');
    const wire = response.data;
    return {
      active: wire.active,
      ...(wire.sub != null ? { sub: wire.sub } : {}),
      ...(wire.client_id != null ? { clientId: wire.client_id } : {}),
      ...(wire.scope != null ? { scope: wire.scope } : {}),
      ...(wire.token_type != null ? { tokenType: wire.token_type } : {}),
      ...(wire.exp != null ? { exp: wire.exp } : {}),
      ...(wire.iat != null ? { iat: wire.iat } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // 7. revoke
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/revoke` (RFC 7009, §12.1) — revoke an access or refresh
   * token. Returns nothing.
   *
   * Per RFC 7009 the server answers `200` for unknown, expired and
   * already-revoked tokens alike, so revocation is **idempotent**: any `200`
   * is success and no error is raised for a token the server has never seen.
   * Only a `401` (client authentication failed) is an error, surfaced as
   * `OAuthProtocolError` (§12.1 note 5, §12.3 rule 3).
   *
   * @throws AuthError when no `clientSecret` is configured.
   */
  async revoke(params: RevokeParams): Promise<void> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('token', exposeSecret(params.token));
    form.set('client_id', this.#options.clientId);
    form.set('client_secret', this.#requireClientSecret('revoke'));
    if (params.tokenTypeHint !== undefined) {
      form.set('token_type_hint', params.tokenTypeHint);
    }

    const url = this.#endpointUrl(configuration.revocation_endpoint, params.tenantId);
    await this.#postForm<void>(url, form, 'revoke request failed');
  }

  // -------------------------------------------------------------------------
  // 8. ssoStart
  // -------------------------------------------------------------------------

  /**
   * `POST /api/v1/auth/federation/oidc/start` (§12.1) — step 1 of first-time
   * SSO against an **upstream** IdP. No JWT required.
   *
   * One tenant form (`tenantId` or `tenantSlug`) and one org form (`orgId` or
   * `orgSlug`) must be resolvable, from the arguments or from the session's
   * construction options (§5.1). Redirect the browser to the returned
   * `authorizeUrl` and round-trip `state` back into {@link ssoComplete}
   * unmodified — the server keeps the nonce to itself (§12.1 note 7).
   *
   * @throws AuthError client-side, without a wire call, when tenant or org
   *   context cannot be resolved.
   */
  async ssoStart(params: SsoStartParams): Promise<SsoStartResult> {
    const tenantId = params.tenantId ?? this.#session.tenantId;
    const tenantSlug = params.tenantSlug ?? this.#session.tenantSlug;
    const orgId = params.orgId ?? this.#session.orgId;
    const orgSlug = params.orgSlug ?? this.#session.orgSlug;

    if (!tenantId && !tenantSlug) {
      throw new AuthError(
        'ssoStart requires tenant context: pass tenantId or tenantSlug, or construct the client with one (CONTRACT.md §5.1).',
      );
    }
    if (!orgId && !orgSlug) {
      throw new AuthError(
        'ssoStart requires organization context: pass orgId or orgSlug, or construct the client with one (CONTRACT.md §5.1).',
      );
    }

    const body: Record<string, string> = {
      federation_config_id: params.federationConfigId,
      redirect_uri: params.redirectUri,
    };
    // One tenant form AND one org form (§5.1). The UUID form wins when both
    // are present, mirroring how tenantSlug/tenantId already resolve.
    if (tenantId) {
      body.tenant_id = tenantId;
    } else if (tenantSlug) {
      body.tenant_slug = tenantSlug;
    }
    if (orgId) {
      body.org_id = orgId;
    } else if (orgSlug) {
      body.org_slug = orgSlug;
    }

    const response = await this.#postJson<OidcStartResponseWire>(
      SSO_START_PATH,
      body,
      'ssoStart request failed',
    );
    return {
      authorizeUrl: response.data.authorize_url,
      state: response.data.state,
      expiresInSecs: response.data.expires_in_secs,
    };
  }

  // -------------------------------------------------------------------------
  // 9. ssoComplete
  // -------------------------------------------------------------------------

  /**
   * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — step 2 of upstream
   * SSO: consumes the single-use `state`, provisions or links the user, and
   * establishes the session.
   *
   * @remarks
   * The session arrives as **`Set-Cookie`**, not in the response body
   * (§12.1 note 6), so this call must go through the §4 cookie jar: use a
   * `NodeSession` (`createNodeSession`/`createNodeClient`) or the session is
   * silently lost. On success the session is marked authenticated and its
   * post-authentication hook runs, syncing the CSRF token and cached access
   * token out of the jar exactly as `login()` does.
   *
   * §12.4 does not apply here — no ID token ever reaches the SDK on the
   * federation path.
   */
  async ssoComplete(params: SsoCompleteParams): Promise<SsoCompleteResult> {
    const response = await this.#postJson<SsoLoginSuccessResponseWire>(
      SSO_CALLBACK_PATH,
      { state: params.state, code: params.code },
      'ssoComplete request failed',
    );

    this.#session.authenticated = true;
    // Same post-login sync login()/verifyMfa() perform (CR-01/D-05): reads the
    // freshly-set axiam_csrf/axiam_access cookies out of the jar. A no-op on
    // the browser SharedSession, which has no jar.
    await this.#session.onAuthenticated?.();

    return {
      userId: response.data.user_id,
      sessionId: response.data.session_id,
      expiresIn: response.data.expires_in,
      redirectUri: response.data.redirect_uri,
    };
  }

  // -------------------------------------------------------------------------
  // §14 Device Authorization Grant (RFC 8628)
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/device_authorization` (CONTRACT.md §14.1) — start the grant
   * and obtain the code pair.
   *
   * @remarks
   * **Unauthenticated by design.** A device that cannot show a browser also
   * cannot hold a client secret, so this never sends `client_secret` and never
   * refuses a client built without one (§14.1).
   */
  async deviceAuthorize(params: DeviceAuthorizeParams = {}): Promise<DeviceAuthorization> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const endpoint = configuration.device_authorization_endpoint;
    if (!endpoint) {
      throw new AuthError(
        "the authorization server's discovery document advertises no " +
          'device_authorization_endpoint: this server does not support the device grant ' +
          '(CONTRACT.md §14.1)',
      );
    }

    const form = new URLSearchParams();
    form.set('client_id', this.#options.clientId);
    if (params.scope !== undefined) {
      form.set('scope', Array.isArray(params.scope) ? params.scope.join(' ') : params.scope);
    }

    const url = this.#endpointUrl(endpoint, params.tenantId);
    const { data } = await this.#postForm<DeviceAuthorizationResponseWire>(
      url,
      form,
      'device authorization request failed',
    );

    return {
      deviceCode: new Sensitive(data.device_code),
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      ...(data.verification_uri_complete != null
        ? { verificationUriComplete: data.verification_uri_complete }
        : {}),
      expiresIn: data.expires_in,
      // §14.2 rule 2: the interval comes from the response; only its absence
      // falls back to the RFC default. A server-sent 0 is treated as absent —
      // polling with no delay is never what the server meant.
      interval: data.interval != null && data.interval > 0 ? data.interval : DEFAULT_POLL_INTERVAL_SECS,
    };
  }

  // -------------------------------------------------------------------------
  // §26 Pushed Authorization Requests (RFC 9126)
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/par` (CONTRACT.md §26.1) — push the authorization request
   * over the back channel and get an opaque handle to redirect with.
   *
   * @remarks
   * PAR moves the authorization request off the browser. Instead of putting
   * `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
   * agent carries, the client POSTs them straight to AXIAM over an
   * authenticated channel and puts an opaque `request_uri` in the redirect.
   * What travels through the browser is then a random string that cannot be
   * edited into meaning something else.
   *
   * **Required for a FAPI 2.0 client** — `profile: "fapi2"` refuses a
   * registration that does not set `require_par`, so such a client cannot
   * authorize any other way (§21.1).
   *
   * This is a §12 extension, not a replacement: `oidcExchange` afterwards is
   * unchanged, and carries the same `codeVerifier` and `redirectUri`
   * ({@link PushedAuthorizationRequest.codeVerifier} is the one `oidcBegin`
   * produced — §26.2 rule 6).
   *
   * @example
   * ```ts
   * const configuration = await oidc.oidcDiscover();
   * const begun = oidc.oidcBegin({ configuration, redirectUri, scope: 'openid profile' });
   * const pushed = await oidc.oidcPar({ request: begun, redirectUri, scope: 'openid profile' });
   *
   * redirect(pushed.authorizationUrl);           // client_id + request_uri, nothing else
   * // …later, on the callback:
   * const tokens = await oidc.oidcExchange({
   *   code, redirectUri, nonce: pushed.nonce, codeVerifier: pushed.codeVerifier,
   * });
   * ```
   */
  async oidcPar(params: OidcParParams): Promise<PushedAuthorizationRequest> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const endpoint = configuration.pushed_authorization_request_endpoint;
    if (!endpoint) {
      throw new AuthError(
        "the authorization server's discovery document advertises no " +
          'pushed_authorization_request_endpoint: this server does not support RFC 9126 ' +
          '(CONTRACT.md §26.1)',
      );
    }

    // §26.2 rule 1: everything below was computed by `oidcBegin`. There is no
    // second generator here, and there must not be — two sources for `state`
    // or the PKCE pair are two things that can disagree.
    const request = params.request;
    const form = new URLSearchParams();
    form.set('client_id', this.#options.clientId);
    form.set('response_type', 'code');
    form.set('redirect_uri', params.redirectUri);
    form.set('scope', normalizeScope(params.scope));
    form.set('state', request.state);
    form.set('nonce', request.nonce);
    form.set('code_challenge', computeCodeChallenge(exposeSecret(request.codeVerifier)));
    form.set('code_challenge_method', CODE_CHALLENGE_METHOD_S256);
    this.#appendClientSecret(form);

    const url = this.#endpointUrl(endpoint, params.tenantId);
    // Deliberately NOT routed through the §16 retry helper: this is a POST that
    // creates server state, so it falls outside §16.2's read-only eligibility
    // exactly as `oidcExchange` does. The safe recovery from a transport
    // failure is a fresh push, which costs one round trip and cannot
    // double-consume anything (§26.2 rule 4).
    const { data } = await this.#postForm<PushedAuthorizationResponseWire>(
      url,
      form,
      'pushed authorization request failed',
    );

    // §26.2 rule 2: exactly two query parameters. Not `response_type`, not
    // `redirect_uri`, not `scope`, not `state`, not the PKCE pair — the server
    // REFUSES a request carrying both a `request_uri` and any inline
    // authorization parameter rather than merging them, because merging is
    // where parameter confusion lives: an attacker supplies the inline value
    // they want and lets the pushed copy satisfy whichever check reads the
    // other one. Re-adding them "for compatibility" restores the attack.
    const target = new URL(configuration.authorization_endpoint);
    const query = new URLSearchParams();
    query.set('client_id', this.#options.clientId);
    query.set('request_uri', data.request_uri);
    target.search = query.toString().replace(/\+/g, '%20');

    return {
      authorizationUrl: target.toString(),
      requestUri: new Sensitive(data.request_uri),
      expiresIn: data.expires_in,
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
    };
  }

  /**
   * `POST /oauth2/token` with the device-code grant (CONTRACT.md §14.1) —
   * **one** poll attempt.
   *
   * @remarks
   * The raw single call, so an application driving its own loop (a UI
   * rendering a countdown, say) can. The five RFC 8628 §3.5 answers surface as
   * {@link OAuthProtocolError} — `authorization_pending` and `slow_down`
   * included — so a hand-rolled loop sees exactly what {@link deviceLogin}
   * sees. Most callers want {@link deviceLogin}.
   */
  async devicePoll(params: DevicePollParams): Promise<OidcTokenSet> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', DEVICE_CODE_GRANT_TYPE);
    form.set('device_code', exposeSecret(params.deviceCode));
    form.set('client_id', this.#options.clientId);

    const wire = await this.#postToken(configuration, form, params.tenantId);
    // No nonce: the device grant has no authorization request to carry one,
    // and §12.4 rule 6 applies to the authorization-code flow.
    return this.#toTokenSet(wire, configuration, undefined);
  }

  /**
   * The composed §14.3 helper: start the grant, hand the caller the user code,
   * poll to completion.
   *
   * @remarks
   * `onUserCode` is awaited **before the first poll** — §14.3 rule 2 requires
   * the caller to have had the chance to display the code before polling
   * begins. The SDK never prints it.
   *
   * Per §14.3 rule 4 (contract 1.7 errata) this SDK **returns** the token set;
   * whether it is adopted is the same MAY as `loginClientCredentials`.
   *
   * Polling follows §14.2: the interval comes from the response; `slow_down`
   * adds 5 s **permanently**; `authorization_pending` loops; `access_denied`
   * and `expired_token` raise distinct errors; polling stops at `expires_in`
   * even if the server has not yet said `expired_token`. A 5xx or transport
   * failure mid-poll is **not** terminal (rule 6) — the loop absorbs it and
   * tries again, bounded by the same deadline, because a server restart must
   * not lose a grant the user has already approved.
   */
  async deviceLogin(params: DeviceLoginParams): Promise<OidcTokenSet> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const authorization = await this.deviceAuthorize({
      ...(params.scope !== undefined ? { scope: params.scope } : {}),
      ...(params.tenantId !== undefined ? { tenantId: params.tenantId } : {}),
      configuration,
    });

    // §14.3 rule 2 — before any polling.
    await params.onUserCode(authorization);

    const schedule = new PollSchedule(authorization.interval, authorization.expiresIn);

    for (;;) {
      // §14.2 rule 4: the deadline is authoritative. Checking before sleeping
      // keeps the SDK from issuing a request that can only be refused, and
      // reports it under the same `expired_token` code the server would have
      // used — so a caller's branch does not care which side noticed first.
      if (!schedule.tick()) {
        throw new OAuthProtocolError(
          'expired_token',
          'the device authorization expired before the user completed it ' +
            '(client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)',
        );
      }

      await sleep(schedule.intervalSecs * 1000);

      try {
        return await this.devicePoll({
          deviceCode: authorization.deviceCode,
          ...(params.tenantId !== undefined ? { tenantId: params.tenantId } : {}),
          configuration,
        });
      } catch (err) {
        if (err instanceof OAuthProtocolError) {
          if (err.error === 'authorization_pending') {
            continue;
          }
          if (err.error === 'slow_down') {
            schedule.slowDown(); // §14.2 rule 1: cumulative, never reset.
            continue;
          }
          throw err; // expired_token / access_denied / invalid_grant
        }
        // §14.2 rule 6: transport and 5xx failures are not among the five
        // protocol answers and are not terminal.
        if (err instanceof NetworkError) {
          continue;
        }
        throw err;
      }
    }
  }

  // -------------------------------------------------------------------------
  // §15 Token Exchange (RFC 8693)
  // -------------------------------------------------------------------------

  /**
   * `POST /oauth2/token` with the RFC 8693 grant (CONTRACT.md §15.1) —
   * exchange a token for a **narrower** one.
   *
   * @remarks
   * The exchanging client authenticates (`client_secret_post`): unlike §14's
   * device, this is a confidential service.
   *
   * What this method deliberately does **not** do:
   *
   * - **No default `actorToken`** (§15.2 rule 1). Passing none asks for
   *   *impersonation*; the SDK will not quietly reuse the client's own session
   *   token as the actor and turn that into a delegation.
   * - **No retry or downgrade on `unauthorized_client`** (rule 2) — a
   *   registration fact an operator must fix.
   * - **No auto-narrowing on `invalid_scope`** (rule 3). The server refuses
   *   instead of silently narrowing precisely so the caller finds out here.
   * - **No adoption** (rule 5). The returned token is handed onward in one
   *   outbound call; adopting it would silently re-privilege every subsequent
   *   call this client makes.
   *
   * A cross-tenant subject token answers `invalid_grant`, identically to an
   * expired one. The SDK does not try to tell them apart (§15.3): the server
   * collapses them because distinguishing them is a tenant-enumeration signal.
   *
   * @throws AuthError when no `clientSecret` is configured — client-side, with
   * no wire call.
   */
  async tokenExchange(params: TokenExchangeParams): Promise<ExchangedToken> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', TOKEN_EXCHANGE_GRANT_TYPE);
    form.set('subject_token', exposeSecret(params.subjectToken));
    // Whatever the caller named, verbatim. The subject token is NEVER decoded
    // to pick this (§15.7): which kind of token the caller holds is the
    // caller's to know, and a guess here is the difference between a request
    // that is refused and one that is silently reinterpreted.
    form.set('subject_token_type', params.subjectTokenType);
    if (params.actorToken !== undefined) {
      form.set('actor_token', exposeSecret(params.actorToken));
      // Sent exactly when `actor_token` is: RFC 8693 §2.1 requires the pair,
      // and the type alone is a malformed request.
      form.set('actor_token_type', ACCESS_TOKEN_TYPE);
    }
    if (params.scopes !== undefined) {
      form.set('scope', params.scopes.join(' '));
    }
    if (params.audience !== undefined) {
      form.set('audience', params.audience);
    }
    if (params.resource !== undefined) {
      form.set('resource', params.resource);
    }
    form.set('client_id', this.#options.clientId);
    form.set('client_secret', this.#requireClientSecret('tokenExchange'));

    const url = this.#endpointUrl(configuration.token_endpoint, params.tenantId);
    const { data } = await this.#postForm<TokenExchangeResponseWire>(
      url,
      form,
      'token exchange request failed',
    );

    return {
      accessToken: new Sensitive(data.access_token),
      issuedTokenType: data.issued_token_type,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      ...(data.scope != null ? { scope: data.scope } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // §20 UMA 2.0 — Protection API and ticket grant
  // -------------------------------------------------------------------------

  /**
   * `POST /uma2/rreg/resource_set` — register a resource set (CONTRACT.md §20.1).
   *
   * @remarks
   * The `pat` is an explicit parameter, not this client's session. A Protection
   * API Token must be a **client-credentials** token, because a ticket binds to
   * the `client_id` that minted it — and this client's session is usually a
   * *user* session, which names no client to bind to (§20.2 rule 1).
   */
  async umaRegisterResource(
    pat: Sensitive<string> | string,
    resource: ResourceSet,
  ): Promise<ResourceSet> {
    const wire = await this.#umaProtection<ResourceSetWire>(
      'post',
      '/uma2/rreg/resource_set',
      pat,
      toResourceSetWire(resource),
    );
    return fromResourceSetWire(wire);
  }

  /** `GET /uma2/rreg/resource_set/{id}` — read a resource set (§20.1). */
  async umaReadResource(pat: Sensitive<string> | string, id: string): Promise<ResourceSet> {
    const wire = await this.#umaProtection<ResourceSetWire>(
      'get',
      `/uma2/rreg/resource_set/${encodeURIComponent(id)}`,
      pat,
    );
    return fromResourceSetWire(wire);
  }

  /**
   * `PUT /uma2/rreg/resource_set/{id}` — replace a resource set (§20.1).
   *
   * @remarks
   * **The scope list is replaced, not merged** (§20.2 rule 8). Whatever
   * `resource.resourceScopes` holds becomes the complete declared set; omitting
   * a scope removes it, which is how a resource server drops an authority. This
   * method performs no read-before-write.
   */
  async umaUpdateResource(
    pat: Sensitive<string> | string,
    id: string,
    resource: ResourceSet,
  ): Promise<ResourceSet> {
    const wire = await this.#umaProtection<ResourceSetWire>(
      'put',
      `/uma2/rreg/resource_set/${encodeURIComponent(id)}`,
      pat,
      toResourceSetWire(resource),
    );
    return fromResourceSetWire(wire);
  }

  /** `DELETE /uma2/rreg/resource_set/{id}` — deregister (§20.1). */
  async umaDeleteResource(pat: Sensitive<string> | string, id: string): Promise<void> {
    await this.#umaProtection<void>(
      'delete',
      `/uma2/rreg/resource_set/${encodeURIComponent(id)}`,
      pat,
    );
  }

  /**
   * `GET /uma2/rreg/resource_set` — list the ids **this client** registered
   * (§20.1).
   *
   * @remarks
   * Not the tenant's whole resource tree: a protection scope does not entitle a
   * caller to enumerate it.
   */
  async umaListResources(pat: Sensitive<string> | string): Promise<string[]> {
    return this.#umaProtection<string[]>('get', '/uma2/rreg/resource_set', pat);
  }

  /**
   * `POST /uma2/perm` — mint a permission ticket (§20.1).
   *
   * @remarks
   * Scope names are validated **here**, against each resource's declared set.
   * Asking for an undeclared scope is a `400`, not a denial — the two are
   * different failures, and this SDK surfaces the distinction the server draws
   * rather than flattening it.
   */
  async umaRequestTicket(
    pat: Sensitive<string> | string,
    permissions: RequestedPermission[],
  ): Promise<Sensitive<string>> {
    const wire = await this.#umaProtection<{ ticket: string }>(
      'post',
      '/uma2/perm',
      pat,
      permissions.map((p) => ({
        resource_id: p.resourceId,
        resource_scopes: p.resourceScopes,
      })),
    );
    return new Sensitive(wire.ticket);
  }

  /**
   * `POST /oauth2/token` with the uma-ticket grant (§20.1) — exchange a ticket
   * for an RPT.
   *
   * @remarks
   * **This method never retries.** It issues exactly one request and is outside
   * the §16 retry policy — not on `5xx`, not on timeout, not on any transport
   * failure (§20.2 rule 6). The ticket is consumed *before* the request is
   * evaluated, so a failed exchange has already spent it: a retry cannot
   * succeed, and under concurrency it is precisely the concurrent redemption a
   * server whose storage engine this SDK cannot attest may admit twice
   * (ilpanich/axiam#302). On failure, request a **new** ticket.
   *
   * What it deliberately does not do:
   *
   * - **No default `claimToken`** (rule 2) — it is required. Defaulting it to
   *   the resource server's own PAT would mint an RPT for the resource server
   *   instead of for the user.
   * - **No auto-narrowing on `access_denied`** (rule 3). A partial grant is
   *   refused whole; whether two-of-three permissions is useful is the
   *   application's judgement, not this SDK's.
   * - **No adoption** (rule 4). The RPT is the *requesting party's* token.
   *   Adopting it would re-privilege every later call this client makes as that
   *   user.
   *
   * The four ticket refusals — unknown, expired, already used, wrong client —
   * all answer `invalid_grant` with one message. This SDK does not try to tell
   * them apart (§20.4): the server collapses them so a caller cannot probe for
   * live ticket handles.
   *
   * @throws AuthError when no `clientSecret` is configured — client-side, with
   * no wire call.
   */
  async umaExchangeTicket(params: UmaExchangeTicketParams): Promise<RequestingPartyToken> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', UMA_TICKET_GRANT_TYPE);
    form.set('ticket', exposeSecret(params.ticket));
    form.set('claim_token', exposeSecret(params.claimToken));
    form.set('claim_token_format', UMA_CLAIM_TOKEN_FORMAT);
    form.set('client_id', this.#options.clientId);
    form.set('client_secret', this.#requireClientSecret('umaExchangeTicket'));

    const url = this.#endpointUrl(configuration.token_endpoint, params.tenantId);
    // One POST, no retry wrapper. See the rule-6 note above — this is the §16
    // exception, and it is load-bearing rather than stylistic.
    let data: RptResponseWire;
    try {
      const config: AxiosRequestConfig = {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      };
      const response = await this.#session.axios.post<RptResponseWire>(
        url,
        form.toString(),
        config,
      );
      data = response.data;
    } catch (err) {
      throw mapUmaGrantError(err, url, 'uma ticket exchange request failed');
    }

    return {
      accessToken: new Sensitive(data.access_token),
      tokenType: data.token_type,
      expiresIn: data.expires_in,
    };
  }

  /** Shared PAT-authenticated Protection API request. */
  async #umaProtection<T>(
    method: 'get' | 'post' | 'put' | 'delete',
    path: string,
    pat: Sensitive<string> | string,
    body?: unknown,
  ): Promise<T> {
    const config: AxiosRequestConfig = {
      headers: { Authorization: `Bearer ${exposeSecret(pat)}` },
    };
    try {
      const response =
        method === 'get' || method === 'delete'
          ? await this.#session.axios[method]<T>(path, config)
          : await this.#session.axios[method]<T>(path, body, config);
      return response.data;
    } catch (err) {
      throw mapOidcError(err, path, 'UMA protection API request failed');
    }
  }

  // -------------------------------------------------------------------------
  // §12.7 Logout helpers
  // -------------------------------------------------------------------------

  /**
   * Build the RP-initiated logout URL to redirect the user agent to
   * (CONTRACT.md §12.7.2).
   *
   * @remarks
   * Performs **no network I/O** beyond the discovery fetch the SDK caches
   * anyway, and does **not** clear this client's own session: whether the
   * local session ends is the application's decision — a backend holding a
   * service-account session must not lose it because a *user* logged out.
   *
   * `end_session_endpoint` is read from discovery and never synthesised from
   * the issuer (rule 1). Code that concatenates works against AXIAM and breaks
   * against every other OP the same application is pointed at.
   *
   * `postLogoutRedirectUri` is passed through **unvalidated against any local
   * list** (rule 3): the allow-list lives in the client's server-side
   * registration, and a client-side copy would drift and reject a URI an
   * operator had just registered.
   */
  async logoutUrl(params: LogoutUrlParams): Promise<string> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const endpoint = configuration.end_session_endpoint;
    if (!endpoint) {
      throw new AuthError(
        "the authorization server's discovery document advertises no " +
          'end_session_endpoint: this server does not support RP-initiated logout ' +
          '(CONTRACT.md §12.7.2 rule 1)',
      );
    }

    const url = new URL(endpoint);
    url.searchParams.set('id_token_hint', exposeSecret(params.idToken));
    if (params.postLogoutRedirectUri !== undefined) {
      url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
    }
    if (params.state !== undefined) {
      url.searchParams.set('state', params.state);
    }
    return url.toString();
  }

  /**
   * Verify a back-channel logout token the OP POSTed to this application's
   * `backchannel_logout_uri` (CONTRACT.md §12.7.3).
   *
   * @remarks
   * Every check exists because skipping it has a name:
   *
   * 1. **Signature**, through the same §12.4 JWKS verifier the ID-token path
   *    uses — no second key-fetching path — with the same `kid`-required
   *    discipline.
   * 2. **`iss`/`aud`**: a token minted for another RP is not accepted here.
   * 3. **`events` carries the back-channel-logout key.** This is what
   *    distinguishes a logout token from an ID token; skipping it means
   *    accepting a replayed ID token as a logout instruction.
   * 4. **`nonce` is absent.** Back-Channel Logout 1.0 §2.4 forbids it, and its
   *    presence is the documented signature of an ID token being replayed.
   *    Rejected, not ignored.
   * 5. **At least one of `sid`/`sub`** — a token naming neither identifies
   *    nothing.
   * 6. **`exp` in the future, `iat` recent.**
   *
   * @returns `sid`, `sub` and `jti` — never a bare boolean, because the RP has
   * to know *which* session to end.
   */
  async verifyLogoutToken(
    token: string,
    configuration?: OidcConfiguration,
  ): Promise<VerifiedLogoutToken> {
    const config = configuration ?? (await this.oidcDiscover());
    const { decodeProtectedHeader } = await import('jose');

    // Same alg/kid discipline as §12.4 rules 1-2, applied before any key
    // lookup: a token with no `kid` gets no "the only key" fallback.
    let header: { alg?: string; kid?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AuthError('logout token is not a well-formed JWS');
    }
    if (header.alg !== 'EdDSA') {
      throw new AuthError(`logout token alg must be EdDSA, got ${String(header.alg)}`);
    }
    if (!header.kid) {
      throw new AuthError('logout token carries no kid header');
    }

    const claims = (await this.#verifierFor(config.jwks_uri).verifySignatureOnlyUnchecked(
      token,
    )) as unknown as LogoutTokenClaims;

    if (claims.iss !== config.issuer) {
      throw new AuthError('logout token issuer does not match the discovery document');
    }
    if (claims.aud !== this.#options.clientId) {
      throw new AuthError('logout token audience does not match this client_id');
    }

    // Without this check the whole method is an elaborate way to accept an ID
    // token.
    const event = claims.events?.[BACKCHANNEL_LOGOUT_EVENT];
    if (event === undefined || typeof event !== 'object' || event === null || Array.isArray(event)) {
      throw new AuthError(
        'not a logout token: the events claim does not carry ' +
          'http://schemas.openid.net/event/backchannel-logout',
      );
    }

    if (claims.nonce !== undefined) {
      throw new AuthError(
        'logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: ' +
          'this is an ID token being replayed as a logout token',
      );
    }

    if (claims.sid === undefined && claims.sub === undefined) {
      throw new AuthError('logout token names neither sid nor sub, so it identifies no session');
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const skew = this.#options.clockSkewSec ?? 0;
    if (typeof claims.exp !== 'number' || claims.exp + skew < nowSec) {
      throw new AuthError('logout token has expired');
    }
    if (typeof claims.iat !== 'number' || claims.iat - skew > nowSec) {
      throw new AuthError('logout token was issued in the future');
    }
    if (nowSec - claims.iat > MAX_LOGOUT_TOKEN_AGE_SECS + skew) {
      throw new AuthError('logout token is too old to be a live delivery');
    }

    if (typeof claims.jti !== 'string' || claims.jti === '') {
      throw new AuthError('logout token carries no jti, so the RP cannot dedup redeliveries');
    }

    return {
      ...(claims.sid !== undefined ? { sid: claims.sid } : {}),
      ...(claims.sub !== undefined ? { sub: claims.sub } : {}),
      jti: claims.jti,
    };
  }

  // -------------------------------------------------------------------------
  // internals
  // -------------------------------------------------------------------------

  /**
   * Run one `refresh_token` grant under the session's §9 single-flight guard.
   *
   * The guard's callback signature returns `void`, so the token set is
   * published through a local variable. When the callback does NOT run, the
   * guard was already busy with a *different* refresh (the §1 cookie-session
   * path, which cannot produce an `OidcTokenSet`); rather than return a stale
   * or wrong result we simply try again now that the other refresh has
   * settled. Bounded, so a pathologically busy guard fails loudly instead of
   * spinning.
   */
  async #refreshUnderGuard(params: OidcRefreshParams): Promise<OidcTokenSet> {
    const configuration = params.configuration ?? (await this.oidcDiscover());
    const form = new URLSearchParams();
    form.set('grant_type', 'refresh_token');
    form.set('refresh_token', exposeSecret(params.refreshToken));
    form.set('client_id', this.#options.clientId);
    this.#appendClientSecret(form);
    if (params.scope !== undefined) {
      form.set('scope', params.scope);
    }

    for (let attempt = 0; attempt < 3; attempt += 1) {
      let refreshed: OidcTokenSet | undefined;
      await this.#session.refreshGuard(async () => {
        const wire = await this.#postToken(configuration, form, params.tenantId);
        // No nonce: rule 6 does not apply to a refresh-issued ID token.
        refreshed = await this.#toTokenSet(wire, configuration, undefined);
      });
      if (refreshed) {
        return refreshed;
      }
    }
    throw new AuthError(
      'oidcRefresh could not acquire the single-flight refresh guard (CONTRACT.md §9); another refresh kept it busy.',
    );
  }

  /** POST a form body to the token endpoint from the discovery document. */
  async #postToken(
    configuration: OidcConfiguration,
    form: URLSearchParams,
    tenantId: string | undefined,
  ): Promise<TokenResponseWire> {
    const url = this.#endpointUrl(configuration.token_endpoint, tenantId);
    const response = await this.#postForm<TokenResponseWire>(url, form, 'token request failed');
    return response.data;
  }

  /**
   * Convert a `TokenResponse` into an {@link OidcTokenSet}, validating any
   * `id_token` first (§12.4). Validation precedes construction, so a failure
   * discards the whole set — the caller never sees the access or refresh token
   * from a response whose ID token was rejected (§12.4 rule 7).
   */
  async #toTokenSet(
    wire: TokenResponseWire,
    configuration: OidcConfiguration,
    nonce: string | undefined,
  ): Promise<OidcTokenSet> {
    let idClaims: IdTokenClaims | undefined;
    if (wire.id_token) {
      idClaims = await this.#verifierFor(configuration.jwks_uri).verifyIdToken(wire.id_token, {
        issuer: configuration.issuer,
        clientId: this.#options.clientId,
        ...(nonce !== undefined ? { nonce } : {}),
        ...(this.#options.clockSkewSec !== undefined ? { clockSkewSec: this.#options.clockSkewSec } : {}),
      });
    }

    return {
      accessToken: new Sensitive(wire.access_token),
      tokenType: wire.token_type,
      expiresIn: wire.expires_in,
      ...(wire.scope != null ? { scope: wire.scope } : {}),
      ...(wire.refresh_token != null ? { refreshToken: new Sensitive(wire.refresh_token) } : {}),
      ...(wire.id_token != null ? { idToken: new Sensitive(wire.id_token) } : {}),
      ...(idClaims !== undefined ? { idClaims } : {}),
    };
  }

  /** Lazily build (and reuse) the JWKS verifier for a `jwks_uri` (§12.3 rule 6). */
  #verifierFor(jwksUri: string): JwksVerifier {
    const existing = this.#verifiers.get(jwksUri);
    if (existing) {
      return existing;
    }
    const verifier = createJwksVerifier(jwksUri);
    this.#verifiers.set(jwksUri, verifier);
    return verifier;
  }

  /**
   * Build the final endpoint URL: the discovery document's endpoint plus the
   * mandatory `?tenant_id=<uuid>` query parameter (§12.1 note 2). Existing
   * query parameters on the endpoint are preserved.
   */
  #endpointUrl(endpoint: string, tenantId: string | undefined): string {
    const url = new URL(endpoint);
    url.searchParams.set('tenant_id', this.#resolveTenantId(tenantId));
    return url.toString();
  }

  /**
   * Resolve the tenant UUID for the `tenant_id` query parameter (§12.3
   * rule 4): the explicit argument, else the client-level `tenantId`, else the
   * session's `tenantId` — and only ever a UUID. A slug-only client raises the
   * taxonomy error client-side, with no wire call, rather than sending a slug
   * where the server requires a UUID.
   */
  #resolveTenantId(explicit: string | undefined): string {
    const candidate = explicit ?? this.#options.tenantId ?? this.#session.tenantId;
    if (!candidate) {
      throw new AuthError(
        'this operation requires a tenant_id UUID for the /oauth2 query parameter: pass tenantId explicitly, ' +
          'or construct the client with the tenantId (UUID) form (CONTRACT.md §12.3 rule 4).',
      );
    }
    if (!UUID_RE.test(candidate)) {
      throw new AuthError(
        'tenant_id must be a UUID for the /oauth2 query parameter; a tenant slug cannot be substituted ' +
          '(CONTRACT.md §12.3 rule 4).',
      );
    }
    return candidate;
  }

  /**
   * Add `client_secret` to a form body for a confidential client, and omit it
   * entirely for a public client — §12.1 forbids sending an empty/null value
   * for an absent optional field.
   */
  #appendClientSecret(form: URLSearchParams): void {
    const secret = this.#options.clientSecret;
    if (secret !== undefined) {
      form.set('client_secret', exposeSecret(secret));
    }
  }

  /** The `client_secret` for an operation that cannot be performed without one (§12.1 note 4). */
  #requireClientSecret(operation: string): string {
    const secret = this.#options.clientSecret;
    if (secret === undefined) {
      throw new AuthError(
        `${operation} requires confidential-client credentials: construct the OidcClient with a clientSecret ` +
          '(CONTRACT.md §12.1 note 4).',
      );
    }
    return exposeSecret(secret);
  }

  /**
   * Adopt an access token as this session's bearer credential (§12.1, opt-in).
   *
   * The token lives only inside the interceptor closure, behind
   * {@link Sensitive} — never on `axios.defaults`, a public property or the
   * cookie jar — so it stays unreachable through any public getter (§12.3
   * rule 2). It is deliberately NOT sent to `/oauth2/*`: those endpoints
   * authenticate the client through the form body (§12.1 note 3).
   */
  #adoptCredential(accessToken: Sensitive<string>): void {
    this.#adoptedCredential = accessToken;
    if (this.#adoptionInterceptorInstalled) {
      return;
    }
    this.#adoptionInterceptorInstalled = true;
    this.#session.axios.interceptors.request.use((config) => {
      const adopted = this.#adoptedCredential;
      const url = config.url ?? '';
      if (!adopted || this.#session.isForeignHost(url) || url.includes('/oauth2/')) {
        return config;
      }
      config.headers = config.headers ?? {};
      config.headers['Authorization'] = `Bearer ${adopted.expose()}`;
      return config;
    });
  }

  /** GET through the session transport, mapping failures onto the §2 taxonomy. */
  async #get<T>(url: string, fallbackMessage: string): Promise<AxiosResponse<T>> {
    try {
      return await this.#session.axios.get<T>(url);
    } catch (err) {
      throw mapOidcError(err, url, fallbackMessage);
    }
  }

  /** POST a form-encoded body (§12.1 note 1) through the session transport. */
  async #postForm<T>(
    url: string,
    form: URLSearchParams,
    fallbackMessage: string,
  ): Promise<AxiosResponse<T>> {
    const config: AxiosRequestConfig = {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    };
    try {
      return await this.#session.axios.post<T>(url, form.toString(), config);
    } catch (err) {
      throw mapOidcError(err, url, fallbackMessage);
    }
  }

  /** POST a JSON body (the federation endpoints) through the session transport. */
  async #postJson<T>(
    url: string,
    body: Record<string, string>,
    fallbackMessage: string,
  ): Promise<AxiosResponse<T>> {
    try {
      return await this.#session.axios.post<T>(url, body);
    } catch (err) {
      throw mapOidcError(err, url, fallbackMessage);
    }
  }
}

/**
 * Normalize the requested scope to a space-separated string that always
 * contains `openid` (§12.1 rule 4 — the helper adds it when the caller omits
 * it). Duplicate entries are collapsed so `"openid openid profile"` cannot be
 * produced.
 */
function normalizeScope(scope: string | string[] | undefined): string {
  const requested = Array.isArray(scope) ? scope : (scope ?? '').split(' ');
  const values = requested.map((value) => value.trim()).filter(Boolean);
  if (!values.includes(OPENID_SCOPE)) {
    values.unshift(OPENID_SCOPE);
  }
  return [...new Set(values)].join(' ');
}

/**
 * Build an {@link OidcClient} on an existing session (CONTRACT.md §12).
 *
 * @param session the session the rest of the SDK already uses — normally a
 *   `NodeSession` from `createNodeSession`, so the §4 cookie jar is in place
 *   for `ssoComplete` (its session arrives as `Set-Cookie`).
 * @param options the relying party's `clientId`, optional `clientSecret`, and
 *   optional tenant/TTL/skew overrides.
 *
 * @example
 * ```ts
 * import { createNodeSession, createOidcClient } from 'axiam-sdk/node';
 *
 * const session = createNodeSession({ baseUrl, tenantId, orgId });
 * const oidc = createOidcClient(session, {
 *   clientId: process.env.AXIAM_CLIENT_ID!,
 *   clientSecret: process.env.AXIAM_CLIENT_SECRET,
 * });
 * ```
 */
export function createOidcClient(session: SharedSession, options: OidcClientOptions): OidcClient {
  return new OidcClient(session, options);
}
