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
  mapHttpStatusToError,
  NetworkError,
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
