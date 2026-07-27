// Public types for the OIDC / SSO relying-party helpers (CONTRACT.md §12.1).
//
// Naming convention used throughout — deliberate, and worth copying verbatim
// into the other SDKs so the eight implementations stay legible as one family:
//
//   * Types that ARE a protocol document keep their wire spelling in
//     snake_case: `OidcConfiguration` (the OIDC Discovery 1.0 metadata
//     document) and `IdTokenClaims` (JWT claims). A caller cross-references
//     these field names against OIDC Core / RFC 8414, so renaming them would
//     be a lossy translation. `AxiamClaims` in node/jwks.ts already sets this
//     precedent.
//   * Types that are an SDK-shaped RESULT use the repo's camelCase public-API
//     convention (as `LoginResult` does): `OidcTokenSet`, `IntrospectionResult`,
//     `AuthorizationRequest`, `SsoStartResult`, `SsoCompleteResult`. These are
//     not verbatim wire objects — they carry `Sensitive<T>`-wrapped fields and
//     derived data (`idClaims`) that the wire body does not have.
//
// The five §12.5 secret fields — `access_token`, `refresh_token`, `id_token`,
// `client_secret`, `code_verifier` — are `Sensitive<string>` wherever they
// appear below. `state` and `nonce` are NOT secrets (§12.3 rule 2) and are
// plain strings.

import type { Sensitive } from '../core/index.js';
import type { IdTokenClaims } from './oidcIdToken.js';

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/**
 * The OIDC Discovery 1.0 metadata document served by
 * `GET /.well-known/openid-configuration` (wire schema
 * `OidcDiscoveryDocument`). Every field is required by the server's schema.
 *
 * @remarks
 * `issuer` is the **authoritative** issuer for ID-token validation
 * (CONTRACT.md §12.4 rule 3). It may legitimately differ from the client's
 * `baseUrl` when AXIAM runs behind a proxy, so this SDK never rejects a
 * document on an issuer/base-URL mismatch (§12.3 rule 6). Likewise `jwks_uri`
 * is read from here rather than hardcoded.
 */
export interface OidcConfiguration {
  /** The authorization server's issuer identifier — the value an ID token's `iss` claim must equal exactly. */
  issuer: string;
  /** The authorization endpoint `oidcBegin` builds its redirect URL from. */
  authorization_endpoint: string;
  /** The token endpoint used by `oidcExchange`, `oidcRefresh` and `loginClientCredentials`. */
  token_endpoint: string;
  /** The userinfo endpoint. Advertised by the server but deliberately NOT called by any SDK (§12.3 rule 5). */
  userinfo_endpoint: string;
  /** URI of the JWKS document whose keys verify ID-token signatures (§12.4 rule 2). */
  jwks_uri: string;
  /** The RFC 7009 revocation endpoint used by `revoke`. */
  revocation_endpoint: string;
  /** The RFC 7662 introspection endpoint used by `introspect`. */
  introspection_endpoint: string;
  /** OAuth2 `response_type` values the server supports. */
  response_types_supported: string[];
  /** Subject identifier types the server supports. */
  subject_types_supported: string[];
  /** ID-token signing algorithms the server advertises. Informational only: §12.4 rule 1 pins verification to `EdDSA` regardless of what appears here. */
  id_token_signing_alg_values_supported: string[];
  /** Scopes the server supports. */
  scopes_supported: string[];
  /** Client-authentication methods the token endpoint supports (`client_secret_post`, §12.1 note 3). */
  token_endpoint_auth_methods_supported: string[];
  /** Claims the server may include in an ID token. */
  claims_supported: string[];
  /** Grant types the token endpoint supports. */
  grant_types_supported: string[];
}

// ---------------------------------------------------------------------------
// oidcBegin
// ---------------------------------------------------------------------------

/**
 * The result of `oidcBegin` — everything the caller needs to start an
 * authorization-code + PKCE login (CONTRACT.md §12.1).
 *
 * @remarks
 * **The caller owns this state** (§12.3 rule 1). The SDK stores nothing: it
 * keeps no copy of `state`, `nonce` or `codeVerifier` in process-global state
 * or any implicit cache. Persist all three in your own HTTP session (or in an
 * {@link OidcStateStore}), redirect the browser to {@link url}, and pass
 * `nonce` + `codeVerifier` back into `oidcExchange` when the code arrives.
 */
export interface AuthorizationRequest {
  /** The fully-built authorization URL to redirect the browser to. */
  url: string;
  /** CSPRNG CSRF value (≥128 bits, base64url unpadded) to compare against the `state` the IdP returns. Not a secret (§12.3 rule 2). */
  state: string;
  /** CSPRNG replay-protection value (≥128 bits) that must equal the ID token's `nonce` claim. Not a secret (§12.3 rule 2). */
  nonce: string;
  /** The PKCE verifier, secret for its whole lifetime (§12.5). Pass it back into `oidcExchange`. */
  codeVerifier: Sensitive<string>;
}

/** Arguments to `oidcBegin` (pure local computation — no network I/O). */
export interface OidcBeginParams {
  /** The discovery document, as returned by `oidcDiscover`. `authorization_endpoint` is taken from it and never hardcoded (§12.1 rule 5). */
  configuration: OidcConfiguration;
  /** The relying party's redirect URI, echoed back into `oidcExchange` unchanged. */
  redirectUri: string;
  /** Requested scope, as a string or an array. `openid` is added automatically when absent (§12.1 rule 4). Defaults to `openid`. */
  scope?: string | string[];
  /**
   * Extra authorization-request parameters (e.g. `prompt`, `login_hint`,
   * `ui_locales`). §12.1 rule 5 allows caller-supplied additions but forbids
   * the SDK from adding any of its own beyond the mandated eight, so
   * attempting to override one of those eight throws.
   */
  extraParams?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Token sets
// ---------------------------------------------------------------------------

/**
 * A token set returned by the OAuth2 token endpoint (wire schema
 * `TokenResponse`), returned by `oidcExchange`, `oidcRefresh` and
 * `loginClientCredentials`.
 *
 * @remarks
 * `accessToken`, `refreshToken` and `idToken` are {@link Sensitive} (§12.5):
 * `toString()`, `JSON.stringify()` and `console.log`/`util.inspect` all
 * redact them to `[SENSITIVE]`, and the raw value is reachable only through
 * the documented-`@internal` `expose()` accessor.
 *
 * `idClaims` is present exactly when `idToken` is, and holds the
 * **already-validated** claim set (§12.4) — validation happens before this
 * object is ever constructed, so an `OidcTokenSet` in your hands is never
 * partially trusted (§12.4 rule 7).
 */
export interface OidcTokenSet {
  /** The OAuth2 access token (§12.5 secret). */
  accessToken: Sensitive<string>;
  /** The token type the server issued (`Bearer`). */
  tokenType: string;
  /** Access-token lifetime in seconds from the time of the response. */
  expiresIn: number;
  /** Granted scope, when the server narrowed or echoed it. */
  scope?: string;
  /** The refresh token, when the grant issued one (§12.5 secret). */
  refreshToken?: Sensitive<string>;
  /** The raw ID token, when the grant issued one (§12.5 secret). */
  idToken?: Sensitive<string>;
  /** The validated ID-token claims — present exactly when {@link idToken} is (§12.1, §12.4). */
  idClaims?: IdTokenClaims;
}

/** Arguments to `oidcExchange` (`grant_type=authorization_code`). */
export interface OidcExchangeParams {
  /** The authorization code the IdP redirected back with. */
  code: string;
  /** The verifier from the matching {@link AuthorizationRequest}. Accepts the `Sensitive` wrapper or a bare string (e.g. rehydrated from your own session store). */
  codeVerifier: Sensitive<string> | string;
  /** The same `redirect_uri` that was sent on the authorization request. */
  redirectUri: string;
  /** The `nonce` from the matching {@link AuthorizationRequest}. MANDATORY — §12.4 rule 6 is not optional for this grant. */
  nonce: string;
  /** Tenant UUID for the token endpoint's required `tenant_id` query parameter. Defaults to the client's configured `tenantId` when it was built in UUID form (§12.3 rule 4). */
  tenantId?: string;
  /** A pre-fetched discovery document, to avoid re-reading the (cached) one. Fetched via `oidcDiscover` when omitted. */
  configuration?: OidcConfiguration;
}

/** Arguments to `oidcRefresh` (`grant_type=refresh_token`). */
export interface OidcRefreshParams {
  /** The refresh token to redeem. Accepts the `Sensitive` wrapper or a bare string. */
  refreshToken: Sensitive<string> | string;
  /** Optional narrowed scope to request. Omitted from the form body when absent. */
  scope?: string;
  /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
  tenantId?: string;
  /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
  configuration?: OidcConfiguration;
}

/** Arguments to `loginClientCredentials` (`grant_type=client_credentials`). */
export interface LoginClientCredentialsParams {
  /** Optional scope to request. This grant requests no `openid` scope and the response carries no `id_token` (§12.1). */
  scope?: string;
  /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
  tenantId?: string;
  /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
  configuration?: OidcConfiguration;
  /**
   * Adopt the returned `access_token` as this client's bearer credential for
   * subsequent REST calls on the same session — the §12.1
   * "`login_client_credentials` as a credential source" allowance (a **MAY**,
   * hence opt-in and `false` by default).
   *
   * When `true` the token is held behind {@link Sensitive} inside a request
   * interceptor closure and emitted as `Authorization: Bearer …`; it is never
   * written to `axios.defaults`, a public property, or the cookie jar, so it
   * stays unreachable through any public getter (§12.3 rule 2).
   */
  adoptAsCredential?: boolean;
}

// ---------------------------------------------------------------------------
// Introspection / revocation
// ---------------------------------------------------------------------------

/** Arguments to `introspect` (RFC 7662). Requires confidential-client credentials (§12.1 note 4). */
export interface IntrospectParams {
  /** The token to introspect. Accepts the `Sensitive` wrapper or a bare string. */
  token: Sensitive<string> | string;
  /** Optional RFC 7662 `token_type_hint` (`access_token` / `refresh_token`). */
  tokenTypeHint?: string;
  /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
  tenantId?: string;
  /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
  configuration?: OidcConfiguration;
}

/** Arguments to `revoke` (RFC 7009). Requires confidential-client credentials (§12.1 note 4). */
export interface RevokeParams {
  /** The token to revoke. Accepts the `Sensitive` wrapper or a bare string. */
  token: Sensitive<string> | string;
  /** Optional RFC 7009 `token_type_hint`. */
  tokenTypeHint?: string;
  /** Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4). */
  tenantId?: string;
  /** A pre-fetched discovery document. Fetched via `oidcDiscover` when omitted. */
  configuration?: OidcConfiguration;
}

/**
 * The RFC 7662 introspection result (wire schema `IntrospectionResponse`).
 * Only `active` is guaranteed; the server omits the metadata fields for an
 * inactive token.
 */
export interface IntrospectionResult {
  /** Whether the token is currently active. */
  active: boolean;
  /** Subject the token was issued to. */
  sub?: string;
  /** Client the token was issued to. */
  clientId?: string;
  /** Scope granted to the token. */
  scope?: string;
  /** Token type (`Bearer`). */
  tokenType?: string;
  /** Expiry time, epoch seconds. */
  exp?: number;
  /** Issued-at time, epoch seconds. */
  iat?: number;
}

// ---------------------------------------------------------------------------
// Federation SSO (upstream IdP)
// ---------------------------------------------------------------------------

/** Arguments to `ssoStart` (`POST /api/v1/auth/federation/oidc/start`). */
export interface SsoStartParams {
  /** UUID of the server-side federation configuration identifying the upstream IdP. */
  federationConfigId: string;
  /** Post-login destination, stored server-side and echoed back by `ssoComplete`. */
  redirectUri: string;
  /** Tenant UUID. One tenant form (`tenantId` or `tenantSlug`) is required; defaults to the client's configuration (§5.1). */
  tenantId?: string;
  /** Tenant slug. Alternative to {@link tenantId}. */
  tenantSlug?: string;
  /** Organization UUID. One org form (`orgId` or `orgSlug`) is required; defaults to the client's configuration (§5.1). */
  orgId?: string;
  /** Organization slug. Alternative to {@link orgId}. */
  orgSlug?: string;
}

/**
 * The result of `ssoStart` (wire schema `OidcStartResponse`).
 *
 * @remarks
 * There is deliberately **no nonce**: on the federation path the nonce never
 * leaves the server (§12.1 note 7). Round-trip {@link state} into
 * `ssoComplete` unmodified — the server stores it single-use with a 10-minute
 * TTL and recovers the whole login context from it.
 */
export interface SsoStartResult {
  /** The upstream IdP authorization URL to redirect the browser to. */
  authorizeUrl: string;
  /** Single-use CSRF state to round-trip back into `ssoComplete` unmodified. */
  state: string;
  /** Remaining TTL of the server-side state row, in seconds (600 = 10 min). */
  expiresInSecs: number;
}

/** Arguments to `ssoComplete` (`POST /api/v1/auth/federation/oidc/callback`). */
export interface SsoCompleteParams {
  /** The `state` value the IdP redirected back with — must be the one `ssoStart` returned. */
  state: string;
  /** The authorization code the IdP redirected back with. */
  code: string;
}

/**
 * The result of `ssoComplete` (wire schema `SsoLoginSuccessResponse`).
 *
 * @remarks
 * Carries **no token material** — the session arrives as `Set-Cookie`, so the
 * §4 cookie jar is what actually captures it (§12.1 note 6). Use a Node
 * session (`createNodeSession`) or the session is silently lost.
 */
export interface SsoCompleteResult {
  /** The provisioned/linked user's UUID. */
  userId: string;
  /** The established session's UUID. */
  sessionId: string;
  /** Session/access-token lifetime in seconds. */
  expiresIn: number;
  /** The post-login destination that was stored during `ssoStart`. */
  redirectUri: string;
}

// ---------------------------------------------------------------------------
// Wire types (snake_case, mirror the server schemas verbatim)
// ---------------------------------------------------------------------------

/** 200 body of `POST /oauth2/token` (wire schema `TokenResponse`). */
export interface TokenResponseWire {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string | null;
  refresh_token?: string | null;
  id_token?: string | null;
}

/** 200 body of `POST /oauth2/introspect` (wire schema `IntrospectionResponse`). */
export interface IntrospectionResponseWire {
  active: boolean;
  sub?: string | null;
  client_id?: string | null;
  scope?: string | null;
  token_type?: string | null;
  exp?: number | null;
  iat?: number | null;
}

/** 200 body of `POST /api/v1/auth/federation/oidc/start` (wire schema `OidcStartResponse`). */
export interface OidcStartResponseWire {
  authorize_url: string;
  state: string;
  expires_in_secs: number;
}

/** 200 body of `POST /api/v1/auth/federation/oidc/callback` (wire schema `SsoLoginSuccessResponse`). */
export interface SsoLoginSuccessResponseWire {
  user_id: string;
  session_id: string;
  expires_in: number;
  redirect_uri: string;
}
