// AXIAM SDK — Node entry (`axiam-sdk/node`), Node-only opt-in subpath.
//
// The Node persona's REST construction path (SDK-Q05): `createNodeClient`
// builds an `AxiamClient` backed by a `NodeSession` (tough-cookie jar +
// CSRF/refresh token sync) so httpOnly login/refresh cookies persist under
// Node. Importing this entry pulls in the Node-only deps (tough-cookie, jose,
// node:https) — it is NOT reachable from the browser-safe `.`/`/rest` entries,
// which keep bundling zero Node dependencies (SC#1, D-01/D-25).

export { createNodeClient, createNodeSession, NodeSession } from './session.js';
export { TokenManager } from './tokenManager.js';
export {
  createVerifier,
  createJwksVerifier,
  assertTenantClaim,
  CLOCK_SKEW_LEEWAY_SEC,
  type AccessTokenExpectations,
  type Verifier,
  type IdTokenVerifier,
  type JwksVerifier,
  type AxiamClaims,
  JWKS_PATH,
} from './jwks.js';
// OIDC / SSO relying-party helpers (CONTRACT.md §12). Node-only: PKCE needs
// node:crypto and ID-token validation needs jose, so these deliberately do
// NOT hang off the browser-safe AxiamClient (see src/node/oidc.ts's header).
export {
  createOidcClient,
  normalizeOrigin,
  OidcClient,
  type OidcClientOptions,
  DISCOVERY_PATH,
  MIN_DISCOVERY_TTL_MS,
  SSO_CALLBACK_PATH,
  SSO_START_PATH,
  ACCESS_TOKEN_TYPE,
  BACKCHANNEL_LOGOUT_EVENT,
  DEFAULT_POLL_INTERVAL_SECS,
  DEVICE_CODE_GRANT_TYPE,
  JWT_TOKEN_TYPE,
  MAX_LOGOUT_TOKEN_AGE_SECS,
  PollSchedule,
  SLOW_DOWN_INCREMENT_SECS,
  TOKEN_EXCHANGE_GRANT_TYPE,
  UMA_TICKET_GRANT_TYPE,
  UMA_PROTECTION_SCOPE,
  UMA_CLAIM_TOKEN_FORMAT,
  umaParseChallenge,
  umaChallengeHeader,
} from './oidc.js';
export type {
  AuthorizationRequest,
  IntrospectionResult,
  IntrospectParams,
  LoginClientCredentialsParams,
  OidcBeginParams,
  OidcConfiguration,
  OidcExchangeParams,
  OidcRefreshParams,
  OidcTokenSet,
  RevokeParams,
  SsoCompleteParams,
  SsoCompleteResult,
  SsoStartParams,
  SsoStartResult,
  DeviceAuthorization,
  DeviceAuthorizeParams,
  DeviceLoginParams,
  DevicePollParams,
  ExchangedToken,
  LogoutUrlParams,
  TokenExchangeParams,
  VerifiedLogoutToken,
  RequestedPermission,
  RequestingPartyToken,
  ResourceSet,
  RptPermission,
  UmaChallenge,
  UmaExchangeTicketParams,
} from './oidcTypes.js';
export {
  MemoryOidcStateStore,
  OIDC_STATE_TTL_MS,
  type OidcStateEntry,
  type OidcStateStore,
} from './oidcState.js';
export {
  CODE_CHALLENGE_METHOD_S256,
  computeCodeChallenge,
  CSPRNG_BYTES,
  generateCodeVerifier,
  randomUrlSafeToken,
} from './oidcPkce.js';
export {
  ID_TOKEN_ALG,
  MAX_CLOCK_SKEW_SEC,
  type IdTokenClaims,
  type IdTokenExpectations,
} from './oidcIdToken.js';
export {
  createJar,
  wrapAxios,
  extractCookieValue,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  CSRF_COOKIE,
} from './cookieJar.js';
// Webhook signature verification (CONTRACT.md §13, T-145). Node-only: needs
// node:crypto for the HMAC/constant-time compare, so — like the OIDC helpers
// above — it deliberately does not hang off the browser-safe AxiamClient.
export {
  verifyWebhook,
  WebhookVerifyError,
  DEFAULT_WEBHOOK_TOLERANCE_SEC,
  type VerifiedWebhookEvent,
  type VerifyWebhookOptions,
  type WebhookVerifyFailureReason,
} from './webhook.js';
// Re-exported here (mirroring amqp/index.ts) so `verifyWebhook`'s required
// `Sensitive<string>` secret can be constructed from this same subpath
// import, without a second import from the root entry.
export { Sensitive } from '../core/index.js';
