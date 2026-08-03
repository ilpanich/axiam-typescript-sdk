// AXIAM SDK — middleware entry point (D-27, CONTRACT.md §10; declarative
// authorization helpers, CONTRACT.md §11).
//
// Re-exports the Express and Fastify middleware/guards plus the shared
// verify core / authz core / cookie parser they're all built on.

export {
  axiamMiddleware,
  oidcLoginHandlers,
  requireAccess,
  requireAuth,
  requireRole,
  type AxiamRequest,
} from './express.js';
export {
  axiamPlugin,
  oidcLoginPlugin,
  requireAccessHook,
  requireAuthHook,
  requireRoleHook,
  type AxiamFastifyRequest,
  type OidcLoginRoutePaths,
  type PreHandlerHook,
} from './fastify.js';
// The §12 "Login with AXIAM" core both framework adapters above are built on.
export {
  beginOidcLogin,
  completeOidcLogin,
  type OidcCallbackQuery,
  type OidcLoginOptions,
  type OidcLoginOutcome,
  type OidcLoginSuccessBody,
} from './oidcLoginCore.js';
export { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';
// Re-exported so the middleware entry point's own generated docs can resolve
// `VerifiableSession.jwksVerifier`'s `Verifier` type (and the `AxiamClaims` it
// returns) without a dangling cross-module link (`node/jwks.ts` is not itself
// a TypeDoc entry point) — single source of truth stays node/jwks.ts.
export type { Verifier, AxiamClaims, AccessTokenExpectations } from '../node/jwks.js';
// CONTRACT.md §10.1 rule 7's named clock-skew bound and rule 4's tenant
// assertion, re-exported so a consumer writing their own guard on top of
// `Verifier` applies the same policy the middleware does.
export { assertTenantClaim, CLOCK_SKEW_LEEWAY_SEC } from '../node/jwks.js';
// Same rationale for the §12 types the login glue's own signatures reference
// (`OidcLoginOptions.client`/`.store`, `onSuccess`'s arguments): re-exported so
// this entry point's generated docs resolve them without a dangling
// cross-module link. Single source of truth stays under `src/node/`, and the
// `axiam-sdk/node` subpath is where a consumer normally imports them from.
export {
  createOidcClient,
  MIN_DISCOVERY_TTL_MS,
  OidcClient,
  type OidcClientOptions,
} from '../node/oidc.js';
export type {
  AuthorizationRequest,
  IntrospectParams,
  IntrospectionResult,
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
} from '../node/oidcTypes.js';
export type { IdTokenClaims } from '../node/oidcIdToken.js';
export {
  MemoryOidcStateStore,
  OIDC_STATE_TTL_MS,
  type OidcStateEntry,
  type OidcStateStore,
} from '../node/oidcState.js';
export {
  assertAuthzClient,
  evaluateAccess,
  fromParam,
  hasAnyRole,
  resolveResourceId,
  ResourceResolutionError,
  type AuthzChecker,
  type AuthzLogger,
  type AuthzVerifiableSession,
  type CheckOutcome,
  type ErrorBody,
  type RequireAccessOptions,
  type ResourceParamRef,
  type ResourceResolver,
  type ResourceSpec,
} from './authzCore.js';
export {
  parseCookieHeader,
  extractToken,
  extractCredential,
  isCsrfValid,
  isSafeMethod,
  type CredentialSource,
  type ExtractedCredential,
  ACCESS_COOKIE_NAME,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
} from './cookieHeader.js';
