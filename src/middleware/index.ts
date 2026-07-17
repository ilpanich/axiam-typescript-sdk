// AXIAM SDK — middleware entry point (D-27, CONTRACT.md §10; declarative
// authorization helpers, CONTRACT.md §11).
//
// Re-exports the Express and Fastify middleware/guards plus the shared
// verify core / authz core / cookie parser they're all built on.

export {
  axiamMiddleware,
  requireAccess,
  requireAuth,
  requireRole,
  type AxiamRequest,
} from './express.js';
export {
  axiamPlugin,
  requireAccessHook,
  requireAuthHook,
  requireRoleHook,
  type AxiamFastifyRequest,
  type PreHandlerHook,
} from './fastify.js';
export { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';
// Re-exported so the middleware entry point's own generated docs can resolve
// `VerifiableSession.jwksVerifier`'s `Verifier` type (and the `AxiamClaims` it
// returns) without a dangling cross-module link (`node/jwks.ts` is not itself
// a TypeDoc entry point) — single source of truth stays node/jwks.ts.
export type { Verifier, AxiamClaims } from '../node/jwks.js';
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
