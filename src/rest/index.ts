// AXIAM SDK — REST entry (`axiam-sdk/rest`).
//
// Isomorphic REST core (browser + Node). The AxiamClient class, SharedSession,
// and REST auth/authz methods are implemented across 17-02 (browser persona);
// the Node persona (17-03) augments the same SharedSession with a cookie jar
// and local JWKS verification.

export { AxiamClient } from './client.js';
export { SharedSession } from './session.js';
export { SKIP_REFRESH } from './interceptors.js';
export { withRetry } from './retry.js';
export type { RetryOptions } from './retry.js';
export type {
  AccessCheck,
  AccessDecision,
  AxiamUserInfo,
  LoginResult,
} from './types.js';
// AxiamClientOptions is the AxiamClient constructor's public parameter type
// (docs-only addition — genuinely part of the public API surface, not an
// internal detail; RefreshGuard, by contrast, stays unexported/@internal
// since it's SDK-internal cross-transport wiring, not something consumers
// invoke directly).
export type { AxiamClientOptions } from '../core/index.js';
// The CONTRACT.md §2 error taxonomy every persona throws, plus the §7/§12.5
// redaction wrapper the token-carrying result types use. Exported from the
// root/`/rest` entry so `catch (e) { e instanceof AuthError }` works for
// consumers of any subpath (they all funnel through these classes) — including
// the §12 `OAuthProtocolError` sub-type, whose `error`/`error_description`
// fields §12.3 rule 3 requires to be publicly accessible.
export {
  AuthError,
  AuthzError,
  AxiamError,
  NetworkError,
  OAuthProtocolError,
  Sensitive,
  type IdTokenFailureReason,
} from '../core/index.js';
