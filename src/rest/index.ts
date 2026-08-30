// AXIAM SDK — REST entry (`axiam-sdk/rest`).
//
// Isomorphic REST core (browser + Node). The AxiamClient class, SharedSession,
// and REST auth/authz methods are implemented across 17-02 (browser persona);
// the Node persona (17-03) augments the same SharedSession with a cookie jar
// and local JWKS verification.

export { AxiamClient } from './client.js';
export { SharedSession } from './session.js';
// §23 OPAQUE (RFC 9807). `loginOpaque` is a method on AxiamClient; these are
// the standalone pieces an application needs for enrolment.
export { opaqueEnrollment, opaqueEnrollmentForSelf, opaqueAvailable, OpaqueUnavailableError } from './opaque.js';
export type { OpaqueEnrollment } from './opaque.js';
export { SKIP_REFRESH } from './interceptors.js';
export { withRetry, backoffMs, delayMs, MAX_ATTEMPTS, BASE_DELAY_MS, MAX_DELAY_MS } from './retry.js';
export type { RetryOptions } from './retry.js';

// §17 decision memo and §19 telemetry hooks (D5). Re-exported here — not just
// from `core` — because typedoc resolves references from the entry points
// listed in typedoc.json, and `AxiamClient.decisionMemo`/`.telemetry` and
// `AxiamClientOptions.telemetryHook` reference these types. Leaving them out
// makes `npm run docs` exit non-zero on dangling references, which is a CI
// gate here.
export { DecisionMemo, MAX_TTL_MS, memoKey } from '../core/decisionMemo.js';
export { TelemetryDispatcher } from '../core/telemetry.js';
export { TelemetryReporter } from '../core/telemetryReporter.js';
export type {
  TelemetryEvent,
  TelemetryHook,
  Outcome,
  RefreshRole,
  RequestStartEvent,
  RequestEndEvent,
  RetryEvent,
  RefreshEvent,
  ConfigClampedEvent,
} from '../core/telemetry.js';
export type { FinishRequest } from '../core/telemetryReporter.js';
export type {
  AccessCheck,
  AccessDecision,
  AxiamUserInfo,
  LoginResult,
} from './types.js';

// §24 WebAuthn / passkeys — the relying-party layer. Isomorphic: these six run
// in Node too, where the SDK is the relying party for a ceremony that happened
// on a handset. The ceremony itself is `axiam-sdk/browser` (§24.6).
export { webauthnRequestJson } from './webauthn.js';
// §24.6b rule 5 — isomorphic, so an Android or server-side caller classifying a
// ceremony error it was handed gets the same five outcomes a browser does.
export { classifyWebauthnError, webauthnErrorMessage } from './webauthnErrors.js';
export type { WebauthnFailure } from './webauthnErrors.js';
export type {
  WebauthnAuthenticationChallenge,
  WebauthnLoginResult,
  WebauthnRegistrationChallenge,
} from './webauthn.js';
export type {
  WebauthnAuthenticationResponse,
  WebauthnCreationChallenge,
  WebauthnCreationOptionsJson,
  WebauthnCredential,
  WebauthnCredentialDescriptorJson,
  WebauthnRegistrationResponse,
  WebauthnRequestChallenge,
  WebauthnRequestOptionsJson,
  WebauthnWorkspace,
} from './webauthnTypes.js';

// §25 account lifecycle and MFA enrolment.
export type {
  MfaEnrollment,
  PasswordResetConfirmation,
  PasswordResetContext,
  PasswordResetRequest,
} from './accountLifecycle.js';
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

// CONTRACT.md §27 — the management API. Exported from the root/`/rest` entry
// because it is REST and browser-safe: an admin UI is exactly its audience,
// and it pulls in no Node-only dependency (the SC#1 bundle gate covers this).
// The namespace handles themselves are reached from the client
// (`client.users`, `client.roles`, …); what is exported here is the models,
// the page and error types, and the declarative manifest surface.
export * from '../management/index.js';
