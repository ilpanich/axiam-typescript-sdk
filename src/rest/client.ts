// AxiamClient — the isomorphic REST + auth core (D-01/D-25).
//
// Constructor validates the required tenant (§5), builds the SharedSession
// (D-13), and installs the CSRF + reactive single-flight refresh
// interceptors (D-05/D-07). REST method implementations (login/verifyMfa/
// refresh/logout/checkAccess/can/batchCheck) are added by Task 2's
// auth.ts/authz.ts, which extend this class's prototype.

import type { AxiamClientOptions } from '../core/index.js';
import { NetworkError } from '../core/index.js';
import { DecisionMemo } from '../core/decisionMemo.js';
import { TelemetryDispatcher } from '../core/telemetry.js';
import { TelemetryReporter } from '../core/telemetryReporter.js';
import type { RetryOptions } from './retry.js';
import { createSession, SharedSession } from './session.js';
import { installInterceptors } from './interceptors.js';
import * as authMethods from './auth.js';
import * as opaqueMethods from './opaque.js';
import * as authzMethods from './authz.js';
import * as webauthnMethods from './webauthn.js';
import * as accountMethods from './accountLifecycle.js';
import type { AccessCheck, AccessDecision, LoginResult } from './types.js';
import type { Sensitive } from '../core/index.js';
import type {
  WebauthnAuthenticationResponse,
  WebauthnCredential,
  WebauthnRegistrationResponse,
  WebauthnWorkspace,
} from './webauthnTypes.js';

/**
 * The main entry point for the AXIAM TypeScript/JavaScript SDK — an
 * isomorphic (browser + Node) REST client for authentication and
 * authorization against an AXIAM server.
 *
 * @remarks
 * `AxiamClient` implements the SDK's cross-language behavioral contract
 * (see `CONTRACT.md` §1–§10): the canonical `login`/`verifyMfa`/`refresh`/
 * `logout`/`checkAccess`/`can`/`batchCheck` method vocabulary (§1), the
 * three-way `AuthError`/`AuthzError`/`NetworkError` taxonomy (§2), automatic
 * CSRF forwarding (§3), the required tenant context (§5), and a per-instance
 * single-flight refresh guard that de-duplicates concurrent token refreshes
 * (§9).
 *
 * A `tenantSlug` or `tenantId` is mandatory at construction — there is no
 * default tenant, and AXIAM is a multi-tenant system where every
 * authenticated call is scoped by the `X-Tenant-ID` header this client
 * injects on every request (§5). Session tokens never appear as a return
 * value or public property anywhere on this class: they arrive exclusively
 * via `httpOnly` cookies set by the server.
 *
 * @example
 * ```ts
 * const client = new AxiamClient({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
 *
 * const result = await client.login('user@example.com', 'hunter2');
 * if (result.status === 'mfa_required') {
 *   await client.verifyMfa(result.mfaToken, '123456');
 * }
 *
 * const decision = await client.checkAccess({ action: 'read', resourceId: 'document:42' });
 * if (!decision.allowed) {
 *   throw new Error(decision.reason ?? 'access denied');
 * }
 * ```
 */
import { ManifestApi } from '../management/manifest/engine.js';
import type { ManagementNamespaces } from '../management/ops/index.js';
import { managementNamespaces } from '../management/ops/index.js';

/**
 * The §27 management namespaces, merged onto the client.
 *
 * Declaration merging rather than 24 hand-written getters: the namespace set
 * is generated from `management-registry.json`, and a hand-maintained copy of
 * it on this class is the thing §27.8 exists to prevent.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AxiamClient extends ManagementNamespaces {}

export class AxiamClient {
  /** @internal — exposed for auth.ts/authz.ts method implementations and other transports (D-13). */
  readonly session: SharedSession;

  /**
   * @param options client configuration (§5/§6).
   * @param session optional pre-built session to adopt instead of the default
   *   browser `SharedSession`. This is the injection point for the Node
   *   persona (SDK-Q05): a Node REST consumer builds a `NodeSession` (cookie
   *   jar + CSRF/refresh token sync) via `createNodeClient`/`createNodeSession`
   *   from the Node-only `axiam-sdk/node` (or `axiam-sdk/grpc`) subpath and it
   *   is adopted here, so httpOnly login/refresh cookies persist. When omitted
   *   the browser `SharedSession` is built by default — the Node modules are
   *   NEVER statically imported from this browser-safe module, so a `/rest`
   *   browser bundle keeps pulling zero Node dependencies (SC#1).
   */
  /** §17 decision memo. Disabled unless `decisionMemoTtlMs` was configured. */
  readonly decisionMemo: DecisionMemo;

  /** §19 telemetry dispatcher. Empty unless a hook was installed. */
  readonly telemetry: TelemetryReporter;

  /** §16.1 disable switch. Defaults to enabled. */
  private readonly retryEnabled: boolean;

  /** §18 shutdown flag. Set once by close(); read on every operation. */
  private closed = false;

  constructor(options: AxiamClientOptions, session?: SharedSession) {
    this.session = session ?? createSession(options);
    installInterceptors(this.session.axios, this.session);
    // §17.1 rule 1: off unless the caller asked for it.
    this.decisionMemo = new DecisionMemo(options.decisionMemoTtlMs ?? 0);
    this.telemetry = new TelemetryReporter(new TelemetryDispatcher(options.telemetryHook));
    // §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
    // here, because construction is the only moment an operator can act on it.
    this.decisionMemo.reportClamp(options.decisionMemoTtlMs ?? 0, this.telemetry.dispatcher);
    this.retryEnabled = options.retryEnabled ?? true;
    // §27.2 rule 1: acquiring a handle performs no I/O and is not meant to be
    // observable. Copying the *descriptors* keeps the generated getters lazy,
    // so constructing a client does not construct 24 namespace objects; a
    // plain `Object.assign` would invoke every getter here.
    Object.defineProperties(this, Object.getOwnPropertyDescriptors(managementNamespaces(this)));
  }

  /**
   * Declarative management — CONTRACT.md §27.6.
   *
   * `client.manifest.plan(m)` says what would change and writes nothing;
   * `client.manifest.apply(m)` reconciles.
   */
  get manifest(): ManifestApi {
    return new ManifestApi(this);
  }

  /**
   * Every §27 namespace behind one accessor (§27.2 rule 4).
   *
   * `client.management.users` and `client.users` are the same handle; this
   * exists for callers who prefer the management surface not to be mixed in
   * with §1's eight methods when reading a call site.
   */
  get management(): ManagementNamespaces {
    return managementNamespaces(this);
  }

  /**
   * Release this client's local resources (CONTRACT.md §18).
   *
   * Idempotent — calling it twice is not an error. Cleanup runs from error
   * paths, and an error path that itself throws hides the original failure.
   *
   * **This does not log out.** §18.1 rule 5: shutting down a client releases
   * *local* resources and never reaches the network. The server-side session
   * deliberately outlives the client object, which is what lets a process
   * restart and resume; a `close()` that logged out would silently end every
   * user's session on each deploy. Call {@link logout} first if ending the
   * session is what you want.
   *
   * After this returns, any operation on the client rejects rather than
   * silently reconnecting.
   */
  close(): void {
    this.closed = true;
    this.decisionMemo.clear();
  }

  /**
   * Throws if {@link close} has been called (§18.1 rule 4).
   *
   * @internal
   */
  ensureOpen(): void {
    if (this.closed) {
      throw new NetworkError('client is closed: this AxiamClient was shut down with close()');
    }
  }

  /**
   * §16 options for `operation`, bound to this client's switch and telemetry.
   *
   * @internal
   */
  retryOptions(operation: string): RetryOptions {
    return {
      idempotent: true,
      operation,
      enabled: this.retryEnabled,
      telemetry: this.telemetry.dispatcher,
    };
  }

  /** `POST /api/v1/auth/login` (§1, D-18). */
  login(email: string, password: string): Promise<LoginResult> {
    return authMethods.login(this, email, password);
  }

  /**
   * OPAQUE login (§23) — the password never leaves this process.
   *
   * Returns the same `LoginResult` as {@link login}, including the
   * `mfa_required` branch, so one result handler serves both. Rejects with a
   * `NetworkError` naming OPAQUE when the tenant has it disabled, so a caller
   * can fall back to {@link login} rather than mistaking it for a bad password.
   *
   * **Only that case may fall back.** Any other rejection is a failed login,
   * and retrying it over {@link login} would hand the plaintext to a server
   * that just failed to prove it holds the record.
   */
  loginOpaque(usernameOrEmail: string, password: string): Promise<LoginResult> {
    return opaqueMethods.loginOpaque(this, usernameOrEmail, password);
  }

  /**
   * Build an OPAQUE registration record to send with any request that sets a
   * password (§23). The server cannot build one — it never sees the plaintext.
   *
   * Asynchronous because it performs a `register/start` round trip: the
   * envelope is sealed under the server's oblivious PRF, so unlike the SRP
   * verifier this replaces there is no offline computation that produces a
   * valid record.
   */
  opaqueEnrollment(password: string): Promise<opaqueMethods.OpaqueEnrollment> {
    return opaqueMethods.opaqueEnrollment(this, password);
  }

  /**
   * Whether this installation can perform OPAQUE (§23.2).
   *
   * Asynchronous, and genuinely able to answer `false`: `@axiam/opaque-wasm` is
   * an optional peer dependency, so an installation that skipped it reports
   * rather than throwing at login time.
   */
  opaqueAvailable(): Promise<boolean> {
    return opaqueMethods.opaqueAvailable();
  }

  /** `POST /api/v1/auth/mfa/verify` (§1, D-18). Completes the two-phase flow started by login(). */
  verifyMfa(mfaToken: string, code: string): Promise<LoginResult> {
    return authMethods.verifyMfa(this, mfaToken, code);
  }

  /** `POST /api/v1/auth/refresh` (§1). Usually driven reactively by the response interceptor (D-07). */
  refresh(): Promise<void> {
    return authMethods.refresh(this);
  }

  /** `POST /api/v1/auth/logout` (§1). Clears session csrf/auth state. */
  logout(): Promise<void> {
    return authMethods.logout(this);
  }

  /** `POST /api/v1/authz/check` (§1, FND-04). */
  checkAccess(check: AccessCheck): Promise<AccessDecision> {
    return authzMethods.checkAccess(this, check);
  }

  /** `can` — alias for checkAccess targeting browser/UI scenarios (§1 note). */
  can(action: string, resourceId: string, scope?: string): Promise<boolean> {
    return authzMethods.can(this, action, resourceId, scope);
  }

  /** `POST /api/v1/authz/check/batch` (§1). Results preserve input order. */
  batchCheck(checks: AccessCheck[]): Promise<AccessDecision[]> {
    return authzMethods.batchCheck(this, checks);
  }

  // -------------------------------------------------------------------------
  // §24 WebAuthn / passkeys — the relying-party layer
  //
  // These six work in Node as well as the browser: a service completing a
  // ceremony its native client ran is the relying party, exactly as a browser
  // is. The ceremony itself — the half that needs an authenticator — is
  // `axiam-sdk/browser` (§24.6).
  // -------------------------------------------------------------------------

  /** `POST /api/v1/auth/webauthn/register/start` (§24.1). Requires a session. */
  webauthnRegisterStart(): Promise<webauthnMethods.WebauthnRegistrationChallenge> {
    return webauthnMethods.webauthnRegisterStart(this);
  }

  /** `POST /api/v1/auth/webauthn/register/finish` (§24.1). Requires a session. */
  webauthnRegisterFinish(
    stateToken: Sensitive<string> | string,
    credentialName: string,
    response: WebauthnRegistrationResponse | string,
  ): Promise<WebauthnCredential> {
    return webauthnMethods.webauthnRegisterFinish(this, stateToken, credentialName, response);
  }

  /** `POST /api/v1/auth/webauthn/authenticate/start` (§24.1) — passkey as a second factor. */
  webauthnAuthenticateStart(
    challengeToken: Sensitive<string> | string,
  ): Promise<webauthnMethods.WebauthnAuthenticationChallenge> {
    return webauthnMethods.webauthnAuthenticateStart(this, challengeToken);
  }

  /** `POST /api/v1/auth/webauthn/authenticate/finish` (§24.1). Leaves the client authenticated (§24.3). */
  webauthnAuthenticateFinish(
    stateToken: Sensitive<string> | string,
    response: WebauthnAuthenticationResponse | string,
  ): Promise<webauthnMethods.WebauthnLoginResult> {
    return webauthnMethods.webauthnAuthenticateFinish(this, stateToken, response);
  }

  /** `POST .../authenticate/discoverable/start` (§24.1) — usernameless sign-in. */
  webauthnDiscoverableStart(
    workspace?: WebauthnWorkspace,
  ): Promise<webauthnMethods.WebauthnAuthenticationChallenge> {
    return webauthnMethods.webauthnDiscoverableStart(this, workspace);
  }

  /** `POST .../authenticate/discoverable/finish` (§24.1). Leaves the client authenticated (§24.3). */
  webauthnDiscoverableFinish(
    stateToken: Sensitive<string> | string,
    response: WebauthnAuthenticationResponse | string,
  ): Promise<webauthnMethods.WebauthnLoginResult> {
    return webauthnMethods.webauthnDiscoverableFinish(this, stateToken, response);
  }

  // -------------------------------------------------------------------------
  // §25 Account lifecycle and MFA enrolment
  // -------------------------------------------------------------------------

  /** `POST /api/v1/auth/mfa/enroll` (§25.1) — voluntary TOTP enrolment, by a signed-in user. */
  mfaEnroll(): Promise<accountMethods.MfaEnrollment> {
    return accountMethods.mfaEnroll(this);
  }

  /** `POST /api/v1/auth/mfa/confirm` (§25.1) — activate the factor `mfaEnroll` offered. */
  mfaConfirm(totpCode: string): Promise<boolean> {
    return accountMethods.mfaConfirm(this, totpCode);
  }

  /** `POST /api/v1/auth/mfa/setup/enroll` (§25.1) — start the enrolment a `login()` demanded. */
  mfaSetupEnroll(setupToken: Sensitive<string> | string): Promise<accountMethods.MfaEnrollment> {
    return accountMethods.mfaSetupEnroll(this, setupToken);
  }

  /** `POST /api/v1/auth/mfa/setup/confirm` (§25.1) — finish it, completing the interrupted login. */
  mfaSetupConfirm(setupToken: Sensitive<string> | string, totpCode: string): Promise<LoginResult> {
    return accountMethods.mfaSetupConfirm(this, setupToken, totpCode);
  }

  /** `POST /api/v1/auth/verify-email` (§25.1). */
  verifyEmail(token: Sensitive<string> | string, tenantId: string): Promise<void> {
    return accountMethods.verifyEmail(this, token, tenantId);
  }

  /** `POST /api/v1/auth/resend-verification` (§25.1). */
  resendVerification(email: string, tenantId: string): Promise<void> {
    return accountMethods.resendVerification(this, email, tenantId);
  }

  /** `POST /api/v1/auth/reset` (§25.1). Resolves whether or not the address exists (§25.4). */
  requestPasswordReset(request: accountMethods.PasswordResetRequest): Promise<void> {
    return accountMethods.requestPasswordReset(this, request);
  }

  /** `GET /api/v1/auth/reset/context` (§25.1) — the OPAQUE policy for a reset token's account. */
  passwordResetContext(
    token: Sensitive<string> | string,
  ): Promise<accountMethods.PasswordResetContext> {
    return accountMethods.passwordResetContext(this, token);
  }

  /** `POST /api/v1/auth/reset/confirm` (§25.1). */
  confirmPasswordReset(confirmation: accountMethods.PasswordResetConfirmation): Promise<void> {
    return accountMethods.confirmPasswordReset(this, confirmation);
  }
}
