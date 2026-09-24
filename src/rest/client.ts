// AxiamClient — the isomorphic REST + auth core (D-01/D-25).
//
// Constructor validates the required tenant (§5), builds the SharedSession
// (D-13), and installs the CSRF + reactive single-flight refresh
// interceptors (D-05/D-07). REST method implementations (login/verifyMfa/
// refresh/logout/checkAccess/can/batchCheck) are added by Task 2's
// auth.ts/authz.ts, which extend this class's prototype.

import type { AxiamClientOptions } from '../core/index.js';
import { AuthzError, NetworkError } from '../core/index.js';
import type { DecisionMemo } from '../core/decisionMemo.js';
import type { TelemetryReporter } from '../core/telemetryReporter.js';
import type { RetryOptions } from './retry.js';
import { createSession, SharedSession } from './session.js';
import { installInterceptors } from './interceptors.js';
import * as authMethods from './auth.js';
import type { DeviceToken } from './auth.js';
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
   * CONTRACT.md §5.2 rule 1 (contract 1.51) — the tenant **this handle** acts
   * on. Held here rather than on `session` (which every handle over one login
   * shares): a provisioning task acting on tenant A and another acting on
   * tenant B can share one session without either rewriting the other's
   * header between the moment it decides and the moment it sends. Set only
   * by {@link actingTenant} / {@link AxiamClientOptions.actingTenantId};
   * `undefined` means "send no `X-Axiam-Tenant`", byte-for-byte what every
   * client sent before contract 1.51.
   */
  readonly #actingTenantId: string | undefined;

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
  constructor(options: AxiamClientOptions, session?: SharedSession) {
    this.session = session ?? createSession(options);
    // Guarded (contract 1.51): `actingTenant()`/`clearActingTenant()` build a
    // second `AxiamClient` over this same session (see `#cloneWithActingTenant`
    // below) so that handle's own §5.2 gating and management-namespace getters
    // are wired correctly by this same constructor — installing the CSRF/
    // refresh interceptors a second time on one shared axios instance would
    // double-run both on every request the second handle makes.
    if (!this.session.interceptorsInstalled) {
      installInterceptors(this.session.axios, this.session);
      this.session.interceptorsInstalled = true;
    }
    // §5.2 rule 1: the value is a Uuid-shaped string, checked client-side —
    // the server silently ignores a value that does not parse and answers for
    // the caller's own tenant, so a helper that forwarded a non-UUID would
    // report success about the wrong tenant. The builder/construction form
    // cannot gate on organizationLevel: it precedes the login that would
    // reveal it (§5.2 rule 1's gating note), so only the shape is checked
    // here — see `actingTenant` for the on-client form, which does gate.
    this.#actingTenantId = options.actingTenantId === undefined
      ? undefined
      : requireUuid(options.actingTenantId, 'AxiamClientOptions.actingTenantId');
    // §27.2 rule 1: acquiring a handle performs no I/O and is not meant to be
    // observable. Copying the *descriptors* keeps the generated getters lazy,
    // so constructing a client does not construct 24 namespace objects; a
    // plain `Object.assign` would invoke every getter here.
    Object.defineProperties(this, Object.getOwnPropertyDescriptors(managementNamespaces(this)));
  }

  /** §17 decision memo. Disabled unless `decisionMemoTtlMs` was configured. Shared by every handle over this session (contract 1.51: moved onto `session` so `actingTenant()`'s clone shares it too). */
  get decisionMemo(): DecisionMemo {
    return this.session.decisionMemo;
  }

  /** §19 telemetry dispatcher. Empty unless a hook was installed. Shared by every handle over this session. */
  get telemetry(): TelemetryReporter {
    return this.session.telemetry;
  }

  /**
   * CONTRACT.md §5.2 rule 1 (contract 1.51) — act on another tenant of the
   * caller's organization, without a second login.
   *
   * Returns a **new handle** over this same `session` (§9's refresh guard,
   * §17's decision memo, the cookie jar/token manager — everything the
   * session holds — stay shared); `this` is unchanged. That is deliberate: a
   * provisioning task holding one login result but acting on several tenants
   * builds one handle per tenant and can run them concurrently without either
   * rewriting the other's `X-Axiam-Tenant` between deciding and sending.
   *
   * Meaningful only for an **organization-level** principal (§5.2): such a
   * principal is already a principal of every tenant in its organization, so
   * switching what it acts on needs no re-login. For an ordinary tenant
   * principal the same header change gets a `403` from the server.
   *
   * **Gating** (§5.2 rule 1's "gate on what the SDK knows, and let the server
   * decide the rest"):
   * - `tenantId` MUST be a UUID — refused client-side (`NetworkError`, zero
   *   wire calls) otherwise, the same §2 client-side error §27.4 rule 2 uses.
   *   The server parses the header as a UUID and silently ignores a value
   *   that does not, then answers for the caller's own tenant — a helper
   *   that forwarded a non-UUID would report success about the wrong one.
   * - When this session holds a completed login's reach (`session.principalScope`
   *   is set — a password/MFA/OPAQUE/WebAuthn/MFA-setup login has reported
   *   one), the switch is refused client-side (`AuthzError`, zero wire calls)
   *   unless `organizationLevel` is `true`, and refused when `reachableTenantIds`
   *   is present and does not name `tenantId` (§5.2.3 rule 4).
   * - A session holding **no** login result — a service account from
   *   `authenticateDevice()`, or a client an application injected a token
   *   into directly — has nothing to gate on: the header is sent as asked,
   *   and the server's `403` is the answer.
   *
   * **REST-only** (§5.2 rule 1). The gRPC interceptor reads no acting-tenant
   * metadata — the server's gRPC interceptor takes the tenant from the
   * bearer token's own claim, not from a header — so a gRPC call made through
   * this handle still acts on the token's tenant whatever this says. The SDK
   * does not invent a metadata key for it.
   */
  actingTenant(tenantId: string): AxiamClient {
    requireUuid(tenantId, 'tenantId');
    const scope = this.session.principalScope;
    if (scope !== undefined) {
      if (!scope.organizationLevel) {
        throw new AuthzError(
          'actingTenant() is meaningful only for an organization-level principal ' +
            '(CONTRACT.md §5.2 rule 1); this session\'s login result reported organizationLevel: false',
        );
      }
      if (scope.reachableTenantIds !== undefined && !scope.reachableTenantIds.includes(tenantId)) {
        throw new AuthzError(
          `actingTenant(${JSON.stringify(tenantId)}) is outside this principal's ` +
            'reachableTenantIds (CONTRACT.md §5.2.3 rule 4)',
        );
      }
    }
    return this.#cloneWithActingTenant(tenantId);
  }

  /**
   * Stop acting on another tenant — the inverse of {@link actingTenant}.
   *
   * Returns a new handle over the same session that sends no
   * `X-Axiam-Tenant` header at all, exactly as a client that never called
   * `actingTenant` does. `this` is unchanged.
   */
  clearActingTenant(): AxiamClient {
    return this.#cloneWithActingTenant(undefined);
  }

  /**
   * The `X-Axiam-Tenant` header this handle sends, or `undefined` when it
   * acts on no other tenant — the common case, and the only one before
   * contract 1.51.
   *
   * @internal — read by auth.ts/authz.ts/management/request.ts so the header
   * reaches every call site §5.2 rule 1 names (management, check_access /
   * batch_check, refresh, logout, and the self-service/WebAuthn posts) from
   * one place rather than 1.51 re-deriving it at each of them.
   */
  actingTenantHeaders(): Record<string, string> | undefined {
    return this.#actingTenantId === undefined
      ? undefined
      : { 'X-Axiam-Tenant': this.#actingTenantId };
  }

  /** @internal — the raw value, for the §17 memo key (contract 1.51: the key includes the acting tenant). */
  get actingTenantId(): string | undefined {
    return this.#actingTenantId;
  }

  /**
   * Build the new handle {@link actingTenant}/{@link clearActingTenant}
   * return, via the real constructor (never `Object.create` bypassing it —
   * `#actingTenantId` is a genuine private class field, which only the
   * constructor can install; an instance built any other way throws on the
   * first access to it).
   *
   * Passes `this.session` itself as the pre-built session, so the clone
   * shares it exactly as `createNodeClient` shares a `NodeSession` between
   * the client it builds and every transport attached to it — §9's refresh
   * guard, §17's decision memo, `session.principalScope`, the cookie jar and
   * token manager (Node persona) all stay one shared object, not duplicated.
   * The synthetic options object below carries only what the constructor
   * still reads when a session is supplied (§5.2 rule 1's shape check on
   * `actingTenantId`) — `session.interceptorsInstalled` (set `true` by the
   * very first `AxiamClient` built over this session) stops the constructor
   * from re-installing the CSRF/refresh interceptors a second time.
   */
  #cloneWithActingTenant(actingTenantId: string | undefined): AxiamClient {
    const options: AxiamClientOptions = {
      baseUrl: this.session.baseUrl,
      tenantId: this.session.tenantId,
      tenantSlug: this.session.tenantSlug,
      ...(actingTenantId !== undefined ? { actingTenantId } : {}),
    };
    return new AxiamClient(options, this.session);
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
    // §18 shutdown flag now lives on `session` (contract 1.51): every handle
    // over one session — this client and any `actingTenant()`/
    // `clearActingTenant()` clone of it — closes together, exactly as the
    // Rust reference's `Arc<AxiamClientInner>` closes every handle over it.
    this.session.closed = true;
    this.decisionMemo.clear();
  }

  /**
   * Throws if {@link close} has been called (§18.1 rule 4).
   *
   * @internal
   */
  ensureOpen(): void {
    if (this.session.closed) {
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
      enabled: this.session.retryEnabled,
      telemetry: this.telemetry.dispatcher,
    };
  }

  /** `POST /api/v1/auth/login` (§1, D-18). */
  login(email: string, password: string): Promise<LoginResult> {
    return authMethods.login(this, email, password);
  }

  /**
   * `POST /api/v1/auth/device` (§6.1 rules 6–10, contract 1.51) — the mTLS
   * device login: authenticate by the client certificate this client was
   * built with (`clientCert`/`clientKey`) rather than a username/password.
   * No request body; identity comes entirely from the TLS handshake.
   *
   * **Reachable only when this client was constructed with a client
   * certificate.** Elsewhere it fails client-side with `AuthError`, with
   * zero wire calls — going to the wire would only earn the `401` the
   * server already knows it would give.
   *
   * Adopts the returned {@link DeviceToken} as this client's credential
   * exactly as a completed `login()` is adopted: every subsequent
   * same-origin REST request carries it as `Authorization: Bearer`. **There
   * is no refresh token** — a device re-authenticates by calling this
   * operation again, and a later `401` on the adopted token surfaces as
   * `AuthError` without a refresh attempt.
   */
  authenticateDevice(): Promise<DeviceToken> {
    return authMethods.authenticateDevice(this);
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
   * password (§23), sealed against the tenant this client is **acting on**.
   * The server cannot build one — it never sees the plaintext.
   *
   * Right for creating **another** account (§27 `users.create`); for the
   * caller's *own* password change use {@link opaqueEnrollmentForSelf}, which
   * seals against the tenant the account lives in (§5.2.2 rule 2).
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
   * Build an OPAQUE registration record for the **caller's own** new password,
   * sealed against the tenant the caller's account lives in (§5.2.2 rule 2).
   *
   * Identical to {@link opaqueEnrollment} for every ordinary principal — the
   * two tenants are the same value there. They diverge for an
   * organization-level principal that has selected another tenant to act on,
   * and a record sealed against the acting one is refused with *"the OPAQUE
   * session was issued for a different tenant"*.
   *
   * Requires a completed login: the principal tenant is reported by the login
   * response, so there is nothing to seal against before then.
   */
  opaqueEnrollmentForSelf(password: string): Promise<opaqueMethods.OpaqueEnrollment> {
    return opaqueMethods.opaqueEnrollmentForSelf(this, password);
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

  /**
   * `POST /api/v1/auth/webauthn/setup/register/start` (§24.1, contract 1.45)
   * — the WebAuthn twin of `mfaSetupEnroll`. Takes no session; the setup
   * token from `login()`'s `mfa_setup_required` outcome is the only credential.
   */
  webauthnSetupRegisterStart(
    setupToken: Sensitive<string> | string,
  ): Promise<webauthnMethods.WebauthnRegistrationChallenge> {
    return webauthnMethods.webauthnSetupRegisterStart(this, setupToken);
  }

  /**
   * `POST /api/v1/auth/webauthn/setup/register/finish` (§24.1, contract 1.45)
   * — the WebAuthn twin of `mfaSetupConfirm`. Adopts credentials exactly as
   * `mfaSetupConfirm` does (§25.2 rule 2): it completes the login `login()`
   * left interrupted.
   */
  webauthnSetupRegisterFinish(
    setupToken: Sensitive<string> | string,
    stateToken: Sensitive<string> | string,
    credentialName: string,
    response: WebauthnRegistrationResponse | string,
  ): Promise<LoginResult> {
    return webauthnMethods.webauthnSetupRegisterFinish(
      this,
      setupToken,
      stateToken,
      credentialName,
      response,
    );
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

  /**
   * `POST /api/v1/auth/resend-verification` (§25.1) — the unauthenticated
   * resend. Resolves whatever the outcome; use {@link resendOwnVerification}
   * when there is a session (§25.7).
   */
  resendVerification(email: string, tenantId: string): Promise<void> {
    return accountMethods.resendVerification(this, email, tenantId);
  }

  /**
   * `POST /api/v1/users/me/resend-verification` (§25.1, §25.7) — the
   * authenticated resend, which takes no address and reports what happened.
   */
  resendOwnVerification(): Promise<void> {
    return accountMethods.resendOwnVerification(this);
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

/** Canonical 8-4-4-4-12 hex UUID shape. Shape only — no version/variant check, matching §27.4 rule 2's own check elsewhere in this SDK. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * CONTRACT.md §5.2 rule 1 — refuse a non-UUID acting-tenant value
 * client-side, with zero wire calls, the same §2 client-side error §27.4
 * rule 2 uses for a non-UUID path identifier. The server parses the header
 * as a UUID and *silently ignores* a value that does not parse, then
 * answers for the caller's own tenant — reporting success about the wrong
 * one is worse than refusing up front.
 */
function requireUuid(value: string, paramName: string): string {
  if (!UUID_RE.test(value)) {
    throw new NetworkError(
      `${paramName} must be a UUID (CONTRACT.md §5.2 rule 1 / §27.4 rule 2); got ${JSON.stringify(value)}`,
    );
  }
  return value;
}
