// SharedSession — the object other transports (Node persona 17-03, middleware
// 17-05) attach gRPC/JWKS/middleware state to (D-13).
//
// Holds: the axios instance, the tenant header value (computed once at
// construction), a mutable csrfToken store, the base URL, and a per-instance
// single-flight refresh guard (CR-02: NOT the module-level default guard —
// each SharedSession gets its own via createRefreshGuard(), so two
// independent AxiamClient/NodeSession instances never cross-wire refreshes).
// One login() drives all transports for a given session.

import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios';
import type { AxiamClientOptions, ClientIdentity, RefreshGuard, Sensitive } from '../core/index.js';
import {
  CERT_PEM_MARKER,
  createRefreshGuard,
  DecisionMemo,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  resolveClientIdentity,
  TelemetryDispatcher,
  TelemetryReporter,
} from '../core/index.js';

const PEM_MARKER = CERT_PEM_MARKER;

/**
 * The single session object every AXIAM transport (REST here, gRPC/AMQP in
 * 17-03/17-04, middleware in 17-05) attaches to. Constructed once per
 * `AxiamClient` instance.
 */
export class SharedSession {
  /** The underlying axios instance this session's requests are issued through, pre-configured with `baseUrl`, credential forwarding, and (Node) an optional custom-CA `httpsAgent`. */
  readonly axios: AxiosInstance;
  /** The AXIAM server base URL this session was constructed with (`AxiamClientOptions.baseUrl`). */
  readonly baseUrl: string;
  /** The resolved tenant identifier (`tenantSlug` or `tenantId`) injected as the `X-Tenant-ID` header on every same-origin request (§5.2). */
  readonly tenantHeaderValue: string;
  /** Configured tenant UUID (`AxiamClientOptions.tenantId`), if the client was built with the UUID form. */
  readonly tenantId: string | undefined;
  /** Configured tenant slug (`AxiamClientOptions.tenantSlug`), if the client was built with the slug form. */
  readonly tenantSlug: string | undefined;
  /** Configured organization UUID (`AxiamClientOptions.orgId`), if supplied (§5). */
  readonly orgId: string | undefined;
  /** Configured organization slug (`AxiamClientOptions.orgSlug`), if supplied (§5). */
  readonly orgSlug: string | undefined;
  /** Expected `iss` for locally-verified access tokens (§10.1 rule 5), if configured; `undefined` means no issuer check. */
  readonly expectedIssuer: string | undefined;
  /** Expected `aud` for locally-verified access tokens (§10.1 rule 6), if configured; `undefined` means no audience check. */
  readonly expectedAudience: string | undefined;
  /**
   * True when this session was constructed with a §6.1 mTLS client identity
   * (`clientCert` + `clientKey`), and therefore presents a client certificate
   * on every request it makes.
   *
   * Read by the §12 OIDC helpers to decide whether CONTRACT.md §21.3 rule 2
   * applies: an `mtls_endpoint_aliases` entry is preferred only on a call that
   * is actually going over mutual TLS, and a session without an identity must
   * keep using the top-level endpoints.
   */
  readonly presentsClientCertificate: boolean;
  /**
   * Resolved tenant UUID used to build the `refresh` body (`RefreshRequest`
   * requires the UUID form, not a slug). Seeded from `orgId`/`tenantId` config
   * when the UUID was supplied, then updated from the access-token `tenant_id`
   * claim after each successful login/refresh (Node persona only — the browser
   * cannot read the httpOnly access-token cookie).
   */
  resolvedTenantId: string | undefined;
  /**
   * Resolved organization UUID used to build the `refresh` body. Seeded from
   * `orgId` config, then updated from the access-token `org_id` claim after a
   * successful login (Node persona). Mirrors the Rust SDK's `resolved_org_id`.
   */
  resolvedOrgId: string | undefined;
  /**
   * The tenant the signed-in principal's record *lives* in — CONTRACT.md
   * §5.2.2 — as reported by the login response.
   *
   * Distinct from `resolvedTenantId`, which is the tenant being acted on: the
   * two diverge for an organization-level principal that has selected another
   * one. Read by `opaqueEnrollmentForSelf`, which must seal a §23 record
   * against the account's own tenant rather than whichever one this client is
   * currently pointed at. `undefined` until a login completes.
   */
  resolvedPrincipalTenantId: string | undefined;
  /** Mutable CSRF token store — populated by the request/response interceptors (D-05). */
  csrfToken: string | undefined;
  /** Set true once a successful login/verifyMfa has completed. */
  authenticated = false;
  /**
   * §17 decision memo (contract 1.51: moved here from `AxiamClient` so every
   * handle sharing this session — the base client and any
   * `actingTenant(id)`/`clearActingTenant()` clone of it — shares one memo
   * rather than each getting an empty one of its own). Disabled unless
   * `decisionMemoTtlMs` was configured.
   */
  readonly decisionMemo: DecisionMemo;
  /**
   * §19 telemetry dispatcher (moved here alongside `decisionMemo`, same
   * reason). Empty unless a hook was installed.
   */
  readonly telemetry: TelemetryReporter;
  /** §16.1 disable switch (moved here alongside `decisionMemo`). Defaults to enabled. */
  readonly retryEnabled: boolean;
  /**
   * §18 shutdown flag (moved here from `AxiamClient`, contract 1.51): a
   * handle and every clone of it sharing this session close together, exactly
   * as the Rust reference's `Arc<AxiamClientInner>` closes every handle over
   * it. Set once by `AxiamClient.close()`; read by `ensureOpen()`.
   */
  closed = false;
  /**
   * Whether {@link installInterceptors} has already run for this session's
   * axios instance (contract 1.51). Guards `AxiamClient.actingTenant()` /
   * `.clearActingTenant()`, which construct a second `AxiamClient` handle
   * over this same session: without this flag that second construction would
   * install the CSRF/refresh interceptors a second time, double-running them
   * on every request. Checked and set only by `rest/client.ts`.
   *
   * @internal
   */
  interceptorsInstalled = false;
  /**
   * CONTRACT.md §5.2 / §5.2.3 (contract 1.51) — what the last completed login
   * reported about the principal's reach, when it reported anything at all.
   *
   * `undefined` until a session-establishing response has carried a user
   * object, and reset to `undefined` by `logout()` and by
   * `authenticateDevice()` (§6.1: a device token is a service-account
   * credential with no `LoginUserInfo` behind it). It is `undefined` on
   * purpose rather than a defaulted `false` — "the server did not say"
   * must not gate `AxiamClient.actingTenant()` as though the server had
   * said "not organization-level" (§5.2 rule 1: a client holding no login
   * result has nothing to gate on, so it sends the header and lets the
   * server's `403` decide).
   *
   * Shared across every handle over this session, not per-handle — the
   * principal did not change because a caller asked for a different acting
   * tenant.
   */
  principalScope: { organizationLevel: boolean; reachableTenantIds?: string[] } | undefined;
  /**
   * CONTRACT.md §6.1 rules 6–10 (contract 1.51) — the access token
   * `authenticateDevice()` adopted, when this session's credential is a
   * device/mTLS one rather than a cookie session.
   *
   * `undefined` is the state every session starts in and the only one
   * before contract 1.51: nothing about REST authentication changes for a
   * client that never calls `authenticateDevice()`. Once set, the request
   * interceptor installed in `createSession` sends it as
   * `Authorization: Bearer <token>` and switches this request to the
   * jar-free agent pair `noCredentialsConfig()` builds — the server reads
   * the `axiam_access` cookie **before** the `Authorization` header (rule 3
   * of the "what the plan did not anticipate" note), so a cookie left over
   * from an earlier session would otherwise silently outrank this token and
   * the request would run as that earlier session's principal. There is no
   * refresh token behind a device token (rule 6), so `installRefreshInterceptor`
   * checks this field too and never attempts one.
   *
   * Cleared by `logout()`, and by a subsequent `login()`/`verifyMfa()` that
   * establishes an ordinary cookie session on the same client.
   */
  deviceAccessToken: Sensitive<string> | undefined;
  /**
   * Per-instance single-flight refresh guard (CR-02, D-13). Shared across
   * this session's REST and gRPC transports (rest/interceptors.ts,
   * grpc/callWithRefresh.ts both call `session.refreshGuard(...)`), but
   * NEVER shared with a different SharedSession/NodeSession instance.
   *
   * @internal SDK-internal transport wiring, not intended to be invoked
   * directly by SDK consumers — refreshes are driven automatically by the
   * response interceptor (rest) or `callWithRefresh` (grpc).
   */
  readonly refreshGuard: RefreshGuard;

  constructor(options: AxiamClientOptions, axiosInstance: AxiosInstance, tenantHeaderValue: string) {
    this.axios = axiosInstance;
    this.baseUrl = options.baseUrl;
    this.tenantHeaderValue = tenantHeaderValue;
    this.tenantId = options.tenantId;
    this.tenantSlug = options.tenantSlug;
    this.orgId = options.orgId;
    this.orgSlug = options.orgSlug;
    this.expectedIssuer = options.expectedIssuer;
    this.expectedAudience = options.expectedAudience;
    // Both halves, because §6.1 is all-or-nothing: `resolveClientIdentity`
    // rejects one without the other before this line is reached.
    this.presentsClientCertificate =
      options.clientCert !== undefined && options.clientKey !== undefined;
    // Seed the resolved UUIDs from any UUID-form config so the browser persona
    // (which cannot decode the httpOnly access token) can still build a valid
    // refresh body. The Node persona later overwrites these from the
    // access-token claims (NodeSession#resolveIdentifiersFromToken).
    this.resolvedTenantId = options.tenantId;
    this.resolvedOrgId = options.orgId;
    this.refreshGuard = createRefreshGuard();
    // §17.1 rule 1: off unless the caller asked for it.
    this.decisionMemo = new DecisionMemo(options.decisionMemoTtlMs ?? 0);
    this.telemetry = new TelemetryReporter(new TelemetryDispatcher(options.telemetryHook));
    // §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
    // here, because construction is the only moment an operator can act on it.
    this.decisionMemo.reportClamp(options.decisionMemoTtlMs ?? 0, this.telemetry.dispatcher);
    this.retryEnabled = options.retryEnabled ?? true;
  }

  /**
   * Build the `POST /api/v1/auth/refresh` request body (§1). The server's
   * `RefreshRequest` requires both `tenant_id` and `org_id` as UUIDs, so this
   * emits the resolved UUIDs — from the access-token claims after login, or
   * from UUID-form construction options as a fallback. Fields that could not
   * be resolved are omitted (the server then answers with a clear 400), rather
   * than sending a slug where a UUID is required.
   */
  buildRefreshBody(): Record<string, string> {
    const body: Record<string, string> = {};
    if (this.resolvedTenantId) {
      body.tenant_id = this.resolvedTenantId;
    }
    if (this.resolvedOrgId) {
      body.org_id = this.resolvedOrgId;
    }
    return body;
  }

  /**
   * Build the `POST /api/v1/auth/login` request body (§1/§5). Carries the
   * configured tenant and organization identifiers (UUID or slug form) in
   * addition to the credentials — the server resolves the workspace from the
   * body, not the `X-Tenant-ID` header, and rejects a login that omits org
   * context. Undefined identifiers are omitted.
   */
  buildLoginBody(email: string, password: string): Record<string, string> {
    const body: Record<string, string> = { username_or_email: email, password };
    if (this.tenantId) {
      body.tenant_id = this.tenantId;
    }
    if (this.tenantSlug) {
      body.tenant_slug = this.tenantSlug;
    }
    if (this.orgId) {
      body.org_id = this.orgId;
    }
    if (this.orgSlug) {
      body.org_slug = this.orgSlug;
    }
    return body;
  }

  /**
   * Optional session-level hook invoked by rest/auth.ts after a successful
   * login()/verifyMfa() (CR-01, D-05). The base SharedSession (browser
   * persona) does not implement it — the browser reads document.cookie
   * directly on every request and has no jar to sync from. NodeSession
   * overrides this to populate `csrfToken` from its cookie jar and refresh
   * the cached access token.
   */
  onAuthenticated?(): Promise<void>;

  /**
   * Host-isolation guard (3A, defense in depth): returns `true` when `url`
   * targets a host other than this session's base origin — an absolute
   * third-party URL, or a redirect that axios/the browser resolved off-origin.
   * The tenant identifier and CSRF token must never be attached to such a
   * request. A relative/host-less `url` (the normal case, merged against
   * `baseUrl`) is same-origin and returns `false`. Mirrors the Python SDK's
   * `_prepare_request` guard. Malformed input fails closed (treated as
   * foreign).
   */
  isForeignHost(url: string | undefined): boolean {
    if (!url) {
      return false;
    }
    try {
      const target = new URL(url, this.baseUrl);
      return target.host !== new URL(this.baseUrl).host;
    } catch {
      return true;
    }
  }

  /**
   * Axios config for a call that MUST NOT carry this session's own credential
   * — no jar cookie, no `Authorization` header — even when the session is
   * otherwise authenticated (CONTRACT.md §24.1, contract 1.45: the
   * `setup/register/*` pair takes a setup token as its only credential, and
   * an SDK MUST NOT attach a second one).
   *
   * The browser persona has no jar of its own to bypass: cookies ride solely
   * because of `withCredentials`, so turning it off for this one request is
   * the whole fix — the platform manages the rest, and this SDK never sets an
   * `Authorization` header on an `AxiamClient` call in the first place.
   * `NodeSession` overrides this: `withCredentials` has no effect on
   * axios's Node http adapter, whose cookie behaviour comes from the agent
   * attached to the instance, not from per-request config.
   */
  noCredentialsConfig(): AxiosRequestConfig {
    return { withCredentials: false };
  }
}

/**
 * Resolve the required tenant header value from options (§5). Throws if
 * neither tenantSlug nor tenantId is provided — there is no default tenant.
 */
export function resolveTenantHeaderValue(options: AxiamClientOptions): string {
  if (options.tenantSlug) {
    return options.tenantSlug;
  }
  if (options.tenantId) {
    return options.tenantId;
  }
  throw new Error(
    'AxiamClient construction requires a tenant: provide either tenantSlug or tenantId (CONTRACT.md §5).',
  );
}

/**
 * Build the Node-only `https.Agent` carrying the customCa server-trust PEM
 * (§6) and/or the mTLS client identity (§6.1). Guarded by
 * `typeof process !== 'undefined'` as a CAPABILITY guard (Node has node:https
 * available), NOT a persona-sniffing branch — browsers ignore both customCa
 * and the client certificate entirely since the platform manages TLS itself.
 *
 * The client cert/key (§6.1) is an ADDITIVE client credential: it is passed
 * as `{ cert, key }` alongside `{ ca }` and NEVER touches `rejectUnauthorized`
 * — strict server verification stays at its secure default. The private key is
 * exposed from its {@link ClientIdentity} `Sensitive` wrapper only here, at the
 * point of handing it to the TLS stack, and is not retained anywhere else.
 */
/**
 * Load a Node builtin without ever statically referencing it — this file is
 * shared with the browser-safe `.`/`/rest` entries, so it must not import
 * `node:https`/`node:http` at the top level, yet the Node persona needs one
 * synchronously (session construction, and {@link SharedSession.noCredentialsConfig}).
 *
 * `process.getBuiltinModule` (Node >= 20.16 / >= 22.3) loads a builtin with no
 * module system involved — no `import`, no `require`, nothing for a bundler to
 * rewrite. A bare `require('node:...')` satisfies the "no static import"
 * constraint but not the synchronous-under-ESM one: tsup rewrites it into a
 * shim that throws `Dynamic require of "..." is not supported`, so under
 * genuine Node ESM (`axiam-sdk/node`'s `import` condition) it would fail
 * before the module ever loaded. Reached off `process`, which every caller has
 * already capability-guarded, so a browser bundle never evaluates this.
 */
function loadNodeBuiltin<T>(id: 'node:https' | 'node:http'): T {
  const getBuiltinModule = (
    process as unknown as { getBuiltinModule?: (moduleId: string) => unknown }
  ).getBuiltinModule;
  if (typeof getBuiltinModule === 'function') {
    return getBuiltinModule.call(process, id) as T;
  }
  // Older Node (the package still declares engines.node >= 18). `require` is
  // real in the CJS build, so this keeps working there; in the ESM build it is
  // the throwing shim, and the catch turns that into an error that says what
  // to actually do instead of leaking a bundler implementation detail.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(id) as T;
  } catch {
    throw new Error(
      `this call requires Node's ${id} module, which this ESM build cannot load on Node ${process.version}: ` +
        'process.getBuiltinModule is unavailable (added in Node 20.16 / 22.3) and `require` does not exist in an ES module. ' +
        'Upgrade Node to >= 20.16, or load the CommonJS build (CONTRACT.md §6 / §6.1).',
    );
  }
}

/**
 * Build the Node-only `https.Agent` carrying the customCa server-trust PEM
 * (§6) and/or the mTLS client identity (§6.1). Guarded by
 * `typeof process !== 'undefined'` as a CAPABILITY guard (Node has node:https
 * available), NOT a persona-sniffing branch — browsers ignore both customCa
 * and the client certificate entirely since the platform manages TLS itself.
 *
 * The client cert/key (§6.1) is an ADDITIVE client credential: it is passed
 * as `{ cert, key }` alongside `{ ca }` and NEVER touches `rejectUnauthorized`
 * — strict server verification stays at its secure default. The private key is
 * exposed from its {@link ClientIdentity} `Sensitive` wrapper only here, at the
 * point of handing it to the TLS stack, and is not retained anywhere else.
 */
function loadNodeHttps(): typeof import('node:https') {
  return loadNodeBuiltin<typeof import('node:https')>('node:https');
}

export interface NodeTlsOptions {
  /** §6 server-trust PEM bundle. */
  ca?: string;
  /** §6.1 client-certificate chain (PEM). */
  cert?: string;
  /** §6.1 private key (PEM). Secret material — never logged or retained. */
  key?: string;
}

/**
 * The TLS material for a Node agent, or `undefined` when there is nothing to
 * configure. `rejectUnauthorized` is deliberately absent: strict server
 * verification stays at its secure default and this object never carries a
 * TLS-bypass switch (§6).
 *
 * Split out from {@link maybeBuildHttpsAgent} because the Node persona cannot
 * use a plain `https.Agent` at all — see {@link resolveNodeTlsOptions}.
 */
function tlsOptionsFrom(
  customCa: string | undefined,
  identity: ClientIdentity | undefined,
): NodeTlsOptions | undefined {
  if (!customCa) {
    // Still short-circuit only when there is nothing to configure at all.
    if (!identity) {
      return undefined;
    }
  } else if (!customCa.includes(PEM_MARKER)) {
    throw new Error(
      'customCa must be a PEM-encoded certificate (expected to contain "-----BEGIN CERTIFICATE-----") (CONTRACT.md §6).',
    );
  }
  return {
    ...(customCa ? { ca: customCa } : {}),
    ...(identity ? { cert: identity.cert, key: identity.key.expose() } : {}),
  };
}

/**
 * Re-derive the Node TLS options from client options, for a persona that must
 * build its own agent rather than use the one {@link createSession} attaches.
 *
 * The Node persona is exactly that case. `axios-cookiejar-support`'s request
 * interceptor THROWS ("does not support for use with other http(s).Agent")
 * when it finds an `httpsAgent` it did not create, and otherwise overwrites
 * the agent with a bare `HttpsCookieAgent` — so under `createNodeClient` a
 * customCa or client certificate was either fatal or silently discarded,
 * independently of the ESM/require problem in {@link loadNodeHttps}. The Node
 * persona therefore constructs ONE agent that is both jar-aware and
 * TLS-configured (see `src/node/cookieJar.ts`), using these options.
 *
 * Not exported from the package barrel: the returned object holds the private
 * key (§6.1 rule 3 / §7), and its only legitimate consumer is the agent
 * construction inside this SDK.
 */
export function resolveNodeTlsOptions(options: AxiamClientOptions): NodeTlsOptions | undefined {
  return tlsOptionsFrom(options.customCa, resolveClientIdentity(options));
}

/**
 * A pair of plain (non-jar) Node agents, TLS-configured from the same
 * material {@link resolveNodeTlsOptions} produces, for `NodeSession`'s
 * {@link SharedSession.noCredentialsConfig}. Deliberately **not** the
 * jar-wrapped `HttpCookieAgent`/`HttpsCookieAgent` `wrapAxios` builds
 * (`src/node/cookieJar.ts`): that agent injects this session's cookies into
 * every request it carries regardless of axios per-request config (it acts at
 * the raw `http.ClientRequest` layer — see `create_cookie_agent.js`'s
 * `addRequest` override), so a call that must not carry them needs a
 * different agent object entirely, not a config flag.
 *
 * Built once, lazily, and cached by the caller — `https.Agent`/`http.Agent`
 * pool connections, and there is no reason for the one call a client makes
 * with no session to open a fresh socket every time.
 */
export function buildPlainNodeAgents(tls: NodeTlsOptions | undefined): {
  httpAgent: unknown;
  httpsAgent: unknown;
} {
  const http = loadNodeBuiltin<typeof import('node:http')>('node:http');
  const https = loadNodeHttps();
  return {
    httpAgent: new http.Agent(),
    httpsAgent: new https.Agent(tls ?? {}),
  };
}

function maybeBuildHttpsAgent(
  customCa: string | undefined,
  identity: ClientIdentity | undefined,
): unknown {
  const tls = tlsOptionsFrom(customCa, identity);
  if (!tls) {
    return undefined;
  }
  if (typeof process === 'undefined') {
    // Browser: platform manages TLS; customCa and the client cert have no
    // effect there (a browser cannot present a client certificate from JS).
    return undefined;
  }
  // Node capability guard — resolved lazily (see loadNodeHttps) so this
  // branch never executes, and never needs to resolve, in a browser bundle.
  const https = loadNodeHttps();
  return new https.Agent(tls);
}

/** Build the axios instance + SharedSession for an AxiamClient (D-13/D-25). */
export function createSession(options: AxiamClientOptions): SharedSession {
  const tenantHeaderValue = resolveTenantHeaderValue(options);

  // customCa is validated (PEM-shape) even when running in an environment
  // that will end up ignoring it (browser), so construction fails fast and
  // consistently across personas (§6).
  if (options.customCa !== undefined && !options.customCa.includes(PEM_MARKER)) {
    throw new Error(
      'customCa must be a PEM-encoded certificate (expected to contain "-----BEGIN CERTIFICATE-----") (CONTRACT.md §6).',
    );
  }

  // The mTLS client identity (§6.1) is likewise validated on every persona so
  // a one-of/bad-PEM misconfiguration throws identically in browser and Node,
  // even though only Node presents the certificate.
  const clientIdentity = resolveClientIdentity(options);

  const httpsAgent = maybeBuildHttpsAgent(options.customCa, clientIdentity);

  const axiosInstance = axios.create({
    baseURL: options.baseUrl,
    withCredentials: true,
    timeout: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
    ...(httpsAgent ? { httpsAgent } : {}),
  });

  const session = new SharedSession(options, axiosInstance, tenantHeaderValue);

  // Attach X-Tenant-ID to every outgoing request (§5.2) — except when the
  // request targets a host other than our own origin (host-isolation, 3A).
  axiosInstance.interceptors.request.use((config) => {
    if (session.isForeignHost(config.url)) {
      return config;
    }
    config.headers = config.headers ?? {};
    config.headers['X-Tenant-ID'] = session.tenantHeaderValue;
    return config;
  });

  // The §6.1 device-token interceptor (contract 1.51) is installed by
  // `installInterceptors` (rest/interceptors.ts) instead of here, alongside
  // CSRF/refresh — NOT here, deliberately. This function's `session` is
  // discarded by the Node persona once its `.axios`/`.tenantHeaderValue` are
  // lifted into a wrapping `NodeSession` (see `createNodeSession`); an
  // interceptor closing over it would keep reading a `deviceAccessToken`
  // that `authenticateDevice()` actually sets on the *NodeSession*, and
  // never see it. `installInterceptors` runs against whichever session
  // `AxiamClient`'s constructor was actually given, which is always the
  // right one.
  return session;
}
