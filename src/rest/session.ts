// SharedSession — the object other transports (Node persona 17-03, middleware
// 17-05) attach gRPC/JWKS/middleware state to (D-13).
//
// Holds: the axios instance, the tenant header value (computed once at
// construction), a mutable csrfToken store, the base URL, and a per-instance
// single-flight refresh guard (CR-02: NOT the module-level default guard —
// each SharedSession gets its own via createRefreshGuard(), so two
// independent AxiamClient/NodeSession instances never cross-wire refreshes).
// One login() drives all transports for a given session.

import axios, { type AxiosInstance } from 'axios';
import type { AxiamClientOptions, ClientIdentity, RefreshGuard } from '../core/index.js';
import {
  CERT_PEM_MARKER,
  createRefreshGuard,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  resolveClientIdentity,
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
  /** Mutable CSRF token store — populated by the request/response interceptors (D-05). */
  csrfToken: string | undefined;
  /** Set true once a successful login/verifyMfa has completed. */
  authenticated = false;
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
    // Seed the resolved UUIDs from any UUID-form config so the browser persona
    // (which cannot decode the httpOnly access token) can still build a valid
    // refresh body. The Node persona later overwrites these from the
    // access-token claims (NodeSession#resolveIdentifiersFromToken).
    this.resolvedTenantId = options.tenantId;
    this.resolvedOrgId = options.orgId;
    this.refreshGuard = createRefreshGuard();
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
function loadNodeHttps(): typeof import('node:https') {
  // Node >= 20.16 / >= 22.3: `process.getBuiltinModule` loads a builtin
  // SYNCHRONOUSLY with no module system involved — no `import`, no `require`,
  // nothing for a bundler to rewrite. That is the whole point here: this file
  // is shared with the browser-safe `.`/`/rest` entries, so it must never
  // statically reference a Node builtin, yet the Node persona needs one
  // synchronously (buildSession is called from a constructor).
  //
  // The previous `require('node:https')` satisfied the first constraint but
  // not the second: tsup rewrites a bare `require` in ESM output into a shim
  // that throws `Dynamic require of "https" is not supported`, so under
  // genuine Node ESM — which is what `axiam-sdk/node`'s `import` condition
  // resolves to — EVERY call needing customCa or a client certificate failed
  // before the TLS handshake. It is reached off `process`, which the caller
  // has already capability-guarded, so a browser bundle never evaluates it.
  const getBuiltinModule = (
    process as unknown as { getBuiltinModule?: (id: string) => unknown }
  ).getBuiltinModule;
  if (typeof getBuiltinModule === 'function') {
    return getBuiltinModule.call(process, 'node:https') as typeof import('node:https');
  }
  // Older Node (the package still declares engines.node >= 18). `require` is
  // real in the CJS build, so this keeps working there; in the ESM build it is
  // the throwing shim, and the catch turns that into an error that says what
  // to actually do instead of leaking a bundler implementation detail.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('node:https') as typeof import('node:https');
  } catch {
    throw new Error(
      `customCa and clientCert require Node's https module, which this ESM build cannot load on Node ${process.version}: ` +
        'process.getBuiltinModule is unavailable (added in Node 20.16 / 22.3) and `require` does not exist in an ES module. ' +
        'Upgrade Node to >= 20.16, or load the CommonJS build (CONTRACT.md §6 / §6.1).',
    );
  }
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

  return session;
}
