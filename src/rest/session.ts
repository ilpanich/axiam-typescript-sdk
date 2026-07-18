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
    this.refreshGuard = createRefreshGuard();
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
function maybeBuildHttpsAgent(
  customCa: string | undefined,
  identity: ClientIdentity | undefined,
): unknown {
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
  if (typeof process === 'undefined') {
    // Browser: platform manages TLS; customCa and the client cert have no
    // effect there (a browser cannot present a client certificate from JS).
    return undefined;
  }
  // Node capability guard — require lazily so this branch never executes
  // (and never needs to resolve) in a browser bundle.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const https = require('node:https') as typeof import('node:https');
  return new https.Agent({
    ...(customCa ? { ca: customCa } : {}),
    // rejectUnauthorized is intentionally left at its secure default (true).
    ...(identity ? { cert: identity.cert, key: identity.key.expose() } : {}),
  });
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
