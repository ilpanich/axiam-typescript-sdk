// TokenManager — Node-persona token state (CONTRACT.md §7, D-09/D-11/D-26).
//
// Tokens are read from the tough-cookie jar by name (the ONLY token-source
// path — login/refresh response bodies carry no token fields; see
// RESEARCH.md Area 3) and wrapped in Sensitive<T> immediately. A
// synchronous, non-blocking `cachedAccessToken()` fast-path is provided for
// the grpc-js interceptor's `start()`, which cannot await (Pitfall 3) —
// mirrors the Rust SDK's src/token/manager.rs::cached_access_token exactly.

import type { CookieJar } from 'tough-cookie';
import { Sensitive } from '../core/index.js';
import { ACCESS_COOKIE, REFRESH_COOKIE, extractCookieValue } from './cookieJar.js';

/** Path the server scopes the `axiam_refresh` cookie to (mirrors csrf.rs). */
const REFRESH_COOKIE_PATH = '/api/v1/auth/refresh';

/** Tracks the access/refresh token pair for a Node session, kept in sync with the cookie jar after each REST call/refresh. */
export class TokenManager {
  readonly #jar: CookieJar;
  readonly #baseUrl: string;
  #tenantId: string | undefined;
  /**
   * Non-blocking cached copy of the current access token, kept in sync via
   * `syncFromJar()` after each REST call/refresh. Read via
   * `cachedAccessToken()` without ever touching the jar's async API — this
   * is the fast-path the grpc-js interceptor's synchronous `start()` needs
   * (Pitfall 3).
   */
  #cachedAccess: Sensitive<string> | null = null;

  constructor(jar: CookieJar, baseUrl: string, tenantId?: string) {
    this.#jar = jar;
    this.#baseUrl = baseUrl;
    this.#tenantId = tenantId;
  }

  /**
   * Synchronous, best-effort read of the last-known access token. Returns
   * `null` if no token has been cached yet (no request/refresh has
   * completed since construction, or `syncFromJar()` was never called).
   */
  cachedAccessToken(): Sensitive<string> | null {
    return this.#cachedAccess;
  }

  /**
   * Async read of the current `axiam_refresh` cookie value from the jar,
   * wrapped in Sensitive<T>. Queried against the refresh endpoint's URL
   * since the cookie is path-scoped to `/api/v1/auth/refresh` (not visible
   * at the bare base URL).
   */
  async refreshTokenValue(): Promise<Sensitive<string> | null> {
    const value = await extractCookieValue(this.#jar, `${this.#baseUrl}${REFRESH_COOKIE_PATH}`, REFRESH_COOKIE);
    return value === undefined ? null : new Sensitive(value);
  }

  /**
   * Refresh the in-memory cached access token from the jar. Call this after
   * every REST request/refresh so the synchronous gRPC-interceptor fast-path
   * (`cachedAccessToken()`) stays current (Pitfall 3).
   */
  async syncFromJar(): Promise<void> {
    const value = await extractCookieValue(this.#jar, this.#baseUrl, ACCESS_COOKIE);
    this.#cachedAccess = value === undefined ? null : new Sensitive(value);
  }

  /** The resolved tenant identifier (slug or UUID form), if known. */
  tenantId(): string | undefined {
    return this.#tenantId;
  }

  /** Set/update the resolved tenant identifier (e.g. after decoding the access token's tenant_id claim). */
  setTenantId(tenantId: string): void {
    this.#tenantId = tenantId;
  }

  /**
   * Best-effort decode of the `tenant_id`/`org_id` claims out of the cached
   * access token, WITHOUT signature verification. Used only to populate the
   * `refresh` request body (`RefreshRequest` requires both UUIDs) — never as a
   * trust decision: the actual credential is the httpOnly `axiam_access` cookie
   * the server verifies, and the server re-derives the authoritative `org_id`
   * from the tenant on refresh (see crates/axiam-api-rest handlers/auth.rs),
   * so echoing these values back carries no security weight. A malformed or
   * absent token yields an empty result (the caller then keeps whatever UUIDs
   * were resolved from construction options).
   */
  claimsFromCachedToken(): { tenantId?: string; orgId?: string } {
    const token = this.#cachedAccess?.expose();
    if (!token) {
      return {};
    }
    const claims = decodeJwtPayload(token);
    return {
      tenantId: typeof claims.tenant_id === 'string' ? claims.tenant_id : undefined,
      orgId: typeof claims.org_id === 'string' ? claims.org_id : undefined,
    };
  }

  /** Clear all cached token state (used by logout()). */
  clear(): void {
    this.#cachedAccess = null;
  }
}

/**
 * Decode a JWT's payload segment (the middle base64url part) into an object,
 * without verifying its signature. Returns `{}` for anything that is not a
 * well-formed three-segment JWT with a JSON object payload. This is a routing
 * helper, not a verifier — see {@link TokenManager.claimsFromCachedToken}.
 */
function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const segments = token.split('.');
    if (segments.length !== 3) {
      return {};
    }
    const json = Buffer.from(segments[1], 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
