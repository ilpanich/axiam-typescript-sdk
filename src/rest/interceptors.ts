// Axios interceptors: CSRF forwarding (D-05, §3) + reactive single-flight
// 401->refresh (D-07, §9). Mirrors frontend/src/lib/api.ts's proven pattern,
// generalized off the app store: this is a library, not an app — refresh
// failure clears session auth state and rejects; it never redirects
// (no window.location access anywhere in this module).

import type { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { csrfHeaderForMethod, mapHttpStatusToError } from '../core/index.js';
import type { SharedSession } from './session.js';

/**
 * Endpoints that must never trigger a silent refresh (§9.3, §12.3 rule 3).
 *
 * Two groups:
 * - the refresh endpoint itself plus login/logout — not
 *   authenticated-session-continuation calls, so refreshing would only build
 *   an infinite loop;
 * - the `/oauth2/*` endpoints — they authenticate the *client* with
 *   `client_id`/`client_secret`, not the user session. A `401` there is a
 *   client-credential failure, not a session expiry, so retrying after a
 *   session refresh cannot help and MUST NOT enter the §9 guard
 *   (CONTRACT.md §12.3 rule 3). `oidcRefresh` reaches the §9 guard through
 *   its own explicit call path instead (`OidcClient.oidcRefresh`).
 */
export const SKIP_REFRESH = [
  '/api/v1/auth/refresh',
  '/api/v1/auth/login',
  '/api/v1/auth/logout',
  '/oauth2/token',
  '/oauth2/introspect',
  '/oauth2/revoke',
];

type RetryableRequestConfig = InternalAxiosRequestConfig & { _retry?: boolean };

/**
 * Request interceptor: forwards the axiam_csrf cookie as X-CSRF-Token on
 * state-changing methods (POST/PUT/PATCH/DELETE) per §3/D-05.
 *
 * Browser: reads `document.cookie` directly (guarded by `typeof document !==
 * 'undefined'`). Node: reads the session's csrfToken store, populated by the
 * Node persona's cookie-jar read (17-03) — left undefined here since no jar
 * exists in the browser-only REST core built by this plan.
 */
export function installCsrfInterceptor(axiosInstance: AxiosInstance, session: SharedSession): void {
  axiosInstance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    // Host-isolation (3A): never echo the CSRF token to an off-origin host.
    if (session.isForeignHost(config.url)) {
      return config;
    }
    const method = (config.method ?? 'get').toLowerCase();
    const cookieString = typeof document !== 'undefined' ? document.cookie : '';
    const csrfToken =
      typeof document !== 'undefined' ? csrfHeaderForMethod(method, cookieString) : csrfHeaderForMethod(method, session.csrfToken ? `axiam_csrf=${session.csrfToken}` : '');

    if (csrfToken) {
      config.headers = config.headers ?? {};
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
  });
}

/**
 * Response interceptor: on 401 (when authenticated, not a SKIP_REFRESH url,
 * not already retried) performs a reactive single-flight refresh and replays
 * the original request (D-07/§9). Non-2xx responses are mapped through
 * core's mapHttpStatusToError.
 */
export function installRefreshInterceptor(axiosInstance: AxiosInstance, session: SharedSession): void {
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config as RetryableRequestConfig | undefined;

      if (!originalRequest || !error.response) {
        // No response at all (network/timeout) — surface as NetworkError below via caller mapping.
        return Promise.reject(error);
      }

      const status = error.response.status;
      const url = originalRequest.url ?? '';
      const isSkipRefresh = SKIP_REFRESH.some((skipUrl) => url.includes(skipUrl));

      if (status === 401 && !originalRequest._retry && !isSkipRefresh && session.authenticated) {
        // CQ-F32: set _retry BEFORE the refresh call so a 401 on the replayed
        // request cannot trigger a second refresh cycle.
        originalRequest._retry = true;

        try {
          await session.refreshGuard(async () => {
            await session.axios.post('/api/v1/auth/refresh', session.buildRefreshBody());
          });
          return axiosInstance(originalRequest);
        } catch (refreshError) {
          session.authenticated = false;
          session.csrfToken = undefined;
          return Promise.reject(
            mapHttpStatusToError(401, 'session refresh failed; re-authentication required', {
              cause: refreshError,
            }),
          );
        }
      }

      if (status === 401 && isSkipRefresh) {
        // url + body are forwarded so the mapper can apply the
        // endpoint-qualified §2 row: a 401 from /oauth2/introspect or
        // /oauth2/revoke carrying an OAuth2ErrorResponse body becomes an
        // OAuthProtocolError rather than a bare AuthError (§12.3 rule 3).
        return Promise.reject(
          mapHttpStatusToError(401, 'authentication failed', {
            url,
            body: error.response.data,
            cause: error,
          }),
        );
      }

      return Promise.reject(error);
    },
  );
}

/** Install both the CSRF and reactive single-flight refresh interceptors. */
export function installInterceptors(axiosInstance: AxiosInstance, session: SharedSession): void {
  installCsrfInterceptor(axiosInstance, session);
  installRefreshInterceptor(axiosInstance, session);
}
