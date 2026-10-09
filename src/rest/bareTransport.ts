// A session-free transport for calls that carry a credential of their own.
//
// CONTRACT.md §28.12.2 rule 3 (RFC 7592 client configuration) and §32.7
// (`SsfReceiver.poll`) both send a bearer that is NOT this SDK's session — a
// registration access token, a receiver's client-credentials token — and both
// say the SDK's own session must not ride along: no session cookie, no access
// token, no CSRF header, and no §9 refresh on a `401`. The session's axios
// instance cannot give that guarantee, because its request interceptors add
// those things and its response interceptor refreshes, so these calls go out
// on a fresh axios instance instead:
//
//   * no interceptors at all (no `X-Tenant-ID`, no `X-CSRF-Token`, no
//     `Authorization` the session adopted, no refresh-on-401);
//   * no cookie jar — under Node the session's TLS material is reused through
//     `noCredentialsConfig()`'s plain (jar-free) agents, so §6's custom CA and
//     §6.1's client certificate still apply; in a browser `withCredentials` is
//     off;
//   * no redirect following (`maxRedirects: 0`) — a redirect would hand the
//     bearer to whichever host the `Location` names. **Node only:** a browser's
//     XHR/fetch follows same-origin redirects itself and offers no way to stop
//     it, which is one reason these helpers are documented as server-side;
//   * every status resolved rather than thrown (`validateStatus`), so the
//     caller maps it with the tolerant `/oauth2` decoder and decides retries
//     itself.

import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import { NetworkError } from '../core/index.js';
import type { SharedSession } from './session.js';

/**
 * Issue one request on a fresh, interceptor-free, jar-free, redirect-free
 * axios instance carrying this session's TLS configuration only.
 *
 * A transport failure (no response at all) becomes a {@link NetworkError}
 * whose message names the operation and the low-level error code only. The
 * axios error itself is **not** attached as `cause`: its `config` holds the
 * request headers — the bearer this call exists to protect — and the request
 * body.
 *
 * @internal
 */
export async function bareRequest<T>(
  session: SharedSession,
  operation: string,
  config: AxiosRequestConfig,
): Promise<AxiosResponse<T>> {
  const defaults = session.axios.defaults;
  const instance = axios.create({
    timeout: defaults.timeout,
    // The base session's own TLS agent (custom CA / client certificate, no
    // jar). Under the Node persona this is the jar-wrapped cookie agent, which
    // `noCredentialsConfig()` below replaces with a plain one.
    ...(defaults.httpsAgent !== undefined ? { httpsAgent: defaults.httpsAgent } : {}),
    ...session.noCredentialsConfig(),
    withCredentials: false,
    maxRedirects: 0,
    validateStatus: () => true,
  });
  try {
    return await instance.request<T>(config);
  } catch (err) {
    const code =
      err && typeof err === 'object' && 'code' in err && typeof (err as { code?: unknown }).code === 'string'
        ? ` (${(err as { code: string }).code})`
        : '';
    throw new NetworkError(`${operation}: the request failed before any response arrived${code}`);
  }
}

/**
 * Parse a `Retry-After` header (delta-seconds form only) into milliseconds, for
 * the §16 runner's floor. An HTTP-date or anything unparseable is ignored.
 *
 * @internal
 */
export function retryAfterMs(response: AxiosResponse): number | undefined {
  const raw = response.headers?.['retry-after'];
  const value = typeof raw === 'string' ? raw.trim() : undefined;
  if (value === undefined || !/^\d+$/.test(value)) return undefined;
  return Number(value) * 1000;
}

/**
 * Whether §16 may retry a response with this status: `408`, `429` and every
 * `5xx`. Every other `4xx` is a decisive answer — including a bodiless `400`,
 * which §2 maps to `NetworkError` and which the shared runner would otherwise
 * retry because it retries every `NetworkError`.
 *
 * @internal
 */
export function statusIsRetryable(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * A `NetworkError` the §16 runner may retry, carrying the server's
 * `Retry-After` as the floor it reads.
 *
 * @internal
 */
export function retryableNetworkError(message: string, response?: AxiosResponse): NetworkError {
  const error = new NetworkError(message);
  const floor = response ? retryAfterMs(response) : undefined;
  if (floor !== undefined) {
    Object.defineProperty(error, 'retryAfterMs', { value: floor, enumerable: false });
  }
  return error;
}
