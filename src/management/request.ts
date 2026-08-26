/**
 * The one request path every §27 management operation goes through.
 *
 * §27.8 is explicit that the generated layer MUST sit on the SDK's existing
 * request path and MUST NOT build its own. That is what this module is: 146
 * generated operations all funnel into {@link sendManagement}, so they inherit
 * §3 (CSRF), §4 (the cookie jar), §5 (`X-Tenant-ID`), §6 (TLS), §9 (the
 * reactive single-flight refresh the response interceptor already performs),
 * §16 (retry) and §19 (telemetry) by construction rather than by 146
 * opportunities to forget one.
 */

import type { AxiosResponse } from 'axios';

import { AuthError, mapHttpStatusToError } from '../core/index.js';
import { withRetry } from '../rest/retry.js';
import type { AxiamClient } from '../rest/client.js';
import { ConflictError, NotFoundError, ValidationError, parseFieldErrors } from './errors.js';

/** The HTTP verbs this surface uses. */
export type ManagementMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

/** One management call, fully resolved. */
export interface ManagementCall {
  /** `"users.create"` — the registry's namespace-qualified operation name. */
  operation: string;
  /** The HTTP verb. Only `GET` is retry-eligible (§27.4 rule 8). */
  method: ManagementMethod;
  /** `"/api/v1/users/{user_id}"`, ids **not** substituted — the §19.1 label. */
  pathTemplate: string;
  /** The same path with ids substituted, ready to send. */
  path: string;
  /** Query parameters; `undefined` values are dropped rather than sent empty. */
  query?: Record<string, string | undefined>;
  /** The request body, already converted to its wire shape. */
  body?: unknown;
}

/**
 * Issue a management request and return its parsed body.
 *
 * @internal — reached through the generated namespace handles.
 */
export async function sendManagement<T>(client: AxiamClient, call: ManagementCall): Promise<T> {
  // §18.1 rule 4: use-after-close is an error, never a silent reconnect.
  client.ensureOpen();

  // §27.4 rule 1: no session, no wire call. Letting the request go out trades
  // a clear local error for a 401 that then enters the §9 refresh guard and
  // fails there, two indirections from the actual mistake.
  if (!client.session.authenticated) {
    throw new AuthError(
      `${call.operation}: no active session — call login() before using the management API`,
    );
  }

  const params = Object.fromEntries(
    Object.entries(call.query ?? {}).filter(([, v]) => v !== undefined),
  );

  const attempt = async (n: number): Promise<T> => {
    const done = client.telemetry.startRequest(call.operation, call.method, call.pathTemplate, n);
    try {
      const response: AxiosResponse<T> = await client.session.axios.request<T>({
        method: call.method,
        url: call.path,
        params,
        data: call.body,
      });
      done(response.status, 'success');
      return response.data;
    } catch (err) {
      done(statusOf(err), 'failure');
      throw mapManagementError(call.operation, err);
    }
  };

  // §16.2 and §27.4 rule 8: only reads are retried, and only through the
  // shared runner so the backoff, jitter and `Retry-After` floor are the
  // contract's rather than this module's. No write here is retriable, not even
  // the ones that look idempotent — generating a certificate twice mints two,
  // and rotating a secret twice invalidates the one the caller already stored.
  return withRetry(attempt, {
    ...client.retryOptions(call.operation),
    idempotent: call.method === 'GET',
  });
}

function statusOf(err: unknown): number | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    return (err as { response?: { status?: number } }).response?.status;
  }
  return undefined;
}

function bodyOf(err: unknown): unknown {
  if (err && typeof err === 'object' && 'response' in err) {
    return (err as { response?: { data?: unknown } }).response?.data;
  }
  return undefined;
}

/**
 * Map a failed management response onto the §2 taxonomy.
 *
 * Delegates to the shared `mapHttpStatusToError` for everything §27 does not
 * classify, so the two mappers cannot drift: this function's whole job is the
 * three statuses §27.4 rule 7 names, and 404 is the one §2 genuinely lacks.
 */
function mapManagementError(operation: string, err: unknown): unknown {
  const status = statusOf(err);
  if (status === undefined) {
    // No response at all — a transport failure. The shared mapper owns it.
    return mapHttpStatusToError(0, `${operation}: request failed`, { cause: err });
  }
  const body = bodyOf(err);
  const detail = describe(body);

  if (status === 404) {
    return new NotFoundError(
      operation,
      `${operation}: not found (or not visible to this tenant)${detail}`,
    );
  }
  if (status === 409) {
    return new ConflictError(operation, `${operation}: conflict${detail}`);
  }
  if (status === 400 || status === 422) {
    return new ValidationError(
      operation,
      status,
      `${operation}: request rejected${detail}`,
      parseFieldErrors(body),
    );
  }
  return mapHttpStatusToError(status, `${operation}${detail}`, { cause: err });
}

function describe(body: unknown): string {
  if (typeof body === 'string' && body) return `: ${body}`;
  if (body && typeof body === 'object') {
    const message = (body as { message?: unknown; error?: unknown }).message
      ?? (body as { error?: unknown }).error;
    if (typeof message === 'string') return `: ${message}`;
  }
  return '';
}
