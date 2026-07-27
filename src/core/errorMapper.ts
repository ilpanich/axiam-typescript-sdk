// Central status -> error mapper (CONTRACT.md §2, D-17).
//
// The single source of truth for both rest/ and grpc/ transports so the two
// cannot drift on the error taxonomy. Transcribes CONTRACT.md §2's HTTP and
// gRPC tables exactly.
//
// GrpcStatus is exported here (not imported from @grpc/grpc-js) so that
// core stays dependency-free — grpc/ imports the numeric codes from core
// rather than the other way around.

import {
  AuthError,
  AuthzError,
  NetworkError,
  OAuthProtocolError,
  type AxiamError,
} from './errors.js';

/** gRPC status codes referenced by CONTRACT.md §2 (subset of the full grpc.status enum). */
export const GrpcStatus = {
  DEADLINE_EXCEEDED: 4,
  PERMISSION_DENIED: 7,
  RESOURCE_EXHAUSTED: 8,
  INTERNAL: 13,
  UNAVAILABLE: 14,
  UNAUTHENTICATED: 16,
} as const;

export interface HttpErrorContext {
  action?: string;
  resourceId?: string;
  cause?: unknown;
  /**
   * The request URL (absolute or path-only) the error came from, when
   * available. Load-bearing for the two **endpoint-qualified** rows of §2's
   * HTTP table (added by contract 1.4): a `400`/`401` carrying an
   * `OAuth2ErrorResponse` body maps to `OAuthProtocolError` only when it came
   * from an `/oauth2/*` endpoint. Omitting it simply keeps the generic rows.
   */
  url?: string;
  /**
   * The parsed JSON response body (when available). For a 403/409
   * authorization-denied response the server shapes this as
   * `{ error: "authorization_denied", message, action?, resource_id? }`
   * (`action` present when known, `resource_id` present only for a
   * resource-scoped denial). `mapHttpStatusToError` prefers these body
   * fields over `action`/`resourceId` above when populating `AuthzError`.
   */
  body?: unknown;
}

/**
 * Extract `action`/`resource_id` (snake_case -> camelCase) from a parsed
 * authorization-denied response body, if present and string-typed. Any other
 * shape (missing fields, non-object body, older servers with no body at all)
 * yields `{}`, so callers fall back to caller-supplied context.
 */
function extractAuthzFieldsFromBody(body: unknown): { action?: string; resourceId?: string } {
  if (body === null || typeof body !== 'object') {
    return {};
  }
  const record = body as Record<string, unknown>;
  const action = typeof record.action === 'string' ? record.action : undefined;
  const resourceId = typeof record.resource_id === 'string' ? record.resource_id : undefined;
  return { action, resourceId };
}

/**
 * The RFC 6749 error body shape (`OAuth2ErrorResponse` in `openapi.json`)
 * returned by AXIAM's `/oauth2/*` endpoints. Both fields are required by the
 * schema.
 */
export interface OAuth2ErrorResponseWire {
  /** RFC 6749 error code, e.g. `invalid_grant`. */
  error: string;
  /** Human-readable description of the failure. */
  error_description: string;
}

/**
 * Path prefix identifying AXIAM's OAuth2 endpoint family (`/oauth2/token`,
 * `/oauth2/introspect`, `/oauth2/revoke`, …). The two endpoint-qualified §2
 * rows apply only to URLs whose path starts with it.
 */
const OAUTH2_PATH_PREFIX = '/oauth2/';

/**
 * Whether `url` targets an `/oauth2/*` endpoint. Accepts both an absolute URL
 * (as taken from the discovery document) and a bare path (as axios request
 * configs carry), and never throws on a malformed value — an unparseable URL
 * simply falls back to a substring test, so a mis-shaped URL can only ever
 * *fail* to qualify for the OAuth2 rows, never wrongly qualify for them.
 */
export function isOAuth2EndpointUrl(url: string | undefined): boolean {
  if (!url) {
    return false;
  }
  try {
    // A relative path has no base here, so `URL` throws and we fall through.
    return new URL(url).pathname.startsWith(OAUTH2_PATH_PREFIX);
  } catch {
    return url.startsWith(OAUTH2_PATH_PREFIX) || url.includes(OAUTH2_PATH_PREFIX);
  }
}

/**
 * Narrow a parsed response body to {@link OAuth2ErrorResponseWire}. Both
 * `error` and `error_description` must be present and string-typed — a body
 * that carries only one of them is NOT an `OAuth2ErrorResponse` and keeps the
 * generic §2 mapping (better a generic error than a fabricated
 * `error_description`).
 */
export function isOAuth2ErrorBody(body: unknown): body is OAuth2ErrorResponseWire {
  if (body === null || typeof body !== 'object') {
    return false;
  }
  const record = body as Record<string, unknown>;
  return typeof record.error === 'string' && typeof record.error_description === 'string';
}

/**
 * ALLOWLIST (X-3) of response headers that are safe to preserve in a
 * NetworkError.cause. Every header NOT listed here has its value redacted to a
 * placeholder, so a custom sensitive header (e.g. `X-Auth-Token`) can never
 * survive into a thrown error — unlike a small denylist, which only catches the
 * headers it happens to enumerate. Names are compared case-insensitively (all
 * entries are lower-case). Keep this list small and strictly non-secret:
 * standard diagnostic response headers plus this SDK's own non-secret request
 * headers (e.g. `x-tenant-id`).
 */
const SAFE_RESPONSE_HEADERS = new Set([
  'content-type',
  'content-length',
  'date',
  'server',
  'retry-after',
  'x-request-id',
  'x-tenant-id',
]);

/** Placeholder substituted for the value of any non-allowlisted header. */
const REDACTED_HEADER = '[REDACTED]';

/**
 * Redact every non-allowlisted response header from an axios-error-shaped
 * `err` before it is attached as `NetworkError.cause` (CR-04, D-16, X-3). On
 * login/refresh error paths the server may have already issued Set-Cookie
 * headers containing raw `axiam_access`/`axiam_refresh` values (and callers may
 * set custom sensitive headers such as `X-Auth-Token`); none of these must be
 * reachable via `console.log`/`JSON.stringify`/`util.inspect` of the thrown
 * error. Only headers on `SAFE_RESPONSE_HEADERS` keep their value; all others
 * are replaced with `[REDACTED]`.
 *
 * Returns a new, shallow-cloned object for any input shaped like
 * `{ response: { headers: {...} } }` — the caller's original axios error
 * object is left untouched. Non-object inputs (plain Error, string,
 * undefined) and objects with no `response.headers` are returned unchanged.
 */
export function sanitizeAxiosError(err: unknown): unknown {
  if (err === null || typeof err !== 'object') {
    return err;
  }
  const candidate = err as { response?: unknown };
  if (candidate.response === null || typeof candidate.response !== 'object') {
    return err;
  }
  const response = candidate.response as { headers?: unknown };
  if (response.headers === null || typeof response.headers !== 'object') {
    return err;
  }

  const sanitizedHeaders: Record<string, unknown> = { ...(response.headers as Record<string, unknown>) };
  for (const key of Object.keys(sanitizedHeaders)) {
    if (!SAFE_RESPONSE_HEADERS.has(key.toLowerCase())) {
      sanitizedHeaders[key] = REDACTED_HEADER;
    }
  }

  return {
    ...err,
    response: {
      ...response,
      headers: sanitizedHeaders,
    },
  };
}

/**
 * Map an HTTP status code to an AxiamError variant per CONTRACT.md §2's HTTP
 * status table.
 *
 * | Status    | Type         |
 * |-----------|--------------|
 * | 400       | NetworkError |
 * | 400 from `/oauth2/*` with an `OAuth2ErrorResponse` body | OAuthProtocolError |
 * | 401       | AuthError    |
 * | 401 from `/oauth2/*` with an `OAuth2ErrorResponse` body | OAuthProtocolError |
 * | 403       | AuthzError   |
 * | 408, 429  | NetworkError |
 * | 409       | AuthzError   |
 * | 5xx       | NetworkError |
 * | other     | NetworkError |
 *
 * Where two rows match the same response the more specific
 * (endpoint- and body-qualified) row wins, per §2 — so the two
 * `OAuthProtocolError` rows are evaluated first. They require BOTH an
 * `/oauth2/*` `ctx.url` AND an `OAuth2ErrorResponse`-shaped `ctx.body`;
 * anything else keeps the generic mapping.
 *
 * NetworkError's `cause` (when provided via `ctx.cause`) is always passed
 * through `sanitizeAxiosError` first (CR-04) — this is the single choke
 * point for both rest/ auth call sites and any future caller.
 *
 * For 403/409, `action`/`resourceId` are sourced from the response body
 * (`ctx.body`) when the body carries them, falling back to the
 * caller-supplied `ctx.action`/`ctx.resourceId` (the request call-args)
 * otherwise — this keeps compatibility with older servers that don't yet
 * echo `action`/`resource_id` in the denial body.
 */
export function mapHttpStatusToError(
  status: number,
  message: string,
  ctx?: HttpErrorContext,
): AxiamError {
  // Endpoint-qualified rows first (§2 "the more specific row wins",
  // §12.3 rule 3). `message` is deliberately ignored here: the contract fixes
  // OAuthProtocolError's message to "<error>: <error_description>".
  if ((status === 400 || status === 401) && isOAuth2EndpointUrl(ctx?.url) && isOAuth2ErrorBody(ctx?.body)) {
    return new OAuthProtocolError(ctx.body.error, ctx.body.error_description);
  }
  if (status === 401) {
    return new AuthError(message);
  }
  if (status === 403 || status === 409) {
    const fromBody = extractAuthzFieldsFromBody(ctx?.body);
    return new AuthzError(message, fromBody.action ?? ctx?.action, fromBody.resourceId ?? ctx?.resourceId);
  }
  // 400, 408, 429, 5xx, and any other status fall through to NetworkError.
  return new NetworkError(message, sanitizeAxiosError(ctx?.cause));
}

/**
 * Map a gRPC status code to an AxiamError variant per CONTRACT.md §2's gRPC
 * status table.
 *
 * | Code                   | Type         |
 * |------------------------|--------------|
 * | 16 UNAUTHENTICATED     | AuthError    |
 * | 7 PERMISSION_DENIED    | AuthzError   |
 * | 14 UNAVAILABLE         | NetworkError |
 * | 4 DEADLINE_EXCEEDED    | NetworkError |
 * | 13 INTERNAL            | NetworkError |
 * | 8 RESOURCE_EXHAUSTED   | NetworkError |
 * | other                  | NetworkError |
 */
export function mapGrpcStatusToError(code: number, message: string): AxiamError {
  if (code === GrpcStatus.UNAUTHENTICATED) {
    return new AuthError(message);
  }
  if (code === GrpcStatus.PERMISSION_DENIED) {
    return new AuthzError(message);
  }
  return new NetworkError(message);
}
