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
 * The tolerant `/oauth2/*` error decoder (CONTRACT.md §2, §28.12.3, §33.4):
 * an {@link OAuthProtocolError} for any body that is an object carrying a
 * **non-empty string `error`**, whatever the status, with `error_description`
 * used when it is a string and left empty otherwise.
 *
 * Distinct from {@link isOAuth2ErrorBody}, which requires both members and
 * gates the two status-qualified rows of {@link mapHttpStatusToError}: those
 * rows are unchanged. This is for the call paths whose contract text says to
 * dispatch on `error` at any status — the RFC 7592 client-configuration
 * operations (a `401 {"error":"invalid_token"}` carries no description) and
 * CIBA (a `429 {"error":"rate_limit_exceeded"}`).
 *
 * Returns `undefined` for anything else, so the caller falls back to §2's
 * status rows.
 */
export function oauth2ErrorFromBody(body: unknown): OAuthProtocolError | undefined {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  if (typeof record.error !== 'string' || record.error === '') {
    return undefined;
  }
  const description = typeof record.error_description === 'string' ? record.error_description : '';
  return new OAuthProtocolError(record.error, description);
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
 * Reduce an axios-error-shaped `err` to the diagnostics that are safe to keep
 * as `NetworkError.cause` (CR-04, D-16, X-3; contract 1.59 R-18).
 *
 * An axios error is a map of everything the request touched: `config` holds
 * the serialized request body (`config.data` — a password, a `bind_secret`, a
 * SCIM `credential`, an SSF `authorization_header`, a form-encoded client
 * secret) and the request headers (the session's bearer and CSRF token);
 * `request` is the live `ClientRequest`, whose buffered output holds the same
 * body; and `response` carries both again (`response.config`,
 * `response.request`) beside the server's headers, which may set cookies. A
 * shallow copy that redacted only the response headers left all of that
 * reachable from `console.log(err)` on any `5xx` or transport failure.
 *
 * So the cause is **rebuilt from an allow-list**, never copied: `name`,
 * `message` and `code` when they are strings, `status` when it is a number,
 * and a `response` of `status`, `statusText`, the server's `data` and its
 * headers with every value not on `SAFE_RESPONSE_HEADERS` replaced by
 * `[REDACTED]`. Nothing else survives — no `config`, no `request`, no stack.
 *
 * Applies to anything carrying `response`, `config` or `request`, or flagged
 * `isAxiosError`, including a transport failure that has no response at all.
 * The caller's original object is never mutated. Other inputs — a plain
 * `Error`, a string, `undefined` — are returned unchanged.
 */
export function sanitizeAxiosError(err: unknown): unknown {
  if (err === null || typeof err !== 'object') {
    return err;
  }
  const candidate = err as {
    name?: unknown;
    message?: unknown;
    code?: unknown;
    status?: unknown;
    response?: unknown;
    isAxiosError?: unknown;
  };
  const hasResponse = candidate.response !== null && typeof candidate.response === 'object';
  const isRequestError =
    hasResponse || 'config' in candidate || 'request' in candidate || candidate.isAxiosError === true;
  if (!isRequestError) {
    return err;
  }

  const sanitized: Record<string, unknown> = {};
  for (const key of ['name', 'message', 'code'] as const) {
    const value = candidate[key];
    if (typeof value === 'string') sanitized[key] = value;
  }
  if (typeof candidate.status === 'number') sanitized.status = candidate.status;

  if (hasResponse) {
    const response = candidate.response as {
      status?: unknown;
      statusText?: unknown;
      headers?: unknown;
      data?: unknown;
    };
    const kept: Record<string, unknown> = {};
    if (typeof response.status === 'number') kept.status = response.status;
    if (typeof response.statusText === 'string') kept.statusText = response.statusText;
    if (response.headers !== null && typeof response.headers === 'object') {
      const headers: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(response.headers as Record<string, unknown>)) {
        headers[key] = SAFE_RESPONSE_HEADERS.has(key.toLowerCase()) ? value : REDACTED_HEADER;
      }
      kept.headers = headers;
    }
    if ('data' in response) kept.data = response.data;
    sanitized.response = kept;
  }
  return sanitized;
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
