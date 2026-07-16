// Shared declarative-authorization core (CONTRACT.md §11) — the ONE
// resource-resolution + check-access + error-mapping path both the Express
// and Fastify `requireAccess`/`requireAccessHook` guards call, mirroring how
// `verifyCore.ts`'s `authenticateRequest` is the one §10 verification path
// shared by both frameworks.
//
// §11.2.1 (composition with the §10 guard): these helpers NEVER perform
// their own token extraction/verification — they only read the identity
// already injected onto the request by `axiamMiddleware`/`axiamPlugin` (or
// by `requireAuth`/`requireAuthHook` mounted earlier in the same chain). If
// that identity is absent, the caller (express.ts/fastify.ts) responds 401
// without ever reaching this module.

import { AuthzError, NetworkError } from '../core/index.js';
import type { AccessCheck, AccessDecision } from '../rest/types.js';
import type { VerifiableSession } from './verifyCore.js';

/**
 * The minimal shape `requireAccess`/`requireAccessHook` need from an authz
 * transport — satisfied structurally by `AxiamClient` (`checkAccess`
 * already accepts `subjectId`, §1/FND-04) without importing the class
 * itself, so this module pulls in no axios/grpc dependency.
 */
export interface AuthzChecker {
  checkAccess(check: AccessCheck): Promise<AccessDecision>;
}

/**
 * `VerifiableSession` extended with an optional authz-capable client
 * (CONTRACT.md §11). `requireAuth`/`requireRole` only need the base
 * `VerifiableSession` shape; `requireAccess`/`requireAccessHook` additionally
 * require `authzClient` to be set — enforced by {@link assertAuthzClient},
 * which throws synchronously at guard-construction time (route-setup time),
 * not per-request, when it is absent.
 */
export interface AuthzVerifiableSession extends VerifiableSession {
  authzClient?: AuthzChecker;
}

/** Marker produced by {@link fromParam} — resolve the resource id from a named path/route parameter. */
export interface ResourceParamRef {
  readonly kind: 'param';
  readonly name: string;
}

/**
 * `resource_param` precedence option (§11.2.3.b): resolve the resource id
 * from the named path/route parameter (`req.params[name]` /
 * `request.params[name]`) at request time.
 */
export function fromParam(name: string): ResourceParamRef {
  return { kind: 'param', name };
}

/** `resolver` precedence option (§11.2.3.c): a language-idiomatic callback resolving the resource id from the request. */
export type ResourceResolver<TReq> = (req: TReq) => string;

/**
 * The `resource` argument accepted by `requireAccess`/`requireAccessHook`:
 * a static literal (§11.2.3.a, for singleton resources), {@link fromParam}
 * (§11.2.3.b), or a resolver callback (§11.2.3.c).
 */
export type ResourceSpec<TReq> = string | ResourceParamRef | ResourceResolver<TReq>;

/** Thrown by {@link resolveResourceId} when the resource id cannot be resolved — mapped to 400 `invalid_request` by callers, never a silent allow (§11.2.3). */
export class ResourceResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResourceResolutionError';
    Object.setPrototypeOf(this, ResourceResolutionError.prototype);
  }
}

/**
 * Resolve the resource id from `req` per `spec`'s precedence (§11.2.3).
 * `getParams` abstracts over Express's `req.params` and Fastify's
 * `request.params`, both `Record<string, string | undefined>`-shaped at
 * runtime. A missing/empty resolution — a missing path parameter, or a
 * resolver returning an empty string — is a **programming error** raised as
 * {@link ResourceResolutionError}; it is never a silent allow and never a
 * nil/empty-id fallback (§11.2.3).
 */
export function resolveResourceId<TReq>(
  req: TReq,
  spec: ResourceSpec<TReq>,
  getParams: (req: TReq) => Record<string, string | undefined> | undefined,
): string {
  let resourceId: string | undefined;
  if (typeof spec === 'function') {
    resourceId = spec(req);
  } else if (typeof spec === 'string') {
    resourceId = spec;
  } else {
    resourceId = getParams(req)?.[spec.name];
  }
  if (!resourceId) {
    const label = typeof spec === 'object' ? `route param "${spec.name}"` : 'resource';
    throw new ResourceResolutionError(`unable to resolve ${label} from request`);
  }
  return resourceId;
}

/** Optional per-guard settings for `requireAccess`/`requireAccessHook`. */
export interface RequireAccessOptions {
  /** Sub-resource scope, passed through to `checkAccess` verbatim (§11.2.4). */
  scope?: string;
  /** Debug-only denial logger (§11.2.8) — never receives the token, only `action`/`resourceId`. */
  logger?: AuthzLogger;
}

/** Minimal logger seam for the §11.2.8 debug-only denial/error log (mirrors `amqp/consumer.ts`'s `ConsumeLogger`). */
export interface AuthzLogger {
  debug(event: string, message: string, context?: Record<string, unknown>): void;
}

/**
 * Validate that `session.authzClient` is configured, returning it. Throws
 * synchronously (guard-construction time, i.e. route-setup time — not
 * per-request) when absent, per the task's "helpers throw at construction
 * if absent" requirement.
 */
export function assertAuthzClient(session: AuthzVerifiableSession): AuthzChecker {
  if (!session.authzClient) {
    throw new Error(
      'requireAccess/requireAccessHook require session.authzClient (an AuthzChecker with checkAccess) to be configured (CONTRACT.md §11)',
    );
  }
  return session.authzClient;
}

/** Standardized JSON error body shape (§10/§11 — `{ error, message }`). */
export interface ErrorBody {
  error: string;
  message: string;
}

export function missingAuthBody(): ErrorBody {
  return {
    error: 'authentication_failed',
    message: 'no authenticated identity on the request — mount axiamMiddleware/axiamPlugin (or requireAuth/requireAuthHook) first',
  };
}

export function invalidRequestBody(message: string): ErrorBody {
  return { error: 'invalid_request', message };
}

export function authzDeniedBody(message: string): ErrorBody {
  return { error: 'authorization_denied', message };
}

export function authzUnavailableBody(message: string): ErrorBody {
  return { error: 'authz_unavailable', message };
}

/** The outcome of an `evaluateAccess` call — one arm per §11.2.5's error-mapping table (the 401/400 arms are handled by callers before this is ever invoked). */
export type CheckOutcome =
  | { kind: 'allowed' }
  | { kind: 'denied'; message: string }
  | { kind: 'unavailable'; message: string };

/**
 * Call `checker.checkAccess` with `subjectId` set to the *authenticated
 * request's* user id (§11.2.2 — never the app's own service-account
 * identity) and map the outcome per §11.2.5:
 * - `allowed: false` → `denied`
 * - `AuthzError` (server 403/409) → `denied`
 * - `NetworkError`, or any other unexpected failure → `unavailable`
 *   (fail-closed: a transport failure is never treated as an allow).
 *
 * Never caches the decision (§11.2.6) — a plain per-call `await`.
 */
export async function evaluateAccess(
  checker: AuthzChecker,
  action: string,
  resourceId: string,
  subjectId: string,
  scope?: string,
): Promise<CheckOutcome> {
  try {
    const decision = await checker.checkAccess({ action, resourceId, scope, subjectId });
    if (!decision.allowed) {
      return { kind: 'denied', message: decision.reason ?? 'access denied' };
    }
    return { kind: 'allowed' };
  } catch (err) {
    if (err instanceof AuthzError) {
      return { kind: 'denied', message: err.message };
    }
    if (err instanceof NetworkError) {
      return { kind: 'unavailable', message: err.message };
    }
    // Fail closed (§11.2.5): any unexpected failure is treated as
    // "couldn't decide", never a silent allow.
    return { kind: 'unavailable', message: 'authorization service unavailable' };
  }
}

/** Local (no server round-trip) role check (§11.2.9): true iff `roles` and the identity's roles share at least one entry. */
export function hasAnyRole(identityRoles: readonly string[], roles: readonly string[]): boolean {
  return roles.some((role) => identityRoles.includes(role));
}
