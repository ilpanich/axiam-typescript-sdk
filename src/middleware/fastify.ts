// Fastify middleware (D-27, CONTRACT.md §10) — registered as a
// `preHandler` hook via a FastifyPluginAsync, mirroring express.ts's
// verification flow through the same shared verifyCore.

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AuthError, AuthzError } from '../core/index.js';
import {
  assertAuthzClient,
  authzDeniedBody as authzDeniedBodyShared,
  authzUnavailableBody,
  evaluateAccess,
  hasAnyRole,
  invalidRequestBody,
  missingAuthBody,
  resolveResourceId,
  ResourceResolutionError,
  type AuthzVerifiableSession,
  type RequireAccessOptions,
  type ResourceSpec,
} from './authzCore.js';
import { CSRF_HEADER_NAME, extractCredential, isCsrfValid, isSafeMethod } from './cookieHeader.js';
import { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';

/** A Fastify `FastifyRequest` augmented with the AXIAM identity that `axiamPlugin` injects after §10 verification. */
export interface AxiamFastifyRequest extends FastifyRequest {
  /** The authenticated identity, present once `axiamPlugin` (or `requireAuthHook`) has run; absent on an unauthenticated request. */
  axiamUser?: AxiamIdentity;
}

/** A Fastify `preHandler`-compatible hook function (CONTRACT.md §11) — usable both via `fastify.addHook('preHandler', ...)` and per-route as `{ preHandler: hook }`. */
export type PreHandlerHook = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

interface ErrorBody {
  error: string;
  message: string;
}

function missingCredentialsBody(): ErrorBody {
  return { error: 'authentication_failed', message: 'missing authentication credentials' };
}

function invalidTokenBody(message: string): ErrorBody {
  return { error: 'authentication_failed', message };
}

function authzDeniedBody(message: string): ErrorBody {
  return { error: 'authorization_denied', message };
}

function csrfDeniedBody(): ErrorBody {
  return { error: 'authorization_denied', message: 'csrf validation failed' };
}

/**
 * The `preHandler` body shared by `axiamPlugin` (registered globally as a
 * hook) and `requireAuthHook` (mounted per-route) — extracts the session
 * (cookie-first, then `Authorization: Bearer` fallback), verifies it
 * locally against the cached JWKS (D-11), and injects `request.axiamUser`
 * on success. Replies 401 (AuthError) or 403 (AuthzError/CSRF) with a
 * standardized JSON error body on failure.
 *
 * **CSRF (cookie double-submit, CONTRACT.md §3):** when the credential was
 * sourced from the `axiam_access` COOKIE (not the `Authorization` header)
 * and the request method is state-changing (anything other than
 * GET/HEAD/OPTIONS), this hook additionally requires the `X-CSRF-Token`
 * request header to be present and equal (constant time) to the
 * `axiam_csrf` cookie value, replying 403 on mismatch/absence. Bearer-header
 * requests are CSRF-immune by construction — a cross-site attacker cannot
 * set arbitrary request headers — but a cookie automatically attached by
 * the browser is not, and in any same-site deployment where `axiam_access`
 * reaches this app, the non-`httpOnly` `axiam_csrf` cookie does too. This
 * mirrors, locally, the same double-submit check the AXIAM server performs
 * on its own endpoints (§3).
 */
function buildAuthHook(session: VerifiableSession): PreHandlerHook {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const credential = extractCredential(request.headers.cookie, request.headers.authorization);
    if (!credential) {
      await reply.code(401).send(missingCredentialsBody());
      return;
    }

    if (credential.source === 'cookie' && !isSafeMethod(request.method)) {
      const csrfHeader = request.headers[CSRF_HEADER_NAME];
      const csrfValue = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader;
      if (!isCsrfValid(request.headers.cookie, csrfValue)) {
        await reply.code(403).send(csrfDeniedBody());
        return;
      }
    }

    try {
      const identity = await authenticateRequest(session, credential.token);
      (request as AxiamFastifyRequest).axiamUser = identity;
    } catch (err) {
      if (err instanceof AuthzError) {
        await reply.code(403).send(authzDeniedBody(err.message));
        return;
      }
      if (err instanceof AuthError) {
        await reply.code(401).send(invalidTokenBody(err.message));
        return;
      }
      await reply.code(401).send(invalidTokenBody('invalid or expired token'));
    }
  };
}

/**
 * `axiamPlugin(session)` — a `FastifyPluginAsync` registering the shared
 * auth `preHandler` hook globally (D-27, CONTRACT.md
 * §10). Marked with fastify's own `skip-override` plugin symbol (the same
 * mechanism the `fastify-plugin` package wraps) so the `preHandler` hook
 * applies to routes registered as siblings of this plugin rather than
 * being scoped only to its own encapsulation context — avoids adding
 * `fastify-plugin` as a dependency for a one-line escape hatch.
 */
export const axiamPlugin: (session: VerifiableSession) => FastifyPluginAsync = (session) => {
  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.addHook('preHandler', buildAuthHook(session));
  };
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for('skip-override')] = true;
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] =
    'axiam-plugin';
  return plugin;
};

/**
 * `requireAuthHook(session)` (CONTRACT.md §11.1) — the canonical §11 name
 * for the same §10 guard `axiamPlugin` already provides, as a plain
 * `preHandler` function usable per-route:
 * `fastify.get('/x', { preHandler: requireAuthHook(session) }, handler)`,
 * rather than registered globally via `fastify.register(axiamPlugin(session))`.
 * Pure sugar: it performs no verification of its own beyond what the shared
 * auth `preHandler` hook (also used by `axiamPlugin`) already does.
 */
export function requireAuthHook(session: VerifiableSession): PreHandlerHook {
  return buildAuthHook(session);
}

/**
 * `requireAccessHook(session, action, resource, opts?)` (CONTRACT.md §11) —
 * the Fastify `preHandler` counterpart to `requireAccess` (see that
 * function's doc for the full §11 semantics). Throws synchronously (at
 * route-setup time) if `session.authzClient` is not configured. Requires
 * `request.axiamUser` to already be set (by `axiamPlugin`/`requireAuthHook`
 * mounted earlier in the chain) — replies 401 immediately when absent.
 */
export function requireAccessHook(
  session: AuthzVerifiableSession,
  action: string,
  resource: ResourceSpec<FastifyRequest>,
  opts?: RequireAccessOptions,
): PreHandlerHook {
  const checker = assertAuthzClient(session);

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    if (!axiamUser) {
      await reply.code(401).send(missingAuthBody());
      return;
    }

    let resourceId: string;
    try {
      resourceId = resolveResourceId(
        request,
        resource,
        (r) => r.params as Record<string, string | undefined>,
      );
    } catch (err) {
      const message = err instanceof ResourceResolutionError ? err.message : 'invalid resource';
      await reply.code(400).send(invalidRequestBody(message));
      return;
    }

    const outcome = await evaluateAccess(checker, action, resourceId, axiamUser.userId, opts?.scope);
    if (outcome.kind === 'denied') {
      opts?.logger?.debug('axiam_sdk.authz', 'access denied', { action, resourceId });
      await reply.code(403).send(authzDeniedBodyShared(outcome.message));
      return;
    }
    if (outcome.kind === 'unavailable') {
      opts?.logger?.debug('axiam_sdk.authz', 'authz check unavailable', { action, resourceId });
      await reply.code(503).send(authzUnavailableBody(outcome.message));
      return;
    }
  };
}

/**
 * `requireRoleHook(session, ...roles)` (CONTRACT.md §11.1, MAY) — the
 * Fastify `preHandler` counterpart to `requireRole`; see that function's
 * doc for the full semantics (local-only check, no server round-trip).
 * `session` is accepted only for signature parity with
 * `requireAuthHook`/`requireAccessHook` — this check never dereferences it.
 */
export function requireRoleHook(session: VerifiableSession, ...roles: string[]): PreHandlerHook {
  void session;
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    if (!axiamUser) {
      await reply.code(401).send(missingAuthBody());
      return;
    }
    if (!hasAnyRole(axiamUser.roles, roles)) {
      await reply.code(403).send(authzDeniedBodyShared('missing required role'));
      return;
    }
  };
}
