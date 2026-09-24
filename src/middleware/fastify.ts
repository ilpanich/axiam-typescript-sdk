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
import {
  challengeFor401,
  challengeFor403,
  isMetadataDocumentRequest,
  mcpGuardChallenges,
} from './mcpCore.js';
import {
  beginOidcLogin,
  completeOidcLogin,
  type OidcLoginOptions,
  type OidcLoginOutcome,
} from './oidcLoginCore.js';
import { certificateProofFromSocket } from './peerCertificate.js';
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
function buildAuthHook(session: VerifiableSession, operation: string): PreHandlerHook {
  // §28.5: validated and precomputed at construction, `undefined` when
  // `resourceMetadataUrl` is unset — which is what keeps a guard without §28
  // byte-for-byte identical to one from before §28 existed.
  const challenges = mcpGuardChallenges(session, operation);

  return async (request: FastifyRequest, reply: FastifyReply) => {
    // §28.3 rule 2: the metadata document MUST answer without a credential.
    // A Fastify `preHandler` hook applies to every route in its context
    // regardless of registration order, so there is no ordering trick that
    // would exempt the path — the exemption has to be here, and explicit.
    if (isMetadataDocumentRequest(challenges, request.method, request.url)) return;

    const credential = extractCredential(request.headers.cookie, request.headers.authorization);
    if (!credential) {
      // §28.4: no credential is not a bad credential, so the challenge names
      // no error code (RFC 6750 §3).
      if (challenges) void reply.header('WWW-Authenticate', challenges.noCredential);
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
      // §10.1 rule 9: same evidence as the Express guard — the peer
      // certificate the TLS layer verified for THIS connection, from
      // Fastify's raw Node request. `{}` (no evidence) when it is not
      // TLS-shaped or carries no certificate.
      const proofs = await certificateProofFromSocket(request.raw.socket);
      const identity = await authenticateRequest(session, credential.token, proofs);
      (request as AxiamFastifyRequest).axiamUser = identity;
    } catch (err) {
      if (err instanceof AuthzError) {
        // §28.5 rule 5: this 403 is not a `no_grant` scope denial, so it gains
        // no header.
        await reply.code(403).send(authzDeniedBody(err.message));
        return;
      }
      // §28.4: a credential was presented and rejected. Expired, not yet
      // valid, wrong tenant, wrong audience, bad signature, an unsatisfiable
      // `cnf`, a revoked `sid` — all of them are `invalid_token`,
      // indistinguishably. Every distinction a 401 draws for an
      // unauthenticated stranger is an oracle.
      if (challenges) void reply.header('WWW-Authenticate', challenges.invalidToken);
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
  // Built here rather than inside the plugin body so §28.5's configuration
  // refusal happens when `axiamPlugin(session)` is called — construction time,
  // before `register` and before the server is listening.
  const hook = buildAuthHook(session, 'axiamPlugin');
  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.addHook('preHandler', hook);
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
  return buildAuthHook(session, 'requireAuthHook');
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
  // §28.5 rule 5's challenge is built here, from this route's own `scope`
  // argument, so a scope outside RFC 6750's syntax fails at route setup rather
  // than on the first denial.
  const challenges = mcpGuardChallenges(session, 'requireAccessHook', opts?.scope);

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    if (!axiamUser) {
      if (challenges) {
        void reply.header(
          'WWW-Authenticate',
          challengeFor401(challenges, request.headers.cookie, request.headers.authorization),
        );
      }
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

    const outcome = await evaluateAccess(
      checker,
      action,
      resourceId,
      axiamUser.userId,
      opts?.scope,
      opts?.umaChallenge,
    );
    if (outcome.kind === 'denied') {
      opts?.logger?.debug('axiam_sdk.authz', 'access denied', { action, resourceId });
      // §20.3's UMA challenge wins where both apply — see `requireAccess` for
      // why. Only one `WWW-Authenticate` value is emitted either way.
      const challenge = outcome.challenge ?? challengeFor403(challenges, outcome.reasonCode);
      if (challenge) {
        // §20.3 / §28.5 rule 5, additive: the body keeps the unchanged §11.2.5
        // shape, so `insufficient_scope` appears only in the header and the
        // body is still `authorization_denied`.
        void reply.header('WWW-Authenticate', challenge);
      }
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
 * `session` is taken first for signature parity with
 * `requireAuthHook`/`requireAccessHook`; the role check reads nothing from it,
 * and §28.5 is the only thing that does.
 */
export function requireRoleHook(session: VerifiableSession, ...roles: string[]): PreHandlerHook {
  // The one thing this guard does read off the session: §28.5 rule 4 puts the
  // challenge on every 401 the guard emits, and this guard emits one.
  const challenges = mcpGuardChallenges(session, 'requireRoleHook');

  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    if (!axiamUser) {
      if (challenges) {
        void reply.header(
          'WWW-Authenticate',
          challengeFor401(challenges, request.headers.cookie, request.headers.authorization),
        );
      }
      await reply.code(401).send(missingAuthBody());
      return;
    }
    if (!hasAnyRole(axiamUser.roles, roles)) {
      // §28.5 rule 5: a role failure is not a scope failure — no header.
      await reply.code(403).send(authzDeniedBodyShared('missing required role'));
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// "Login with AXIAM" routes (CONTRACT.md §12)
// ---------------------------------------------------------------------------

/** Apply an {@link OidcLoginOutcome} to a Fastify reply. */
async function sendOidcOutcome(reply: FastifyReply, outcome: OidcLoginOutcome): Promise<void> {
  if (outcome.kind === 'redirect') {
    // 302 + Location, written directly rather than via @fastify/redirect — the
    // SDK adds no new dependency for a two-line response.
    await reply.code(302).header('location', outcome.url).send();
    return;
  }
  if (outcome.kind === 'json') {
    await reply.code(200).send(outcome.body);
    return;
  }
  await reply.code(outcome.status).send(outcome.body);
}

/** Route paths the {@link oidcLoginPlugin} registers, relative to where it is registered. */
export interface OidcLoginRoutePaths {
  /** Path of the login-redirect route. Defaults to `/auth/login`. */
  loginPath?: string;
  /** Path of the callback route — must match the public URL in `redirectUri`. Defaults to `/auth/callback`. */
  callbackPath?: string;
}

/**
 * `oidcLoginPlugin(options)` (CONTRACT.md §12) — a `FastifyPluginAsync`
 * registering the two "Login with AXIAM" routes: a login-redirect route and
 * the callback route that consumes `state`, exchanges the code, and validates
 * the ID token.
 *
 * @remarks
 * The Fastify counterpart of Express's `oidcLoginHandlers`, built on the same
 * {@link beginOidcLogin} / {@link completeOidcLogin} core, so the two
 * frameworks cannot drift on flow semantics or error mapping. See
 * `oidcLoginHandlers` for the `returnTo` open-redirect caveat and the
 * `onSuccess` session-establishment contract, which apply identically here.
 *
 * Unlike `axiamPlugin` this plugin is deliberately **encapsulated** (no
 * `skip-override` marker): it registers routes rather than a hook, so there is
 * nothing that needs to escape its own context.
 *
 * @example
 * ```ts
 * await fastify.register(oidcLoginPlugin({
 *   client: oidc,
 *   store: new MemoryOidcStateStore(),
 *   redirectUri: 'https://app.example.com/auth/callback',
 *   onSuccess: (tokens) => { myAppSession.establish(tokens.idClaims!.sub); },
 * }));
 * ```
 */
export const oidcLoginPlugin: (
  options: OidcLoginOptions & OidcLoginRoutePaths,
) => FastifyPluginAsync = (options) => {
  const loginPath = options.loginPath ?? '/auth/login';
  const callbackPath = options.callbackPath ?? '/auth/callback';

  const plugin: FastifyPluginAsync = async (fastify) => {
    fastify.get(loginPath, async (request: FastifyRequest, reply: FastifyReply) => {
      const query = request.query as Record<string, unknown>;
      const returnTo = typeof query.returnTo === 'string' ? query.returnTo : undefined;
      await sendOidcOutcome(reply, await beginOidcLogin(options, returnTo));
    });

    fastify.get(callbackPath, async (request: FastifyRequest, reply: FastifyReply) => {
      const query = request.query as Record<string, unknown>;
      await sendOidcOutcome(
        reply,
        await completeOidcLogin(options, {
          ...(typeof query.state === 'string' ? { state: query.state } : {}),
          ...(typeof query.code === 'string' ? { code: query.code } : {}),
          ...(typeof query.error === 'string' ? { error: query.error } : {}),
          ...(typeof query.error_description === 'string'
            ? { error_description: query.error_description }
            : {}),
        }),
      );
    });
  };

  (plugin as unknown as Record<symbol, unknown>)[Symbol.for('fastify.display-name')] =
    'axiam-oidc-login';
  return plugin;
};
