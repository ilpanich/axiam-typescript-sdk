// Express middleware (D-27, CONTRACT.md §10). Express 5 handlers may be
// async — an async middleware that rejects is automatically forwarded to
// Express's error handling, but this middleware always resolves (never
// rejects) since every failure path is caught and turned into a 401/403
// JSON response itself.

import type { NextFunction, Request, RequestHandler, Response } from 'express';
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
  beginOidcLogin,
  completeOidcLogin,
  type OidcLoginOptions,
  type OidcLoginOutcome,
} from './oidcLoginCore.js';
import { authenticateRequest, type AxiamIdentity, type VerifiableSession } from './verifyCore.js';

/** An Express `Request` augmented with the AXIAM identity that `axiamMiddleware` injects after §10 verification. */
export interface AxiamRequest extends Request {
  /** The authenticated identity, present once `axiamMiddleware` (or `requireAuth`) has run; absent on an unauthenticated request. */
  axiamUser?: AxiamIdentity;
}

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
 * `axiamMiddleware(session)` — extracts the session (cookie-first, then
 * `Authorization: Bearer` fallback), verifies it locally against the
 * cached JWKS (D-11, no per-request server round-trip on a cache hit),
 * and injects `req.axiamUser` on success. Returns 401 (AuthError) or 403
 * (AuthzError) with a standardized JSON error body on failure.
 *
 * **CSRF (cookie double-submit, CONTRACT.md §3):** when the credential was
 * sourced from the `axiam_access` COOKIE (not the `Authorization` header)
 * and the request method is state-changing (anything other than
 * GET/HEAD/OPTIONS), this middleware additionally requires the
 * `X-CSRF-Token` request header to be present and equal (constant time) to
 * the `axiam_csrf` cookie value, rejecting with 403 on mismatch/absence.
 * Bearer-header requests are CSRF-immune by construction — a cross-site
 * attacker cannot set arbitrary request headers — but a cookie
 * automatically attached by the browser is not, and in any same-site
 * deployment where `axiam_access` reaches this app, the non-`httpOnly`
 * `axiam_csrf` cookie does too. This mirrors, locally, the same
 * double-submit check the AXIAM server performs on its own endpoints (§3).
 */
export function axiamMiddleware(session: VerifiableSession): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const credential = extractCredential(req.headers.cookie, req.headers.authorization);
    if (!credential) {
      res.status(401).json(missingCredentialsBody());
      return;
    }

    if (credential.source === 'cookie' && !isSafeMethod(req.method)) {
      const csrfHeader = req.headers[CSRF_HEADER_NAME];
      const csrfValue = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader;
      if (!isCsrfValid(req.headers.cookie, csrfValue)) {
        res.status(403).json(csrfDeniedBody());
        return;
      }
    }

    try {
      const identity = await authenticateRequest(session, credential.token);
      (req as AxiamRequest).axiamUser = identity;
      next();
    } catch (err) {
      if (err instanceof AuthzError) {
        res.status(403).json(authzDeniedBody(err.message));
        return;
      }
      if (err instanceof AuthError) {
        res.status(401).json(invalidTokenBody(err.message));
        return;
      }
      res.status(401).json(invalidTokenBody('invalid or expired token'));
    }
  };
}

/**
 * `requireAuth(session)` (CONTRACT.md §11.1) — the canonical §11 name for
 * the same §10 guard `axiamMiddleware` already provides, for mounting
 * per-route (`router.get('/x', requireAuth(session), handler)`) rather than
 * globally via `app.use(axiamMiddleware(session))`. Pure sugar: it performs
 * no verification of its own beyond what `axiamMiddleware` already does.
 */
export function requireAuth(session: VerifiableSession): RequestHandler {
  return axiamMiddleware(session);
}

/**
 * `requireAccess(session, action, resource, opts?)` (CONTRACT.md §11) — a
 * per-route authorization guard layered strictly on top of the §10 guard.
 *
 * Throws synchronously (at route-setup time, not per-request) if
 * `session.authzClient` is not configured. Requires `req.axiamUser` to
 * already be set (by `axiamMiddleware`/`requireAuth` mounted earlier in the
 * chain) — this helper never extracts or verifies a token itself (§11.2.1),
 * so responds 401 immediately when it is absent.
 *
 * `resource` is resolved per §11.2.3's precedence: a literal string, a
 * {@link fromParam} route-parameter reference, or a `(req) => string`
 * resolver. `subjectId` on the wire is always the *authenticated request's*
 * user id (§11.2.2), never the SDK client's own service-account identity.
 * Error mapping (§11.2.5): 401 unauthenticated, 403 denied, 400 unresolvable
 * resource, 503 `authz_unavailable` on any transport/unexpected failure
 * (fail closed — never a silent allow).
 */
export function requireAccess(
  session: AuthzVerifiableSession,
  action: string,
  resource: ResourceSpec<Request>,
  opts?: RequireAccessOptions,
): RequestHandler {
  const checker = assertAuthzClient(session);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const axiamUser = (req as AxiamRequest).axiamUser;
    if (!axiamUser) {
      res.status(401).json(missingAuthBody());
      return;
    }

    let resourceId: string;
    try {
      resourceId = resolveResourceId(req, resource, (r) => r.params as Record<string, string | undefined>);
    } catch (err) {
      const message = err instanceof ResourceResolutionError ? err.message : 'invalid resource';
      res.status(400).json(invalidRequestBody(message));
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
      if (outcome.challenge) {
        // §20.3: tell the caller where to obtain authority. Additive — the body
        // is the unchanged §11.2.5 shape, so a client that does not speak UMA
        // sees exactly the 403 it saw before.
        res.setHeader('WWW-Authenticate', outcome.challenge);
      }
      res.status(403).json(authzDeniedBodyShared(outcome.message));
      return;
    }
    if (outcome.kind === 'unavailable') {
      opts?.logger?.debug('axiam_sdk.authz', 'authz check unavailable', { action, resourceId });
      res.status(503).json(authzUnavailableBody(outcome.message));
      return;
    }
    next();
  };
}

/**
 * `requireRole(session, ...roles)` (CONTRACT.md §11.1, MAY) — a local
 * (no server round-trip) check that the authenticated identity's `roles`
 * (from `req.axiamUser`, itself derived from the verified token's `scope`
 * claim) contain at least one of `roles`. `session` is accepted only for
 * signature parity with `requireAuth`/`requireAccess` (every §11 helper
 * takes the session first) — this check never dereferences it. Cheaper but
 * coarser than `requireAccess`; NOT a substitute for a resource-level check.
 */
export function requireRole(session: VerifiableSession, ...roles: string[]): RequestHandler {
  void session;
  return (req: Request, res: Response, next: NextFunction): void => {
    const axiamUser = (req as AxiamRequest).axiamUser;
    if (!axiamUser) {
      res.status(401).json(missingAuthBody());
      return;
    }
    if (!hasAnyRole(axiamUser.roles, roles)) {
      res.status(403).json(authzDeniedBodyShared('missing required role'));
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// "Login with AXIAM" route handlers (CONTRACT.md §12)
// ---------------------------------------------------------------------------

/** Apply an {@link OidcLoginOutcome} to an Express response. */
function sendOidcOutcome(res: Response, outcome: OidcLoginOutcome): void {
  if (outcome.kind === 'redirect') {
    res.redirect(outcome.url);
    return;
  }
  if (outcome.kind === 'json') {
    res.status(200).json(outcome.body);
    return;
  }
  res.status(outcome.status).json(outcome.body);
}

/**
 * `oidcLoginHandlers(options)` (CONTRACT.md §12) — the two Express route
 * handlers an application needs for "Login with AXIAM": a `login` handler that
 * redirects the browser to AXIAM's authorization endpoint, and a `callback`
 * handler that consumes the returned `state`, exchanges the code, and
 * validates the ID token.
 *
 * @remarks
 * Both handlers are thin adapters over {@link beginOidcLogin} /
 * {@link completeOidcLogin}, which the Fastify variant
 * (`oidcLoginPlugin`) also uses — so the two frameworks cannot drift on flow
 * semantics or error mapping.
 *
 * The `login` handler reads an optional `?returnTo=` query parameter and
 * stores it with the login state, so the callback can send the user back where
 * they started. **Validate or allowlist that value in your own application if
 * you accept it from user input** — an unchecked `returnTo` is an open-redirect
 * vector, and the SDK cannot know which destinations your app considers safe.
 *
 * Establishing your application's own session is the `onSuccess` hook's job:
 * the SDK validates the login and hands you the token set, but what a session
 * means (a signed cookie, a database row, a JWT of your own) is your decision.
 *
 * @example
 * ```ts
 * const store = new MemoryOidcStateStore();
 * const oidc = createOidcClient(session, { clientId, clientSecret });
 * const { login, callback } = oidcLoginHandlers({
 *   client: oidc,
 *   store,
 *   redirectUri: 'https://app.example.com/auth/callback',
 *   scope: 'openid profile email',
 *   onSuccess: (tokens) => { myAppSession.establish(tokens.idClaims!.sub); },
 * });
 *
 * app.get('/auth/login', login);
 * app.get('/auth/callback', callback);
 * ```
 */
export function oidcLoginHandlers(options: OidcLoginOptions): {
  /** `GET` handler that redirects the browser to the AXIAM authorization endpoint. */
  login: RequestHandler;
  /** `GET` handler for the redirect URI: consumes `state`, exchanges `code`, validates the ID token. */
  callback: RequestHandler;
} {
  const login: RequestHandler = async (req: Request, res: Response): Promise<void> => {
    const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : undefined;
    sendOidcOutcome(res, await beginOidcLogin(options, returnTo));
  };

  const callback: RequestHandler = async (req: Request, res: Response): Promise<void> => {
    const query = req.query as Record<string, unknown>;
    sendOidcOutcome(
      res,
      await completeOidcLogin(options, {
        ...(typeof query.state === 'string' ? { state: query.state } : {}),
        ...(typeof query.code === 'string' ? { code: query.code } : {}),
        ...(typeof query.error === 'string' ? { error: query.error } : {}),
        ...(typeof query.error_description === 'string'
          ? { error_description: query.error_description }
          : {}),
      }),
    );
  };

  return { login, callback };
}
