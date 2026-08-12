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

import { AuthzError, NetworkError, type Sensitive } from '../core/index.js';
import type { AccessCheck, AccessDecision } from '../rest/types.js';
import type { VerifiableSession } from './verifyCore.js';

/**
 * The minimal shape `requireAccess`/`requireAccessHook` need from an authz
 * transport — satisfied structurally by `AxiamClient` (`checkAccess`
 * already accepts `subjectId`, §1/FND-04) without importing the class
 * itself, so this module pulls in no axios/grpc dependency.
 */
export interface AuthzChecker {
  /** Issue a single access check for the authenticated end user (`subjectId`, §11.2.2). Satisfied structurally by `AxiamClient.checkAccess`. */
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
  /** Authz transport required by `requireAccess`/`requireAccessHook` (validated by {@link assertAuthzClient}); unused by `requireAuth`/`requireRole`. */
  authzClient?: AuthzChecker;
}

/** Marker produced by {@link fromParam} — resolve the resource id from a named path/route parameter. */
export interface ResourceParamRef {
  /** Discriminant marking the path/route-parameter resolution strategy (§11.2.3.b). */
  readonly kind: 'param';
  /** The path/route parameter name the resource id is read from. */
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
  /**
   * When set, a denial also carries a `WWW-Authenticate: UMA` challenge
   * (§20.3): the guard mints a permission ticket for the action it just refused
   * and tells the caller where to redeem it.
   *
   * Opt-in — see {@link UmaChallenger} for why that matters.
   */
  umaChallenge?: UmaChallenger;
}

/**
 * Mints a permission ticket. Structurally the `umaRequestTicket` method of an
 * `OidcClient`, taken as a function so this module does not depend on the
 * Node-only OIDC entry point — the middleware core is shared with the browser
 * build, which has no Protection API client.
 */
export type UmaTicketMinter = (
  pat: string,
  permissions: ReadonlyArray<{ resourceId: string; resourceScopes: string[] }>,
) => Promise<Sensitive<string>>;

/**
 * A configured `WWW-Authenticate: UMA` challenge emitter (§20.3, emit half).
 *
 * Attach one via {@link RequireAccessOptions.umaChallenge} and a denial stops
 * being a bare 403: the guard mints a fresh permission ticket for the pairs the
 * caller lacked and returns it in the header, so a UMA-aware client knows where
 * to go for authority instead of only being told "no".
 *
 * **Opt-in, and deliberately so.** Emitting a challenge means minting a
 * credential — a wire call to the Protection API, and a live ticket, produced
 * on a path the caller did not explicitly request. A guard that did that on
 * every denial by default would turn each unauthorized request into a
 * Protection API call, which is a denial-of-service amplifier pointed at your
 * own authorization server.
 *
 * **Failure is not escalation.** If minting fails — the PAT expired, the
 * Protection API is down, the resource declares none of the requested scopes —
 * the denial still surfaces as an ordinary 403 without a challenge. A caller
 * who was going to be refused is refused either way; letting a Protection API
 * outage turn a deny into a 500 would hand the outage a second consequence, and
 * letting it turn into an allow would be a security bug.
 */
export interface UmaChallenger {
  /** The protection realm to name in the header. */
  realm: string;
  /**
   * The authorization server to send the caller to — normally this
   * deployment's issuer, read from discovery rather than concatenated by hand.
   */
  asUri: string;
  /**
   * A Protection API Token: a *client-credentials* token carrying the
   * `uma_protection` scope (§20.2 rule 1). A user token cannot stand in — a
   * minted ticket is bound to the `client_id` that minted it.
   */
  pat: string;
  /** Typically `oidcClient.umaRequestTicket.bind(oidcClient)`. */
  mint: UmaTicketMinter;
}

/** Minimal logger seam for the §11.2.8 debug-only denial/error log (mirrors `amqp/consumer.ts`'s `ConsumeLogger`). */
export interface AuthzLogger {
  /** Emit a debug-only denial/error record (§11.2.8) — receives `action`/`resourceId` context, never the token. */
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
  /** Stable machine-readable error code (e.g. `authentication_failed`, `authorization_denied`). */
  error: string;
  /** Human-readable explanation; never contains token material. */
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
  | {
      /** The check passed — the caller proceeds to the handler. */
      kind: 'allowed';
    }
  | {
      /** The check was evaluated and denied (`allowed: false` or a server 403) → HTTP 403. */
      kind: 'denied';
      /** Denial message surfaced in the 403 body. */
      message: string;
      /**
       * The complete `WWW-Authenticate` value, when a {@link UmaChallenger} was
       * configured *and* minting succeeded (§20.3). Absent otherwise, including
       * when minting failed — the denial stands either way.
       */
      challenge?: string;
    }
  | {
      /** The authz transport failed — fail-closed → HTTP 503, never an allow. */
      kind: 'unavailable';
      /** Failure message surfaced in the 503 body. */
      message: string;
    };

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
  challenger?: UmaChallenger,
): Promise<CheckOutcome> {
  try {
    const decision = await checker.checkAccess({ action, resourceId, scope, subjectId });
    if (!decision.allowed) {
      return deny(decision.reason ?? 'access denied', action, resourceId, challenger);
    }
    return { kind: 'allowed' };
  } catch (err) {
    if (err instanceof AuthzError) {
      return deny(err.message, action, resourceId, challenger);
    }
    if (err instanceof NetworkError) {
      return { kind: 'unavailable', message: err.message };
    }
    // Fail closed (§11.2.5): any unexpected failure is treated as
    // "couldn't decide", never a silent allow.
    return { kind: 'unavailable', message: 'authorization service unavailable' };
  }
}

/**
 * Build the denial, minting a §20.3 challenge when one was configured.
 *
 * Only ever reached on a path that has already decided to refuse, so minting
 * cannot change the outcome — at worst it fails and the caller gets the plain
 * 403 they would have got anyway.
 */
async function deny(
  message: string,
  action: string,
  resourceId: string,
  challenger?: UmaChallenger,
): Promise<CheckOutcome> {
  if (!challenger) return { kind: 'denied', message };
  try {
    // §20.2: the UMA scope is the AXIAM *action*, which is what makes the ticket
    // ask for exactly the authority this check just refused — and what keeps a
    // deny rule vetoing the resulting RPT the same way it vetoed the check.
    const ticket = await challenger.mint(challenger.pat, [{ resourceId, resourceScopes: [action] }]);
    return {
      kind: 'denied',
      message,
      challenge: umaChallengeHeaderValue(challenger.realm, challenger.asUri, ticket.expose()),
    };
  } catch {
    // Deliberately swallowed; see UmaChallenger's "failure is not escalation".
    // Not logged either: the §11.2.8 logger never receives credentials, and the
    // failure reason from a Protection API call can contain a token echo.
    return { kind: 'denied', message };
  }
}

/**
 * Format the header value. Duplicated from the Node-only `umaChallengeHeader`
 * rather than imported, because this module is in the browser build's
 * dependency graph and that one is not — the format is four literals and a
 * template, and a shared import would drag the whole OIDC entry point along.
 */
function umaChallengeHeaderValue(realm: string, asUri: string, ticket: string): string {
  return `UMA realm="${realm}", as_uri="${asUri}", ticket="${ticket}"`;
}

/** Local (no server round-trip) role check (§11.2.9): true iff `roles` and the identity's roles share at least one entry. */
export function hasAnyRole(identityRoles: readonly string[], roles: readonly string[]): boolean {
  return roles.some((role) => identityRoles.includes(role));
}
