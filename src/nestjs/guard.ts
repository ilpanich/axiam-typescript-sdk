// AxiamGuard — the enforcement side of the §11 NestJS decorators (Tier 2).
//
// Reads the metadata `decorators.ts` attaches via `Reflector`, then reuses
// the EXACT same `middleware/authzCore.ts` primitives
// (`assertAuthzClient`/`evaluateAccess`/`hasAnyRole`/`ResourceResolutionError`)
// that back the Express/Fastify guards, so the three framework integrations
// can never drift on the §11 error-mapping/subject-propagation/no-caching
// rules. Never performs its own token extraction (§11.2.1): it only reads
// `request.axiamUser`, which must already be set by `axiamMiddleware`/
// `axiamPlugin` mounted on the underlying HTTP adapter (Nest runs on top of
// Express or Fastify) — 401 if absent.

import {
  BadRequestException,
  ForbiddenException,
  ServiceUnavailableException,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Reflector } from '@nestjs/core';
import {
  assertAuthzClient,
  evaluateAccess,
  hasAnyRole,
  ResourceResolutionError,
  type AuthzVerifiableSession,
} from '../middleware/authzCore.js';
import type { AxiamIdentity } from '../middleware/verifyCore.js';
import {
  AXIAM_REQUIRE_ACCESS_METADATA,
  AXIAM_REQUIRE_AUTH_METADATA,
  AXIAM_REQUIRE_ROLE_METADATA,
} from './metadata.js';
import type { NestResourceSpec, RequireAccessMetadata } from './decorators.js';

/** DI token for the `AuthzVerifiableSession` `AxiamGuard` is constructed with — provide it with `{ provide: AXIAM_SESSION, useValue: session }`. */
export const AXIAM_SESSION = Symbol('AXIAM_SESSION');

interface RequestWithAxiamUser {
  axiamUser?: AxiamIdentity;
  params?: Record<string, string | undefined>;
}

/**
 * Resolve the resource id from `request` per `spec` (mirrors
 * `middleware/authzCore.ts`'s `resolveResourceId`, adapted to the
 * `{ param }`-object resource shape `@RequireAccess` uses). A missing or
 * empty resolution is a **programming error** raised as
 * {@link ResourceResolutionError} — never a silent allow (§11.2.3).
 */
function resolveNestResourceId(request: RequestWithAxiamUser, spec: NestResourceSpec): string {
  let resourceId: string | undefined;
  if (typeof spec === 'function') {
    resourceId = spec(request);
  } else if (typeof spec === 'string') {
    resourceId = spec;
  } else {
    resourceId = request.params?.[spec.param];
  }
  if (!resourceId) {
    const label = typeof spec === 'object' ? `route param "${spec.param}"` : 'resource';
    throw new ResourceResolutionError(`unable to resolve ${label} from request`);
  }
  return resourceId;
}

/**
 * `AxiamGuard` (CONTRACT.md §11, Tier 2) — a Nest `CanActivate` guard
 * enforcing the `@RequireAuth`/`@RequireAccess`/`@RequireRole` decorators. A
 * handler/controller with none of the three decorators is left unrestricted
 * by this guard (`true`).
 *
 * Deliberately a **plain class with no Nest decorators of its own** (no
 * `@Injectable()`/`@Inject()`) — this SDK's tsconfig does not enable
 * `experimentalDecorators` (only the consuming Nest app's does), so
 * `AxiamGuard` is wired into a Nest app via an explicit factory provider
 * rather than Nest's implicit constructor-injection-via-metadata:
 *
 * ```ts
 * import { APP_GUARD, Reflector } from '\@nestjs/core';
 * import { AxiamGuard, AXIAM_SESSION } from 'axiam-sdk/nestjs';
 *
 * providers: [
 *   { provide: AXIAM_SESSION, useValue: authzSession },
 *   {
 *     provide: APP_GUARD,
 *     useFactory: (reflector: Reflector, session: AuthzVerifiableSession) => new AxiamGuard(reflector, session),
 *     inject: [Reflector, AXIAM_SESSION],
 *   },
 * ],
 * ```
 *
 * Requires an `AuthzVerifiableSession` — only dereferenced (via
 * `assertAuthzClient`, throwing if `authzClient` is absent) when a
 * `@RequireAccess` decorator is actually present on the matched
 * handler/controller, mirroring the Express/Fastify guards' construction-time
 * check.
 */
export class AxiamGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly session?: AuthzVerifiableSession,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    const requireAuth = this.reflector.getAllAndOverride<boolean>(AXIAM_REQUIRE_AUTH_METADATA, targets);
    const requireRoles = this.reflector.getAllAndOverride<string[]>(AXIAM_REQUIRE_ROLE_METADATA, targets);
    const requireAccessMeta = this.reflector.getAllAndOverride<RequireAccessMetadata>(
      AXIAM_REQUIRE_ACCESS_METADATA,
      targets,
    );

    if (!requireAuth && !requireRoles && !requireAccessMeta) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithAxiamUser>();
    const axiamUser = request.axiamUser;
    if (!axiamUser) {
      throw new UnauthorizedException({
        error: 'authentication_failed',
        message: 'no authenticated identity on the request — mount axiamMiddleware/axiamPlugin first',
      });
    }

    if (requireRoles && !hasAnyRole(axiamUser.roles, requireRoles)) {
      throw new ForbiddenException({ error: 'authorization_denied', message: 'missing required role' });
    }

    if (requireAccessMeta) {
      const checker = assertAuthzClient(this.session ?? ({} as AuthzVerifiableSession));

      let resourceId: string;
      try {
        resourceId = resolveNestResourceId(request, requireAccessMeta.resource);
      } catch (err) {
        const message = err instanceof ResourceResolutionError ? err.message : 'invalid resource';
        throw new BadRequestException({ error: 'invalid_request', message });
      }

      const outcome = await evaluateAccess(
        checker,
        requireAccessMeta.action,
        resourceId,
        axiamUser.userId,
        requireAccessMeta.opts?.scope,
      );
      if (outcome.kind === 'denied') {
        requireAccessMeta.opts?.logger?.debug('axiam_sdk.authz', 'access denied', {
          action: requireAccessMeta.action,
          resourceId,
        });
        throw new ForbiddenException({ error: 'authorization_denied', message: outcome.message });
      }
      if (outcome.kind === 'unavailable') {
        requireAccessMeta.opts?.logger?.debug('axiam_sdk.authz', 'authz check unavailable', {
          action: requireAccessMeta.action,
          resourceId,
        });
        throw new ServiceUnavailableException({ error: 'authz_unavailable', message: outcome.message });
      }
    }

    return true;
  }
}
