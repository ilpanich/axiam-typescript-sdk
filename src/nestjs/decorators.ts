// NestJS metadata decorators (CONTRACT.md §11, Tier 2). Pure metadata
// attachment via `@nestjs/common`'s `SetMetadata` — no enforcement logic
// lives here (that's `guard.ts`'s `AxiamGuard`, which reads the metadata
// back out via `Reflector`). Uses NestJS's own decorator machinery, so this
// SDK's tsconfig does NOT enable `experimentalDecorators` — only the
// consuming Nest application needs it (which it already does, by being a
// Nest app).

import { SetMetadata } from '@nestjs/common';
import type { RequireAccessOptions } from '../middleware/authzCore.js';
import {
  AXIAM_REQUIRE_ACCESS_METADATA,
  AXIAM_REQUIRE_AUTH_METADATA,
  AXIAM_REQUIRE_ROLE_METADATA,
} from './metadata.js';

/** `{ param: 'id' }` form of the `@RequireAccess` `resource` argument (§11.2.3.b): resolve the resource id from the named route parameter at request time. */
export interface NestParamResource {
  /** The route parameter name (e.g. `request.params[name]`) carrying the resource id. */
  readonly param: string;
}

/** The `resource` argument accepted by `@RequireAccess` (CONTRACT.md §11.2.3): a static literal, {@link NestParamResource} (route parameter), or a `(request) => string` resolver. */
export type NestResourceSpec = string | NestParamResource | ((request: unknown) => string);

/** The metadata value `@RequireAccess` attaches, read back by {@link AxiamGuard} via `Reflector`. */
export interface RequireAccessMetadata {
  /** The action being performed (e.g. `"read"`, `"write"`, `"delete"`), passed through to `checkAccess` verbatim. */
  action: string;
  /** How to resolve the checked resource's id from the request (§11.2.3). */
  resource: NestResourceSpec;
  /** Optional scope/logger settings, passed through to `checkAccess`/the debug-only denial log. */
  opts?: RequireAccessOptions;
}

/**
 * `@RequireAuth()` (CONTRACT.md §11.1) — marks a handler/controller as
 * requiring an authenticated AXIAM identity. `AxiamGuard` responds 401 if
 * `request.axiamUser` (injected by `axiamMiddleware`/`axiamPlugin` mounted
 * on the underlying HTTP adapter) is absent.
 */
export function RequireAuth(): ClassDecorator & MethodDecorator {
  return SetMetadata(AXIAM_REQUIRE_AUTH_METADATA, true);
}

/**
 * `@RequireAccess(action, resource, opts?)` (CONTRACT.md §11) — a per-route
 * authorization requirement enforced by `AxiamGuard`. `resource` is resolved
 * per §11.2.3's precedence: a literal string, `{ param: 'id' }` (a route
 * parameter), or a `(request) => string` resolver.
 *
 * @example
 * ```ts
 * \@RequireAccess('read', { param: 'id' })
 * \@Get(':id')
 * getDocument(\@Param('id') id: string) { ... }
 * ```
 */
export function RequireAccess(
  action: string,
  resource: NestResourceSpec,
  opts?: RequireAccessOptions,
): ClassDecorator & MethodDecorator {
  const metadata: RequireAccessMetadata = { action, resource, opts };
  return SetMetadata(AXIAM_REQUIRE_ACCESS_METADATA, metadata);
}

/**
 * `@RequireRole(...roles)` (CONTRACT.md §11.1, MAY) — a local (no server
 * round-trip) check that the authenticated identity's roles contain at
 * least one of `roles`. Cheaper but coarser than `@RequireAccess`; NOT a
 * substitute for a resource-level check.
 */
export function RequireRole(...roles: string[]): ClassDecorator & MethodDecorator {
  return SetMetadata(AXIAM_REQUIRE_ROLE_METADATA, roles);
}
