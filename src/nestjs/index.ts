// AXIAM SDK — NestJS entry (`axiam-sdk/nestjs`), optional Tier 2 of
// CONTRACT.md §11's declarative authorization helpers.
//
// `@nestjs/common` and `@nestjs/core` are optional peer dependencies (like
// `express`/`fastify` on the `axiam-sdk/middleware` entry) — this subpath is
// only reachable by an application that already depends on NestJS.

export {
  RequireAccess,
  RequireAuth,
  RequireRole,
  RequireScope,
  type NestParamResource,
  type NestResourceSpec,
  type RequireAccessMetadata,
} from './decorators.js';
export { AxiamGuard, AXIAM_SESSION } from './guard.js';
export {
  AXIAM_REQUIRE_ACCESS_METADATA,
  AXIAM_REQUIRE_AUTH_METADATA,
  AXIAM_REQUIRE_ROLE_METADATA,
  AXIAM_REQUIRE_SCOPE_METADATA,
} from './metadata.js';
// Re-exported so the nestjs entry point's own generated docs can resolve
// `RequireAccessMetadata.opts`/`AxiamGuard`'s constructor parameter without a
// dangling cross-module link (`middleware/authzCore.ts` is not itself a
// TypeDoc entry point) — single source of truth stays authzCore.ts.
export type { AuthzVerifiableSession, RequireAccessOptions } from '../middleware/authzCore.js';
