// Reflect-metadata keys shared by the §11 decorators (decorators.ts) and the
// enforcement guard (guard.ts). Symbols, not strings, so a consuming app's
// own metadata never collides with these by coincidence.

/** Set by {@link RequireAuth}; read by {@link AxiamGuard}. */
export const AXIAM_REQUIRE_AUTH_METADATA = Symbol('axiam:requireAuth');

/** Set by {@link RequireAccess}; read by {@link AxiamGuard}. Value shape: {@link RequireAccessMetadata}. */
export const AXIAM_REQUIRE_ACCESS_METADATA = Symbol('axiam:requireAccess');

/** Set by {@link RequireRole}; read by {@link AxiamGuard}. Value shape: `string[]`. */
export const AXIAM_REQUIRE_ROLE_METADATA = Symbol('axiam:requireRole');
