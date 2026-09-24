// Shared verify core (D-27, CONTRACT.md §10) — the ONE verification path
// both Express and Fastify middleware call. Reuses the 17-03 local-JWKS
// verifier (jose against the cached remote JWKS, EdDSA-only) — no
// per-request round-trip to the AXIAM server on a cache hit, and no
// additional TTL bookkeeping beyond jose's own `exp` check (§10 "MUST NOT
// cache session verification results longer than the token's remaining
// TTL").

import { AuthError } from '../core/index.js';
import { assertTenantClaim, type PresentedProofs, type Verifier } from '../node/jwks.js';
import type { RevocationFeed } from '../node/revocationFeed.js';

/**
 * Minimal session shape the middleware needs: a JWKS verifier (D-11) and the
 * tenant this resource server is configured for (CR-03). JWKS is org-wide,
 * not tenant-scoped (node/jwks.ts) — `tenantHeaderValue` is what lets
 * `authenticateRequest` reject a validly-signed token minted for a
 * DIFFERENT tenant in the same org (CONTRACT.md §10.1 rule 4).
 */
export interface VerifiableSession {
  /** Local JWKS verifier (D-11) — validates the token's EdDSA signature against the org-wide cached JWKS, offline on a cache hit. */
  jwksVerifier: Verifier;
  /**
   * The tenant this resource server is configured for (CR-03, §10.1 rule 4);
   * a validly-signed token minted for a different tenant in the same org is
   * rejected.
   *
   * @remarks
   * The claim it is compared against is the token's `tenant_id`, which is
   * always a UUID — so a resource server guarding routes MUST be configured
   * with `tenantId` (the UUID form), not `tenantSlug`. A slug-configured
   * session can never match and therefore rejects every request; that is
   * fail-closed by design, not a silent pass.
   */
  tenantHeaderValue: string;
  /**
   * CONTRACT.md §10.1 rule 5 — expected token issuer. Optional and unset by
   * default: the rule is conditional on configuration, and the SDK never
   * hardcodes an issuer. When set, a token whose `iss` differs is rejected.
   * Populated from `AxiamClientOptions.expectedIssuer`.
   */
  expectedIssuer?: string;
  /**
   * CONTRACT.md §10.1 rule 6 — expected token audience. Optional and unset by
   * default. A resource server guarding user-facing routes SHOULD set
   * `"axiam:user"`. Populated from `AxiamClientOptions.expectedAudience`.
   */
  expectedAudience?: string;
  /**
   * CONTRACT.md §28.5 (contract 1.48) — the URL of this resource server's RFC
   * 9728 protected-resource metadata document.
   *
   * Unset by default, and **setting it is what turns §28 on**. With it unset
   * every guard built from this session behaves byte-for-byte as it did before
   * §28 existed: no `WWW-Authenticate` header on any response, no status
   * changed, no body changed.
   *
   * With it set, the guard's 401s carry §28.4's challenge, a
   * `require_access`/`requireAccessHook` denial that named a scope and came
   * back `no_grant` carries `insufficient_scope`, and the path this URL names
   * is served without authentication so the document can start the handshake
   * it exists to start.
   *
   * **{@link VerifiableSession.expectedAudience} becomes mandatory.** Every
   * guard factory refuses the configuration at construction — before the first
   * request — when this is set and that is not, and the refusal names both. A
   * resource server that publishes "tokens for me carry this `aud`" and then
   * does not check `aud` is opened by a token minted for a different resource
   * server, which is the confusion RFC 8707 exists to prevent.
   *
   * Feed it from `protectedResourceMetadata(...).metadataUrl` rather than by
   * retyping the string — retyping is how the guard and the document come to
   * disagree.
   */
  resourceMetadataUrl?: string;
  /**
   * CONTRACT.md §10.4 (contract 1.44) — the optional session-revocation feed.
   *
   * Unset by default, and with it unset this guard behaves exactly as it did
   * before 1.44: a revoked session's access token verifies locally until it
   * expires, which is the §10.2 posture this narrows rather than replaces.
   *
   * It is never a control. A feed that cannot be read denies nothing, every
   * §10.1 rule runs first and still decides, and a token with no `sid` is
   * never matched against it.
   */
  revocationFeed?: RevocationFeed;
}

/** Authenticated identity injected as req.axiamUser / request.axiamUser (§10). */
export interface AxiamIdentity {
  /** The authenticated end user's id (the token's `sub` claim). */
  userId: string;
  /** The tenant the verified token was minted for (the token's `tenant_id` claim). */
  tenantId: string;
  /** Roles derived from the token's space-separated `scope` claim (§10). */
  roles: string[];
}

/**
 * Verify `token` locally against `session`'s cached JWKS and map the
 * verified claims to the identity shape injected by both middleware
 * modules. Roles are derived from the `scope` claim (space-separated) —
 * AXIAM's access token carries no dedicated `roles` claim server-side
 * (mirrors the Rust SDK's src/middleware/actix.rs).
 *
 * This is the SDK's **documented §10 guard entry point** for TypeScript, and
 * it applies the complete CONTRACT.md §10.1 minimum local-verification set:
 * rules 1/2/3/5/6/7 inside `verifyAccessToken` (EdDSA `alg` pinned before key
 * lookup, REQUIRED numeric `exp`, `nbf` when present, conditional `iss`/`aud`,
 * a named bounded clock skew), rule 4 — the `tenant_id` assertion — both
 * there and again here, so a caller-supplied `Verifier` implementation that
 * ignores its expectations still cannot get a cross-tenant token past the
 * middleware, and rule 9 — see `proofs` below.
 *
 * **`proofs` and rule 9.** A token carrying `cnf` is not a bearer token
 * (§10.1 rule 9): it may be used only by a presenter that proves possession
 * of the key it names. `proofs` is this function's transport evidence — a
 * certificate thumbprint the caller's TLS layer verified for this
 * connection, a DPoP key thumbprint from a proof the caller has **itself**
 * verified, or both — and it is passed straight into `verifyAccessToken`,
 * which is where rule 9 is now enforced (contract 1.51 fix; see
 * `verifyAccessToken`'s own doc in `node/jwks.ts`). There is deliberately no
 * *second* rule-9 check here: `verifyAccessToken` already reuses
 * `verifyTokenBinding` internally, and re-running that same check against
 * the same `proofs` a moment later would only be able to agree with itself —
 * the risk worth guarding against is a check run against *different* inputs
 * (for example the transport's real evidence at one call site and `{}` at
 * another), not the same evidence read twice.
 *
 * `proofs` defaults to `{}` — **no evidence** — so a `cnf`-bound token is
 * refused by default, which is the fail-closed, spec-correct behaviour for a
 * caller that has not supplied any: rule 9's table has no row where absent
 * evidence accepts a bound token. `axiamMiddleware`/`axiamPlugin` pass
 * `certificateProofFromSocket(req.socket)` automatically, so a resource
 * server whose Node process terminates TLS itself accepts a
 * certificate-bound token with no extra wiring; a deployment behind a proxy
 * that forwards nothing still refuses one, exactly as §10.1 rule 9 detail 3
 * requires. An unbound token is unaffected either way — this is the
 * positive regression rule 9 exists to protect, and its own test asserts it
 * explicitly.
 *
 * Throws `AuthError` on any verification failure (missing/invalid/expired
 * token, a token with no `exp`, a not-yet-valid `nbf`, a malformed/mismatched
 * sub/tenant_id claim, or an unsatisfiable `cnf`).
 */
export async function authenticateRequest(
  session: VerifiableSession,
  token: string,
  proofs: PresentedProofs = {},
): Promise<AxiamIdentity> {
  let claims;
  try {
    // proofs flows straight into verifyAccessToken, which now applies rule 9
    // itself (contract 1.51 fix) — see the doc comment above for why this
    // stays a single check rather than a second one against the same
    // evidence.
    claims = await session.jwksVerifier.verifyAccessToken(
      token,
      {
        expectedTenantId: session.tenantHeaderValue,
        expectedIssuer: session.expectedIssuer,
        expectedAudience: session.expectedAudience,
      },
      proofs,
    );
  } catch (err) {
    throw new AuthError(err instanceof Error ? err.message : 'invalid or expired token');
  }

  if (!claims.sub) {
    throw new AuthError('invalid sub claim');
  }
  // CR-03 / §10.1 rule 4: JWKS is org-wide (node/jwks.ts), so signature
  // validity alone does NOT imply the token was minted for THIS resource
  // server's tenant. Re-asserted on the guard side (the verifier already did
  // it) because `VerifiableSession.jwksVerifier` is an interface a consumer
  // may implement themselves — the middleware must not delegate a
  // fail-closed control to a type it does not own.
  assertTenantClaim(claims.tenant_id, session.tenantHeaderValue);

  // §10.4 rules 4 and 6. Runs LAST: every §10.1 rule has already decided, and
  // the feed can only turn an accept into a reject. A token with no `sid`
  // names no session and is never matched — there is no fallback to `jti`,
  // which would match nothing while looking like it worked.
  const sid = (claims as { sid?: unknown }).sid;
  if (session.revocationFeed && typeof sid === 'string' && sid.length > 0) {
    if (await session.revocationFeed.isRevoked(sid)) {
      throw new AuthError(
        'the session behind this access token has been revoked (CONTRACT.md §10.4)',
      );
    }
  }

  const roles = (claims.scope ?? '').split(' ').filter(Boolean);

  return {
    userId: claims.sub,
    tenantId: claims.tenant_id,
    roles,
  };
}
