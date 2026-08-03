// Local JWKS verification (D-11, CONTRACT.md §7 defense-in-depth via
// explicit algorithm allowlist) — for BOTH inbound access tokens (§10
// middleware) and relying-party ID tokens (§12.4). One verifier, one cached
// remote key set, two entry points: `verifyAccessToken` and `verifyIdToken`.
// §12 explicitly forbids forking this module for the OIDC flow.
//
// Endpoint: `{baseUrl}/oauth2/jwks` — organization-wide, NOT tenant-scoped,
// serving exactly one EdDSA (Ed25519) key in the common case
// (RESEARCH.md Area 3, mirrors the Rust SDK's src/token/jwks.rs). `jose`'s
// `createRemoteJWKSet` handles fetch + cache + refetch-on-unknown-kid
// natively; we use its single-cooldown model rather than porting the Rust
// SDK's two-timer (TTL + forced-refetch) design (RESEARCH.md Area 3 explicit
// recommendation).
//
// Pitfall 1 (jose is ESM-only): `jose` 5+/6.x ships no CJS entry condition,
// so a tsup CJS build's transpiled `require('jose')` would throw
// `ERR_REQUIRE_ESM`. `createVerifier` obtains jose via a dynamic
// `await import('jose')`, deferring resolution to first call rather than
// module-load time — this keeps `require('axiam-sdk/grpc')` (or any other
// CJS entry that reaches this module) from throwing at import time.

import { AuthError } from '../core/index.js';
import {
  assertIdTokenAlg,
  checkIdTokenClaims,
  ID_TOKEN_ALG,
  idTokenAuthError,
  resolveClockSkewSec,
  type IdTokenClaims,
  type IdTokenExpectations,
} from './oidcIdToken.js';

/** Verified claims carried by an AXIAM access token (the JWT payload {@link Verifier.verifyAccessToken} returns). */
export interface AxiamClaims {
  /** Subject — user ID (UUID). */
  sub: string;
  /** Tenant ID (UUID). */
  tenant_id: string;
  /** Organization ID (UUID), if present. */
  org_id?: string;
  /** Issuer — the AXIAM authorization server that minted the token. */
  iss: string;
  /** Issued-at time (epoch seconds), if present. */
  iat?: number;
  /** Expiry time (epoch seconds); the verifier rejects the token once it has passed. */
  exp: number;
  /** Unique token ID / session id — needed for logout(). */
  jti?: string;
  /** Token audience — "axiam:user" | "axiam:m2m". */
  aud?: string;
  /** OAuth2 scopes (space-separated). */
  scope?: string;
}

/** Path (relative to the client base URL) of the org-wide JWKS endpoint. */
export const JWKS_PATH = '/oauth2/jwks';

const COOLDOWN_DURATION_MS = 60_000;
const TIMEOUT_DURATION_MS = 5_000;

/**
 * Clock-skew leeway applied to the `exp` and `nbf` checks (CONTRACT.md §10.1
 * rule 7).
 *
 * A **named, bounded, non-configurable** constant, fixed at the contract's
 * RECOMMENDED 60 seconds. Rule 7 forbids both an inline literal and an
 * operator-settable value that could be widened without bound, so there is
 * deliberately no option to override it — widening the window is a source
 * change, reviewable as such.
 */
export const CLOCK_SKEW_LEEWAY_SEC = 60;

/**
 * The verification policy {@link Verifier.verifyAccessToken} enforces, per
 * CONTRACT.md §10.1.
 *
 * `expectedTenantId` is **required** (rule 4): the `/oauth2/jwks` trust
 * anchor is organization-wide, so a valid signature proves only "some tenant
 * in this organization". `expectedIssuer` and `expectedAudience` are
 * **conditional** (rules 5 and 6) — omitted means the check is not performed,
 * and the SDK never assumes a default issuer.
 */
export interface AccessTokenExpectations {
  /**
   * §10.1 rule 4 — the tenant this resource server is configured for. The
   * token's `tenant_id` claim MUST equal it; an absent claim, an empty
   * expectation, or a mismatch all reject (fail closed).
   */
  expectedTenantId: string;
  /** §10.1 rule 5 — expected `iss`. Omit for no issuer check. */
  expectedIssuer?: string;
  /**
   * §10.1 rule 6 — expected `aud`. Omit for no audience check. A resource
   * server guarding user-facing routes SHOULD pass `"axiam:user"`.
   */
  expectedAudience?: string;
}

/** Verifies an AXIAM access token's EdDSA signature against the org-wide remote JWKS. */
export interface Verifier {
  /**
   * Verify `token` against the **complete** CONTRACT.md §10.1 minimum
   * local-verification set and return its claims.
   *
   * | § | rule | how it is enforced |
   * |---|---|---|
   * | 1 | signature | `algorithms: ['EdDSA']` is checked by `jose` against the JWS header *before* the remote key set function is invoked, so `alg: none` and an HS-signed token bearing an EdDSA `kid` are rejected without a key lookup. |
   * | 2 | `exp` | `requiredClaims: ['exp']` — `jose` only checks `exp` *if present* by default, so an absent `exp` (a permanent credential) would otherwise sail through. A non-numeric `exp` is rejected by `jose`'s own type check. |
   * | 3 | `nbf` | honoured by `jose` when present, bounded by {@link CLOCK_SKEW_LEEWAY_SEC}. |
   * | 4 | `tenant_id` | asserted against {@link AccessTokenExpectations.expectedTenantId}; absent claim, absent expectation, or mismatch all reject. |
   * | 5 | `iss` | checked only when `expectedIssuer` is supplied. |
   * | 6 | `aud` | checked only when `expectedAudience` is supplied. |
   * | 7 | clock skew | {@link CLOCK_SKEW_LEEWAY_SEC}, passed as `clockTolerance`. |
   *
   * Rejects with the underlying error on any failed rule; the §10 middleware
   * wraps that into an `AuthError`.
   */
  verifyAccessToken(token: string, expectations: AccessTokenExpectations): Promise<AxiamClaims>;

  /**
   * Verify **only** the EdDSA signature of `token` — CONTRACT.md §10.1's
   * "raw signature-only primitive".
   *
   * @remarks
   * **This is not a guard.** It performs no `exp`, `nbf`, `tenant_id`, `iss`
   * or `aud` check whatsoever: an expired token, a not-yet-valid token, and a
   * token minted for a *different tenant* in the same organization all pass.
   * It exists only for integrators deliberately implementing their own
   * policy on top of the signature — the `Unchecked` suffix is there to make
   * that omission obvious at the call site. Anything guarding a route MUST
   * use {@link Verifier.verifyAccessToken} (or, better, the §10 middleware
   * built on it).
   */
  verifySignatureOnlyUnchecked(token: string): Promise<AxiamClaims>;
}

/**
 * The relying-party half of the same verifier (CONTRACT.md §12.4): validates
 * an OIDC **ID token** rather than an AXIAM access token.
 *
 * @remarks
 * Kept as its own interface, and *added* to the object {@link createVerifier}
 * returns rather than to {@link Verifier} itself, so existing code that
 * implements `Verifier` (e.g. a hand-rolled test double supplied as
 * `VerifiableSession.jwksVerifier`) keeps compiling — contract 1.4 is
 * additive.
 */
export interface IdTokenVerifier {
  /**
   * Validate an OIDC ID token per CONTRACT.md §12.4 and return its claims.
   *
   * Enforces rule 1 (`alg` MUST be `EdDSA`, read from the header *before* any
   * signature work — `none` and every other algorithm rejected), rule 2
   * (Ed25519 signature against the key selected by `kid`, with the single
   * JWKS re-fetch policy §10 already implements), then rules 3–6 via
   * {@link checkIdTokenClaims}. Rejects with `AuthError` carrying the
   * matching §12.3 reason code on the first failure.
   */
  verifyIdToken(token: string, expectations: IdTokenExpectations): Promise<IdTokenClaims>;
}

/**
 * The concrete verifier {@link createVerifier} / {@link createJwksVerifier}
 * return: one object, one cached remote key set, both the §10 access-token
 * path and the §12.4 ID-token path. §12 forbids a second verifier.
 */
export interface JwksVerifier extends Verifier, IdTokenVerifier {}

/**
 * Build a verifier bound to `{baseUrl}/oauth2/jwks`.
 *
 * `jose` is loaded lazily via dynamic `import()` (Pitfall 1 — CJS-safe); the
 * remote JWKS itself is also fetched/cached lazily by `jose`, not eagerly
 * here.
 *
 * For the relying-party (§12) flow use {@link createJwksVerifier} with the
 * `jwks_uri` the discovery document advertises instead of hardcoding
 * {@link JWKS_PATH} — §12.3 rule 6 requires reading the URI from the document.
 */
export function createVerifier(baseUrl: string): JwksVerifier {
  return createJwksVerifier(`${baseUrl}${JWKS_PATH}`);
}

/**
 * Build a verifier bound to an explicit, absolute JWKS URI — the `jwks_uri`
 * value taken from the OIDC discovery document (CONTRACT.md §12.3 rule 6).
 *
 * Identical machinery to {@link createVerifier}: one lazily-resolved
 * `createRemoteJWKSet` singleton per verifier instance, shared by
 * `verifyAccessToken` and `verifyIdToken`.
 */
export function createJwksVerifier(jwksUri: string): JwksVerifier {
  // Lazily-resolved singleton so repeated verifyAccessToken() calls reuse
  // the same createRemoteJWKSet cache instead of rebuilding it per call.
  //
  // D-08/D-09 (single-flight, PERF-03): a concurrent invalid-`kid` burst
  // against a cold cache must collapse to exactly ONE network fetch. Proven
  // (not just assumed) by `test/node/jwks.test.ts`'s "collapses N concurrent
  // verifyAccessToken calls ... to exactly one JWKS fetch" test, which mocks
  // global `fetch` with a call counter and fires 8 concurrent calls: jose's
  // `createRemoteJWKSet` (see jose's `RemoteJWKSet.reload()`,
  // `this.#pendingFetch ||= fetchJwks(...).then(...)`) ALREADY holds its own
  // internal lazy-promise-singleton around the underlying fetch, so
  // concurrent callers reaching a cold/unknown-kid getter share the same
  // in-flight fetch promise natively — no additional `inFlightFetch` guard
  // is added here (it would be redundant). If a future `jose` upgrade
  // removes that internal guarantee, the burst test above will start
  // failing and an explicit guard (mirroring `jwksPromise`'s shape) must be
  // added at that point.
  let jwksPromise: Promise<ReturnType<typeof import('jose').createRemoteJWKSet>> | null = null;

  async function getJwks() {
    if (!jwksPromise) {
      // eslint-disable-next-line @typescript-eslint/consistent-type-imports
      jwksPromise = import('jose').then(({ createRemoteJWKSet }) =>
        createRemoteJWKSet(new URL(jwksUri), {
          cooldownDuration: COOLDOWN_DURATION_MS,
          timeoutDuration: TIMEOUT_DURATION_MS,
        }),
      );
    }
    return jwksPromise;
  }

  return {
    async verifyAccessToken(
      token: string,
      expectations: AccessTokenExpectations,
    ): Promise<AxiamClaims> {
      const { jwtVerify } = await import('jose');
      const jwks = await getJwks();
      // §10.1 rule 1: explicit algorithm allowlist — never trust the token's
      // own `alg` header; defense against algorithm-confusion attacks
      // (T-17-14). jose checks this against the JWS protected header BEFORE
      // it calls the remote-key-set resolver, so `alg: none` and an HS256
      // token carrying our EdDSA `kid` both die without a key lookup.
      //
      // §10.1 rule 2: `requiredClaims: ['exp']` is load-bearing and NOT a
      // jose default — jose validates `exp` only `if (payload.exp !==
      // undefined)`, so a token minted with no `exp` at all (a permanent
      // credential) would otherwise verify. This is precisely the SEC-080
      // defect. A present-but-non-numeric `exp` is rejected by jose's own
      // `"exp" claim must be a number` check.
      //
      // §10.1 rules 5/6: `issuer`/`audience` are passed ONLY when configured
      // — supplying them also makes jose require the corresponding claim to
      // be present, which is the intended fail-closed behaviour; omitting
      // them means no check, per the conditional wording of the rules.
      //
      // §10.1 rules 3/7: jose honours `nbf` when present; `clockTolerance`
      // bounds both the `exp` and the `nbf` comparison.
      const { payload } = await jwtVerify(token, jwks, {
        algorithms: ['EdDSA'],
        requiredClaims: ['exp'],
        clockTolerance: CLOCK_SKEW_LEEWAY_SEC,
        ...(expectations.expectedIssuer !== undefined
          ? { issuer: expectations.expectedIssuer }
          : {}),
        ...(expectations.expectedAudience !== undefined
          ? { audience: expectations.expectedAudience }
          : {}),
      });

      // §10.1 rule 4 — the tenant assertion, which no JWT library can do for
      // us: `tenant_id` is an AXIAM claim, and the JWKS trust anchor is
      // organization-wide. Fails closed on all three failure shapes: no
      // configured tenant, an absent/ill-typed claim, and a mismatch.
      // "Nothing to compare against, so nothing to check" is the SEC-080
      // defect, not a pass.
      assertTenantClaim(payload.tenant_id, expectations.expectedTenantId);

      return payload as unknown as AxiamClaims;
    },

    async verifySignatureOnlyUnchecked(token: string): Promise<AxiamClaims> {
      const { jwtVerify } = await import('jose');
      const jwks = await getJwks();
      // Signature + algorithm pinning ONLY — see the interface docs. No
      // `requiredClaims`, no `clockTolerance`, and deliberately no tenant
      // assertion. `jose` still refuses an *expired* token here because its
      // `exp` check is unconditional when the claim is present; a token with
      // no `exp` at all is accepted, which is exactly why this entry point
      // must never guard a route.
      const { payload } = await jwtVerify(token, jwks, { algorithms: ['EdDSA'] });
      return payload as unknown as AxiamClaims;
    },

    async verifyIdToken(token: string, expectations: IdTokenExpectations): Promise<IdTokenClaims> {
      const { decodeProtectedHeader, jwtVerify } = await import('jose');

      // §12.4 rule 1 — read `alg` from the header and reject anything but
      // EdDSA BEFORE touching the JWKS or the signature. A malformed token
      // (not three base64url segments) cannot even yield a header, which is
      // itself an `invalid_alg` failure: no algorithm was assertable.
      let header: { alg?: string; kid?: string };
      try {
        header = decodeProtectedHeader(token);
      } catch {
        throw idTokenAuthError('invalid_alg', 'token is not a well-formed JWS');
      }
      assertIdTokenAlg(header.alg);

      // §12.4 rule 2 — a token with no `kid` is rejected outright: there is
      // no key to select, and guessing "the only key" would defeat rotation.
      if (!header.kid) {
        throw idTokenAuthError('unknown_kid', 'token carries no kid header');
      }

      const jwks = await getJwks();
      const skew = resolveClockSkewSec(expectations.clockSkewSec);
      let claims: IdTokenClaims;
      try {
        // `algorithms` is passed again (belt and braces with rule 1) so jose
        // can never be talked into another algorithm either. `clockTolerance`
        // keeps jose's own exp/nbf checks aligned with rule 5's bound; the
        // explicit re-checks in checkIdTokenClaims cover iat and give each
        // failure its own reason code.
        const { payload } = await jwtVerify(token, jwks, {
          algorithms: [ID_TOKEN_ALG],
          clockTolerance: skew,
        });
        claims = payload as unknown as IdTokenClaims;
      } catch (err) {
        throw mapJoseVerifyError(err);
      }

      return checkIdTokenClaims(claims, { ...expectations, clockSkewSec: skew });
    },
  };
}

/**
 * CONTRACT.md §10.1 rule 4 — assert the token's `tenant_id` claim against the
 * tenant the relying party is configured for.
 *
 * Exported so the §10 middleware can re-assert it on the guard side, where it
 * cannot be bypassed by a caller-supplied {@link Verifier} implementation
 * that ignores its expectations.
 *
 * @param claim - the raw `tenant_id` claim value off the verified payload.
 * @param expected - the configured tenant.
 * @throws AuthError when no tenant is configured, when the claim is absent or
 * not a non-empty string, or when the two differ.
 */
export function assertTenantClaim(claim: unknown, expected: string | undefined): void {
  if (typeof expected !== 'string' || expected === '') {
    throw new AuthError(
      'no configured tenant to verify the token against; refusing the request ' +
        '(CONTRACT.md §10.1 rule 4 fails closed)',
    );
  }
  if (typeof claim !== 'string' || claim === '') {
    throw new AuthError('invalid tenant_id claim');
  }
  if (claim !== expected) {
    throw new AuthError('token tenant_id does not match configured tenant');
  }
}

/**
 * Translate a `jose` verification failure into the §12.3 reason-code
 * vocabulary. jose's error `code` strings are stable public API
 * (`ERR_JWKS_NO_MATCHING_KEY`, `ERR_JWT_EXPIRED`, …); anything unrecognized
 * degrades to `invalid_signature`, the safest catch-all — an unclassifiable
 * verification failure is never treated as success.
 */
function mapJoseVerifyError(err: unknown): AuthError {
  const code = typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : '';
  switch (code) {
    case 'ERR_JWKS_NO_MATCHING_KEY':
      // jose has already performed its single re-fetch-then-fail dance here
      // (createRemoteJWKSet reloads once per cooldown window on an unmatched
      // kid) — exactly the §12.4 rule 2 / §10 policy.
      return idTokenAuthError('unknown_kid', 'no JWKS key matches the token kid');
    case 'ERR_JWT_EXPIRED':
      return idTokenAuthError('token_expired', 'exp is in the past');
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      return idTokenAuthError('token_expired', 'a time-based claim (nbf/iat) is not yet valid');
    default:
      return idTokenAuthError('invalid_signature', 'signature verification failed');
  }
}
