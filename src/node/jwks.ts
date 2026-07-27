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

import type { AuthError } from '../core/index.js';
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

/** Verifies an AXIAM access token's EdDSA signature against the org-wide remote JWKS. */
export interface Verifier {
  /** Verify `token` against the cached JWKS (EdDSA only) and return its claims; rejects any invalid/expired/wrong-algorithm token. */
  verifyAccessToken(token: string): Promise<AxiamClaims>;
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
    async verifyAccessToken(token: string): Promise<AxiamClaims> {
      const { jwtVerify } = await import('jose');
      const jwks = await getJwks();
      // Explicit algorithm allowlist — never trust the token's own `alg`
      // header; defense against algorithm-confusion attacks (T-17-14).
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
