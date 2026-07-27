// ID-token claim validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.
//
// PURE logic only: no network, no jose, no crypto beyond a constant-time
// compare. The signature half of §12.4 (rules 1–2: `alg` allowlist, `kid`
// lookup, Ed25519 verification, single JWKS re-fetch) lives in node/jwks.ts,
// on the SAME verifier the §10 middleware already uses — §12 forbids forking
// it. This module holds rules 3–6 (issuer, audience, time, nonce) plus the
// reason-code vocabulary, so both halves can be unit-tested independently and
// ported as one pair.
//
// Every failure raises `AuthError` carrying one of the seven stable reason
// codes from §12.3 rule 3. Rule 7 (all-or-nothing discard) is enforced by the
// caller — `OidcClient.oidcExchange` never returns a token set whose ID token
// failed here, so `access_token`/`refresh_token` from the same response are
// dropped with it.

import { timingSafeEqual } from 'node:crypto';
import { AuthError, type IdTokenFailureReason } from '../core/index.js';

/**
 * The decoded, **already-validated** ID-token claim set carried by
 * {@link OidcTokenSet.idClaims} (CONTRACT.md §12.1).
 *
 * @remarks
 * Claim names are kept verbatim in their JWT/OIDC spelling (`iss`, `sub`,
 * `aud`, …) rather than camelCased: they are protocol identifiers a caller
 * cross-references against OIDC Core, exactly as {@link AxiamClaims} already
 * does for access-token claims. The open index signature is mandated by
 * §12.1 — the ID token's full claim set is not enumerated by `openapi.json`,
 * so unknown claims MUST be preserved and MUST NOT be rejected.
 */
export interface IdTokenClaims {
  /** Issuer — matched for exact string equality against the discovery document's `issuer` (§12.4 rule 3). */
  iss: string;
  /** Subject — the authenticated end user's stable identifier at AXIAM. */
  sub: string;
  /** Audience — contains the relying party's `client_id` (§12.4 rule 4). */
  aud: string | string[];
  /** Expiry time (epoch seconds). */
  exp: number;
  /** Issued-at time (epoch seconds). */
  iat: number;
  /** Not-before time (epoch seconds), when the server sends one. */
  nbf?: number;
  /** The `nonce` echoed back from the authorization request (§12.4 rule 6). */
  nonce?: string;
  /** Authorized party — required to equal `client_id` when `aud` holds multiple audiences (§12.4 rule 4). */
  azp?: string;
  /** Any further claim the server sends (e.g. `email`, `preferred_username`) — preserved, never rejected (§12.1). */
  [claim: string]: unknown;
}

/**
 * What an ID token is checked against by {@link IdTokenVerifier.verifyIdToken}
 * (CONTRACT.md §12.4 rules 3–6).
 */
export interface IdTokenExpectations {
  /**
   * The authoritative issuer — always the `issuer` value of the discovery
   * document the token endpoint was read from, never the client base URL
   * (§12.3 rule 6: behind a proxy the two legitimately differ).
   */
  issuer: string;
  /** The relying party's own `client_id`, matched against `aud`/`azp` (rule 4). */
  clientId: string;
  /**
   * The `nonce` returned by `oidcBegin` and passed back into `oidcExchange`.
   *
   * Mandatory for `oidcExchange`. Left `undefined` by `oidcRefresh` and
   * `loginClientCredentials`, which skip rule 6 entirely — OIDC Core §12.2
   * does not require a `nonce` in a refresh-issued ID token.
   */
  nonce?: string;
  /**
   * Permitted clock skew in seconds for `exp`/`iat`/`nbf` (rule 5). Defaults
   * to {@link MAX_CLOCK_SKEW_SEC} and is clamped to it — the contract forbids
   * configuring it *above* 60 s, so a larger value is silently reduced rather
   * than honoured.
   */
  clockSkewSec?: number;
}

/**
 * Maximum (and default) permitted clock skew in seconds for ID-token time
 * claims. CONTRACT.md §12.4 rule 5 caps this at 60 s and forbids any
 * configuration above the bound.
 */
export const MAX_CLOCK_SKEW_SEC = 60;

/**
 * Build the `AuthError` for a §12.4 failure: a stable machine-readable
 * `reason` code plus a human-readable message that — per §12.3 rule 3 and §2's
 * construction rules — never embeds the token, a claim value that could carry
 * secret material, or the expected nonce.
 */
export function idTokenAuthError(reason: IdTokenFailureReason, message: string): AuthError {
  return new AuthError(`id_token validation failed (${reason}): ${message}`, reason);
}

/**
 * Resolve the effective clock skew: the caller's value clamped into
 * `[0, MAX_CLOCK_SKEW_SEC]`, or the maximum when unset.
 */
export function resolveClockSkewSec(clockSkewSec?: number): number {
  if (clockSkewSec === undefined) {
    return MAX_CLOCK_SKEW_SEC;
  }
  return Math.min(Math.max(clockSkewSec, 0), MAX_CLOCK_SKEW_SEC);
}

/**
 * Constant-time string equality, used for the `nonce` comparison §12.4 rule 6
 * requires. A length mismatch short-circuits to `false` (`timingSafeEqual`
 * throws on unequal-length buffers) — the same idiom
 * `middleware/cookieHeader.ts` and `amqp/hmac.ts` already use.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

/** Reject the JOSE header `alg` unless it is exactly `EdDSA` (§12.4 rule 1). */
export const ID_TOKEN_ALG = 'EdDSA';

/**
 * §12.4 rule 1 — algorithm check, run against the JOSE **header** and BEFORE
 * any signature work, so the token can never select its own verification
 * algorithm. `none` is rejected by the same equality test as every other
 * non-`EdDSA` value; it gets no special case and no separate code path.
 */
export function assertIdTokenAlg(alg: unknown): void {
  if (alg !== ID_TOKEN_ALG) {
    throw idTokenAuthError(
      'invalid_alg',
      `expected alg "${ID_TOKEN_ALG}", got ${typeof alg === 'string' ? `"${alg}"` : 'no alg header'}`,
    );
  }
}

/**
 * §12.4 rules 3–6 — issuer, audience, time and nonce checks over an
 * already-signature-verified claim set. Returns the claims unchanged on
 * success; throws the matching `AuthError` reason code on the first failure.
 *
 * @param claims the verified JWT payload.
 * @param expectations issuer/client_id/nonce to check against.
 * @param nowSec current time in epoch seconds — injectable so tests can pin it.
 */
export function checkIdTokenClaims(
  claims: IdTokenClaims,
  expectations: IdTokenExpectations,
  nowSec: number = Math.floor(Date.now() / 1000),
): IdTokenClaims {
  const skew = resolveClockSkewSec(expectations.clockSkewSec);

  // Rule 3 — exact string comparison. No normalization, no trailing-slash
  // tolerance, no prefix matching.
  if (claims.iss !== expectations.issuer) {
    throw idTokenAuthError('invalid_issuer', 'iss does not equal the discovery document issuer');
  }

  // Rule 4 — aud must contain our client_id; with multiple audiences an azp
  // claim must be present and equal to it.
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(expectations.clientId)) {
    throw idTokenAuthError('invalid_audience', 'aud does not contain this client_id');
  }
  if (audiences.length > 1 && claims.azp !== expectations.clientId) {
    throw idTokenAuthError(
      'invalid_audience',
      'aud holds multiple audiences and azp is absent or does not equal this client_id',
    );
  }

  // Rule 5 — exp must be in the future, iat must not be in the future, nbf is
  // honored when present; all within `skew` seconds. `exp` is treated as
  // REQUIRED: a token with no expiry could never satisfy "exp must be in the
  // future", so its absence is an expiry failure rather than a free pass.
  if (typeof claims.exp !== 'number') {
    throw idTokenAuthError('token_expired', 'exp claim is missing or not a number');
  }
  if (claims.exp + skew <= nowSec) {
    throw idTokenAuthError('token_expired', 'exp is in the past');
  }
  if (typeof claims.iat !== 'number') {
    throw idTokenAuthError('token_expired', 'iat claim is missing or not a number');
  }
  if (claims.iat - skew > nowSec) {
    throw idTokenAuthError('token_expired', 'iat is in the future');
  }
  if (typeof claims.nbf === 'number' && claims.nbf - skew > nowSec) {
    throw idTokenAuthError('token_expired', 'nbf is in the future');
  }

  // Rule 6 — mandatory for oidcExchange, skipped when the caller supplied no
  // expected nonce (oidcRefresh / loginClientCredentials).
  if (expectations.nonce !== undefined) {
    if (typeof claims.nonce !== 'string' || !constantTimeEquals(claims.nonce, expectations.nonce)) {
      throw idTokenAuthError('nonce_mismatch', 'nonce claim is absent or does not match the request nonce');
    }
  }

  return claims;
}
