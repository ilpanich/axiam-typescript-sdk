// Unit tests for the pure §12.4 claim-check half of ID-token validation
// (rules 3–6 plus the reason-code vocabulary). The signature half (rules 1–2)
// is exercised end-to-end in oidcExchange.test.ts.

import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/index.js';
import {
  assertIdTokenAlg,
  checkIdTokenClaims,
  constantTimeEquals,
  ID_TOKEN_ALG,
  idTokenAuthError,
  MAX_CLOCK_SKEW_SEC,
  resolveClockSkewSec,
  type IdTokenClaims,
} from '../../src/node/oidcIdToken.js';

const NOW = 1_800_000_000;

function claims(overrides: Partial<IdTokenClaims> = {}): IdTokenClaims {
  return {
    iss: 'https://iam.example.com',
    sub: 'user-1',
    aud: 'axiam-rp',
    exp: NOW + 3600,
    iat: NOW,
    nonce: 'nonce-value',
    ...overrides,
  };
}

const expectations = { issuer: 'https://iam.example.com', clientId: 'axiam-rp', nonce: 'nonce-value' };

describe('assertIdTokenAlg (§12.4 rule 1)', () => {
  it('accepts EdDSA', () => {
    expect(() => assertIdTokenAlg(ID_TOKEN_ALG)).not.toThrow();
  });

  it.each(['none', 'HS256', 'RS256', 'ES256', 'EDDSA', ''])('rejects "%s"', (alg) => {
    expect(() => assertIdTokenAlg(alg)).toThrow(/invalid_alg/);
  });

  it('rejects a missing alg header', () => {
    expect(() => assertIdTokenAlg(undefined)).toThrow(/no alg header/);
  });
});

describe('resolveClockSkewSec (§12.4 rule 5)', () => {
  it('defaults to the 60-second maximum', () => {
    expect(resolveClockSkewSec(undefined)).toBe(MAX_CLOCK_SKEW_SEC);
    expect(MAX_CLOCK_SKEW_SEC).toBe(60);
  });

  it('clamps a value above the maximum — the bound is not configurable upward', () => {
    expect(resolveClockSkewSec(3600)).toBe(60);
  });

  it('honours a smaller value and floors a negative one at zero', () => {
    expect(resolveClockSkewSec(5)).toBe(5);
    expect(resolveClockSkewSec(-10)).toBe(0);
  });
});

describe('constantTimeEquals (§12.4 rule 6)', () => {
  it('is true for equal strings and false for different ones', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
  });

  it('returns false rather than throwing on a length mismatch', () => {
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
    expect(constantTimeEquals('', 'a')).toBe(false);
  });
});

describe('idTokenAuthError (§12.3 rule 3)', () => {
  it('produces an AuthError carrying the stable reason code', () => {
    const error = idTokenAuthError('invalid_issuer', 'iss mismatch');
    expect(error).toBeInstanceOf(AuthError);
    expect(error.reason).toBe('invalid_issuer');
    expect(error.message).toContain('invalid_issuer');
  });
});

describe('checkIdTokenClaims (§12.4 rules 3–6)', () => {
  it('returns the claims unchanged when every rule passes', () => {
    const input = claims();
    expect(checkIdTokenClaims(input, expectations, NOW)).toBe(input);
  });

  it('rule 3 — rejects any issuer difference, including a trailing slash', () => {
    expect(() => checkIdTokenClaims(claims({ iss: 'https://iam.example.com/' }), expectations, NOW)).toThrow(
      /invalid_issuer/,
    );
    expect(() => checkIdTokenClaims(claims({ iss: 'https://iam.example.com' }), { ...expectations, issuer: 'https://iam.example.com/x' }, NOW)).toThrow(
      /invalid_issuer/,
    );
  });

  it('rule 4 — accepts a single matching audience and an array containing it', () => {
    expect(() => checkIdTokenClaims(claims({ aud: 'axiam-rp' }), expectations, NOW)).not.toThrow();
    expect(() => checkIdTokenClaims(claims({ aud: ['axiam-rp'] }), expectations, NOW)).not.toThrow();
  });

  it('rule 4 — rejects a wrong audience', () => {
    expect(() => checkIdTokenClaims(claims({ aud: 'other' }), expectations, NOW)).toThrow(/invalid_audience/);
    expect(() => checkIdTokenClaims(claims({ aud: [] }), expectations, NOW)).toThrow(/invalid_audience/);
  });

  it('rule 4 — with multiple audiences, requires azp to equal the client_id', () => {
    const multi = { aud: ['axiam-rp', 'other-rp'] };
    expect(() => checkIdTokenClaims(claims(multi), expectations, NOW)).toThrow(/invalid_audience/);
    expect(() => checkIdTokenClaims(claims({ ...multi, azp: 'other-rp' }), expectations, NOW)).toThrow(
      /invalid_audience/,
    );
    expect(() =>
      checkIdTokenClaims(claims({ ...multi, azp: 'axiam-rp' }), expectations, NOW),
    ).not.toThrow();
  });

  it('rule 5 — rejects a missing or non-numeric exp/iat', () => {
    expect(() =>
      checkIdTokenClaims(claims({ exp: undefined as unknown as number }), expectations, NOW),
    ).toThrow(/token_expired/);
    expect(() =>
      checkIdTokenClaims(claims({ iat: 'soon' as unknown as number }), expectations, NOW),
    ).toThrow(/token_expired/);
  });

  it('rule 5 — allows up to 60 s of skew on exp but no more', () => {
    // Expired 30 s ago: inside the allowance.
    expect(() => checkIdTokenClaims(claims({ exp: NOW - 30 }), expectations, NOW)).not.toThrow();
    // Expired 61 s ago: outside it.
    expect(() => checkIdTokenClaims(claims({ exp: NOW - 61 }), expectations, NOW)).toThrow(/token_expired/);
  });

  it('rule 5 — allows up to 60 s of skew on a future iat but no more', () => {
    expect(() => checkIdTokenClaims(claims({ iat: NOW + 30 }), expectations, NOW)).not.toThrow();
    expect(() => checkIdTokenClaims(claims({ iat: NOW + 61 }), expectations, NOW)).toThrow(/token_expired/);
  });

  it('rule 5 — honours nbf when present', () => {
    expect(() => checkIdTokenClaims(claims({ nbf: NOW + 30 }), expectations, NOW)).not.toThrow();
    expect(() => checkIdTokenClaims(claims({ nbf: NOW + 600 }), expectations, NOW)).toThrow(
      /token_expired/,
    );
  });

  it('rule 5 — a caller-narrowed skew is respected', () => {
    expect(() =>
      checkIdTokenClaims(claims({ exp: NOW - 30 }), { ...expectations, clockSkewSec: 5 }, NOW),
    ).toThrow(/token_expired/);
  });

  it('rule 6 — rejects a mismatched, missing, or non-string nonce', () => {
    expect(() => checkIdTokenClaims(claims({ nonce: 'other' }), expectations, NOW)).toThrow(
      /nonce_mismatch/,
    );
    expect(() => checkIdTokenClaims(claims({ nonce: undefined }), expectations, NOW)).toThrow(
      /nonce_mismatch/,
    );
    expect(() =>
      checkIdTokenClaims(claims({ nonce: 42 as unknown as string }), expectations, NOW),
    ).toThrow(/nonce_mismatch/);
  });

  it('rule 6 — is skipped when the caller expects no nonce (oidcRefresh path)', () => {
    const noNonceExpectations = { issuer: expectations.issuer, clientId: expectations.clientId };
    expect(() => checkIdTokenClaims(claims({ nonce: undefined }), noNonceExpectations, NOW)).not.toThrow();
    expect(() => checkIdTokenClaims(claims({ nonce: 'anything' }), noNonceExpectations, NOW)).not.toThrow();
  });

  it('never embeds the expected nonce or a claim value in the error message (§2, §12.3 rule 3)', () => {
    const error = checkIdTokenClaims.bind(null, claims({ nonce: 'wrong-value' }), expectations, NOW);
    expect(error).toThrow();
    try {
      error();
    } catch (err) {
      const message = (err as AuthError).message;
      expect(message).not.toContain('nonce-value');
      expect(message).not.toContain('wrong-value');
    }
  });

  it('defaults `now` to the current clock when not injected', () => {
    const nowSec = Math.floor(Date.now() / 1000);
    expect(() => checkIdTokenClaims(claims({ exp: nowSec + 60, iat: nowSec }), expectations)).not.toThrow();
  });
});
